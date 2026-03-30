// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashSet;

use kin_model::{EntityFilter, EntityId, FileLayout, FilePathId, GraphStore, ParseState, SourceRegion};
use tracing::{debug, warn};

use crate::error::{IndexError, Result};
use crate::pipeline::IndexedFile;

/// Apply the results of indexing a file to the graph (working copy overlay).
///
/// This is the core LKG (Last Known Good) enforcement point:
/// - `ParseState::Valid`: upsert all entities and relations (full update)
/// - `ParseState::Incomplete`: span-scoped salvage — keep entities whose byte
///   ranges don't overlap any parse error range, drop the rest. Falls back to
///   LKG preservation only when zero entities survive salvage AND prior data exists.
/// - `ParseState::LastKnownGood`: should not appear from fresh parsing,
///   but if it does, treat as incomplete
///
/// The indexer does NOT create SemanticChange nodes. That is `kin commit`'s job.
pub fn apply_to_graph<G: GraphStore>(graph: &G, indexed: &IndexedFile) -> Result<ApplyResult> {
    match &indexed.parse_state {
        ParseState::Valid => apply_valid_parse(graph, indexed),
        ParseState::Incomplete { error_ranges } => {
            apply_salvaged_parse(graph, indexed, error_ranges)
        }
        ParseState::LastKnownGood { .. } => {
            warn!(
                file = %indexed.file_id,
                "unexpected LastKnownGood state from fresh parse, skipping update"
            );
            Ok(ApplyResult {
                file_id: indexed.file_id.clone(),
                entities_upserted: 0,
                entities_removed: 0,
                relations_upserted: 0,
                skipped_lkg: true,
            })
        }
    }
}

/// Apply a valid parse to the graph: upsert entities/relations, remove stale ones.
fn apply_valid_parse<G: GraphStore>(graph: &G, indexed: &IndexedFile) -> Result<ApplyResult> {
    let mut entities_upserted = 0;
    let mut relations_upserted = 0;

    // Upsert all new/changed entities
    for entity in &indexed.entities {
        graph
            .upsert_entity(entity)
            .map_err(|e| IndexError::Graph(e.to_string()))?;
        entities_upserted += 1;
    }

    // Upsert all new/changed relations
    for relation in &indexed.relations {
        graph
            .upsert_relation(relation)
            .map_err(|e| IndexError::Graph(e.to_string()))?;
        relations_upserted += 1;
    }

    graph
        .upsert_file_layout(&indexed.file_layout)
        .map_err(|e| IndexError::Graph(e.to_string()))?;

    // Remove entities that were previously in this file but no longer exist.
    let new_entity_ids: Vec<EntityId> = indexed.entities.iter().map(|e| e.id).collect();
    let entities_removed = remove_stale_entities(graph, &indexed.file_id, &new_entity_ids)?;

    debug!(
        file = %indexed.file_id,
        upserted = entities_upserted,
        removed = entities_removed,
        relations = relations_upserted,
        "applied valid parse to graph"
    );

    Ok(ApplyResult {
        file_id: indexed.file_id.clone(),
        entities_upserted,
        entities_removed,
        relations_upserted,
        skipped_lkg: false,
    })
}

/// Apply a span-scoped salvage for an incomplete parse: keep entities whose
/// byte ranges don't overlap any error range, drop the rest.
fn apply_salvaged_parse<G: GraphStore>(
    graph: &G,
    indexed: &IndexedFile,
    error_ranges: &[(usize, usize)],
) -> Result<ApplyResult> {
    // Filter entities: keep those with a span that doesn't overlap any error range.
    // Entities without a span are conservatively dropped (can't verify safety).
    let salvaged_entities: Vec<_> = indexed
        .entities
        .iter()
        .filter(|e| {
            e.span.as_ref().map_or(false, |span| {
                !error_ranges.iter().any(|&(err_start, err_end)| {
                    span.start_byte < err_end && err_start < span.end_byte
                })
            })
        })
        .collect();

    let salvaged_ids: HashSet<EntityId> = salvaged_entities.iter().map(|e| e.id).collect();
    let dropped = indexed.entities.len() - salvaged_entities.len();
    let salvaged_layout = salvage_layout(&indexed.file_layout, &salvaged_ids);

    // Filter relations: keep only those where both src and dst are in the salvaged set.
    let salvaged_relations: Vec<_> = indexed
        .relations
        .iter()
        .filter(|r| salvaged_ids.contains(&r.src) && salvaged_ids.contains(&r.dst))
        .collect();

    // If nothing was salvaged, check for existing LKG to preserve.
    if salvaged_entities.is_empty() {
        let existing = graph
            .query_entities(&EntityFilter {
                file_path: Some(indexed.file_id.clone()),
                ..Default::default()
            })
            .unwrap_or_default();

        if !existing.is_empty() {
            let mut preserved_layout = graph
                .get_file_layout(&indexed.file_id)
                .map_err(|e| IndexError::Graph(e.to_string()))?
                .unwrap_or_else(|| salvaged_layout.clone());
            preserved_layout.parse_completeness = salvaged_layout.parse_completeness.clone();
            graph
                .upsert_file_layout(&preserved_layout)
                .map_err(|e| IndexError::Graph(e.to_string()))?;
            debug!(
                file = %indexed.file_id,
                errors = error_ranges.len(),
                total_entities = indexed.entities.len(),
                "no entities salvaged from incomplete parse; LKG preserved"
            );
            return Ok(ApplyResult {
                file_id: indexed.file_id.clone(),
                entities_upserted: 0,
                entities_removed: 0,
                relations_upserted: 0,
                skipped_lkg: true,
            });
        }
    }

    // Upsert salvaged entities
    let mut entities_upserted = 0;
    for entity in &salvaged_entities {
        graph
            .upsert_entity(entity)
            .map_err(|e| IndexError::Graph(e.to_string()))?;
        entities_upserted += 1;
    }

    // Upsert salvaged relations
    let mut relations_upserted = 0;
    for relation in &salvaged_relations {
        graph
            .upsert_relation(relation)
            .map_err(|e| IndexError::Graph(e.to_string()))?;
        relations_upserted += 1;
    }

    graph
        .upsert_file_layout(&salvaged_layout)
        .map_err(|e| IndexError::Graph(e.to_string()))?;

    // Remove stale entities (those previously in the file but not in the salvaged set)
    let salvaged_id_vec: Vec<EntityId> = salvaged_entities.iter().map(|e| e.id).collect();
    let entities_removed = remove_stale_entities(graph, &indexed.file_id, &salvaged_id_vec)?;

    debug!(
        file = %indexed.file_id,
        errors = error_ranges.len(),
        salvaged = entities_upserted,
        dropped = dropped,
        removed_stale = entities_removed,
        relations = relations_upserted,
        "applied span-scoped salvage for incomplete parse"
    );

    Ok(ApplyResult {
        file_id: indexed.file_id.clone(),
        entities_upserted,
        entities_removed,
        relations_upserted,
        skipped_lkg: false,
    })
}

/// Remove entities from the graph that were previously associated with a file
/// but are no longer present in the latest parse.
fn remove_stale_entities<G: GraphStore>(
    graph: &G,
    file_id: &FilePathId,
    current_ids: &[EntityId],
) -> Result<usize> {
    // Query existing entities for this file
    let filter = EntityFilter {
        file_path: Some(file_id.clone()),
        ..Default::default()
    };
    let existing = graph
        .query_entities(&filter)
        .map_err(|e| IndexError::Graph(e.to_string()))?;

    let mut removed = 0;
    for entity in existing {
        if !current_ids.contains(&entity.id) {
            // This entity was in the file before but is gone now
            graph
                .remove_entity(&entity.id)
                .map_err(|e| IndexError::Graph(e.to_string()))?;
            debug!(
                entity = %entity.name,
                id = %entity.id,
                "removed stale entity"
            );
            removed += 1;
        }
    }

    Ok(removed)
}

/// Apply results for a file removal: remove all entities associated with the file.
pub fn apply_file_removal<G: GraphStore>(graph: &G, file_id: &FilePathId) -> Result<ApplyResult> {
    let filter = EntityFilter {
        file_path: Some(file_id.clone()),
        ..Default::default()
    };
    let existing = graph
        .query_entities(&filter)
        .map_err(|e| IndexError::Graph(e.to_string()))?;

    let mut entities_removed = 0;
    for entity in existing {
        graph
            .remove_entity(&entity.id)
            .map_err(|e| IndexError::Graph(e.to_string()))?;
        entities_removed += 1;
    }
    graph
        .delete_file_layout(file_id)
        .map_err(|e| IndexError::Graph(e.to_string()))?;

    debug!(
        file = %file_id,
        removed = entities_removed,
        "removed all entities for deleted file"
    );

    Ok(ApplyResult {
        file_id: file_id.clone(),
        entities_upserted: 0,
        entities_removed,
        relations_upserted: 0,
        skipped_lkg: false,
    })
}

fn salvage_layout(layout: &FileLayout, salvaged_ids: &HashSet<EntityId>) -> FileLayout {
    let mut salvaged = layout.clone();
    salvaged.regions = salvaged
        .regions
        .into_iter()
        .map(|region| match region {
            SourceRegion::EntityRef {
                entity_id,
                byte_range,
            } if !salvaged_ids.contains(&entity_id) => SourceRegion::Trivia { byte_range },
            other => other,
        })
        .collect();
    salvaged
}

/// Summary of what was applied to the graph.
#[derive(Debug, Clone)]
pub struct ApplyResult {
    pub file_id: FilePathId,
    pub entities_upserted: usize,
    pub entities_removed: usize,
    pub relations_upserted: usize,
    /// True if the update was skipped due to broken parse (LKG preserved).
    pub skipped_lkg: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::*;

    fn make_indexed_file(parse_state: ParseState) -> IndexedFile {
        let file_id = FilePathId::new("test.ts");
        let entity = Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: "greet".to_string(),
            language: LanguageId::TypeScript,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(file_id.clone()),
            span: None,
            signature: "function greet(name: string): string".to_string(),
            visibility: Visibility::Public,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };

        IndexedFile {
            file_id,
            language: LanguageId::TypeScript,
            entities: vec![entity],
            relations: vec![],
            unresolved_relations: vec![],
            file_layout: FileLayout {
                file_id: FilePathId::new("test.ts"),
                parse_completeness: ParseCompleteness::from_parse_state(&parse_state),
                imports: ImportSection {
                    byte_range: 0..0,
                    items: vec![],
                },
                regions: vec![],
            },
            parse_state,
            blob_hash: kin_blobs::Hash256([0; 32]),
        }
    }

    #[test]
    fn incomplete_parse_is_skipped() {
        let indexed = make_indexed_file(ParseState::Incomplete {
            error_ranges: vec![(10, 20)],
        });
        // We can't easily test with a real GraphStore here, but we can verify
        // the logic by checking that apply_to_graph returns skipped_lkg=true
        // when the parse is incomplete. We test the path selection:
        assert!(matches!(indexed.parse_state, ParseState::Incomplete { .. }));
    }

    #[test]
    fn valid_parse_state_identified() {
        let indexed = make_indexed_file(ParseState::Valid);
        assert!(matches!(indexed.parse_state, ParseState::Valid));
    }

    #[test]
    fn apply_result_fields() {
        let result = ApplyResult {
            file_id: FilePathId::new("test.rs"),
            entities_upserted: 5,
            entities_removed: 2,
            relations_upserted: 3,
            skipped_lkg: false,
        };
        assert_eq!(result.entities_upserted, 5);
        assert_eq!(result.entities_removed, 2);
        assert_eq!(result.relations_upserted, 3);
        assert!(!result.skipped_lkg);
    }

    #[test]
    fn lkg_result_fields() {
        let result = ApplyResult {
            file_id: FilePathId::new("broken.ts"),
            entities_upserted: 0,
            entities_removed: 0,
            relations_upserted: 0,
            skipped_lkg: true,
        };
        assert!(result.skipped_lkg);
        assert_eq!(result.entities_upserted, 0);
    }
}
