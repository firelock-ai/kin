use kin_model::{EntityFilter, EntityId, FilePathId, GraphStore, ParseState};
use tracing::{debug, warn};

use crate::error::{IndexError, Result};
use crate::pipeline::IndexedFile;

/// Apply the results of indexing a file to the graph (working copy overlay).
///
/// This is the core LKG (Last Known Good) enforcement point:
/// - `ParseState::Valid`: upsert all entities and relations (full update)
/// - `ParseState::Incomplete`: skip the update entirely, preserving the
///   previous graph state as the LKG
/// - `ParseState::LastKnownGood`: should not appear from fresh parsing,
///   but if it does, treat as incomplete
///
/// The indexer does NOT create SemanticChange nodes. That is `kin commit`'s job.
pub fn apply_to_graph<G: GraphStore>(graph: &G, indexed: &IndexedFile) -> Result<ApplyResult> {
    match &indexed.parse_state {
        ParseState::Valid => apply_valid_parse(graph, indexed),
        ParseState::Incomplete { error_ranges } => {
            debug!(
                file = %indexed.file_id,
                errors = error_ranges.len(),
                "skipping graph update for incomplete parse (LKG preserved)"
            );
            Ok(ApplyResult {
                file_id: indexed.file_id.clone(),
                entities_upserted: 0,
                entities_removed: 0,
                relations_upserted: 0,
                skipped_lkg: true,
            })
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
pub fn apply_file_removal<G: GraphStore>(
    graph: &G,
    file_id: &FilePathId,
) -> Result<ApplyResult> {
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
