// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Cross-repo edge resolution.
//!
//! Uses dependency-level data (Tier 2-5: Cargo.toml, package.json, go.mod)
//! to narrow candidate repos, then resolves specific entity references using
//! the spine's metadata index.
//!
//! Language-aware strategy:
//! - Rust: `use kin_db::InMemoryGraph` → crate name = repo, path = module (unambiguous)
//! - TypeScript: `import { X } from 'package'` → package.json resolves package → repo
//! - Python: `from utils import Config` → check deps → if only one has utils.Config, resolve
//!   If ambiguous, create candidate edges ranked by confidence score.

use std::collections::HashSet;

use crate::index::{fingerprint_match_score, CrossRepoEdge, EntityEntry, SpineIndex};
use kin_model::{Entity, EntityId, EntityKind, Relation, RelationKind, SemanticFingerprint};

/// A detected cross-repo import that can potentially be resolved.
#[derive(Debug, Clone)]
pub struct UnresolvedImport {
    /// The repo containing the import statement.
    pub source_repo: String,
    /// The entity that contains the import.
    pub source_entity: EntityId,
    /// The imported name (e.g., "InMemoryGraph", "Config").
    pub imported_name: String,
    /// The imported kind, if known.
    pub imported_kind: Option<EntityKind>,
    /// Candidate target repos (from Tier 2-5 dependency analysis).
    pub candidate_repos: Vec<String>,
    /// Language hint for resolution strategy.
    pub language: Option<String>,
    /// Reference fingerprint from the import site for disambiguation.
    pub reference_fingerprint: Option<SemanticFingerprint>,
    /// Import source module name from Relation.import_source.
    /// When set, the spine uses this to narrow resolution to repos matching this module.
    pub import_source: Option<String>,
}

/// Result of attempting to resolve an import.
#[derive(Debug, Clone)]
pub enum ResolveResult {
    /// Exact match — one entity in one repo.
    Resolved {
        target_repo: String,
        target_entity: EntityId,
        confidence: f32,
    },
    /// Multiple candidates — create edges for each, ranked by confidence.
    Ambiguous {
        candidates: Vec<(String, EntityId, f32)>,
    },
    /// No match found in any candidate repo.
    NotFound,
}

/// Resolve a batch of cross-repo imports against the spine index.
///
/// Resolution order (per import):
/// 1. If `import_source` is set AND matches a registry repo name → resolve ONLY
///    in that repo with high confidence (0.95)
/// 2. If `import_source` is set but doesn't match directly → use it to filter
///    `candidate_repos` (medium confidence 0.8)
/// 3. Fall back to current behavior: name+kind+fingerprint across all candidates
pub fn resolve_imports(
    index: &SpineIndex,
    imports: &[UnresolvedImport],
) -> Vec<(usize, ResolveResult)> {
    let mut results = Vec::with_capacity(imports.len());
    let registered_repos = index.registered_repo_ids();

    for (i, import) in imports.iter().enumerate() {
        let result = resolve_single(index, import, &registered_repos);
        results.push((i, result));
    }

    results
}

/// Resolve a single import using the 3-tier strategy.
fn resolve_single(
    index: &SpineIndex,
    import: &UnresolvedImport,
    registered_repos: &HashSet<String>,
) -> ResolveResult {
    // Tier 1: import_source directly matches a registry repo name
    if let Some(ref source) = import.import_source {
        if registered_repos.contains(source.as_str()) {
            let matches = index.resolve(
                &import.imported_name,
                import.imported_kind,
                import.reference_fingerprint.as_ref(),
            );
            let in_source: Vec<&EntityEntry> =
                matches.iter().filter(|e| e.repo_id == *source).collect();

            match in_source.len() {
                0 => {} // Fall through to tier 2/3
                1 => {
                    return ResolveResult::Resolved {
                        target_repo: in_source[0].repo_id.clone(),
                        target_entity: in_source[0].entity_id,
                        confidence: 0.95,
                    };
                }
                _ => {
                    // Multiple in that repo — still high confidence, return best match
                    let candidates: Vec<(String, EntityId, f32)> = in_source
                        .iter()
                        .map(|e| (e.repo_id.clone(), e.entity_id, 0.95))
                        .collect();
                    return ResolveResult::Ambiguous { candidates };
                }
            }
        }

        // Tier 2: import_source set but doesn't match a repo directly —
        // use it to filter candidate_repos (repos whose name contains the source)
        let source_lower = source.to_lowercase();
        let filtered_candidates: Vec<String> = if import.candidate_repos.is_empty() {
            registered_repos
                .iter()
                .filter(|r| r.to_lowercase().contains(&source_lower))
                .cloned()
                .collect()
        } else {
            import
                .candidate_repos
                .iter()
                .filter(|r| r.to_lowercase().contains(&source_lower))
                .cloned()
                .collect()
        };

        if !filtered_candidates.is_empty() {
            let matches = index.resolve(
                &import.imported_name,
                import.imported_kind,
                import.reference_fingerprint.as_ref(),
            );
            let in_filtered: Vec<&EntityEntry> = matches
                .iter()
                .filter(|e| filtered_candidates.contains(&e.repo_id))
                .collect();

            match in_filtered.len() {
                0 => {} // Fall through to tier 3
                1 => {
                    return ResolveResult::Resolved {
                        target_repo: in_filtered[0].repo_id.clone(),
                        target_entity: in_filtered[0].entity_id,
                        confidence: 0.8,
                    };
                }
                _ => {
                    let candidates: Vec<(String, EntityId, f32)> = in_filtered
                        .iter()
                        .map(|e| (e.repo_id.clone(), e.entity_id, 0.8))
                        .collect();
                    return ResolveResult::Ambiguous { candidates };
                }
            }
        }
    }

    // Tier 3: Fall back to name+kind+fingerprint across all candidate repos
    resolve_fallback(index, import)
}

/// Tier 3 fallback: original name+kind+fingerprint resolution.
fn resolve_fallback(index: &SpineIndex, import: &UnresolvedImport) -> ResolveResult {
    let matches = index.resolve(
        &import.imported_name,
        import.imported_kind,
        import.reference_fingerprint.as_ref(),
    );

    // Filter to candidate repos
    let filtered: Vec<&EntityEntry> = if import.candidate_repos.is_empty() {
        matches.iter().collect()
    } else {
        matches
            .iter()
            .filter(|e| import.candidate_repos.contains(&e.repo_id))
            .collect()
    };

    match filtered.len() {
        0 => ResolveResult::NotFound,
        1 => ResolveResult::Resolved {
            target_repo: filtered[0].repo_id.clone(),
            target_entity: filtered[0].entity_id,
            confidence: if import.candidate_repos.is_empty() {
                0.5
            } else {
                0.9
            },
        },
        _ => {
            let candidates: Vec<(String, EntityId, f32)> = filtered
                .iter()
                .map(|e| {
                    let confidence = if let Some(ref ref_fp) = import.reference_fingerprint {
                        let sim = fingerprint_match_score(&e.fingerprint, ref_fp) / 3.0;
                        let base = if import.candidate_repos.contains(&e.repo_id) {
                            0.4
                        } else {
                            0.1
                        };
                        base + 0.6 * sim
                    } else {
                        if import.candidate_repos.contains(&e.repo_id) {
                            0.7
                        } else {
                            0.3
                        }
                    };
                    (e.repo_id.clone(), e.entity_id, confidence)
                })
                .collect();
            ResolveResult::Ambiguous { candidates }
        }
    }
}

/// Convert resolved imports into cross-repo edges and add them to the spine index.
pub fn materialize_edges(
    index: &SpineIndex,
    imports: &[UnresolvedImport],
    resolutions: &[(usize, ResolveResult)],
) -> usize {
    let mut count = 0;

    for (i, result) in resolutions {
        let import = &imports[*i];

        match result {
            ResolveResult::Resolved {
                target_repo,
                target_entity,
                confidence,
            } => {
                index.add_cross_repo_edge(CrossRepoEdge {
                    src_repo: import.source_repo.clone(),
                    src_entity: import.source_entity,
                    dst_repo: target_repo.clone(),
                    dst_entity: *target_entity,
                    confidence: *confidence,
                });
                count += 1;
            }
            ResolveResult::Ambiguous { candidates } => {
                // Add edges for all candidates with their confidence scores
                for (repo, entity_id, confidence) in candidates {
                    index.add_cross_repo_edge(CrossRepoEdge {
                        src_repo: import.source_repo.clone(),
                        src_entity: import.source_entity,
                        dst_repo: repo.clone(),
                        dst_entity: *entity_id,
                        confidence: *confidence,
                    });
                    count += 1;
                }
            }
            ResolveResult::NotFound => {}
        }
    }

    count
}

/// Walk a repo's entity relations looking for Calls/References where:
/// - The dst entity doesn't exist in the local entity set (external reference)
/// - `import_source` is set on the relation
///
/// Produces `Vec<UnresolvedImport>` that feeds into `resolve_imports()`.
pub fn collect_unresolved_imports(
    entities: &[Entity],
    relations: &[Relation],
    repo_id: &str,
    registry_repo_ids: &[String],
) -> Vec<UnresolvedImport> {
    let local_ids: HashSet<EntityId> = entities.iter().map(|e| e.id).collect();
    let entity_map: std::collections::HashMap<EntityId, &Entity> =
        entities.iter().map(|e| (e.id, e)).collect();

    let mut imports = Vec::new();

    for rel in relations {
        // Only consider Calls and References edges
        if rel.kind != RelationKind::Calls && rel.kind != RelationKind::References {
            continue;
        }

        // dst must not exist locally (external reference)
        let Some(dst_entity_id) = rel.dst.as_entity() else {
            continue;
        };
        if local_ids.contains(&dst_entity_id) {
            continue;
        }

        // Must have import_source set
        let source = match &rel.import_source {
            Some(s) if !s.is_empty() => s.clone(),
            _ => continue,
        };

        // Look up the source entity for name/kind info
        let Some(src_entity_id) = rel.src.as_entity() else {
            continue;
        };
        let src_entity = match entity_map.get(&src_entity_id) {
            Some(e) => e,
            None => continue,
        };

        imports.push(UnresolvedImport {
            source_repo: repo_id.to_string(),
            source_entity: src_entity_id,
            imported_name: format!("{}", rel.dst), // entity name unknown, use graph node label
            imported_kind: None,
            candidate_repos: registry_repo_ids
                .iter()
                .filter(|r| r.as_str() != repo_id)
                .cloned()
                .collect(),
            language: Some(src_entity.language.to_string()),
            reference_fingerprint: None,
            import_source: Some(source),
        });
    }

    imports
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::EntityEntry;
    use kin_model::{FingerprintAlgorithm, Hash256, SemanticFingerprint};

    fn test_fp() -> SemanticFingerprint {
        SemanticFingerprint {
            ast_hash: Hash256::from_bytes([1; 32]),
            signature_hash: Hash256::from_bytes([2; 32]),
            behavior_hash: Hash256::from_bytes([3; 32]),
            algorithm: FingerprintAlgorithm::V1TreeSitter,
            stability_score: 1.0,
        }
    }

    fn test_entry(repo: &str, name: &str, kind: EntityKind) -> EntityEntry {
        EntityEntry {
            repo_id: repo.to_string(),
            entity_id: EntityId::new(),
            name: name.to_string(),
            kind,
            signature: format!("fn {name}()"),
            fingerprint: test_fp(),
            file_path: Some("src/lib.rs".to_string()),
        }
    }

    #[test]
    fn resolve_exact_match_with_dep_hint() {
        let index = SpineIndex::new();
        let target = test_entry("kin-db", "InMemoryGraph", EntityKind::Class);
        index.register_repo("kin-db", vec![target.clone()], "hash");

        let imports = vec![UnresolvedImport {
            source_repo: "kin".to_string(),
            source_entity: EntityId::new(),
            imported_name: "InMemoryGraph".to_string(),
            imported_kind: Some(EntityKind::Class),
            candidate_repos: vec!["kin-db".to_string()],
            language: Some("rust".to_string()),
            reference_fingerprint: None,
            import_source: None,
        }];

        let results = resolve_imports(&index, &imports);
        assert_eq!(results.len(), 1);
        match &results[0].1 {
            ResolveResult::Resolved {
                target_repo,
                confidence,
                ..
            } => {
                assert_eq!(target_repo, "kin-db");
                assert!(*confidence > 0.8);
            }
            other => panic!("expected Resolved, got {other:?}"),
        }
    }

    #[test]
    fn resolve_ambiguous_config() {
        let index = SpineIndex::new();
        index.register_repo(
            "repo-a",
            vec![test_entry("repo-a", "Config", EntityKind::Class)],
            "hash-a",
        );
        index.register_repo(
            "repo-b",
            vec![test_entry("repo-b", "Config", EntityKind::Class)],
            "hash-b",
        );

        let imports = vec![UnresolvedImport {
            source_repo: "repo-c".to_string(),
            source_entity: EntityId::new(),
            imported_name: "Config".to_string(),
            imported_kind: Some(EntityKind::Class),
            candidate_repos: vec!["repo-a".to_string(), "repo-b".to_string()],
            language: None,
            reference_fingerprint: None,
            import_source: None,
        }];

        let results = resolve_imports(&index, &imports);
        match &results[0].1 {
            ResolveResult::Ambiguous { candidates } => {
                assert_eq!(candidates.len(), 2);
            }
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    }

    #[test]
    fn materialize_creates_edges() {
        let index = SpineIndex::new();
        let target = test_entry("kin-db", "InMemoryGraph", EntityKind::Class);
        index.register_repo("kin-db", vec![target.clone()], "hash");

        let imports = vec![UnresolvedImport {
            source_repo: "kin".to_string(),
            source_entity: EntityId::new(),
            imported_name: "InMemoryGraph".to_string(),
            imported_kind: Some(EntityKind::Class),
            candidate_repos: vec!["kin-db".to_string()],
            language: Some("rust".to_string()),
            reference_fingerprint: None,
            import_source: None,
        }];

        let results = resolve_imports(&index, &imports);
        let edge_count = materialize_edges(&index, &imports, &results);
        assert_eq!(edge_count, 1);
        assert_eq!(index.edge_count(), 1);
    }

    #[test]
    fn ambiguous_with_fingerprint_uses_similarity() {
        let index = SpineIndex::new();

        // Two Config classes with different fingerprints
        let mut entry_a = test_entry("repo-a", "Config", EntityKind::Class);
        entry_a.fingerprint.ast_hash = Hash256::from_bytes([10; 32]);
        entry_a.fingerprint.signature_hash = Hash256::from_bytes([11; 32]);

        let mut entry_b = test_entry("repo-b", "Config", EntityKind::Class);
        entry_b.fingerprint.ast_hash = Hash256::from_bytes([20; 32]);
        entry_b.fingerprint.signature_hash = Hash256::from_bytes([21; 32]);

        index.register_repo("repo-a", vec![entry_a], "hash-a");
        index.register_repo("repo-b", vec![entry_b], "hash-b");

        // Reference fingerprint matches repo-b exactly
        let ref_fp = SemanticFingerprint {
            ast_hash: Hash256::from_bytes([20; 32]),
            signature_hash: Hash256::from_bytes([21; 32]),
            behavior_hash: Hash256::from_bytes([3; 32]),
            algorithm: FingerprintAlgorithm::V1TreeSitter,
            stability_score: 1.0,
        };

        let imports = vec![UnresolvedImport {
            source_repo: "repo-c".to_string(),
            source_entity: EntityId::new(),
            imported_name: "Config".to_string(),
            imported_kind: Some(EntityKind::Class),
            candidate_repos: vec!["repo-a".to_string(), "repo-b".to_string()],
            language: None,
            reference_fingerprint: Some(ref_fp),
            import_source: None,
        }];

        let results = resolve_imports(&index, &imports);
        match &results[0].1 {
            ResolveResult::Ambiguous { candidates } => {
                assert_eq!(candidates.len(), 2);
                // Find repo-b's confidence — should be higher than repo-a's
                let b_conf = candidates.iter().find(|c| c.0 == "repo-b").unwrap().2;
                let a_conf = candidates.iter().find(|c| c.0 == "repo-a").unwrap().2;
                assert!(
                    b_conf > a_conf,
                    "repo-b (fingerprint match) should have higher confidence than repo-a: {b_conf} vs {a_conf}"
                );
            }
            other => panic!("expected Ambiguous, got {other:?}"),
        }
    }

    #[test]
    fn import_source_resolves_to_matching_repo() {
        // import_source="requests" should resolve `get` to the requests repo,
        // not to 10 other repos that also have a `get` function.
        let index = SpineIndex::new();
        index.register_repo(
            "requests",
            vec![test_entry("requests", "get", EntityKind::Function)],
            "hash-req",
        );
        index.register_repo(
            "repo-a",
            vec![test_entry("repo-a", "get", EntityKind::Function)],
            "hash-a",
        );
        index.register_repo(
            "repo-b",
            vec![test_entry("repo-b", "get", EntityKind::Function)],
            "hash-b",
        );

        let imports = vec![UnresolvedImport {
            source_repo: "my-app".to_string(),
            source_entity: EntityId::new(),
            imported_name: "get".to_string(),
            imported_kind: Some(EntityKind::Function),
            candidate_repos: vec![
                "requests".to_string(),
                "repo-a".to_string(),
                "repo-b".to_string(),
            ],
            language: Some("python".to_string()),
            reference_fingerprint: None,
            import_source: Some("requests".to_string()),
        }];

        let results = resolve_imports(&index, &imports);
        assert_eq!(results.len(), 1);
        match &results[0].1 {
            ResolveResult::Resolved {
                target_repo,
                confidence,
                ..
            } => {
                assert_eq!(target_repo, "requests");
                assert!(
                    *confidence >= 0.95,
                    "import_source exact match should have 0.95 confidence, got {confidence}"
                );
            }
            other => panic!("expected Resolved to requests repo, got {other:?}"),
        }
    }

    #[test]
    fn import_source_none_falls_back_to_fingerprint() {
        // When import_source is None, should use the existing fingerprint-based resolution
        let index = SpineIndex::new();

        let mut entry_a = test_entry("repo-a", "parse", EntityKind::Function);
        entry_a.fingerprint.ast_hash = Hash256::from_bytes([10; 32]);

        let mut entry_b = test_entry("repo-b", "parse", EntityKind::Function);
        entry_b.fingerprint.ast_hash = Hash256::from_bytes([20; 32]);

        index.register_repo("repo-a", vec![entry_a], "hash-a");
        index.register_repo("repo-b", vec![entry_b], "hash-b");

        // Reference fingerprint matches repo-b
        let ref_fp = SemanticFingerprint {
            ast_hash: Hash256::from_bytes([20; 32]),
            signature_hash: Hash256::from_bytes([2; 32]),
            behavior_hash: Hash256::from_bytes([3; 32]),
            algorithm: FingerprintAlgorithm::V1TreeSitter,
            stability_score: 1.0,
        };

        let imports = vec![UnresolvedImport {
            source_repo: "my-app".to_string(),
            source_entity: EntityId::new(),
            imported_name: "parse".to_string(),
            imported_kind: Some(EntityKind::Function),
            candidate_repos: vec!["repo-a".to_string(), "repo-b".to_string()],
            language: None,
            reference_fingerprint: Some(ref_fp),
            import_source: None, // No import_source — should fall through to tier 3
        }];

        let results = resolve_imports(&index, &imports);
        match &results[0].1 {
            ResolveResult::Ambiguous { candidates } => {
                assert_eq!(candidates.len(), 2);
                let b_conf = candidates.iter().find(|c| c.0 == "repo-b").unwrap().2;
                let a_conf = candidates.iter().find(|c| c.0 == "repo-a").unwrap().2;
                assert!(
                    b_conf > a_conf,
                    "fingerprint fallback: repo-b should rank higher"
                );
            }
            other => panic!("expected Ambiguous with fingerprint ranking, got {other:?}"),
        }
    }

    #[test]
    fn collect_unresolved_finds_external_refs_with_import_source() {
        use kin_model::{EntityMetadata, EntityRole, GraphNodeId, LanguageId, RelationId, RelationOrigin, Visibility};

        let local_entity_id = EntityId::new();
        let external_entity_id = EntityId::new();

        let entities = vec![Entity {
            id: local_entity_id,
            kind: EntityKind::Function,
            name: "my_handler".to_string(),
            language: LanguageId::Python,
            fingerprint: test_fp(),
            file_origin: None,
            span: None,
            signature: "def my_handler()".to_string(),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }];

        let relations = vec![
            // Calls edge to external entity with import_source
            Relation {
                id: RelationId::new(),
                kind: RelationKind::Calls,
                src: GraphNodeId::Entity(local_entity_id),
                dst: GraphNodeId::Entity(external_entity_id),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: Some("requests".to_string()),
            },
            // Contains edge (should be ignored — not Calls/References)
            Relation {
                id: RelationId::new(),
                kind: RelationKind::Contains,
                src: GraphNodeId::Entity(local_entity_id),
                dst: GraphNodeId::Entity(external_entity_id),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: Some("requests".to_string()),
            },
            // Calls edge without import_source (should be ignored)
            Relation {
                id: RelationId::new(),
                kind: RelationKind::Calls,
                src: GraphNodeId::Entity(local_entity_id),
                dst: GraphNodeId::Entity(EntityId::new()),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: None,
            },
        ];

        let registry = vec![
            "my-app".to_string(),
            "requests".to_string(),
            "utils".to_string(),
        ];

        let unresolved = collect_unresolved_imports(&entities, &relations, "my-app", &registry);

        assert_eq!(
            unresolved.len(),
            1,
            "should find exactly one unresolved import (Calls with import_source)"
        );
        assert_eq!(unresolved[0].import_source.as_deref(), Some("requests"));
        assert_eq!(unresolved[0].source_repo, "my-app");
        assert_eq!(unresolved[0].source_entity, local_entity_id);
        // candidate_repos should exclude the source repo
        assert!(!unresolved[0]
            .candidate_repos
            .contains(&"my-app".to_string()));
        assert!(unresolved[0]
            .candidate_repos
            .contains(&"requests".to_string()));
    }
}
