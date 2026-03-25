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

use crate::index::{fingerprint_match_score, CrossRepoEdge, EntityEntry, SpineIndex};
use kin_model::{EntityId, EntityKind, SemanticFingerprint};

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
/// For each unresolved import:
/// 1. Query the spine index for entities matching the imported name/kind
/// 2. Filter to candidate repos from Tier 2-5 dependency data
/// 3. If exactly one match → Resolved with high confidence
/// 4. If multiple matches → rank by fingerprint similarity, return Ambiguous
/// 5. If no matches → NotFound
pub fn resolve_imports(index: &SpineIndex, imports: &[UnresolvedImport]) -> Vec<(usize, ResolveResult)> {
    let mut results = Vec::with_capacity(imports.len());

    for (i, import) in imports.iter().enumerate() {
        let matches = index.resolve(
            &import.imported_name,
            import.imported_kind,
            None, // No reference fingerprint yet
        );

        // Filter to candidate repos
        let filtered: Vec<&EntityEntry> = if import.candidate_repos.is_empty() {
            // No dependency hint — consider all matches (lower confidence)
            matches.iter().collect()
        } else {
            matches
                .iter()
                .filter(|e| import.candidate_repos.contains(&e.repo_id))
                .collect()
        };

        let result = match filtered.len() {
            0 => ResolveResult::NotFound,
            1 => ResolveResult::Resolved {
                target_repo: filtered[0].repo_id.clone(),
                target_entity: filtered[0].entity_id,
                confidence: if import.candidate_repos.is_empty() { 0.5 } else { 0.9 },
            },
            _ => {
                let candidates: Vec<(String, EntityId, f32)> = filtered
                    .iter()
                    .map(|e| {
                        let confidence = if let Some(ref ref_fp) = import.reference_fingerprint {
                            // Use fingerprint similarity: score is 0.0-3.0,
                            // normalize to 0.0-1.0 range
                            let sim = fingerprint_match_score(&e.fingerprint, ref_fp) / 3.0;
                            // Blend: dep-hint presence boosts base, fingerprint refines
                            let base = if import.candidate_repos.contains(&e.repo_id) {
                                0.4
                            } else {
                                0.1
                            };
                            base + 0.6 * sim
                        } else {
                            // No fingerprint available — flat dep-based scores
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
        };

        results.push((i, result));
    }

    results
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
        }];

        let results = resolve_imports(&index, &imports);
        assert_eq!(results.len(), 1);
        match &results[0].1 {
            ResolveResult::Resolved { target_repo, confidence, .. } => {
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
}
