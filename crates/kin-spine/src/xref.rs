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
use kin_model::{
    Entity, EntityId, EntityKind, EntityRole, Relation, RelationKind, SemanticFingerprint,
};

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

/// Normalize a crate name or repo id for cross-repo matching: trim, lowercase,
/// and fold underscores to hyphens. Rust crate names are written with `_`
/// (`kin_db`) while repo ids are hyphenated (`kin-db`), so the two compare equal
/// only after folding.
fn normalize_repo_token(token: &str) -> String {
    token.trim().to_lowercase().replace('_', "-")
}

/// Extract the leading crate/package segment from an import source path. Rust
/// paths separate with `::` (`kin_db::graph` → `kin_db`) and dotted-module
/// languages with `.` (`os.path` → `os`); that leading segment is the crate or
/// top-level package identifying the owning repo.
fn import_source_root(source: &str) -> &str {
    let trimmed = source.trim();
    let crate_seg = trimmed.split("::").next().unwrap_or(trimmed);
    crate_seg.split('.').next().unwrap_or(crate_seg).trim()
}

/// Resolve a single import using the 3-tier strategy.
fn resolve_single(
    index: &SpineIndex,
    import: &UnresolvedImport,
    registered_repos: &HashSet<String>,
) -> ResolveResult {
    // The import_source names the crate/package the referenced symbol came
    // from. Match its root segment against registered repo ids, folding the Rust
    // crate-name / repo-id spelling gap (`kin_db` ↔ `kin-db`) so real cross-repo
    // imports bind at Tier 1 instead of collapsing into name-only Tier 3
    // collisions.
    if let Some(ref source) = import.import_source {
        let normalized_source = normalize_repo_token(import_source_root(source));

        // A relation whose module root names its own repository is not a
        // cross-repo import. Parser/linker gaps can still represent a local
        // target as an external placeholder, but that must remain unresolved
        // here instead of becoming a same-repo "cross-repo" proof edge (or
        // falling through to a similarly named sibling repo).
        if normalize_repo_token(&import.source_repo) == normalized_source {
            return ResolveResult::NotFound;
        }

        // Tier 1: the import's crate/package root names a registered repo.
        if let Some(matched_repo) = registered_repos
            .iter()
            .find(|r| normalize_repo_token(r.as_str()) == normalized_source)
        {
            let matches = index.resolve(
                &import.imported_name,
                import.imported_kind,
                import.reference_fingerprint.as_ref(),
            );
            let in_source: Vec<&EntityEntry> = matches
                .iter()
                .filter(|e| e.repo_id == *matched_repo)
                .collect();

            // The import names one specific repo, so resolve only there. A
            // symbol absent from that repo is a graph gap, not grounds to bind an
            // unrelated repo by name collision.
            return match in_source.len() {
                0 => ResolveResult::NotFound,
                1 => ResolveResult::Resolved {
                    target_repo: in_source[0].repo_id.clone(),
                    target_entity: in_source[0].entity_id,
                    confidence: 0.95,
                },
                _ => ResolveResult::Ambiguous {
                    candidates: in_source
                        .iter()
                        .map(|e| (e.repo_id.clone(), e.entity_id, 0.95))
                        .collect(),
                },
            };
        }

        // Tier 2: import_source set but names no registered repo directly —
        // use its normalized root to narrow candidate_repos by containment.
        let filtered_candidates: Vec<String> = if import.candidate_repos.is_empty() {
            registered_repos
                .iter()
                .filter(|r| normalize_repo_token(r.as_str()).contains(&normalized_source))
                .cloned()
                .collect()
        } else {
            import
                .candidate_repos
                .iter()
                .filter(|r| normalize_repo_token(r.as_str()).contains(&normalized_source))
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
    for edge in materialized_edges(imports, resolutions) {
        if index.add_cross_repo_edge(edge) {
            count += 1;
        }
    }
    count
}

/// Build the cross-repo edges represented by a resolved import batch without
/// mutating the index. The refresh path uses this to replace one source repo's
/// entire outgoing set under a single write lock, so concurrent readers can
/// never observe a union assembled by interleaved per-edge writes.
pub(crate) fn materialized_edges(
    imports: &[UnresolvedImport],
    resolutions: &[(usize, ResolveResult)],
) -> Vec<CrossRepoEdge> {
    let mut edges = Vec::new();

    for (i, result) in resolutions {
        let import = &imports[*i];

        match result {
            ResolveResult::Resolved {
                target_repo,
                target_entity,
                confidence,
            } => {
                let edge = CrossRepoEdge {
                    src_repo: import.source_repo.clone(),
                    src_entity: import.source_entity,
                    dst_repo: target_repo.clone(),
                    dst_entity: *target_entity,
                    confidence: *confidence,
                };
                if edge.src_repo != edge.dst_repo {
                    edges.push(edge);
                }
            }
            ResolveResult::Ambiguous { candidates } => {
                // Add edges for all candidates with their confidence scores
                for (repo, entity_id, confidence) in candidates {
                    let edge = CrossRepoEdge {
                        src_repo: import.source_repo.clone(),
                        src_entity: import.source_entity,
                        dst_repo: repo.clone(),
                        dst_entity: *entity_id,
                        confidence: *confidence,
                    };
                    if edge.src_repo != edge.dst_repo {
                        edges.push(edge);
                    }
                }
            }
            ResolveResult::NotFound => {}
        }
    }

    // One durable edge per (src_repo, src_entity, dst_repo, dst_entity). A source entity
    // that imports the same symbol twice, or reaches one target through both an exact and
    // an ambiguous resolution, yields identical identities, and the publication validator
    // refuses a duplicate. Keep one edge per identity, the highest confidence seen, in a
    // deterministic order.
    edges.sort_by(|left, right| {
        left.src_repo
            .cmp(&right.src_repo)
            .then_with(|| left.src_entity.cmp(&right.src_entity))
            .then_with(|| left.dst_repo.cmp(&right.dst_repo))
            .then_with(|| left.dst_entity.cmp(&right.dst_entity))
            .then_with(|| right.confidence.total_cmp(&left.confidence))
    });
    edges.dedup_by(|later, kept| {
        later.src_repo == kept.src_repo
            && later.src_entity == kept.src_entity
            && later.dst_repo == kept.dst_repo
            && later.dst_entity == kept.dst_entity
    });

    edges
}

/// Derive the real imported symbol name for a cross-repo reference from the
/// relation's parser/linker evidence.
///
/// The graph node label (`entity:<id>`) is never a real symbol, so seeding
/// resolution from it only ever matches a sibling entity by accident. A
/// cross-repo reference can resolve meaningfully only when the relation carries
/// the lexical symbol that was actually called or imported. Returns `None` when
/// no usable symbol token is present; callers must treat that as an unresolved
/// reference rather than fabricate a name.
fn derive_imported_symbol(rel: &Relation) -> Option<String> {
    rel.evidence
        .iter()
        .find_map(|ev| ev.token.as_deref().and_then(symbol_leaf))
}

/// Reduce a (possibly qualified) evidence token to its leaf identifier, e.g.
/// `kin_db::InMemoryGraph` → `InMemoryGraph`, `requests.get` → `get`.
///
/// Returns `None` for tokens whose leaf is not a plain identifier (include
/// directives, macro text, punctuation), so non-symbol evidence is rejected
/// instead of producing a garbage name that could mis-resolve.
fn symbol_leaf(token: &str) -> Option<String> {
    let leaf = token.rsplit(['.', ':']).next().unwrap_or(token).trim();
    if !leaf.is_empty() && leaf.chars().all(|c| c.is_alphanumeric() || c == '_') {
        Some(leaf.to_string())
    } else {
        None
    }
}

/// Walk a repo's entity relations looking for Calls/References where:
/// - The dst is an external reference target rather than a local definition
/// - `import_source` is set on the relation
/// - The relation carries a real imported-symbol token in its evidence
///
/// A destination counts as external when the repo's graph binds it as an
/// external reference target, which is what admission enrichment writes for a
/// symbol another repository owns, or when the repo's graph does not bind it at
/// all, which is the shape graphs written before external targets were bound
/// still carry.
///
/// A target is identified by carrying [`kin_model::EntityRole::External`] *and*
/// no file of its own. Neither half identifies it alone: that role is also
/// carried by real entities a repository vendors under `third_party/` and its
/// siblings, which hold their own source and are local definitions for this
/// purpose, while an absent file on its own only means no path was recorded.
/// Either half used by itself reports a resolved local call as an unresolved
/// cross-repo import.
///
/// The imported symbol name is taken from the relation's parser/linker evidence
/// (the symbol actually called/imported), never from the graph node label. When
/// no symbol evidence is present the reference is left unresolved rather than
/// emitting a wrong edge.
///
/// Produces `Vec<UnresolvedImport>` that feeds into `resolve_imports()`.
pub fn collect_unresolved_imports(
    entities: &[Entity],
    relations: &[Relation],
    repo_id: &str,
    registry_repo_ids: &[String],
) -> Vec<UnresolvedImport> {
    let local_ids: HashSet<EntityId> = entities
        .iter()
        .filter(|e| e.role != EntityRole::External || e.file_origin.is_some())
        .map(|e| e.id)
        .collect();
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

        // The real imported symbol comes from parser/linker evidence on the
        // relation. Without it we cannot pick a specific target entity, so we
        // leave the reference unresolved rather than seed resolution from the
        // graph node label (which only ever matched by accident).
        let Some(imported_name) = derive_imported_symbol(rel) else {
            continue;
        };

        imports.push(UnresolvedImport {
            source_repo: repo_id.to_string(),
            source_entity: src_entity_id,
            imported_name,
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
            equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
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
            role: Some(kin_model::EntityRole::Source),
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
            equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
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
    fn import_source_naming_the_source_repo_never_materializes_cross_repo_proof() {
        let index = SpineIndex::new();
        let local = test_entry("kin", "platform", EntityKind::Function);
        let collision = test_entry("kin-vfs", "platform", EntityKind::Function);
        index.register_repo("kin", vec![local], "hash-kin");
        index.register_repo("kin-vfs", vec![collision], "hash-vfs");

        let imports = vec![UnresolvedImport {
            source_repo: "kin".to_string(),
            source_entity: EntityId::new(),
            imported_name: "platform".to_string(),
            imported_kind: Some(EntityKind::Function),
            candidate_repos: vec!["kin-vfs".to_string()],
            language: Some("rust".to_string()),
            reference_fingerprint: None,
            import_source: Some("kin::platform".to_string()),
        }];

        let results = resolve_imports(&index, &imports);
        assert!(matches!(results[0].1, ResolveResult::NotFound));
        assert_eq!(materialize_edges(&index, &imports, &results), 0);
        assert_eq!(index.edge_count(), 0);
    }

    #[test]
    fn materialization_defensively_discards_a_forged_same_repo_resolution() {
        let index = SpineIndex::new();
        let source_entity = EntityId::new();
        let target_entity = EntityId::new();
        let imports = vec![UnresolvedImport {
            source_repo: "kin".to_string(),
            source_entity,
            imported_name: "platform".to_string(),
            imported_kind: Some(EntityKind::Function),
            candidate_repos: vec![],
            language: Some("rust".to_string()),
            reference_fingerprint: None,
            import_source: None,
        }];
        let forged = vec![(
            0,
            ResolveResult::Resolved {
                target_repo: "kin".to_string(),
                target_entity,
                confidence: 0.5,
            },
        )];

        assert_eq!(materialize_edges(&index, &imports, &forged), 0);
        assert_eq!(index.edge_count(), 0);
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
            equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
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
        use kin_model::{
            EntityMetadata, EntityRole, GraphNodeId, LanguageId, RelationEvidence, RelationId,
            RelationOrigin, Visibility,
        };

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
            // Calls edge to external entity with import_source and a real
            // imported-symbol token in its evidence.
            Relation {
                id: RelationId::new(),
                kind: RelationKind::Calls,
                src: GraphNodeId::Entity(local_entity_id),
                dst: GraphNodeId::Entity(external_entity_id),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: Some("requests".to_string()),
                evidence: vec![RelationEvidence {
                    token: Some("requests.get".to_string()),
                    parser_rule: Some("call_expression".to_string()),
                    ..RelationEvidence::default()
                }],
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
                evidence: vec![],
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
                evidence: vec![],
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
        // The imported name is the real symbol from the relation's evidence
        // token (leaf of `requests.get`), never the graph node label.
        assert_eq!(unresolved[0].imported_name, "get");
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

    /// Build a local source entity for collection tests.
    fn local_entity(id: EntityId, name: &str, language: kin_model::LanguageId) -> Entity {
        use kin_model::{EntityMetadata, EntityRole, Visibility};
        Entity {
            id,
            kind: EntityKind::Function,
            name: name.to_string(),
            language,
            fingerprint: test_fp(),
            file_origin: None,
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    /// Build a Calls relation to an external entity, optionally carrying an
    /// imported-symbol token in its evidence.
    fn external_call(
        src: EntityId,
        dst: EntityId,
        import_source: Option<&str>,
        token: Option<&str>,
    ) -> Relation {
        use kin_model::{GraphNodeId, RelationEvidence, RelationId, RelationOrigin};
        Relation {
            id: RelationId::new(),
            kind: RelationKind::Calls,
            src: GraphNodeId::Entity(src),
            dst: GraphNodeId::Entity(dst),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: import_source.map(|s| s.to_string()),
            evidence: token
                .map(|t| {
                    vec![RelationEvidence {
                        token: Some(t.to_string()),
                        ..RelationEvidence::default()
                    }]
                })
                .unwrap_or_default(),
        }
    }

    #[test]
    fn symbol_leaf_keeps_simple_identifier() {
        assert_eq!(
            symbol_leaf("InMemoryGraph").as_deref(),
            Some("InMemoryGraph")
        );
        assert_eq!(symbol_leaf("get").as_deref(), Some("get"));
    }

    #[test]
    fn symbol_leaf_strips_module_qualifier() {
        assert_eq!(
            symbol_leaf("kin_db::InMemoryGraph").as_deref(),
            Some("InMemoryGraph")
        );
        assert_eq!(symbol_leaf("requests.get").as_deref(), Some("get"));
        assert_eq!(
            symbol_leaf("util.finalizeIssue").as_deref(),
            Some("finalizeIssue")
        );
    }

    #[test]
    fn symbol_leaf_rejects_non_symbol_tokens() {
        // Include directives, quoted paths and empties are not symbols and must
        // not become a fabricated imported name.
        assert_eq!(symbol_leaf("#include \"app.hpp\""), None);
        assert_eq!(symbol_leaf(""), None);
        assert_eq!(symbol_leaf("::"), None);
    }

    #[test]
    fn collect_derives_real_symbol_from_qualified_token() {
        let caller = EntityId::new();
        let external = EntityId::new();
        let entities = vec![local_entity(
            caller,
            "use_graph",
            kin_model::LanguageId::Rust,
        )];
        let relations = vec![external_call(
            caller,
            external,
            Some("kin_db"),
            Some("kin_db::InMemoryGraph"),
        )];

        let unresolved = collect_unresolved_imports(
            &entities,
            &relations,
            "kin",
            &["kin".to_string(), "kin-db".to_string()],
        );

        assert_eq!(unresolved.len(), 1);
        assert_eq!(unresolved[0].imported_name, "InMemoryGraph");
        assert_eq!(unresolved[0].import_source.as_deref(), Some("kin_db"));
    }

    #[test]
    fn collect_skips_external_ref_without_symbol_evidence() {
        // import_source is set, but the relation carries no symbol token. We must
        // NOT fall back to the graph node label (which would resolve only by
        // accident) — the reference stays unresolved.
        let caller = EntityId::new();
        let external = EntityId::new();
        let entities = vec![local_entity(
            caller,
            "use_graph",
            kin_model::LanguageId::Rust,
        )];
        let relations = vec![external_call(caller, external, Some("kin_db"), None)];

        let unresolved = collect_unresolved_imports(
            &entities,
            &relations,
            "kin",
            &["kin".to_string(), "kin-db".to_string()],
        );

        assert!(
            unresolved.is_empty(),
            "a reference without symbol evidence must be left unresolved, got {unresolved:?}"
        );
    }

    #[test]
    fn disambiguates_same_symbol_across_repos_via_import_source() {
        // Two repos both export `Config`. The reference's import_source names
        // one of them, so the resolver must pick that repo deterministically —
        // never a coin-flip across the two equally-named entities.
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

        let caller = EntityId::new();
        let external = EntityId::new();
        let entities = vec![local_entity(caller, "build", kin_model::LanguageId::Python)];
        let relations = vec![external_call(
            caller,
            external,
            Some("repo-a"),
            Some("Config"),
        )];

        let unresolved = collect_unresolved_imports(
            &entities,
            &relations,
            "app",
            &[
                "app".to_string(),
                "repo-a".to_string(),
                "repo-b".to_string(),
            ],
        );
        assert_eq!(unresolved.len(), 1);
        assert_eq!(unresolved[0].imported_name, "Config");

        let results = resolve_imports(&index, &unresolved);
        match &results[0].1 {
            ResolveResult::Resolved {
                target_repo,
                confidence,
                ..
            } => {
                assert_eq!(target_repo, "repo-a", "must pick the import_source repo");
                assert!(*confidence >= 0.95);
            }
            other => panic!("expected Resolved to repo-a, got {other:?}"),
        }

        let edge_count = materialize_edges(&index, &unresolved, &results);
        assert_eq!(edge_count, 1);
    }

    #[test]
    fn same_symbol_without_repo_hint_is_deterministically_ambiguous() {
        // Same two `Config`-exporting repos, but the import_source matches no
        // registered repo and there is no fingerprint. The resolver must mark
        // the reference ambiguous against BOTH candidates (a deterministic
        // result) rather than silently committing to one.
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

        let caller = EntityId::new();
        let external = EntityId::new();
        let entities = vec![local_entity(caller, "build", kin_model::LanguageId::Python)];
        let relations = vec![external_call(
            caller,
            external,
            Some("unknown-module"),
            Some("Config"),
        )];

        let unresolved = collect_unresolved_imports(
            &entities,
            &relations,
            "app",
            &[
                "app".to_string(),
                "repo-a".to_string(),
                "repo-b".to_string(),
            ],
        );
        assert_eq!(unresolved.len(), 1);

        let results = resolve_imports(&index, &unresolved);
        match &results[0].1 {
            ResolveResult::Ambiguous { candidates } => {
                assert_eq!(candidates.len(), 2);
                let repos: HashSet<&str> = candidates.iter().map(|c| c.0.as_str()).collect();
                assert!(repos.contains("repo-a") && repos.contains("repo-b"));
            }
            other => panic!("expected deterministic Ambiguous over both repos, got {other:?}"),
        }
    }

    #[test]
    fn normalize_and_root_fold_crate_spelling() {
        assert_eq!(normalize_repo_token("kin_db"), "kin-db");
        assert_eq!(normalize_repo_token("Kin_DB"), "kin-db");
        assert_eq!(normalize_repo_token("kin-db"), "kin-db");
        assert_eq!(import_source_root("kin_db"), "kin_db");
        assert_eq!(import_source_root("kin_db::graph::Inner"), "kin_db");
        assert_eq!(import_source_root("os.path"), "os");
        assert_eq!(import_source_root("requests"), "requests");
    }

    #[test]
    fn rust_crate_underscore_binds_to_hyphenated_repo() {
        // The Rust parser emits import_source as the crate's module path with an
        // underscore (`kin_db`), while the repo is registered hyphenated
        // (`kin-db`). Tier 1 must fold the spelling and bind at 0.95 instead of
        // dropping to a name-only collision match.
        let index = SpineIndex::new();
        index.register_repo(
            "kin-db",
            vec![test_entry("kin-db", "InMemoryGraph", EntityKind::Class)],
            "hash-db",
        );

        let imports = vec![UnresolvedImport {
            source_repo: "kin".to_string(),
            source_entity: EntityId::new(),
            imported_name: "InMemoryGraph".to_string(),
            imported_kind: Some(EntityKind::Class),
            candidate_repos: vec!["kin-db".to_string()],
            language: Some("rust".to_string()),
            reference_fingerprint: None,
            import_source: Some("kin_db".to_string()),
        }];

        let results = resolve_imports(&index, &imports);
        match &results[0].1 {
            ResolveResult::Resolved {
                target_repo,
                confidence,
                ..
            } => {
                assert_eq!(target_repo, "kin-db");
                assert!(
                    *confidence >= 0.95,
                    "underscore→hyphen crate match must bind at Tier 1 (0.95), got {confidence}"
                );
            }
            other => panic!("expected Tier-1 Resolved to kin-db, got {other:?}"),
        }
    }

    #[test]
    fn multi_segment_module_path_binds_to_crate_repo() {
        // `use kin_db::graph::InMemoryGraph` yields import_source `kin_db::graph`.
        // Only the crate root (`kin_db`) identifies the repo, so the resolver
        // must bind it to `kin-db` rather than miss on the full module path.
        let index = SpineIndex::new();
        index.register_repo(
            "kin-db",
            vec![test_entry("kin-db", "InMemoryGraph", EntityKind::Class)],
            "hash-db",
        );

        let imports = vec![UnresolvedImport {
            source_repo: "kin".to_string(),
            source_entity: EntityId::new(),
            imported_name: "InMemoryGraph".to_string(),
            imported_kind: Some(EntityKind::Class),
            candidate_repos: vec!["kin-db".to_string()],
            language: Some("rust".to_string()),
            reference_fingerprint: None,
            import_source: Some("kin_db::graph".to_string()),
        }];

        let results = resolve_imports(&index, &imports);
        match &results[0].1 {
            ResolveResult::Resolved { target_repo, .. } => {
                assert_eq!(target_repo, "kin-db");
            }
            other => panic!("expected Resolved to kin-db from crate root, got {other:?}"),
        }
    }

    #[test]
    fn named_repo_miss_does_not_bind_collision_repo() {
        // `use kin_db::SomeType` where SomeType is NOT in kin-db but a same-named
        // entity exists in an unrelated repo (kin-vfs). The import names kin-db,
        // so a miss there must report NotFound — never bind the bogus kin→kin-vfs
        // collision edge the hosted org graph was showing.
        let index = SpineIndex::new();
        index.register_repo(
            "kin-db",
            vec![test_entry("kin-db", "InMemoryGraph", EntityKind::Class)],
            "hash-db",
        );
        index.register_repo(
            "kin-vfs",
            vec![test_entry("kin-vfs", "SomeType", EntityKind::Class)],
            "hash-vfs",
        );

        let imports = vec![UnresolvedImport {
            source_repo: "kin".to_string(),
            source_entity: EntityId::new(),
            imported_name: "SomeType".to_string(),
            imported_kind: Some(EntityKind::Class),
            candidate_repos: vec!["kin-db".to_string(), "kin-vfs".to_string()],
            language: Some("rust".to_string()),
            reference_fingerprint: None,
            import_source: Some("kin_db".to_string()),
        }];

        let results = resolve_imports(&index, &imports);
        assert!(
            matches!(results[0].1, ResolveResult::NotFound),
            "import naming kin_db must not bind a kin-vfs name collision, got {:?}",
            results[0].1
        );
    }

    #[test]
    fn materialized_edges_keep_one_edge_per_identity_with_the_highest_confidence() {
        let source_entity = EntityId::new();
        let target_entity = EntityId::new();
        let import = |name: &str| UnresolvedImport {
            source_repo: "kin".to_string(),
            source_entity,
            imported_name: name.to_string(),
            imported_kind: Some(EntityKind::Class),
            candidate_repos: vec!["kin-db".to_string()],
            language: Some("rust".to_string()),
            reference_fingerprint: None,
            import_source: None,
        };
        let imports = vec![import("Graph"), import("Graph"), import("Graph")];
        let resolutions = vec![
            (
                0usize,
                ResolveResult::Resolved {
                    target_repo: "kin-db".to_string(),
                    target_entity,
                    confidence: 0.6,
                },
            ),
            (
                1usize,
                ResolveResult::Ambiguous {
                    candidates: vec![("kin-db".to_string(), target_entity, 0.9)],
                },
            ),
            (
                2usize,
                ResolveResult::Resolved {
                    target_repo: "kin-db".to_string(),
                    target_entity,
                    confidence: 0.7,
                },
            ),
        ];

        let edges = materialized_edges(&imports, &resolutions);

        assert_eq!(
            edges.len(),
            1,
            "one identity must publish as one edge: {edges:?}"
        );
        assert_eq!(edges[0].src_entity, source_entity);
        assert_eq!(edges[0].dst_entity, target_entity);
        assert!(
            (edges[0].confidence - 0.9).abs() < f32::EPSILON,
            "the kept edge carries the highest confidence: {}",
            edges[0].confidence
        );
    }
}
