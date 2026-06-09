// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_model::{EntityStore, Relation, RelationKind};
use std::path::Path;

pub(crate) fn refresh_from_git_history_with_limit(
    graph: &kin_db::InMemoryGraph,
    repo_path: &Path,
    max_commits: usize,
) -> Result<usize> {
    let _span = tracing::info_span!(
        "kin.cochange.refresh_from_git_history",
        repo = %repo_path.display(),
        max_commits = max_commits
    )
    .entered();
    let relations =
        kin_git::mine_from_git_log_with_limit(repo_path, graph, max_commits).map_err(|e| {
            anyhow::anyhow!("failed to mine co-change relations from git history: {}", e)
        })?;
    replace_relations(graph, relations)
}

pub fn refresh_from_changes(
    graph: &kin_db::InMemoryGraph,
    changes: &[kin_model::SemanticChange],
) -> Result<usize> {
    let _span =
        tracing::info_span!("kin.cochange.refresh_from_changes", changes = changes.len()).entered();
    let relations = kin_git::mine_from_change_dag(graph, changes).map_err(|e| {
        anyhow::anyhow!("failed to mine co-change relations from change dag: {}", e)
    })?;
    replace_relations(graph, relations)
}

fn replace_relations(graph: &kin_db::InMemoryGraph, relations: Vec<Relation>) -> Result<usize> {
    let _span = tracing::info_span!(
        "kin.cochange.replace_relations",
        relations = relations.len()
    )
    .entered();
    let count = relations.len();
    graph.replace_relations_of_kind(RelationKind::CoChanges, relations)?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{
        ArtifactDelta, ArtifactDeltaKind, Entity, EntityId, EntityKind, EntityMetadata, EntityRole,
        FilePathId, FingerprintAlgorithm, GraphNodeId, Hash256, LanguageId, RelationId,
        RelationOrigin, SemanticChange, SemanticFingerprint, SourceSpan, Visibility,
    };
    use std::process::Command;

    fn test_entity(name: &str, path: &str, line: u32) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([1; 32]),
                behavior_hash: Hash256::from_bytes([2; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(path)),
            span: Some(SourceSpan {
                file: FilePathId::new(path),
                start_byte: 0,
                end_byte: 0,
                start_line: line,
                start_col: 1,
                end_line: line,
                end_col: 20,
            }),
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

    fn test_change(id_byte: u8, files: &[&str]) -> SemanticChange {
        SemanticChange {
            id: kin_model::SemanticChangeId::from_hash(Hash256::from_bytes([id_byte; 32])),
            parents: vec![],
            timestamp: kin_model::Timestamp::now(),
            author: kin_model::AuthorId::new("test"),
            message: format!("change-{id_byte}"),
            entity_deltas: vec![],
            relation_deltas: vec![],
            artifact_deltas: files
                .iter()
                .map(|file| ArtifactDelta {
                    file_id: FilePathId::new(*file),
                    kind: ArtifactDeltaKind::Modified,
                    old_hash: None,
                    new_hash: None,
                })
                .collect(),
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: None,
        }
    }

    fn init_git_repo(dir: &std::path::Path) -> bool {
        let git_init = Command::new("git").args(["init"]).current_dir(dir).output();
        match git_init {
            Ok(output) if output.status.success() => {
                let _ = Command::new("git")
                    .args(["config", "user.email", "test@test.com"])
                    .current_dir(dir)
                    .output();
                let _ = Command::new("git")
                    .args(["config", "user.name", "Test"])
                    .current_dir(dir)
                    .output();
                true
            }
            _ => false,
        }
    }

    #[test]
    fn refresh_from_changes_replaces_existing_relations() {
        let graph = kin_db::InMemoryGraph::new();
        let alpha = test_entity("alpha", "src/a.rs", 1);
        let beta = test_entity("beta", "src/b.rs", 2);
        let gamma = test_entity("gamma", "src/c.rs", 3);
        graph.upsert_entity(&alpha).unwrap();
        graph.upsert_entity(&beta).unwrap();
        graph.upsert_entity(&gamma).unwrap();
        graph
            .upsert_relation(&kin_model::Relation {
                id: RelationId::new(),
                kind: RelationKind::CoChanges,
                src: GraphNodeId::Entity(alpha.id),
                dst: GraphNodeId::Entity(gamma.id),
                confidence: 1.0,
                origin: RelationOrigin::Inferred,
                created_in: None,
                import_source: None,
                evidence: Vec::new(),
            })
            .unwrap();

        let changes = vec![test_change(1, &["src/a.rs", "src/b.rs"])];
        let inserted = refresh_from_changes(&graph, &changes).unwrap();

        assert_eq!(inserted, 2);
        let alpha_rels = graph
            .get_relations(&alpha.id, &[RelationKind::CoChanges])
            .unwrap();
        assert_eq!(alpha_rels.len(), 1);
        assert_eq!(alpha_rels[0].dst, GraphNodeId::Entity(beta.id));
        let gamma_rels = graph.get_all_relations_for_entity(&gamma.id).unwrap();
        assert!(gamma_rels
            .iter()
            .all(|relation| relation.kind != RelationKind::CoChanges));
    }

    #[test]
    fn refresh_from_git_history_uses_real_changed_files() {
        let dir = tempfile::tempdir().unwrap();
        if !init_git_repo(dir.path()) {
            eprintln!("git not available, skipping co-change refresh test");
            return;
        }

        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/a.rs"), "fn alpha() {}\n").unwrap();
        std::fs::write(dir.path().join("src/b.rs"), "fn beta() {}\n").unwrap();
        Command::new("git")
            .args(["add", "."])
            .current_dir(dir.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "initial"])
            .current_dir(dir.path())
            .output()
            .unwrap();

        std::fs::write(
            dir.path().join("src/a.rs"),
            "fn alpha() { println!(\"a\"); }\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("src/c.rs"), "fn gamma() {}\n").unwrap();
        Command::new("git")
            .args(["add", "."])
            .current_dir(dir.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "followup"])
            .current_dir(dir.path())
            .output()
            .unwrap();

        let graph = kin_db::InMemoryGraph::new();
        let alpha = test_entity("alpha", "src/a.rs", 1);
        let beta = test_entity("beta", "src/b.rs", 2);
        let gamma = test_entity("gamma", "src/c.rs", 3);
        graph.upsert_entity(&alpha).unwrap();
        graph.upsert_entity(&beta).unwrap();
        graph.upsert_entity(&gamma).unwrap();

        let inserted = refresh_from_git_history_with_limit(&graph, dir.path(), 0).unwrap();
        assert!(inserted >= 4);

        let alpha_rels = graph
            .get_relations(&alpha.id, &[RelationKind::CoChanges])
            .unwrap();
        assert!(alpha_rels
            .iter()
            .any(|relation| relation.dst == GraphNodeId::Entity(beta.id)));
        assert!(alpha_rels
            .iter()
            .any(|relation| relation.dst == GraphNodeId::Entity(gamma.id)));
    }
}
