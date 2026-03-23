// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::{Path, PathBuf};

use anyhow::Result;

#[derive(Debug, PartialEq, Eq)]
struct StatusSummary {
    repo_root: PathBuf,
    mode: kin_core::RepoMode,
    source_root: PathBuf,
    world_preset: String,
    default_remote: String,
    branch: String,
    head: String,
    entities: usize,
    import_state: String,
    readiness: String,
}

pub async fn run() -> Result<()> {
    let summary = load_status(&std::env::current_dir()?)?;
    for line in summary.render_lines() {
        println!("{line}");
    }
    Ok(())
}

fn load_status(cwd: &Path) -> Result<StatusSummary> {
    let layout = kin_core::KinLayout::discover(cwd)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout))?;
    let graph = &*snap.graph();
    let current = kin_core::read_current_branch(&layout)?;
    let mode = kin_core::read_repo_mode(&layout);
    let source_root = kin_core::source_dir(&layout);
    let config = kin_core::KinConfig::load_or_default(&layout.config_path())?;
    let default_remote = config
        .resolve_remote(None)
        .map(|remote| format!("{} [{} / {}]", remote.name, remote.host, remote.transport))
        .unwrap_or_else(|| "(not configured)".to_string());

    use kin_model::GraphStore;
    let entities = graph.list_all_entities()?.len();
    let genesis = kin_core::build_genesis_change().id;
    let (branch, head, import_state, readiness) = match graph.get_branch(&current)? {
        Some(branch) => {
            let import_state = if entities == 0 && branch.head == genesis {
                "bootstrap only (run `kin commit` or `kin git import`)".to_string()
            } else if entities == 0 {
                "empty semantic graph (run `kin commit` or `kin git import`)".to_string()
            } else {
                "materialized semantic graph".to_string()
            };
            let readiness = if entities == 0 {
                "blocked: semantic state is not materialized yet".to_string()
            } else {
                "ready: trace, review, and publish can operate on stored semantic state".to_string()
            };
            (
                branch.name.to_string(),
                branch.head.to_string(),
                import_state,
                readiness,
            )
        }
        None => (
            format!("{current} (not found in graph)"),
            "(missing)".to_string(),
            format!("missing semantic branch `{current}`"),
            "blocked: current branch is not stored in the semantic graph".to_string(),
        ),
    };

    Ok(StatusSummary {
        repo_root: layout.working_dir().to_path_buf(),
        mode,
        source_root,
        world_preset: config.world.preset.to_string(),
        default_remote,
        branch,
        head,
        entities,
        import_state,
        readiness,
    })
}

impl StatusSummary {
    fn render_lines(&self) -> Vec<String> {
        vec![
            format!("Repo root: {}", self.repo_root.display()),
            format!("Mode: {}", self.mode),
            format!("Source root: {}", self.source_root.display()),
            format!("World preset: {}", self.world_preset),
            format!("Default remote: {}", self.default_remote),
            format!("Branch: {}", self.branch),
            format!("Head: {}", self.head),
            format!("Entities: {}", self.entities),
            format!("Import state: {}", self.import_state),
            format!("Readiness: {}", self.readiness),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::load_status;
    use kin_model::{
        Entity, EntityId, EntityKind, EntityMetadata, FilePathId, FingerprintAlgorithm, GraphStore,
        Hash256, LanguageId, SemanticFingerprint, SourceSpan, Visibility,
    };

    fn test_entity(name: &str, file: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([1; 32]),
                signature_hash: Hash256::from_bytes([2; 32]),
                behavior_hash: Hash256::from_bytes([3; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(file)),
            span: Some(SourceSpan {
                file: FilePathId::new(file),
                start_byte: 0,
                end_byte: 10,
                start_line: 1,
                start_col: 0,
                end_line: 1,
                end_col: 10,
            }),
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    #[test]
    fn load_status_rejects_non_kin_repo() {
        let dir = tempfile::tempdir().unwrap();
        let err = load_status(dir.path()).unwrap_err();
        assert_eq!(err.to_string(), "not a Kin repository (no .kin/ found)");
    }

    #[test]
    fn load_status_marks_bootstrap_only_repo_as_blocked() {
        let dir = tempfile::tempdir().unwrap();
        let result = kin_core::init(dir.path()).unwrap();

        let summary = load_status(dir.path()).unwrap();

        assert_eq!(summary.repo_root, dir.path());
        assert_eq!(summary.mode, kin_core::RepoMode::Compat);
        assert_eq!(summary.source_root, dir.path());
        assert_eq!(summary.branch, "main");
        assert_eq!(summary.head, result.genesis_id.to_string());
        assert_eq!(summary.entities, 0);
        assert_eq!(
            summary.import_state,
            "bootstrap only (run `kin commit` or `kin git import`)"
        );
        assert_eq!(
            summary.readiness,
            "blocked: semantic state is not materialized yet"
        );
    }

    #[test]
    fn load_status_marks_materialized_repo_as_ready() {
        let dir = tempfile::tempdir().unwrap();
        let result = kin_core::init(dir.path()).unwrap();
        let snapshot_path = crate::backend::kindb_snapshot_path(&result.layout);
        let snap = kin_db::SnapshotManager::open(snapshot_path).unwrap();
        let graph = snap.graph();
        graph
            .upsert_entity(&test_entity("status", "src/status.rs"))
            .unwrap();
        snap.save().unwrap();
        drop(graph);
        drop(snap);

        let summary = load_status(dir.path()).unwrap();

        assert_eq!(summary.branch, "main");
        assert_eq!(summary.head, result.genesis_id.to_string());
        assert_eq!(summary.entities, 1);
        assert_eq!(summary.import_state, "materialized semantic graph");
        assert_eq!(
            summary.readiness,
            "ready: trace, review, and publish can operate on stored semantic state"
        );
    }
}
