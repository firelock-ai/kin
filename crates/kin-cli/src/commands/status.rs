// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::Serialize;

#[derive(Debug, Serialize, PartialEq, Eq)]
struct StatusJson {
    initialized: bool,
    #[serde(rename = "entityCount")]
    entity_count: usize,
    #[serde(rename = "graphState")]
    graph_state: String,
}

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
    blocked: bool,
    merge_state: Option<String>,
}

pub async fn run() -> Result<()> {
    run_for_cwd(&std::env::current_dir()?)
}

pub async fn run_json() -> Result<()> {
    let summary = load_status(&std::env::current_dir()?)?;
    let payload = StatusJson {
        initialized: !summary.blocked,
        entity_count: summary.entities,
        graph_state: if summary.blocked {
            "blocked".to_string()
        } else {
            "ready".to_string()
        },
    };
    println!("{}", serde_json::to_string(&payload)?);
    Ok(())
}

fn run_for_cwd(cwd: &Path) -> Result<()> {
    let summary = load_status(cwd)?;
    for line in summary.render_lines() {
        println!("{line}");
    }
    if summary.blocked {
        if summary.entities == 0 {
            eprintln!("hint: run `kin commit -m \"initial\"` to extract entities and build the semantic graph");
        }
        anyhow::bail!("{}", summary.readiness);
    }
    Ok(())
}

fn load_status(cwd: &Path) -> Result<StatusSummary> {
    let layout = kin_core::KinLayout::discover(cwd).ok_or_else(|| {
        anyhow::anyhow!(
            "not a Kin repository (no .kin/ found)\nhint: run `kin init .` to initialize a Kin repository here"
        )
    })?;
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
    let (branch, head, import_state, readiness, blocked) = match graph.get_branch(&current)? {
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
            let blocked = entities == 0;
            (
                branch.name.to_string(),
                branch.head.to_string(),
                import_state,
                readiness,
                blocked,
            )
        }
        None => (
            format!("{current} (not found in graph)"),
            "(missing)".to_string(),
            format!("missing semantic branch `{current}`"),
            "blocked: current branch is not stored in the semantic graph".to_string(),
            true,
        ),
    };

    // Check for in-progress merge.
    let merge_state = crate::commands::conflicts::load_merge_state(&layout)
        .ok()
        .flatten()
        .map(|ms| {
            format!(
                "merging '{}' -> '{}' ({} unresolved)",
                ms.source_branch,
                ms.target_branch,
                ms.unresolved_count()
            )
        });

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
        blocked,
        merge_state,
    })
}

impl StatusSummary {
    fn render_lines(&self) -> Vec<String> {
        let mut lines = vec![
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
        ];
        if let Some(ref ms) = self.merge_state {
            lines.push(format!("Merge: {}", ms));
        }
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::{load_status, run_for_cwd};
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
        assert!(err.to_string().starts_with("not a Kin repository (no .kin/ found)"));
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
        assert!(summary.blocked);
        assert!(summary.merge_state.is_none());
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
        assert!(!summary.blocked);
    }

    #[test]
    fn run_for_cwd_returns_error_for_bootstrap_only_repo() {
        let dir = tempfile::tempdir().unwrap();
        kin_core::init(dir.path()).unwrap();

        let err = run_for_cwd(dir.path()).unwrap_err();

        assert_eq!(
            err.to_string(),
            "blocked: semantic state is not materialized yet"
        );
    }

    #[test]
    fn run_for_cwd_returns_error_when_current_branch_is_missing_from_graph() {
        let dir = tempfile::tempdir().unwrap();
        let result = kin_core::init(dir.path()).unwrap();
        kin_core::write_current_branch(&result.layout, &kin_model::BranchName::new("feature"))
            .unwrap();

        let summary = load_status(dir.path()).unwrap();
        assert_eq!(summary.branch, "feature (not found in graph)");
        assert_eq!(summary.head, "(missing)");
        assert_eq!(summary.import_state, "missing semantic branch `feature`");
        assert_eq!(
            summary.readiness,
            "blocked: current branch is not stored in the semantic graph"
        );
        assert!(summary.blocked);

        let err = run_for_cwd(dir.path()).unwrap_err();
        assert_eq!(
            err.to_string(),
            "blocked: current branch is not stored in the semantic graph"
        );
    }
}
