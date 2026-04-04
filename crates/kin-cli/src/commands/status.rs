// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::Result;
use kin_model::{ChangeStore, EntityRole, EntityStore};
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
    source_root: PathBuf,
    world_preset: String,
    default_remote: String,
    branch: String,
    head: String,
    entities: usize,
    role_counts: HashMap<EntityRole, usize>,
    import_state: String,
    readiness: String,
    blocked: bool,
    merge_state: Option<String>,
}

pub async fn run() -> Result<()> {
    run_for_cwd(&std::env::current_dir()?).await
}

pub async fn run_json() -> Result<()> {
    let summary = load_status(&std::env::current_dir()?).await?;
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

async fn run_for_cwd(cwd: &Path) -> Result<()> {
    let summary = load_status(cwd).await?;
    for line in summary.render_lines() {
        println!("{line}");
    }
    if summary.blocked {
        if summary.entities == 0 {
            eprintln!("hint: run `kin init` to build the semantic graph from current state");
        }
        anyhow::bail!("{}", summary.readiness);
    }
    Ok(())
}

async fn load_status(cwd: &Path) -> Result<StatusSummary> {
    let layout = kin_core::KinLayout::discover(cwd).ok_or_else(|| {
        anyhow::anyhow!(
            "not a Kin repository (no .kin/ found)\nhint: run `kin init .` to initialize a Kin repository here"
        )
    })?;
    let snap = crate::backend::open_snapshot_local(&layout)?;
    let graph = &*snap.graph();
    let current = kin_core::read_current_branch(&layout)?;
    let source_root = kin_core::source_dir(&layout);
    let config = kin_core::KinConfig::load_or_default(&layout.config_path())?;
    let default_remote = config
        .resolve_remote(None)
        .map(|remote| format!("{} [{} / {}]", remote.name, remote.host, remote.transport))
        .unwrap_or_else(|| "(not configured)".to_string());

    let all_entities = graph.list_all_entities()?;
    let entities = all_entities.len();
    let mut role_counts: HashMap<EntityRole, usize> = HashMap::new();
    for e in &all_entities {
        *role_counts.entry(e.role).or_insert(0) += 1;
    }
    let genesis = kin_core::build_genesis_change().id;
    let (branch, head, import_state, readiness, blocked) = match graph.get_branch(&current)? {
        Some(branch) => {
            let import_state = if entities == 0 && branch.head == genesis {
                "bootstrap only (entities will be populated on next `kin init`)".to_string()
            } else if entities == 0 {
                "empty semantic graph (run `kin init` to populate)".to_string()
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
        source_root,
        world_preset: config.world.preset.to_string(),
        default_remote,
        branch,
        head,
        entities,
        role_counts,
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
            format!("Source root: {}", self.source_root.display()),
            format!("World preset: {}", self.world_preset),
            format!("Default remote: {}", self.default_remote),
            format!("Branch: {}", self.branch),
            format!("Head: {}", self.head),
            format!("Entities: {}", self.entities),
        ];
        if !self.role_counts.is_empty() {
            let roles = [
                (EntityRole::Source, "source"),
                (EntityRole::Test, "test"),
                (EntityRole::External, "external"),
                (EntityRole::Docs, "docs"),
                (EntityRole::Generated, "generated"),
                (EntityRole::Vendored, "vendored"),
            ];
            let parts: Vec<String> = roles
                .iter()
                .filter_map(|(role, label)| {
                    self.role_counts.get(role).map(|c| format!("{label}: {c}"))
                })
                .collect();
            lines.push(format!("  Roles: {}", parts.join(", ")));
        }
        lines.extend([
            format!("Import state: {}", self.import_state),
            format!("Readiness: {}", self.readiness),
        ]);
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
        Entity, EntityId, EntityKind, EntityMetadata, EntityRole, EntityStore, FilePathId,
        FingerprintAlgorithm, Hash256, LanguageId, SemanticFingerprint, SourceSpan, Visibility,
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
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    #[tokio::test]
    async fn load_status_rejects_non_kin_repo() {
        let dir = tempfile::tempdir().unwrap();
        let err = load_status(dir.path()).await.unwrap_err();
        assert!(err
            .to_string()
            .starts_with("not a Kin repository (no .kin/ found)"));
    }

    #[tokio::test]
    async fn load_status_marks_bootstrap_only_repo_as_blocked() {
        let dir = tempfile::tempdir().unwrap();
        let result = kin_core::init(dir.path()).unwrap();

        let summary = load_status(dir.path()).await.unwrap();

        assert_eq!(summary.repo_root, dir.path());
        assert_eq!(summary.source_root, dir.path());
        assert_eq!(summary.branch, "main");
        assert_eq!(summary.head, result.genesis_id.to_string());
        assert_eq!(summary.entities, 0);
        assert_eq!(
            summary.import_state,
            "bootstrap only (entities will be populated on next `kin init`)"
        );
        assert_eq!(
            summary.readiness,
            "blocked: semantic state is not materialized yet"
        );
        assert!(summary.blocked);
        assert!(summary.merge_state.is_none());
    }

    #[tokio::test]
    async fn load_status_marks_materialized_repo_as_ready() {
        let dir = tempfile::tempdir().unwrap();
        let result = kin_core::init(dir.path()).unwrap();
        let snap = crate::backend::open_kindb_snapshot(&result.layout).unwrap();
        let graph = snap.graph();
        graph
            .upsert_entity(&test_entity("status", "src/status.rs"))
            .unwrap();
        snap.save().unwrap();
        drop(graph);
        drop(snap);

        let summary = load_status(dir.path()).await.unwrap();

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

    #[tokio::test]
    async fn run_for_cwd_returns_error_for_bootstrap_only_repo() {
        let dir = tempfile::tempdir().unwrap();
        kin_core::init(dir.path()).unwrap();

        let err = run_for_cwd(dir.path()).await.unwrap_err();

        assert_eq!(
            err.to_string(),
            "blocked: semantic state is not materialized yet"
        );
    }

    #[tokio::test]
    async fn status_hints_do_not_mention_git_import() {
        let dir = tempfile::tempdir().unwrap();
        kin_core::init(dir.path()).unwrap();

        let summary = load_status(dir.path()).await.unwrap();
        assert!(
            !summary.import_state.contains("kin git import"),
            "import_state should not mention kin git import: {}",
            summary.import_state
        );
        assert!(
            !summary.readiness.contains("kin git import"),
            "readiness should not mention kin git import: {}",
            summary.readiness
        );
    }

    #[tokio::test]
    async fn run_for_cwd_returns_error_when_current_branch_is_missing_from_graph() {
        let dir = tempfile::tempdir().unwrap();
        let result = kin_core::init(dir.path()).unwrap();
        kin_core::write_current_branch(&result.layout, &kin_model::BranchName::new("feature"))
            .unwrap();

        let summary = load_status(dir.path()).await.unwrap();
        assert_eq!(summary.branch, "feature (not found in graph)");
        assert_eq!(summary.head, "(missing)");
        assert_eq!(summary.import_state, "missing semantic branch `feature`");
        assert_eq!(
            summary.readiness,
            "blocked: current branch is not stored in the semantic graph"
        );
        assert!(summary.blocked);

        let err = run_for_cwd(dir.path()).await.unwrap_err();
        assert_eq!(
            err.to_string(),
            "blocked: current branch is not stored in the semantic graph"
        );
    }
}
