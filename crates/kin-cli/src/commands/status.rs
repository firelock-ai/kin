// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;

use anyhow::{Context, Result};
use kin_model::{ChangeStore, EntityRole, EntityStore};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct EnrichmentJson {
    #[serde(rename = "embeddingsIndexed")]
    embeddings_indexed: usize,
    #[serde(rename = "embeddingsPending")]
    embeddings_pending: usize,
    #[serde(rename = "embeddingsTotal")]
    embeddings_total: usize,
}

// Not `Eq`: the embedded `semantic_coverage` block reuses
// `locate::SemanticCoverage`, which is only `PartialEq`. This struct is a
// private serialization shape with no `Eq`-dependent uses.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct StatusJson {
    initialized: bool,
    #[serde(rename = "entityCount")]
    entity_count: usize,
    #[serde(rename = "graphState")]
    graph_state: String,
    #[serde(rename = "enrichment")]
    enrichment: EnrichmentJson,
    /// Embedding (semantic signal) coverage, in the SAME shape `kin locate
    /// --json` emits as `semantic_coverage` — same fields, same daemon source
    /// (`graph.embedding_status()`). An agent gauging readiness can parse it
    /// identically from either command. Snake_case key (vs the camelCase keys
    /// above) is deliberate: it mirrors locate so one parser serves both.
    #[serde(rename = "semantic_coverage")]
    semantic_coverage: crate::commands::locate::SemanticCoverage,
    #[serde(skip_serializing_if = "Option::is_none")]
    build: Option<BuildStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StatusSummary {
    pub repo_root: PathBuf,
    pub source_root: PathBuf,
    pub world_preset: String,
    pub default_remote: String,
    pub branch: String,
    pub head: String,
    pub entities: usize,
    pub role_counts: HashMap<EntityRole, usize>,
    pub embeddings_indexed: usize,
    pub embeddings_pending: usize,
    pub embeddings_total: usize,
    pub import_state: String,
    pub readiness: String,
    pub blocked: bool,
    pub merge_state: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandStatusRequest {
    #[serde(default)]
    pub json: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cli_sha: Option<String>,
    #[serde(default)]
    pub cli_dirty: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandStatusResponse {
    pub summary: StatusSummary,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub build: Option<BuildStatus>,
    #[serde(default)]
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BuildStatus {
    pub cli_sha: String,
    pub cli_dirty: bool,
    pub daemon_sha: String,
    pub daemon_dirty: bool,
}

impl CommandStatusRequest {
    pub fn new(json: bool) -> Self {
        let build = kin_buildinfo::get();
        Self {
            json,
            cli_sha: Some(build.sha.to_string()),
            cli_dirty: build.dirty,
        }
    }
}

pub async fn run() -> Result<()> {
    let response = run_daemon_status(false).await?;
    print!("{}", response.text);
    if response.summary.blocked {
        if response.summary.entities == 0 {
            eprintln!("hint: run `kin init` to build the semantic graph from current state");
        }
        anyhow::bail!("{}", response.summary.readiness);
    }
    Ok(())
}

pub async fn run_json() -> Result<()> {
    let response = run_daemon_status(true).await?;
    if let Some(json) = response.json {
        println!("{json}");
    }
    Ok(())
}

async fn run_daemon_status(json: bool) -> Result<CommandStatusResponse> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?).ok_or_else(|| {
        anyhow::anyhow!(
            "not a Kin repository (no .kin/ found)\nhint: run `kin init .` to initialize a Kin repository here"
        )
    })?;
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(&layout).await?);
    let base_url = daemon_url.ok_or_else(|| {
        anyhow::anyhow!("Kin daemon is required for status but no daemon endpoint is available")
    })?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client
        .command_status(&CommandStatusRequest::new(json))
        .await
        .context("daemon status failed")
}

pub fn build_status_summary(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
) -> Result<StatusSummary> {
    let current = kin_core::read_current_branch(layout)?;
    let source_root = kin_core::source_dir(layout);
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
    let embed_status = graph.embedding_status();

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
    let merge_state = crate::commands::conflicts::load_merge_state(layout)
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
        embeddings_indexed: embed_status.indexed,
        embeddings_pending: embed_status.pending,
        embeddings_total: embed_status.total,
        import_state,
        readiness,
        blocked,
        merge_state,
    })
}

impl StatusSummary {
    /// Embedding (semantic signal) coverage in the SAME shape `kin locate
    /// --json` reports as `semantic_coverage`. Sourced from the identical
    /// daemon-owned `graph.embedding_status()` numbers locate consumes (carried
    /// here on the summary), so an agent reads readiness the same way from
    /// either command.
    ///
    /// Honest by construction (R5): `complete` mirrors
    /// `locate::embedding_status_complete` exactly — `total == 0` (nothing to
    /// embed) or every entity indexed with nothing pending. A partial/zero
    /// index yields `complete: false` plus a `note`; we never fabricate
    /// `complete: true`.
    pub fn semantic_coverage(&self) -> crate::commands::locate::SemanticCoverage {
        let indexed = self.embeddings_indexed;
        let total = self.embeddings_total;
        let pending = self.embeddings_pending;
        let complete = total == 0 || (indexed == total && pending == 0);
        let note = if complete {
            None
        } else {
            Some(format!(
                "semantic signal partial: {indexed}/{total} indexed, {} unindexed, {pending} pending. Run `kin embed` for full semantic ranking.",
                total.saturating_sub(indexed)
            ))
        };
        crate::commands::locate::SemanticCoverage {
            indexed,
            total,
            pending,
            complete,
            note,
        }
    }

    pub fn render_lines(&self) -> Vec<String> {
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
        if self.embeddings_total > 0 {
            lines.push(format!(
                "Enrichment: {}/{} embeddings indexed, {} pending",
                self.embeddings_indexed, self.embeddings_total, self.embeddings_pending
            ));
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

pub fn build_command_status_response(
    summary: StatusSummary,
    json: bool,
    build: Option<BuildStatus>,
) -> Result<CommandStatusResponse> {
    let mut lines = summary.render_lines();
    if let Some(build) = &build {
        lines.push(format!(
            "Build: CLI {} / daemon {}",
            build_id(&build.cli_sha, build.cli_dirty),
            build_id(&build.daemon_sha, build.daemon_dirty)
        ));
    }
    let text = lines
        .into_iter()
        .map(|line| format!("{line}\n"))
        .collect::<String>();
    let json = if json {
        let payload = StatusJson {
            initialized: !summary.blocked,
            entity_count: summary.entities,
            graph_state: if summary.blocked {
                "blocked".to_string()
            } else {
                "ready".to_string()
            },
            enrichment: EnrichmentJson {
                embeddings_indexed: summary.embeddings_indexed,
                embeddings_pending: summary.embeddings_pending,
                embeddings_total: summary.embeddings_total,
            },
            semantic_coverage: summary.semantic_coverage(),
            build: build.clone(),
        };
        Some(serde_json::to_string(&payload)?)
    } else {
        None
    };
    Ok(CommandStatusResponse {
        summary,
        build,
        text,
        json,
    })
}

fn build_id(sha: &str, dirty: bool) -> String {
    if dirty && sha != "unknown" {
        format!("{sha}-dirty")
    } else {
        sha.to_string()
    }
}

/// Test-only: open the local snapshot directly, bypassing the daemon, for
/// exercising [`build_status_summary`] against a real repo fixture.
///
/// Deliberately calls `discover_with_daemon_url(cwd, None)` rather than
/// `KinLayout::discover(cwd)`: this helper's whole point is local-only
/// discovery, so it must never pick up whatever `KIN_DAEMON_URL` happens to
/// be set in the process at the moment it runs. `cargo test` runs unit tests
/// from many modules concurrently in one process and process env is global,
/// so reading the ambient var here would make this function's result depend
/// on which *other*, unrelated test happens to be mid-flight — parameterizing
/// it out entirely removes that hazard rather than papering over it with
/// serialization.
#[cfg(test)]
async fn load_status(cwd: &Path) -> Result<StatusSummary> {
    let layout = kin_core::KinLayout::discover_with_daemon_url(cwd, None).ok_or_else(|| {
        anyhow::anyhow!(
            "not a Kin repository (no .kin/ found)\nhint: run `kin init .` to initialize a Kin repository here"
        )
    })?;
    let snap = crate::backend::open_kindb_snapshot_read_only(&layout)?;
    let graph = snap.graph();
    build_status_summary(&layout, graph.as_ref())
}

#[cfg(test)]
async fn run_for_cwd(cwd: &Path) -> Result<()> {
    let summary = load_status(cwd).await?;
    if summary.blocked {
        anyhow::bail!("{}", summary.readiness);
    }
    Ok(())
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

    fn summary_with_embeddings(
        indexed: usize,
        total: usize,
        pending: usize,
    ) -> super::StatusSummary {
        super::StatusSummary {
            repo_root: std::path::PathBuf::from("/tmp/repo"),
            source_root: std::path::PathBuf::from("/tmp/repo"),
            world_preset: "default".to_string(),
            default_remote: "(not configured)".to_string(),
            branch: "main".to_string(),
            head: "deadbeef".to_string(),
            entities: total,
            role_counts: std::collections::HashMap::new(),
            embeddings_indexed: indexed,
            embeddings_pending: pending,
            embeddings_total: total,
            import_state: "materialized semantic graph".to_string(),
            readiness: "ready".to_string(),
            blocked: false,
            merge_state: None,
        }
    }

    #[test]
    fn semantic_coverage_reports_complete_when_fully_indexed() {
        let coverage = summary_with_embeddings(10, 10, 0).semantic_coverage();
        assert_eq!(coverage.indexed, 10);
        assert_eq!(coverage.total, 10);
        assert_eq!(coverage.pending, 0);
        assert!(coverage.complete);
        // no degradation note when truly complete.
        assert!(coverage.note.is_none());
    }

    #[test]
    fn semantic_coverage_reports_complete_when_nothing_to_embed() {
        // total == 0 mirrors locate::embedding_status_complete: nothing eligible.
        let coverage = summary_with_embeddings(0, 0, 0).semantic_coverage();
        assert!(coverage.complete);
        assert!(coverage.note.is_none());
    }

    #[test]
    fn semantic_coverage_is_honest_about_partial_index() {
        // R5: a half-embedded graph must NOT fabricate complete:true.
        let coverage = summary_with_embeddings(3, 10, 7).semantic_coverage();
        assert_eq!(coverage.indexed, 3);
        assert_eq!(coverage.total, 10);
        assert_eq!(coverage.pending, 7);
        assert!(!coverage.complete);
        let note = coverage.note.expect("partial coverage must carry a note");
        assert!(
            note.contains("kin embed"),
            "note should point at remedy: {note}"
        );
    }

    #[test]
    fn semantic_coverage_is_honest_when_indexed_but_still_pending() {
        // indexed == total but pending > 0 is still incomplete.
        let coverage = summary_with_embeddings(10, 10, 4).semantic_coverage();
        assert!(!coverage.complete);
        assert!(coverage.note.is_some());
    }

    #[test]
    fn command_status_response_includes_cli_and_daemon_builds() {
        let build = super::BuildStatus {
            cli_sha: "bd7cd12".to_string(),
            cli_dirty: false,
            daemon_sha: "a09f882".to_string(),
            daemon_dirty: true,
        };
        let response = super::build_command_status_response(
            summary_with_embeddings(1, 1, 0),
            true,
            Some(build),
        )
        .unwrap();

        assert!(response
            .text
            .contains("Build: CLI bd7cd12 / daemon a09f882-dirty"));
        let json: serde_json::Value = serde_json::from_str(&response.json.unwrap()).unwrap();
        assert_eq!(json["build"]["cli_sha"], "bd7cd12");
        assert_eq!(json["build"]["daemon_sha"], "a09f882");
        assert_eq!(json["build"]["daemon_dirty"], true);
    }

    #[tokio::test]
    #[serial_test::serial]
    async fn load_status_rejects_non_kin_repo() {
        let dir = tempfile::tempdir().unwrap();
        let err = load_status(dir.path()).await.unwrap_err();
        assert!(err
            .to_string()
            .starts_with("not a Kin repository (no .kin/ found)"));
    }

    #[tokio::test]
    #[serial_test::serial]
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
        assert_eq!(summary.embeddings_indexed, 0);
        assert_eq!(summary.embeddings_pending, 0);
        assert_eq!(summary.embeddings_total, 0);
        assert!(summary.merge_state.is_none());
    }

    #[tokio::test]
    #[serial_test::serial]
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
    #[serial_test::serial]
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
    #[serial_test::serial]
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
    #[serial_test::serial]
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
