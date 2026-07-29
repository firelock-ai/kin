// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_core::layout::KIN_LAYOUT_VERSION;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::ffi::{OsStr, OsString};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct BenchMeta {
    schema: &'static str,
    kin_version: &'static str,
    graph_build_pipeline_epoch: &'static str,
    parser_schema_epoch: &'static str,
    layout_schema_version: u32,
    graph_snapshot_version: u32,
    text_index_format_version: u32,
    vector_index_metadata_version: Option<u32>,
    feature_flags: Vec<&'static str>,
    embeddings: EmbeddingMeta,
    coordination: CoordinationMeta,
    kin_commit: &'static str,
    kin_dirty: bool,
    kin_source_known: bool,
    dependency_provenance: &'static str,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct CoordinationMeta {
    pub schema: String,
    pub effective_mode: String,
    #[serde(default)]
    pub effective_mode_source: String,
    #[serde(default)]
    pub daemon_runtime_attested: bool,
    pub default_mode: String,
    pub hard_rejection_active: bool,
    pub capability_evaluation_active: bool,
    pub capability_fail_closed_active: bool,
    pub intent_registration_linearized: bool,
    pub max_concurrent_intents_enforced: bool,
    pub hard_intent_capabilities_checked: Vec<String>,
    pub transaction_capabilities_covered: Vec<String>,
    pub surfaces: CoordinationSurfaceMeta,
    pub durable_event_schema: String,
    pub durable_event_store: String,
    pub durable_event_fsync_before_broadcast: bool,
    #[serde(default)]
    pub durable_event_mutation_fail_closed: bool,
    #[serde(default)]
    pub durable_event_lifecycle_complete: bool,
    #[serde(default)]
    pub durable_event_reservation_prefix: String,
    #[serde(default)]
    pub durable_event_requires_terminal_pair: bool,
    pub durable_event_families: Vec<String>,
    pub contract_scope_claim_eligible: bool,
    pub all_write_surfaces_claim_eligible: bool,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct CoordinationSurfaceMeta {
    pub vfs_agent_write_entity: bool,
    pub vfs_agent_write_artifact: bool,
    pub mcp_transaction_entity: bool,
    pub mcp_transaction_artifact: bool,
    pub mcp_relation_endpoint_entities: bool,
    pub contract: bool,
    pub direct_filesystem_write: bool,
    pub non_transaction_graph_mutation_tools: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct EmbeddingMeta {
    vector_enabled: bool,
    embeddings_enabled: bool,
    metal_enabled: bool,
    model_id: Option<String>,
    model_revision: Option<String>,
    pipeline_epoch: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct PreparedManifest {
    schema: &'static str,
    cache_key: String,
    repo_base_key: String,
    repo_identity: String,
    git_head: String,
    git_tree: String,
    graph_build_pipeline_epoch: &'static str,
    parser_schema_epoch: &'static str,
    layout_schema_version: u32,
    graph_snapshot_version: u32,
    text_index_format_version: u32,
    vector_index_metadata_version: Option<u32>,
    feature_flags: Vec<&'static str>,
    embedding_model_id: Option<String>,
    embedding_model_revision: Option<String>,
    embedding_pipeline_epoch: Option<String>,
    embeddings_enabled: bool,
    vector_enabled: bool,
    metal_enabled: bool,
    kin_commit: &'static str,
    kin_dirty: bool,
    kin_version: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RepoBaseManifest {
    schema: &'static str,
    repo_base_key: String,
    repo_identity: String,
    graph_build_pipeline_epoch: &'static str,
    parser_schema_epoch: &'static str,
    layout_schema_version: u32,
    graph_snapshot_version: u32,
    text_index_format_version: u32,
    vector_index_metadata_version: Option<u32>,
    feature_flags: Vec<&'static str>,
    embedding_model_id: Option<String>,
    embedding_model_revision: Option<String>,
    embedding_pipeline_epoch: Option<String>,
    embeddings_enabled: bool,
    vector_enabled: bool,
    metal_enabled: bool,
    kin_commit: &'static str,
    kin_dirty: bool,
    kin_version: &'static str,
    source_git_head: String,
    source_git_tree: String,
}

#[derive(Debug, Clone, Serialize)]
struct BenchMetaWithPreparedState {
    #[serde(flatten)]
    meta: BenchMeta,
    prepared_manifest: PreparedManifest,
    repo_base_manifest: RepoBaseManifest,
}

pub async fn run(json: bool, prepared_state: bool) -> Result<()> {
    let meta = build_meta()?;

    if prepared_state {
        let (prepared_manifest, repo_base_manifest) =
            build_prepared_manifests(&meta, &std::env::current_dir()?)?;
        let payload = BenchMetaWithPreparedState {
            meta,
            prepared_manifest,
            repo_base_manifest,
        };
        if json {
            println!("{}", serde_json::to_string_pretty(&payload)?);
        } else {
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
        return Ok(());
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&meta)?);
    } else {
        println!("schema: {}", meta.schema);
        println!("kin_version: {}", meta.kin_version);
        println!(
            "graph_build_pipeline_epoch: {}",
            meta.graph_build_pipeline_epoch
        );
        println!("parser_schema_epoch: {}", meta.parser_schema_epoch);
        println!("layout_schema_version: {}", meta.layout_schema_version);
        println!("graph_snapshot_version: {}", meta.graph_snapshot_version);
        println!(
            "text_index_format_version: {}",
            meta.text_index_format_version
        );
        if let Some(version) = meta.vector_index_metadata_version {
            println!("vector_index_metadata_version: {}", version);
        } else {
            println!("vector_index_metadata_version: disabled");
        }
        println!("feature_flags: {}", meta.feature_flags.join(","));
        println!(
            "coordination_enforcement_mode: {}",
            meta.coordination.effective_mode
        );
        println!(
            "coordination_contract_scope_claim_eligible: {}",
            meta.coordination.contract_scope_claim_eligible
        );
        println!("kin_commit: {}", meta.kin_commit);
        println!("kin_dirty: {}", meta.kin_dirty);
        println!("kin_source_known: {}", meta.kin_source_known);
        println!("dependency_provenance: {}", meta.dependency_provenance);
        if let Some(model_id) = meta.embeddings.model_id.as_deref() {
            println!("embedding_model_id: {}", model_id);
        }
        if let Some(revision) = meta.embeddings.model_revision.as_deref() {
            println!("embedding_model_revision: {}", revision);
        }
        if let Some(epoch) = meta.embeddings.pipeline_epoch.as_deref() {
            println!("embedding_pipeline_epoch: {}", epoch);
        }
    }

    Ok(())
}

pub(crate) fn build_meta() -> Result<BenchMeta> {
    let build = kin_buildinfo::get();
    Ok(BenchMeta {
        schema: "kin.bench-meta.v2",
        kin_version: env!("CARGO_PKG_VERSION"),
        graph_build_pipeline_epoch: crate::commands::init::GRAPH_BUILD_PIPELINE_EPOCH,
        parser_schema_epoch: kin_parser::PARSER_SCHEMA_EPOCH,
        layout_schema_version: KIN_LAYOUT_VERSION,
        graph_snapshot_version: kin_db::GraphSnapshot::CURRENT_VERSION,
        text_index_format_version: kin_db::TEXT_INDEX_FORMAT_VERSION,
        vector_index_metadata_version: vector_index_metadata_version(),
        feature_flags: feature_flags(),
        embeddings: embedding_meta(),
        coordination: coordination_meta(),
        kin_commit: build.sha,
        kin_dirty: build.dirty,
        kin_source_known: build.source_known,
        dependency_provenance: build.dependency_provenance,
    })
}

pub fn coordination_meta() -> CoordinationMeta {
    coordination_meta_with_source(
        kin_mcp::CoordinationEnforcementMode::from_env(),
        "process_env",
        false,
    )
}

pub fn coordination_meta_for_mode(mode: kin_mcp::CoordinationEnforcementMode) -> CoordinationMeta {
    coordination_meta_with_source(mode, "explicit_mode", false)
}

pub fn coordination_meta_for_daemon_mode(
    mode: kin_mcp::CoordinationEnforcementMode,
) -> CoordinationMeta {
    coordination_meta_with_source(mode, "daemon_startup_snapshot", true)
}

fn coordination_meta_with_source(
    mode: kin_mcp::CoordinationEnforcementMode,
    source: &str,
    daemon_runtime_attested: bool,
) -> CoordinationMeta {
    CoordinationMeta {
        schema: "kin.coordination-enforcement.v1".to_string(),
        effective_mode: mode.as_str().to_string(),
        effective_mode_source: source.to_string(),
        daemon_runtime_attested,
        default_mode: "warn".to_string(),
        hard_rejection_active: mode.is_enforcing(),
        capability_evaluation_active: mode.evaluates(),
        capability_fail_closed_active: mode.is_enforcing(),
        intent_registration_linearized: true,
        max_concurrent_intents_enforced: mode.is_enforcing(),
        hard_intent_capabilities_checked: vec!["can_write".to_string()],
        transaction_capabilities_covered: vec!["can_write".to_string(), "can_commit".to_string()],
        surfaces: CoordinationSurfaceMeta {
            vfs_agent_write_entity: true,
            vfs_agent_write_artifact: true,
            mcp_transaction_entity: true,
            mcp_transaction_artifact: true,
            mcp_relation_endpoint_entities: true,
            contract: false,
            direct_filesystem_write: false,
            non_transaction_graph_mutation_tools: false,
        },
        durable_event_schema: "kin.coordination-event.v1".to_string(),
        durable_event_store: ".kin/coordination_events.jsonl".to_string(),
        durable_event_fsync_before_broadcast: true,
        durable_event_mutation_fail_closed: true,
        durable_event_lifecycle_complete: true,
        durable_event_reservation_prefix: "pending:".to_string(),
        durable_event_requires_terminal_pair: true,
        durable_event_families: vec![
            "intent_registration".to_string(),
            "intent_release".to_string(),
            "transaction_outcome".to_string(),
        ],
        contract_scope_claim_eligible: false,
        all_write_surfaces_claim_eligible: false,
    }
}

/// Whether the Metal embedding backend is *actually* compiled into this binary.
///
/// The real `kin-db/metal` -> `kin-infer/metal` backend is pulled in by the
/// `[target.'cfg(target_os = "macos")'.dependencies] kin-db = { features = ["metal"] }`
/// block in kin-cli/Cargo.toml. Cargo target-dependency sections are gated by the build
/// *target* only — never by the crate's own cargo features (`feature = ...` isn't even
/// allowed in a `[target.'cfg(...)']` key) — so that block is UNCONDITIONAL on macOS:
/// Metal is built for every macOS build, even under `--no-default-features`. The `metal`
/// cargo feature is therefore vestigial for "is Metal built"; the honest predicate is the
/// target OS alone. (`cfg!(feature = "metal")` would be wrong both ways: true on Linux where
/// Metal isn't compiled, and false for a macOS `--no-default-features` build where it is.)
const fn metal_active() -> bool {
    cfg!(target_os = "macos")
}

fn feature_flags() -> Vec<&'static str> {
    let mut flags = Vec::new();
    if cfg!(feature = "vector") {
        flags.push("vector");
    }
    if cfg!(feature = "embeddings") {
        flags.push("embeddings");
    }
    if metal_active() {
        flags.push("metal");
    }
    flags.sort_unstable();
    flags
}

fn embedding_meta() -> EmbeddingMeta {
    #[cfg(feature = "embeddings")]
    {
        let runtime = kin_db::embed::configured_embedding_runtime();
        EmbeddingMeta {
            vector_enabled: cfg!(feature = "vector"),
            embeddings_enabled: true,
            metal_enabled: metal_active(),
            model_id: Some(runtime.model_id),
            model_revision: Some(runtime.revision),
            pipeline_epoch: Some(runtime.pipeline_epoch),
        }
    }

    #[cfg(not(feature = "embeddings"))]
    {
        EmbeddingMeta {
            vector_enabled: cfg!(feature = "vector"),
            embeddings_enabled: false,
            metal_enabled: metal_active(),
            model_id: None,
            model_revision: None,
            pipeline_epoch: None,
        }
    }
}

fn vector_index_metadata_version() -> Option<u32> {
    #[cfg(feature = "vector")]
    {
        Some(kin_db::VECTOR_INDEX_METADATA_VERSION)
    }

    #[cfg(not(feature = "vector"))]
    {
        None
    }
}

pub(crate) fn build_prepared_manifests(
    meta: &BenchMeta,
    repo_path: &Path,
) -> Result<(PreparedManifest, RepoBaseManifest)> {
    let repo_identity = detect_repo_identity(repo_path);
    let git_head = git_output(repo_path, ["rev-parse", "HEAD"])?;
    let git_tree = git_output(repo_path, ["rev-parse", "HEAD^{tree}"])?;
    let cache_key = hash_json(&serde_json::json!({
        "repo_identity": &repo_identity,
        "git_head": &git_head,
        "git_tree": &git_tree,
        "graph_build_pipeline_epoch": meta.graph_build_pipeline_epoch,
        "parser_schema_epoch": meta.parser_schema_epoch,
        "layout_schema_version": meta.layout_schema_version,
        "graph_snapshot_version": meta.graph_snapshot_version,
        "text_index_format_version": meta.text_index_format_version,
        "vector_index_metadata_version": meta.vector_index_metadata_version,
        "feature_flags": &meta.feature_flags,
        "embedding_model_id": &meta.embeddings.model_id,
        "embedding_model_revision": &meta.embeddings.model_revision,
        "embedding_pipeline_epoch": &meta.embeddings.pipeline_epoch,
        "embeddings_enabled": meta.embeddings.embeddings_enabled,
        "vector_enabled": meta.embeddings.vector_enabled,
        "metal_enabled": meta.embeddings.metal_enabled,
        "kin_commit": meta.kin_commit,
        "kin_dirty": meta.kin_dirty,
    }));
    let repo_base_key = hash_json(&serde_json::json!({
        "repo_identity": &repo_identity,
        "graph_build_pipeline_epoch": meta.graph_build_pipeline_epoch,
        "parser_schema_epoch": meta.parser_schema_epoch,
        "layout_schema_version": meta.layout_schema_version,
        "graph_snapshot_version": meta.graph_snapshot_version,
        "text_index_format_version": meta.text_index_format_version,
        "vector_index_metadata_version": meta.vector_index_metadata_version,
        "feature_flags": &meta.feature_flags,
        "embedding_model_id": &meta.embeddings.model_id,
        "embedding_model_revision": &meta.embeddings.model_revision,
        "embedding_pipeline_epoch": &meta.embeddings.pipeline_epoch,
        "embeddings_enabled": meta.embeddings.embeddings_enabled,
        "vector_enabled": meta.embeddings.vector_enabled,
        "metal_enabled": meta.embeddings.metal_enabled,
        "kin_commit": meta.kin_commit,
        "kin_dirty": meta.kin_dirty,
    }));

    let prepared = PreparedManifest {
        schema: "kin.prepared-state.v2",
        cache_key,
        repo_identity,
        git_head,
        git_tree,
        graph_build_pipeline_epoch: meta.graph_build_pipeline_epoch,
        parser_schema_epoch: meta.parser_schema_epoch,
        layout_schema_version: meta.layout_schema_version,
        graph_snapshot_version: meta.graph_snapshot_version,
        text_index_format_version: meta.text_index_format_version,
        vector_index_metadata_version: meta.vector_index_metadata_version,
        feature_flags: meta.feature_flags.clone(),
        embedding_model_id: meta.embeddings.model_id.clone(),
        embedding_model_revision: meta.embeddings.model_revision.clone(),
        embedding_pipeline_epoch: meta.embeddings.pipeline_epoch.clone(),
        embeddings_enabled: meta.embeddings.embeddings_enabled,
        vector_enabled: meta.embeddings.vector_enabled,
        metal_enabled: meta.embeddings.metal_enabled,
        kin_commit: meta.kin_commit,
        kin_dirty: meta.kin_dirty,
        kin_version: meta.kin_version,
        repo_base_key: repo_base_key.clone(),
    };
    let repo_base = RepoBaseManifest {
        schema: "kin.prepared-base.v2",
        repo_base_key,
        repo_identity: prepared.repo_identity.clone(),
        graph_build_pipeline_epoch: meta.graph_build_pipeline_epoch,
        parser_schema_epoch: meta.parser_schema_epoch,
        layout_schema_version: meta.layout_schema_version,
        graph_snapshot_version: meta.graph_snapshot_version,
        text_index_format_version: meta.text_index_format_version,
        vector_index_metadata_version: meta.vector_index_metadata_version,
        feature_flags: meta.feature_flags.clone(),
        embedding_model_id: meta.embeddings.model_id.clone(),
        embedding_model_revision: meta.embeddings.model_revision.clone(),
        embedding_pipeline_epoch: meta.embeddings.pipeline_epoch.clone(),
        embeddings_enabled: meta.embeddings.embeddings_enabled,
        vector_enabled: meta.embeddings.vector_enabled,
        metal_enabled: meta.embeddings.metal_enabled,
        kin_commit: meta.kin_commit,
        kin_dirty: meta.kin_dirty,
        kin_version: meta.kin_version,
        source_git_head: prepared.git_head.clone(),
        source_git_tree: prepared.git_tree.clone(),
    };
    Ok((prepared, repo_base))
}

fn detect_repo_identity(repo_path: &Path) -> String {
    git_output_optional(repo_path, &["remote", "get-url", "origin"])
        .map(|remote| format!("git:{remote}"))
        .unwrap_or_else(|| {
            format!(
                "path:{}",
                repo_path
                    .canonicalize()
                    .unwrap_or_else(|_| repo_path.to_path_buf())
                    .display()
            )
        })
}

fn git_output(repo_path: &Path, args: [&str; 2]) -> Result<String> {
    git_output_inner(repo_path, &args)
}

fn git_output_optional(repo_path: &Path, args: &[&str]) -> Option<String> {
    git_output_inner(repo_path, args).ok()
}

const BENCH_GIT_TIMEOUT: Duration = Duration::from_secs(10);
const BENCH_GIT_CAPTURE_LIMIT: u64 = 256 * 1024;

fn git_output_inner(repo_path: &Path, args: &[&str]) -> Result<String> {
    let host_path = kin_core::shims::unshimmed_path();
    git_output_inner_with_policy(
        repo_path,
        args,
        &host_path,
        BENCH_GIT_TIMEOUT,
        BENCH_GIT_CAPTURE_LIMIT,
    )
}

fn git_output_inner_with_policy(
    repo_path: &Path,
    args: &[&str],
    host_path: &str,
    timeout: Duration,
    capture_limit: u64,
) -> Result<String> {
    let resolution_cwd =
        std::env::current_dir().context("capture host Git resolution directory for benchmark")?;
    git_output_inner_with_resolution_policy(
        repo_path,
        args,
        host_path,
        &resolution_cwd,
        timeout,
        capture_limit,
    )
}

fn git_output_inner_with_resolution_policy(
    repo_path: &Path,
    args: &[&str],
    host_path: &str,
    resolution_cwd: &Path,
    timeout: Duration,
    capture_limit: u64,
) -> Result<String> {
    let repo_root = repo_path
        .canonicalize()
        .with_context(|| format!("canonicalize benchmark repository {}", repo_path.display()))?;
    let host_path = absolute_bench_host_search_path(host_path, resolution_cwd)?;
    let git = which::which_in("git", Some(&host_path), resolution_cwd)
        .context("locate host Git executable for benchmark metadata")?;
    let git = if git.is_absolute() {
        git
    } else {
        resolution_cwd.join(git)
    };
    let mut command = Command::new(git);
    command
        .arg("--no-replace-objects")
        .args(args)
        .current_dir(&repo_root);
    run_bench_git_command(&mut command, args, &host_path, timeout, capture_limit)
}

fn absolute_bench_host_search_path(
    host_path: impl AsRef<OsStr>,
    resolution_cwd: &Path,
) -> Result<OsString> {
    let entries = std::env::split_paths(host_path.as_ref())
        .map(|entry| {
            if entry.is_absolute() {
                entry
            } else {
                resolution_cwd.join(entry)
            }
        })
        .collect::<Vec<_>>();
    std::env::join_paths(entries).with_context(|| {
        format!(
            "normalize host Git PATH against {} for benchmark metadata",
            resolution_cwd.display()
        )
    })
}

fn run_bench_git_command(
    command: &mut Command,
    args: &[&str],
    host_path: &OsStr,
    timeout: Duration,
    capture_limit: u64,
) -> Result<String> {
    let label = format!("Git benchmark metadata query {args:?}");
    finalize_bench_git_process(command, host_path);
    let output = crate::daemon_client::probe_process::output_finalized_with_timeout_and_limit(
        command,
        &label,
        timeout,
        capture_limit,
    )
    .with_context(|| format!("run host Git benchmark metadata query {args:?}"))?;
    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let stdout = String::from_utf8(output.stdout)?;
    let value = stdout.trim();
    if value.is_empty() {
        return Err(anyhow::anyhow!(
            "git {} returned empty output",
            args.join(" ")
        ));
    }
    Ok(value.to_string())
}

/// Apply the complete Git/Kin/VFS/loader authority boundary immediately
/// before bounded spawn. The bounded helper may only attach stdio afterward.
fn finalize_bench_git_process(command: &mut Command, host_path: &OsStr) {
    finalize_bench_git_process_with_ambient(
        command,
        host_path,
        std::env::vars_os().map(|(key, _)| key),
    );
}

fn finalize_bench_git_process_with_ambient(
    command: &mut Command,
    host_path: &OsStr,
    ambient_keys: impl IntoIterator<Item = std::ffi::OsString>,
) {
    let explicit_authority = command
        .get_envs()
        .map(|(key, _)| key.to_os_string())
        .filter(|key| is_bench_git_authority_env(key))
        .collect::<Vec<_>>();
    for key in ambient_keys
        .into_iter()
        .filter(|key| is_bench_git_authority_env(key))
        .chain(explicit_authority)
    {
        command.env_remove(key);
    }
    command
        .env("PATH", host_path)
        .env("KIN_VFS_DISABLE", "1")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_PAGER", "cat")
        .env("GIT_ALLOW_PROTOCOL", "file")
        .env("GIT_PROTOCOL_FROM_USER", "0")
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_OPTIONAL_LOCKS", "0");
    #[cfg(unix)]
    command.env("GIT_CONFIG_GLOBAL", "/dev/null");
    #[cfg(windows)]
    command.env("GIT_CONFIG_GLOBAL", "NUL");
    #[cfg(not(any(unix, windows)))]
    command.env(
        "GIT_CONFIG_GLOBAL",
        command
            .get_current_dir()
            .unwrap_or_else(|| Path::new("."))
            .join(".kin-empty-global-gitconfig"),
    );
}

fn is_bench_git_authority_env(key: &std::ffi::OsStr) -> bool {
    let label = key.to_string_lossy();
    bench_git_env_name_starts_with(&label, "GIT_")
        || bench_git_env_name_starts_with(&label, "KIN_")
        || bench_git_env_name_starts_with(&label, "_KIN_")
        || bench_git_env_name_starts_with(&label, "DYLD_")
        || bench_git_env_name_starts_with(&label, "LD_")
}

#[cfg(windows)]
fn bench_git_env_name_starts_with(actual: &str, expected: &str) -> bool {
    actual
        .get(..expected.len())
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case(expected))
}

#[cfg(not(windows))]
fn bench_git_env_name_starts_with(actual: &str, expected: &str) -> bool {
    actual.starts_with(expected)
}

fn hash_json(value: &serde_json::Value) -> String {
    let bytes = serde_json::to_vec(value).expect("json serialization should succeed");
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::{
        build_meta, build_prepared_manifests, embedding_meta, feature_flags,
        finalize_bench_git_process_with_ambient, git_output_inner, metal_active,
        vector_index_metadata_version,
    };
    #[cfg(unix)]
    use super::{git_output_inner_with_policy, git_output_inner_with_resolution_policy};
    use std::ffi::{OsStr, OsString};
    use std::fs;
    use std::path::Path;
    use std::process::Command;
    #[cfg(unix)]
    use std::time::Duration;
    use tempfile::tempdir;

    fn git<const N: usize>(
        repository: &Path,
        args: [&str; N],
    ) -> kin_git::test_support::FixtureGitCommand {
        let mut command = crate::commands::test_subprocess::fixture_git(repository);
        command.args(args);
        command
    }

    fn require_git<const N: usize>(repository: &Path, args: [&str; N]) {
        let output = git(repository, args).output().unwrap();
        assert!(
            output.status.success(),
            "git {args:?} failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn configured_command_env(command: &Command, key: &str) -> Option<Option<std::ffi::OsString>> {
        command
            .get_envs()
            .find(|(candidate, _)| *candidate == OsStr::new(key))
            .map(|(_, value)| value.map(OsStr::to_os_string))
    }

    #[test]
    fn bench_git_finalizer_scrubs_ambient_and_explicit_authority() {
        let explicit = [
            "GIT_DIR",
            "KIN_SESSION",
            "_KIN_VFS_LAST_DIR",
            "DYLD_INSERT_LIBRARIES",
            "LD_PRELOAD",
        ];
        let ambient = [
            "GIT_WORK_TREE",
            "KIN_SOURCE_ROOT",
            "_KIN_TEST_AUTHORITY",
            "DYLD_LIBRARY_PATH",
            "LD_LIBRARY_PATH",
        ];
        let mut command = Command::new("git");
        for key in explicit {
            command.env(key, "poison");
        }

        finalize_bench_git_process_with_ambient(
            &mut command,
            OsStr::new("trusted-host-path"),
            ambient.into_iter().map(OsString::from),
        );

        for key in explicit.into_iter().chain(ambient) {
            assert_eq!(
                configured_command_env(&command, key),
                Some(None),
                "{key} retained authority"
            );
        }
        assert_eq!(
            configured_command_env(&command, "PATH"),
            Some(Some(OsString::from("trusted-host-path")))
        );
        assert_eq!(
            configured_command_env(&command, "KIN_VFS_DISABLE"),
            Some(Some(OsString::from("1")))
        );
        assert_eq!(
            configured_command_env(&command, "GIT_CONFIG_NOSYSTEM"),
            Some(Some(OsString::from("1")))
        );
        assert_eq!(
            configured_command_env(&command, "GIT_NO_REPLACE_OBJECTS"),
            Some(Some(OsString::from("1")))
        );
        assert_eq!(
            configured_command_env(&command, "GIT_OPTIONAL_LOCKS"),
            Some(Some(OsString::from("0")))
        );
    }

    #[cfg(unix)]
    fn write_bench_fake_git(bin: &Path, body: &str) {
        use std::os::unix::fs::PermissionsExt as _;

        fs::create_dir_all(bin).unwrap();
        let git = bin.join("git");
        fs::write(&git, format!("#!/bin/sh\nset -eu\n{body}\n")).unwrap();
        let mut permissions = fs::metadata(&git).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&git, permissions).unwrap();
    }

    #[cfg(unix)]
    fn fixture_process_is_live(pid: u32) -> bool {
        let system = sysinfo::System::new_all();
        system
            .process(sysinfo::Pid::from_u32(pid))
            .is_some_and(|process| {
                !matches!(
                    process.status(),
                    sysinfo::ProcessStatus::Dead | sysinfo::ProcessStatus::Zombie
                )
            })
    }

    #[test]
    fn bench_git_output_reads_from_a_real_repository() {
        let repo = tempdir().unwrap();
        require_git(repo.path(), ["init"]);

        assert_eq!(
            git_output_inner(repo.path(), &["rev-parse", "--is-inside-work-tree"]).unwrap(),
            "true"
        );
    }

    #[cfg(unix)]
    #[test]
    fn bench_git_output_uses_resolved_host_git_with_closed_stdin() {
        let fixture = tempdir().unwrap();
        let bin = fixture.path().join("host-bin");
        write_bench_fake_git(
            &bin,
            r#"
if IFS= read -r ignored; then
    echo "stdin remained readable" >&2
    exit 90
fi
printf 'path=%s\n' "$PATH"
printf 'vfs=%s\n' "$KIN_VFS_DISABLE"
printf 'nosystem=%s\n' "$GIT_CONFIG_NOSYSTEM"
printf 'global=%s\n' "$GIT_CONFIG_GLOBAL"
"#,
        );
        let host_path = bin.to_string_lossy();

        let output = git_output_inner_with_policy(
            fixture.path(),
            &["rev-parse", "HEAD"],
            &host_path,
            Duration::from_secs(2),
            16 * 1024,
        )
        .unwrap();

        assert!(output.contains(&format!("path={host_path}")), "{output}");
        assert!(output.contains("vfs=1"), "{output}");
        assert!(output.contains("nosystem=1"), "{output}");
        assert!(output.contains("global=/dev/null"), "{output}");
    }

    #[cfg(unix)]
    #[test]
    fn bench_git_relative_host_path_cannot_rebind_under_repository_cwd() {
        let fixture = tempdir().unwrap();
        let resolution_root = fixture.path().join("resolution");
        let repo_root = fixture.path().join("repository");
        write_bench_fake_git(&resolution_root.join("bin"), "printf trusted");
        write_bench_fake_git(&repo_root.join("bin"), "printf hostile");

        let output = git_output_inner_with_resolution_policy(
            &repo_root,
            &["rev-parse", "HEAD"],
            "bin",
            &resolution_root,
            Duration::from_secs(2),
            16 * 1024,
        )
        .unwrap();

        assert_eq!(output, "trusted");
    }

    #[cfg(unix)]
    #[test]
    fn bench_git_output_rejects_runaway_output_and_reaps_descendants() {
        let fixture = tempdir().unwrap();
        let bin = fixture.path().join("host-bin");
        write_bench_fake_git(
            &bin,
            r#"
/bin/sleep 30 &
printf '%s\n' "$!" > "${0%/*}/descendant.pid"
chunk='xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'
while :; do
    printf '%s' "$chunk"
done
"#,
        );
        let error = git_output_inner_with_policy(
            fixture.path(),
            &["rev-parse", "HEAD"],
            &bin.to_string_lossy(),
            Duration::from_secs(5),
            4 * 1024,
        )
        .expect_err("runaway benchmark Git output must fail closed");
        let message = format!("{error:#}");
        assert!(message.contains("exceeded the 4096-byte"), "{message}");
        assert!(message.contains("cleanup=ok"), "{message}");

        let pid = fs::read_to_string(bin.join("descendant.pid"))
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap();
        assert!(
            !fixture_process_is_live(pid),
            "runaway benchmark Git descendant {pid} survived bounded return"
        );
    }

    #[cfg(unix)]
    #[test]
    fn bench_git_output_times_out_and_reaps_descendants() {
        let fixture = tempdir().unwrap();
        let bin = fixture.path().join("host-bin");
        write_bench_fake_git(
            &bin,
            r#"
/bin/sleep 30 &
printf '%s\n' "$!" > "${0%/*}/descendant.pid"
wait
"#,
        );
        let error = git_output_inner_with_policy(
            fixture.path(),
            &["rev-parse", "HEAD"],
            &bin.to_string_lossy(),
            Duration::from_millis(200),
            16 * 1024,
        )
        .expect_err("hung benchmark Git query must time out");
        let message = format!("{error:#}");
        assert!(message.contains("timed out after 200ms"), "{message}");
        assert!(message.contains("cleanup=ok"), "{message}");

        let pid = fs::read_to_string(bin.join("descendant.pid"))
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap();
        assert!(
            !fixture_process_is_live(pid),
            "timed-out benchmark Git descendant {pid} survived bounded return"
        );
    }

    #[test]
    fn feature_flags_reflect_compile_configuration() {
        let flags = feature_flags();
        if cfg!(feature = "vector") {
            assert!(flags.contains(&"vector"));
        } else {
            assert!(!flags.contains(&"vector"));
        }
        if cfg!(feature = "embeddings") {
            assert!(flags.contains(&"embeddings"));
        } else {
            assert!(!flags.contains(&"embeddings"));
        }
    }

    #[test]
    fn embedding_meta_matches_feature_flags() {
        let meta = embedding_meta();
        assert_eq!(meta.vector_enabled, cfg!(feature = "vector"));
        assert_eq!(meta.embeddings_enabled, cfg!(feature = "embeddings"));
        // metal_enabled must track the ACTUAL compiled backend (macOS-only), not the
        // no-op `metal` marker feature which stays on for every target.
        assert_eq!(meta.metal_enabled, metal_active());
        if cfg!(feature = "embeddings") {
            assert!(meta.model_id.is_some());
            assert!(meta.model_revision.is_some());
            assert!(meta.pipeline_epoch.is_some());
        } else {
            assert!(meta.model_id.is_none());
            assert!(meta.model_revision.is_none());
            assert!(meta.pipeline_epoch.is_none());
        }
    }

    #[test]
    fn vector_metadata_version_tracks_vector_feature() {
        assert_eq!(
            vector_index_metadata_version().is_some(),
            cfg!(feature = "vector")
        );
    }

    #[test]
    fn prepared_manifest_tracks_repo_state() {
        let repo = tempdir().unwrap();
        fs::write(repo.path().join("README.md"), "hello\n").unwrap();
        require_git(repo.path(), ["init"]);
        require_git(repo.path(), ["config", "user.email", "kin@example.com"]);
        require_git(repo.path(), ["config", "user.name", "Kin"]);
        require_git(repo.path(), ["add", "README.md"]);
        let commit = git(repo.path(), ["commit", "--signoff", "-m", "init"])
            .author_date("1000000000 +0000")
            .committer_date("1000000000 +0000")
            .output()
            .unwrap();
        assert!(
            commit.status.success(),
            "git commit failed: stdout={} stderr={}",
            String::from_utf8_lossy(&commit.stdout),
            String::from_utf8_lossy(&commit.stderr)
        );

        let meta = build_meta().unwrap();
        let (prepared, repo_base) = build_prepared_manifests(&meta, repo.path()).unwrap();

        assert_eq!(prepared.schema, "kin.prepared-state.v2");
        assert!(!prepared.cache_key.is_empty());
        assert!(!prepared.repo_base_key.is_empty());
        assert!(prepared.repo_identity.starts_with("path:"));
        assert_eq!(
            prepared.graph_build_pipeline_epoch,
            meta.graph_build_pipeline_epoch
        );
        assert_eq!(prepared.parser_schema_epoch, meta.parser_schema_epoch);
        assert_eq!(repo_base.schema, "kin.prepared-base.v2");
        assert_eq!(repo_base.repo_base_key, prepared.repo_base_key);
        assert_eq!(repo_base.source_git_head, prepared.git_head);
    }

    #[test]
    fn prepared_manifest_cache_keys_track_kin_commit_and_dirty() {
        let repo = tempdir().unwrap();
        fs::write(repo.path().join("README.md"), "hello\n").unwrap();
        require_git(repo.path(), ["init"]);
        require_git(repo.path(), ["config", "user.email", "kin@example.com"]);
        require_git(repo.path(), ["config", "user.name", "Kin"]);
        require_git(repo.path(), ["add", "README.md"]);
        let commit = git(repo.path(), ["commit", "--signoff", "-m", "init"])
            .author_date("1000000100 +0000")
            .committer_date("1000000100 +0000")
            .output()
            .unwrap();
        assert!(
            commit.status.success(),
            "git commit failed: stdout={} stderr={}",
            String::from_utf8_lossy(&commit.stdout),
            String::from_utf8_lossy(&commit.stderr)
        );

        let meta = build_meta().unwrap();
        let (prepared_a, repo_base_a) = build_prepared_manifests(&meta, repo.path()).unwrap();

        let (prepared_a2, repo_base_a2) = build_prepared_manifests(&meta, repo.path()).unwrap();
        assert_eq!(
            prepared_a.cache_key, prepared_a2.cache_key,
            "prepared-state cache key must be STABLE across rebuilds of the same commit"
        );
        assert_eq!(
            repo_base_a.repo_base_key, repo_base_a2.repo_base_key,
            "repo-base cache key must be STABLE across rebuilds of the same commit"
        );

        let mut meta_commit = meta.clone();
        meta_commit.kin_commit = "ffffffffffff";
        let (prepared_b, repo_base_b) =
            build_prepared_manifests(&meta_commit, repo.path()).unwrap();
        assert_ne!(
            prepared_a.cache_key, prepared_b.cache_key,
            "prepared-state cache must miss when the Kin commit changes"
        );
        assert_ne!(
            repo_base_a.repo_base_key, repo_base_b.repo_base_key,
            "repo-base cache must miss when the Kin commit changes"
        );

        let mut meta_dirty = meta.clone();
        meta_dirty.kin_dirty = !meta.kin_dirty;
        let (prepared_c, repo_base_c) = build_prepared_manifests(&meta_dirty, repo.path()).unwrap();
        assert_ne!(
            prepared_a.cache_key, prepared_c.cache_key,
            "prepared-state cache must miss when the dirty flag changes"
        );
        assert_ne!(
            repo_base_a.repo_base_key, repo_base_c.repo_base_key,
            "repo-base cache must miss when the dirty flag changes"
        );
    }
}
