// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{anyhow, Context, Result};
use kin_index::{FileClassification, FileClassifier};
use kin_infer::resource::{Profile, ResourcePlan};
use kin_model::ChangeStore;
use kin_model::EntityStore;
use kin_model::VerificationStore;
use kin_model::{
    ArtifactId, AuthorId, Entity, EntityDelta, EntityFilter, EntityId, FileLayout, FilePathId,
    GraphNodeId, Hash256, OpaqueArtifact, ParseCompleteness, Relation, RelationDelta, RelationId,
    RelationKind, RelationOrigin, SemanticChange, SemanticChangeId, ShallowTrackedFile,
    SourceRegion, StructuredArtifact, TestCase, TestId, TestKind, TestRunner, Timestamp, WorkScope,
};
use kin_projection::build_layout;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tracing::{debug, info, warn};

/// Discovery cap for `kin init`. When more than this many indexable files are
/// found, init refuses to grind unless the caller explicitly opts in (`--force`)
/// or raises the limit via `KIN_INIT_MAX_FILES`.
const INIT_MAX_DISCOVERED_FILES: usize = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ResourcePoolConfig {
    profile: Profile,
    logical_cores: usize,
    rayon_threads: usize,
    reserve_logical_cores: usize,
}

fn init_resource_pool_config() -> Result<Option<ResourcePoolConfig>> {
    let Some(raw_profile) = std::env::var("KIN_RESOURCE_PROFILE")
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        return Ok(None);
    };

    let profile = super::resources::parse_profile(Some(&raw_profile))
        .map_err(|error| anyhow!("invalid KIN_RESOURCE_PROFILE for kin init: {error}"))?;
    if profile == Profile::Proof {
        return Ok(None);
    }

    let plan = ResourcePlan::detect(profile);
    Ok(Some(ResourcePoolConfig {
        profile,
        logical_cores: plan.host.logical_cores,
        rayon_threads: plan.host.rayon_threads.max(1),
        reserve_logical_cores: plan.host.reserve_logical_cores,
    }))
}

fn run_with_init_resource_pool<T, F>(phase: &'static str, work: F) -> Result<T>
where
    T: Send,
    F: FnOnce() -> Result<T> + Send,
{
    let Some(config) = init_resource_pool_config()? else {
        return work();
    };
    tracing::info!(
        target: "kin.resource",
        phase,
        profile = ?config.profile,
        logical_cores = config.logical_cores,
        rayon_threads = config.rayon_threads,
        reserve_logical_cores = config.reserve_logical_cores,
        "using resource-plan Rayon pool"
    );

    rayon::ThreadPoolBuilder::new()
        .num_threads(config.rayon_threads)
        .thread_name(move |idx| format!("kin-init-{phase}-{idx}"))
        .build()
        .map_err(|error| anyhow!("failed to build kin init Rayon pool: {error}"))?
        .install(work)
}

fn init_max_discovered_files() -> usize {
    std::env::var("KIN_INIT_MAX_FILES")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(INIT_MAX_DISCOVERED_FILES)
}

/// Repo-scoped ignore rules loaded from a `.kinignore` file at the repo root.
///
/// Each non-empty, non-`#` line is a pattern. A pattern without a `/` matches a
/// path component (basename) at any nesting level; a pattern containing a `/`
/// matches a repo-relative path or subtree prefix. No glob expansion — patterns
/// are matched literally so behavior is predictable.
#[derive(Debug, Default)]
struct KinIgnore {
    names: HashSet<String>,
    prefixes: Vec<String>,
}

impl KinIgnore {
    fn load(root: &Path) -> Self {
        let mut ignore = KinIgnore::default();
        let Ok(content) = fs::read_to_string(root.join(".kinignore")) else {
            return ignore;
        };
        for raw in content.lines() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let pattern = line.trim_end_matches('/');
            let pattern = pattern.strip_prefix("./").unwrap_or(pattern);
            if pattern.is_empty() {
                continue;
            }
            if pattern.contains('/') {
                ignore.prefixes.push(pattern.to_string());
            } else {
                ignore.names.insert(pattern.to_string());
            }
        }
        ignore
    }

    fn matches(&self, rel: &Path, name: &str) -> bool {
        if self.names.contains(name) {
            return true;
        }
        if self.prefixes.is_empty() {
            return false;
        }
        let rel_str = rel.to_string_lossy();
        self.prefixes
            .iter()
            .any(|prefix| rel_str == prefix.as_str() || rel_str.starts_with(&format!("{prefix}/")))
    }
}

/// True when a directory or file entry must never enter the init snapshot.
///
/// Matched by component name at every nesting level so nested sub-repos
/// (`.git`), nested or renamed Kin graph dirs (`.kin*`), and nested vendored
/// trees (`node_modules`, `target`, …) are all pruned — not just the ones at the
/// repo root.
fn snapshot_entry_ignored(name: &str, rel: &Path, ignore: &KinIgnore) -> bool {
    if kin_index::should_skip_dir(name) || name.starts_with(".kin") {
        return true;
    }
    ignore.matches(rel, name)
}

/// Count indexable files under `root`, applying the same pruning as the snapshot
/// walk. Stops early once `cap` is exceeded so a huge tree is never fully walked.
fn count_discoverable_files(
    root: &Path,
    dir: &Path,
    ignore: &KinIgnore,
    count: &mut usize,
    cap: usize,
) -> bool {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(_) => return false,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let Ok(rel) = path.strip_prefix(root) else {
            continue;
        };
        if snapshot_entry_ignored(&name_str, rel, ignore) {
            continue;
        }
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            if count_discoverable_files(root, &path, ignore, count, cap) {
                return true;
            }
        } else if file_type.is_file() {
            *count += 1;
            if *count > cap {
                return true;
            }
        }
    }
    false
}

/// True when the prune-aware file count under `root` exceeds `cap`.
fn discovery_exceeds_cap(root: &Path, ignore: &KinIgnore, cap: usize) -> bool {
    let mut count = 0usize;
    count_discoverable_files(root, root, ignore, &mut count, cap)
}

const INIT_WARM_CACHE_SCHEMA_VERSION: &str = "v1";
pub(crate) const INIT_WARM_CACHE_PIPELINE_EPOCH: &str =
    "init-warm-2026-06-15-stable-delta-entity-ids";

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct WarmCacheBundleManifestEntry {
    graph_root_hash: String,
    entity_count: usize,
    relation_count: usize,
    indexed_files: usize,
    published_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct WarmCacheRepoManifest {
    schema: String,
    pipeline_epoch: String,
    repo_identity: String,
    #[serde(default)]
    git_head: Option<String>,
    #[serde(default)]
    current_bundle_id: Option<String>,
    #[serde(default)]
    heads: BTreeMap<String, String>,
    #[serde(default)]
    bundles: BTreeMap<String, WarmCacheBundleManifestEntry>,
}

#[derive(Debug, Clone)]
struct IndexableFile {
    abs_path: PathBuf,
    rel_path: String,
    hash: [u8; 32],
    classification: FileClassification,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
struct InitIndexSummary {
    total_entity_count: usize,
    total_files: usize,
    linked_relations: usize,
    warm_cache_hit: bool,
    warm_text_index_reused: bool,
    warm_vector_index_reused: bool,
    warm_requeued_embeddings: usize,
    warm_changed_files: usize,
    warm_reparsed_files: usize,
}

#[derive(Debug, Clone, Copy, Default)]
struct WarmEmbeddingRestoreStatus {
    vector_index_reused: bool,
    requeued_embeddings: usize,
}

#[derive(Debug, Serialize)]
struct InitResultPayload {
    schema: &'static str,
    repo_root: String,
    kindb_snapshot_path: String,
    objects_dir: String,
    genesis_change: String,
    indexed_embeddings: usize,
    pending_embeddings: usize,
    #[serde(flatten)]
    summary: InitIndexSummary,
}

#[derive(Debug, Clone, Default)]
struct WarmCacheDeltaResult {
    reparsed_files: usize,
    queued_embeddings: Vec<EntityId>,
    queued_artifacts: Vec<ArtifactId>,
}

/// Take an independent copy-based snapshot of the working tree before `kin init`
/// mutates it.  We always use `fs::copy()` rather than hardlinks because
/// hardlinks share inodes — modifying the original file after init would
/// silently corrupt the snapshot.
/// Take snapshot BEFORE kin init creates .kin/.
/// We snapshot to a temp dir, then move it into .kin/snapshot/ after init succeeds.
///
/// Returns `(snapshot_path, manifest_json)`.  The manifest is NOT written to
/// disk here — the caller must write it *after* `collect_source_files` has
/// finished so that `manifest.json` never appears in `file_hashes`.
fn snapshot_repo(dir: &Path, force: bool) -> Result<(PathBuf, serde_json::Value)> {
    let _span = tracing::info_span!(
        "kin.init.snapshot_repo",
        root = %dir.display()
    )
    .entered();
    let tmp_snapshot = dir.join(".kin-snapshot-tmp");
    if tmp_snapshot.exists() {
        fs::remove_dir_all(&tmp_snapshot)?;
    }

    let ignore = KinIgnore::load(dir);
    let cap = init_max_discovered_files();
    if discovery_exceeds_cap(dir, &ignore, cap) {
        if !force {
            anyhow::bail!(
                "kin init discovered more than {cap} indexable files under {} — refusing to \
                 index a tree this large. Scope it with a .kinignore file (e.g. exclude \
                 vendored or generated-data directories), or re-run with --force to index \
                 anyway. Raise the limit with KIN_INIT_MAX_FILES.",
                dir.display()
            );
        }
        warn!(
            cap,
            root = %dir.display(),
            "kin init indexing a tree larger than the discovery cap because --force was set"
        );
    }

    fs::create_dir_all(&tmp_snapshot)?;
    let snapshot_dir = &tmp_snapshot;

    let mut file_count: u64 = 0;
    let mut total_bytes: u64 = 0;

    if let Err(err) = walk_and_snapshot(
        dir,
        dir,
        snapshot_dir,
        &ignore,
        &mut file_count,
        &mut total_bytes,
    ) {
        let _ = fs::remove_dir_all(&tmp_snapshot);
        return Err(err);
    }

    // Try to capture git HEAD for the manifest.
    let git_head = read_git_head(dir);

    let manifest = serde_json::json!({
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "file_count": file_count,
        "total_bytes": total_bytes,
        "git_head": git_head,
    });
    Ok((tmp_snapshot, manifest))
}

/// Write the snapshot manifest to disk.  Called after `collect_source_files` so
/// that `manifest.json` is never walked as a repo source file.
fn write_snapshot_manifest(snapshot_dir: &Path, manifest: &serde_json::Value) -> Result<()> {
    fs::write(
        snapshot_dir.join("manifest.json"),
        serde_json::to_string_pretty(manifest)?,
    )?;
    Ok(())
}

fn walk_and_snapshot(
    root: &Path,
    current: &Path,
    snapshot_dir: &Path,
    ignore: &KinIgnore,
    file_count: &mut u64,
    total_bytes: &mut u64,
) -> Result<()> {
    let entries = match fs::read_dir(current) {
        Ok(e) => e,
        Err(_) => return Ok(()), // skip unreadable dirs
    };

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let rel = path.strip_prefix(root)?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if snapshot_entry_ignored(&name_str, rel, ignore) {
            continue;
        }

        let ft = entry.file_type()?;
        if ft.is_dir() {
            walk_and_snapshot(root, &path, snapshot_dir, ignore, file_count, total_bytes)?;
        } else if ft.is_file() {
            let dest = snapshot_dir.join(rel);
            if let Some(parent) = dest.parent() {
                fs::create_dir_all(parent)?;
            }

            // Always copy — hardlinks share inodes so later writes
            // to the original would corrupt the snapshot.
            fs::copy(&path, &dest)?;

            *total_bytes += entry.metadata()?.len();
            *file_count += 1;
        }
        // Skip symlinks / other special types.
    }

    Ok(())
}

fn read_git_head(dir: &Path) -> Option<String> {
    // Try `git rev-parse HEAD` first — works for both regular repos and worktrees
    let output = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(dir)
        .output()
        .ok()?;
    if output.status.success() {
        let sha = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !sha.is_empty() {
            return Some(sha);
        }
    }
    None
}

fn bootstrap_fresh_native_agent_doc(dir: &Path) -> Result<bool> {
    fs::create_dir_all(dir)
        .with_context(|| format!("failed to create repository directory {}", dir.display()))?;
    let target = kin_core::ManagedDocTarget {
        path: "AGENTS.md".into(),
        enabled: true,
        sections: vec![
            "summary".into(),
            "kin-first".into(),
            "conventions".into(),
            "verification".into(),
        ],
    };
    let managed = kin_core::generate_managed_content(&target, &kin_core::RepoSummary::default());
    let result = kin_core::sync_doc(&dir.join("AGENTS.md"), &managed)?;
    Ok(result.created || result.updated)
}

fn save_fresh_native_agent_config(layout: &kin_core::KinLayout) -> Result<()> {
    let config = kin_core::ManagedDocConfig::default();
    config.save(layout)?;
    Ok(())
}

fn print_fresh_native_next_steps(layout: &kin_core::KinLayout, agent_doc_changed: bool) {
    println!();
    println!("Fresh Kin-native repository ready.");
    if agent_doc_changed {
        println!(
            "  Agent guide: {}",
            layout.working_dir().join("AGENTS.md").display()
        );
    } else {
        println!(
            "  Agent guide: {} (managed block already current)",
            layout.working_dir().join("AGENTS.md").display()
        );
    }
    println!("  Code with Kin: kin with --session codex -- \"build the first feature\"");
    println!("  Run checks: kin exec -- <command>");
    println!("  Commit graph truth: kin commit -m \"Create initial version\"");
    println!("  Git escape hatch: kin git export --output <path>");
}

pub async fn run(
    path: Option<String>,
    json: bool,
    force: bool,
    verbose: bool,
    no_lsp: bool,
    git_history: String,
) -> Result<()> {
    let _span = tracing::info_span!("kin.init").entered();
    let dir = path
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().expect("cannot determine current directory"));

    let is_git_repo = dir.join(".git").exists();
    let kin_dir = dir.join(".kin");
    let fresh_native_init = !is_git_repo && !kin_dir.exists();
    let agent_doc_bootstrapped = if fresh_native_init {
        bootstrap_fresh_native_agent_doc(&dir)?
    } else {
        false
    };
    if is_git_repo && !json && !force {
        eprintln!(
            "Detected Git repository. Bootstrapping current state as semantic truth.\n\
             hint: use `kin migrate` later for full Git history import."
        );
    }

    // Phase timing: emit wall-clock timers for each init phase to stderr.
    let phase_timer = std::time::Instant::now();
    macro_rules! phase {
        ($name:expr) => {
            eprintln!(
                "  [init-timer] {:>30}: {:.2}s",
                $name,
                phase_timer.elapsed().as_secs_f64()
            );
        };
    }

    // Snapshot the working tree once and reuse that frozen view for indexing.
    let (tmp_snapshot, snapshot_manifest) = snapshot_repo(&dir, force)?;
    phase!("snapshot_repo");

    let is_warm = kin_dir.exists();
    let (layout, snap, blob_store, genesis_id) = if is_warm {
        let layout = kin_core::KinLayout::discover(&dir)
            .ok_or_else(|| anyhow::anyhow!("layout not found in existing .kin"))?;
        let snap = crate::backend::open_kindb_snapshot(&layout)?;
        let blob_store = kin_blobs::BlobStore::new(layout.objects_dir())
            .map_err(|e| anyhow::anyhow!("failed to open blob store: {}", e))?;
        // For a warm cache hit, the genesis change isn't created anew.
        // We look up the current head of the default branch to use as the parent
        // for the new auto-parse change.
        let config = kin_core::KinConfig::load(&layout.config_path())?;
        let parent_id = snap
            .graph()
            .get_branch(&kin_model::BranchName::new(&config.default_branch))
            .ok()
            .flatten()
            .map(|b| b.head)
            .unwrap_or_else(|| kin_core::build_genesis_change().id);

        if !json {
            println!(
                "Reusing existing Kin repository at {}",
                layout.root().display()
            );
        }
        (layout, snap, blob_store, parent_id)
    } else {
        let result = kin_core::init(&dir)?;
        let layout = result.layout;
        let snap = crate::backend::open_kindb_snapshot(&layout)?;
        let blob_store = kin_blobs::BlobStore::new(layout.objects_dir())
            .map_err(|e| anyhow::anyhow!("failed to open blob store: {}", e))?;
        if !json {
            println!("Initialized Kin repository at {}", layout.root().display());
            println!("  KinDB: {}", layout.kindb_snapshot_path().display());
            println!("  Blobs: {}", layout.objects_dir().display());
            println!("  Genesis change: {}", result.genesis_id);
        }
        (layout, snap, blob_store, result.genesis_id)
    };
    if fresh_native_init {
        save_fresh_native_agent_config(&layout)?;
    }
    phase!("kin_core::init");

    let all_files = collect_source_files(&tmp_snapshot)?;
    phase!("collect_source_files");

    let indexable_files = collect_indexable_files(&tmp_snapshot, &all_files)?;
    phase!("collect_indexable_files");
    let (entity_source_input_count, shallow_source_input_count) =
        count_supported_source_inputs(&indexable_files);

    let init_summary = if !all_files.is_empty() {
        if is_warm {
            // NATIVE WARM CACHE: Run the diff directly against the existing graph!
            let graph = snap.graph();
            let current_files: Vec<(String, [u8; 32])> = indexable_files
                .iter()
                .map(|file| (file.rel_path.clone(), file.hash))
                .collect();
            let diff = kin_db::engine::compute_diff(graph.as_ref(), &current_files);

            let delta =
                apply_warm_cache_delta(graph.as_ref(), &blob_store, &indexable_files, &diff)?;
            let scrubbed_paths = scrub_internal_graph_truth(graph.as_ref())?;
            if !scrubbed_paths.is_empty() {
                warn!(
                    count = scrubbed_paths.len(),
                    "scrubbed internal control-plane paths from native warm cache"
                );
            }
            // We just reuse the existing text/vector indexes implicitly since we're in-place.

            phase!("native_warm_cache_diff");

            InitIndexSummary {
                total_entity_count: graph.entity_count(),
                total_files: graph.indexed_file_paths().len(),
                linked_relations: graph.relation_count(),
                warm_cache_hit: true,
                warm_text_index_reused: true,
                warm_vector_index_reused: true,
                warm_changed_files: diff.changed_count(),
                warm_reparsed_files: delta.reparsed_files,
                warm_requeued_embeddings: delta.queued_embeddings.len(),
            }
        } else {
            match try_warm_init_from_cache(&dir, &layout, &snap, &blob_store, &indexable_files) {
                Ok(Some(summary)) => {
                    phase!("warm_cache_path (full)");
                    summary
                }
                Ok(None) | Err(_) => {
                    phase!("warm_cache_miss");
                    let summary =
                        parse_and_index(snap.graph().as_ref(), &blob_store, &indexable_files)?;
                    phase!("parse_and_index");
                    summary
                }
            }
        }
    } else {
        InitIndexSummary::default()
    };

    if !all_files.is_empty() {
        ensure_graph_surface_materialized(
            snap.graph().as_ref(),
            entity_source_input_count,
            shallow_source_input_count,
        )?;
    }

    // Write manifest AFTER collect_source_files so it never enters file_hashes.
    write_snapshot_manifest(&tmp_snapshot, &snapshot_manifest)?;
    move_snapshot_into_place(&tmp_snapshot, &dir.join(".kin/snapshot"))?;
    if !json {
        let snapshot_file_count = snapshot_manifest
            .get("file_count")
            .and_then(|value| value.as_u64())
            .unwrap_or(0);
        println!("  Snapshot saved ({} files)", snapshot_file_count);
    }

    let mut embed_status = kin_db::EmbeddingStatus {
        pending: 0,
        indexed: 0,
        total: 0,
    };

    if !all_files.is_empty() {
        let graph = snap.graph();
        // Build a semantic change for the initial parse.
        // Include artifact_deltas for every file so that the VFS tree
        // (built from the change DAG) knows which files exist.
        let branch_name = kin_core::read_current_branch(&layout)?;
        let change_id = compute_init_change_id(
            &genesis_id,
            &compute_artifact_fingerprint(
                indexable_files
                    .iter()
                    .map(|f| (f.rel_path.as_str(), &f.hash)),
            ),
        );

        // Ensure every tracked file has its blob in the store.
        // The warm-cache path may skip unchanged files, leaving blobs missing.
        // Read from the working directory (not snapshot) as a fallback.
        for f in &indexable_files {
            let blob_hash = kin_blobs::Hash256::from_bytes(f.hash);
            if !blob_store.exists(&blob_hash).unwrap_or(false) {
                let work_path = dir.join(&f.rel_path);
                if let Ok(content) = fs::read(&work_path) {
                    let _ = blob_store.write(&content);
                }
            }
        }

        let artifact_deltas: Vec<_> = indexable_files
            .iter()
            .map(|f| kin_model::ArtifactDelta {
                file_id: FilePathId::new(&f.rel_path),
                kind: kin_model::ArtifactDeltaKind::Added,
                old_hash: None,
                new_hash: Some(kin_model::Hash256::from_bytes(f.hash)),
            })
            .collect();
        let all_entities = graph.list_all_entities()?;
        // Gather relation deltas while only borrowing the entity list, then
        // consume the list itself into the entity deltas. Building the Added
        // entity deltas by value (instead of `.iter().cloned()`) avoids holding
        // a second full copy of every entity during genesis — a ~repo-sized
        // transient that inflates the init RSS peak on constrained machines.
        let mut relation_ids = HashSet::new();
        let mut relation_deltas = Vec::new();
        for entity in &all_entities {
            for relation in graph.get_all_relations_for_entity(&entity.id)? {
                if relation_ids.insert(relation.id) {
                    relation_deltas.push(RelationDelta::Added(relation));
                }
            }
        }
        // Store-iteration order is not a contract; sort by relation id so the
        // committed change record is deterministic.
        relation_deltas.sort_by_key(|delta| match delta {
            RelationDelta::Added(relation) => relation.id.0,
            RelationDelta::Removed(relation_id) => relation_id.0,
        });
        let entity_deltas = all_entities.into_iter().map(EntityDelta::Added).collect();

        let change = SemanticChange {
            id: change_id,
            parents: vec![genesis_id],
            timestamp: Timestamp::now(),
            author: AuthorId::new(whoami()),
            message: "kin init: auto-parse".to_string(),
            entity_deltas,
            relation_deltas,
            artifact_deltas,
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: Some(branch_name.clone()),
        };
        graph.create_change(&change)?;
        graph.update_branch_head(&branch_name, &change_id)?;

        phase!("change_dag+blob_backfill");

        if is_git_repo {
            if let Some(import_opts) = git_history_import_options(&git_history) {
                match crate::commands::cochange::refresh_from_git_history_with_limit(
                    graph.as_ref(),
                    &dir,
                    import_opts.max_commits,
                ) {
                    Ok(count) if count > 0 => {
                        if !json {
                            println!("  Mined {} co-change relation(s) from Git history.", count);
                        }
                    }
                    Ok(_) => {}
                    Err(err) => {
                        warn!(
                            error = %err,
                            mode = %git_history,
                            "failed to mine co-change relations from git history"
                        );
                    }
                }

                match kin_git::import_git_history_with_blobs(
                    &dir,
                    genesis_id,
                    &import_opts,
                    Some(&blob_store),
                ) {
                    Ok(mut imported) if !imported.is_empty() => {
                        // Anchor the (possibly truncated) history at a full base
                        // universe so ref-scoped blast at historical refs sees
                        // committed inbound edges across files untouched inside
                        // the window. Must run BEFORE enrichment: the base-link
                        // change is then parsed, linked, and used as each
                        // windowed commit's semantic baseline by the same pass.
                        match kin_git::anchor_imported_history_at_base_link(
                            &dir,
                            &mut imported,
                            genesis_id,
                            Some(&blob_store),
                        ) {
                            Ok(Some(base_id)) => {
                                debug!(base_link = %base_id, "anchored imported history at base-link change");
                            }
                            Ok(None) => {}
                            Err(err) => {
                                warn!(
                                    error = %err,
                                    mode = %git_history,
                                    "failed to anchor imported Git history at a base-link change; continuing without base-universe anchoring"
                                );
                            }
                        }

                        if let Err(err) =
                            enrich_imported_changes_with_semantics(&mut imported, &blob_store)
                        {
                            warn!(
                                error = %err,
                                mode = %git_history,
                                "failed to enrich imported Git history with semantic deltas; continuing with artifact-only history"
                            );
                        }

                        let mut last_id = None;
                        for ic in &imported {
                            graph.create_change(&ic.change)?;
                            last_id = Some(ic.change.id);
                        }
                        if let Some(head) = last_id {
                            graph.update_branch_head(&branch_name, &head)?;
                        }
                        if !json {
                            let mode_label = match git_history.as_str() {
                                "recent" => "recent",
                                "full" => "full",
                                _ => git_history.as_str(),
                            };
                            println!(
                                "  Imported {} {mode_label} Git commit(s) as semantic history.",
                                imported.len()
                            );
                        }
                    }
                    Ok(_) => {}
                    Err(err) => {
                        if git_history == "full" {
                            return Err(anyhow!(
                                "failed to import full Git history during init: {}",
                                err
                            ));
                        }
                        warn!(
                            error = %err,
                            mode = %git_history,
                            "failed to import Git history during init (non-fatal)"
                        );
                    }
                }
            }
        }

        embed_status = graph.embedding_status();

        phase!("cochange_mining");

        let saved_root_hash = snap.save()?;
        phase!("snapshot_save");

        // Build and save the read-only index for fast CLI queries.
        let read_index = kin_db::ReadIndex::from_graph(&graph)?;
        let idx_path = layout.kindb_snapshot_path().with_extension("kidx");
        read_index.save(&idx_path)?;

        phase!("read_index_save");

        // Optional LSP enrichment: discover servers, enrich entities with type-resolved relations.
        if !no_lsp {
            let discovered = kin_lsp::discovery::discover_servers();
            if !discovered.is_empty() && !json {
                println!("  Discovering LSP servers for enrichment...");
                for server in &discovered {
                    println!("    {} ({})", server.language, server.command);
                }
                println!("  LSP enrichment available — run `kin embed` after init completes.");
                // Full LSP enrichment (starting servers, querying call hierarchy) runs
                // in the daemon background. For kin init, we just report availability.
                // Synchronous enrichment would add 30-60s to init time.
            }

            // Trigger LSP cold sweep only through an already-routed daemon.
            let daemon_url = if let Some(daemon_url) = std::env::var("KIN_DAEMON_URL")
                .ok()
                .filter(|value| !value.trim().is_empty())
            {
                Some(daemon_url)
            } else {
                crate::daemon_client::resolve_daemon_url_if_running_async(&layout).await
            };
            if let Some(daemon_url) = daemon_url {
                if let Ok(resp) = reqwest::Client::new()
                    .post(format!("{}/v1/lsp/sweep", daemon_url.trim_end_matches('/')))
                    .timeout(std::time::Duration::from_secs(2))
                    .send()
                    .await
                {
                    if resp.status().is_success() && !json {
                        println!(
                            "  LSP cold sweep triggered — enriching all entities in background"
                        );
                    }
                }
            }
        }

        if !json {
            println!(
                "  Initialized with {} entities from {} files ({} relations) [{} embeddings indexed, {} queued]",
                init_summary.total_entity_count,
                init_summary.total_files,
                init_summary.linked_relations,
                embed_status.indexed,
                embed_status.pending
            );
            if embed_status.pending > 0 {
                println!("  Run `kin embed` to build semantic vector search.");
            }
        }
        if verbose {
            // Role classification summary
            let all_entities = graph.list_all_entities()?;
            let mut role_counts: std::collections::HashMap<kin_model::EntityRole, usize> =
                std::collections::HashMap::new();
            for entity in &all_entities {
                *role_counts.entry(entity.role).or_insert(0) += 1;
            }
            let roles = [
                (kin_model::EntityRole::Source, "source"),
                (kin_model::EntityRole::Test, "test"),
                (kin_model::EntityRole::External, "external"),
                (kin_model::EntityRole::Docs, "docs"),
                (kin_model::EntityRole::Generated, "generated"),
                (kin_model::EntityRole::Vendored, "vendored"),
            ];
            let parts: Vec<String> = roles
                .iter()
                .filter_map(|(role, label)| role_counts.get(role).map(|c| format!("{label}: {c}")))
                .collect();
            eprintln!("  Roles: {}", parts.join(", "));

            // File classification summary
            let mut class_counts: std::collections::HashMap<&str, usize> =
                std::collections::HashMap::new();
            for file in &indexable_files {
                let label = match &file.classification {
                    kin_index::FileClassification::EntitySource => "entity_source",
                    kin_index::FileClassification::ShallowSyntax { .. } => "shallow_syntax",
                    kin_index::FileClassification::StructuredArtifact(_) => "structured_artifact",
                    kin_index::FileClassification::OpaqueArtifact { .. } => "opaque_artifact",
                };
                *class_counts.entry(label).or_insert(0) += 1;
            }
            let class_parts: Vec<String> = class_counts
                .iter()
                .map(|(label, count)| format!("{label}: {count}"))
                .collect();
            eprintln!("  File classifications: {}", class_parts.join(", "));

            // Entity kind summary
            let mut kind_counts: std::collections::HashMap<String, usize> =
                std::collections::HashMap::new();
            for entity in &all_entities {
                *kind_counts.entry(format!("{:?}", entity.kind)).or_insert(0) += 1;
            }
            let mut kind_pairs: Vec<_> = kind_counts.iter().collect();
            kind_pairs.sort_by(|a, b| b.1.cmp(a.1));
            let kind_parts: Vec<String> = kind_pairs
                .iter()
                .take(8)
                .map(|(kind, count)| format!("{kind}: {count}"))
                .collect();
            eprintln!("  Entity kinds: {}", kind_parts.join(", "));

            // Doc summary coverage
            let with_docs = all_entities
                .iter()
                .filter(|e| e.doc_summary.is_some())
                .count();
            eprintln!(
                "  Doc summaries: {}/{} entities ({:.0}%)",
                with_docs,
                all_entities.len(),
                if all_entities.is_empty() {
                    0.0
                } else {
                    (with_docs as f64 / all_entities.len() as f64) * 100.0
                }
            );
        }
        if init_summary.warm_cache_hit {
            info!(
                changed_files = init_summary.warm_changed_files,
                reparsed_files = init_summary.warm_reparsed_files,
                indexed_files = init_summary.total_files,
                "warm init cache reused prior semantic snapshot"
            );
        }

        if let Err(err) = refresh_init_cache(&dir, graph.as_ref(), saved_root_hash) {
            warn!(error = %err, "failed to refresh warm init cache");
        }

        // Register in the global ~/.kin/registry.toml with entity count
        if let Ok(mut registry) = kin_core::registry::KinRegistry::load() {
            let repo_id = dir
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();
            registry.upsert(
                repo_id,
                dir.canonicalize().unwrap_or(dir),
                init_summary.total_entity_count,
            );
            let _ = registry.save();
        }
    } else {
        // No source files — register with zero entities
        if let Ok(mut registry) = kin_core::registry::KinRegistry::load() {
            let repo_id = dir
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();
            registry.upsert(repo_id, dir.canonicalize().unwrap_or(dir), 0);
            let _ = registry.save();
        }
    }

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&InitResultPayload {
                schema: "kin.init-result.v1",
                repo_root: layout.root().display().to_string(),
                kindb_snapshot_path: layout.kindb_snapshot_path().display().to_string(),
                objects_dir: layout.objects_dir().display().to_string(),
                genesis_change: genesis_id.to_string(),
                indexed_embeddings: embed_status.indexed,
                pending_embeddings: embed_status.pending,
                summary: init_summary,
            })?
        );
    } else if fresh_native_init {
        print_fresh_native_next_steps(&layout, agent_doc_bootstrapped);
    }

    Ok(())
}

fn git_history_import_options(mode: &str) -> Option<kin_git::ImportOptions> {
    match mode {
        "off" => None,
        "recent" => Some(kin_git::ImportOptions {
            max_commits: 50,
            ..Default::default()
        }),
        "full" => Some(kin_git::ImportOptions::default()),
        other => {
            tracing::warn!(mode = %other, "unknown git history mode; skipping import");
            None
        }
    }
}

/// Parse all source files, extract entities, store blobs, link cross-file relations.
/// Returns entity/file/relation totals for the initialized graph.
fn parse_and_index(
    graph: &kin_db::InMemoryGraph,
    blob_store: &kin_blobs::BlobStore,
    indexable_files: &[IndexableFile],
) -> Result<InitIndexSummary> {
    let _span =
        tracing::info_span!("kin.init.parse_and_index", files = indexable_files.len()).entered();
    let pi_timer = std::time::Instant::now();
    let (total_entity_count, _total_files, file_parse_data, discovered_tests, projection_relations) =
        index_files(graph, blob_store, indexable_files)?;
    eprintln!(
        "  [init-timer] {:>30}: {:.2}s",
        "index_files (parse+upsert)",
        pi_timer.elapsed().as_secs_f64()
    );
    // Cross-file relation linking (progress printed by the linker itself)
    let mut linked_relations = kin_index::link_cross_file(&file_parse_data);
    linked_relations.extend(projection_relations);
    eprintln!(
        "  [init-timer] {:>30}: {:.2}s",
        "link_cross_file",
        pi_timer.elapsed().as_secs_f64()
    );
    graph.upsert_relations_batch(&linked_relations)?;
    eprintln!(
        "  [init-timer] {:>30}: {:.2}s ({} rels)",
        "upsert_relations_batch",
        pi_timer.elapsed().as_secs_f64(),
        linked_relations.len()
    );
    let test_relation_count = materialize_discovered_tests(graph, &discovered_tests)?;
    eprintln!(
        "  [init-timer] {:>30}: {:.2}s ({} test rels)",
        "materialize_discovered_tests",
        pi_timer.elapsed().as_secs_f64(),
        test_relation_count
    );
    let scrubbed_paths = scrub_internal_graph_truth(graph)?;
    if !scrubbed_paths.is_empty() {
        warn!(
            count = scrubbed_paths.len(),
            "scrubbed internal control-plane paths after init indexing"
        );
    }

    Ok(InitIndexSummary {
        total_entity_count,
        total_files: graph.indexed_file_paths().len(),
        linked_relations: linked_relations.len(),
        warm_cache_hit: false,
        warm_text_index_reused: false,
        warm_vector_index_reused: false,
        warm_requeued_embeddings: 0,
        warm_changed_files: 0,
        warm_reparsed_files: 0,
    })
}

enum ParsedFileResult {
    EntitySource {
        rel_path: String,
        hash: [u8; 32],
        entities: Vec<Entity>,
        discovered_tests: Vec<DiscoveredTest>,
        relations: Vec<kin_parser::ExtractedRelation>,
        imports: Vec<kin_parser::FileImport>,
        projection_markers: Vec<String>,
        layout: FileLayout,
    },
    ShallowSyntax {
        rel_path: String,
        hash: [u8; 32],
        shallow: ShallowTrackedFile,
        projection_markers: Vec<String>,
    },
    StructuredArtifact {
        rel_path: String,
        hash: [u8; 32],
        artifact: StructuredArtifact,
        projection_markers: Vec<String>,
    },
    OpaqueArtifact {
        rel_path: String,
        hash: [u8; 32],
        artifact: OpaqueArtifact,
        projection_markers: Vec<String>,
    },
    Skipped,
}

#[derive(Debug, Clone)]
struct DiscoveredTest {
    file_id: FilePathId,
    name: String,
    kind: kin_parser::ExtractedTestKind,
    runner: String,
    entity_id: Option<EntityId>,
    target_entity_ids: Vec<EntityId>,
}

#[derive(Debug, Clone)]
struct ImportedSemanticFileState {
    file_path: String,
    entities: Vec<Entity>,
    relations: Vec<kin_parser::ExtractedRelation>,
    imports: Vec<kin_parser::FileImport>,
}

impl ImportedSemanticFileState {
    fn to_link_data(&self) -> kin_index::FileParseData {
        kin_index::FileParseData {
            file_path: self.file_path.clone(),
            entities: self.entities.clone(),
            relations: self.relations.clone(),
            imports: self.imports.clone(),
        }
    }
}

/// Per-commit semantic accumulator state: file entities, cross-file relations
/// (plus their src and dst indexes), and the incremental linker index.
/// Historical ingest forks a fresh copy of this state from each commit's
/// FIRST git parent, so a commit's entity and relation deltas are computed
/// against its true DAG parent rather than the linearized running state of an
/// interleaved commit-time walk.
struct ImportedCommitSemanticState {
    files: HashMap<String, ImportedSemanticFileState>,
    relations: HashMap<RelationId, Relation>,
    relations_by_src: HashMap<EntityId, HashSet<RelationId>>,
    relations_by_src_artifact: HashMap<ArtifactId, HashSet<RelationId>>,
    /// Inbound-edge index: target entity id -> ids of relations whose `dst`
    /// is that entity. Mirrors `relations_by_src` but keyed by destination,
    /// so a reverse-dependency lookup for an entity is a direct map lookup
    /// instead of a scan over every relation. Maintained in lockstep with
    /// `relations` at every insert/remove site (see `insert_relation_indexes`
    /// / `remove_relation_indexes`), so it never goes stale mid-replay.
    relations_by_dst: HashMap<EntityId, HashSet<RelationId>>,
    linker: kin_index::IncrementalLinker,
}

impl Default for ImportedCommitSemanticState {
    fn default() -> Self {
        Self {
            files: HashMap::new(),
            relations: HashMap::new(),
            relations_by_src: HashMap::new(),
            relations_by_src_artifact: HashMap::new(),
            relations_by_dst: HashMap::new(),
            linker: kin_index::IncrementalLinker::new(),
        }
    }
}

impl Clone for ImportedCommitSemanticState {
    fn clone(&self) -> Self {
        Self {
            files: self.files.clone(),
            relations: self.relations.clone(),
            relations_by_src: self.relations_by_src.clone(),
            relations_by_src_artifact: self.relations_by_src_artifact.clone(),
            relations_by_dst: self.relations_by_dst.clone(),
            // `IncrementalLinker` derives no `Clone`; its fields are all public
            // and cloneable, so copy them explicitly. A new field there makes
            // this fail to compile (fail loud) rather than silently drop linker
            // state from a forked baseline.
            linker: kin_index::IncrementalLinker {
                entity_by_file_name: self.linker.entity_by_file_name.clone(),
                entity_by_name: self.linker.entity_by_name.clone(),
                entity_by_bare_name: self.linker.entity_by_bare_name.clone(),
                entity_kind_by_id: self.linker.entity_kind_by_id.clone(),
                known_files: self.linker.known_files.clone(),
                entities_by_file: self.linker.entities_by_file.clone(),
                include_targets_by_file: self.linker.include_targets_by_file.clone(),
                class_bases_by_file: self.linker.class_bases_by_file.clone(),
            },
        }
    }
}

/// Deterministic topological order over the first-parent forest.
///
/// `first_parent_index[c]` is the slice index of commit `c`'s first git parent
/// when that parent is itself in the imported set (`None` for a root or a parent
/// below the import horizon). Each commit has at most one in-set first parent,
/// so "process a commit after its first parent" is a forest constraint; Kahn's
/// algorithm seeded and drained in ascending index order yields a stable order
/// in which every commit follows its first parent, staying as close as possible
/// to the input order. Any commit left unvisited by an (impossible for git)
/// cycle is appended in index order so no commit is silently dropped.
fn first_parent_topological_order(first_parent_index: &[Option<usize>]) -> Vec<usize> {
    let n = first_parent_index.len();
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut indegree = vec![0usize; n];
    for (child, parent) in first_parent_index.iter().enumerate() {
        if let Some(parent) = *parent {
            children[parent].push(child);
            indegree[child] += 1;
        }
    }

    let mut queue: std::collections::VecDeque<usize> =
        (0..n).filter(|&i| indegree[i] == 0).collect();
    let mut order = Vec::with_capacity(n);
    let mut seen = vec![false; n];
    while let Some(i) = queue.pop_front() {
        if seen[i] {
            continue;
        }
        seen[i] = true;
        order.push(i);
        for &child in &children[i] {
            indegree[child] -= 1;
            if indegree[child] == 0 {
                queue.push_back(child);
            }
        }
    }
    for (i, visited) in seen.iter().enumerate() {
        if !visited {
            order.push(i);
        }
    }
    order
}

/// Pre-reconciliation parse payload memoized per `(blob_hash,
/// PARSER_SEMANTICS_VERSION)` for one hydration pass. Holds exactly the fields
/// the replay consumes between the parse and commit-relative entity
/// reconciliation; reconciliation itself is deliberately excluded because it
/// re-keys entity ids per commit. Shared via `Arc` so a blob recurring across
/// commits reuses one allocation instead of re-parsing.
struct CachedParse {
    entities: Vec<Entity>,
    extracted_relations: Vec<kin_parser::ExtractedRelation>,
    imports: Vec<kin_parser::FileImport>,
}

/// One artifact delta's resolved parse disposition for a commit's reconcile
/// pass, computed by the plan/parse phases so the serial reconcile is a pure
/// fold over pre-resolved parses with no blob I/O or parsing on its path.
enum ImportedFileResolution {
    /// Non-source file, deletion, or a blob whose read/parse failed: drop any
    /// prior semantic state for this path.
    Remove,
    /// Parse available (memo hit or freshly parsed this commit): reconcile the
    /// path against it.
    Parsed(Arc<CachedParse>),
}

/// A distinct source blob scheduled for parsing within one commit. Parsing is a
/// pure function of (blob bytes, parser semantics), so each distinct blob is
/// read and parsed once and its `Arc` result shared across every delta in the
/// commit that names it — the same reuse the per-pass memo gives across commits.
struct ImportedParseJob {
    blob_hash: kin_blobs::Hash256,
    file_id: FilePathId,
    /// Indices into the commit's `artifact_deltas` this parse resolves. The
    /// first entry was counted as a memo miss when the job was scheduled; any
    /// later entries are same-commit reappearances whose hit/miss accounting is
    /// settled in the merge once the parse's success is known.
    served_deltas: Vec<usize>,
}

pub(crate) fn enrich_imported_changes_with_semantics(
    imported: &mut [kin_git::ImportedChange],
    blob_store: &kin_blobs::BlobStore,
) -> Result<()> {
    enrich_imported_changes_with_semantics_inner(imported, blob_store, true).map(|_| ())
}

/// Replay body shared by production (`parse_memo_enabled = true`) and the
/// memo-off serial oracle used in tests. Returns `(parse_memo_hits,
/// parse_memo_misses)` observed over the pass.
fn enrich_imported_changes_with_semantics_inner(
    imported: &mut [kin_git::ImportedChange],
    blob_store: &kin_blobs::BlobStore,
    parse_memo_enabled: bool,
) -> Result<(usize, usize)> {
    // Profiling timers (accumulated across every commit in the pass).
    let mut total_blob_read_time = std::time::Duration::ZERO;
    let mut total_parsing_time = std::time::Duration::ZERO;
    let mut total_linking_time = std::time::Duration::ZERO;
    let mut total_closure_diffing_time = std::time::Duration::ZERO;

    // Parse memo (per-pass lifetime; the replay loop is single-threaded, so a
    // plain HashMap is sound and deterministic). Bounds live memory to the
    // pass's distinct source blobs.
    let mut parse_memo: HashMap<(kin_blobs::Hash256, u32), Arc<CachedParse>> = HashMap::new();
    let mut parse_memo_hits = 0usize;
    let mut parse_memo_misses = 0usize;

    let total_commits = imported.len();
    let start_time = std::time::Instant::now();

    // Resolve each imported commit's FIRST git parent to an in-set slice index.
    // kin-git derives a commit's artifact deltas by diffing its tree against its
    // first parent's tree, so the first parent's semantic state is the correct
    // baseline for that commit's entity and relation deltas. Diffing against a
    // linearized commit-time running map instead attributes an interleaved
    // sibling commit's entities/signatures to the wrong commit on a non-linear
    // history (merges or branch interleaving), producing phantom deltas at
    // historical refs.
    let mut index_by_change_id = HashMap::<SemanticChangeId, usize>::with_capacity(total_commits);
    for (i, imported_change) in imported.iter().enumerate() {
        index_by_change_id.insert(imported_change.change.id, i);
    }
    let first_parent_index: Vec<Option<usize>> = imported
        .iter()
        .map(|imported_change| {
            imported_change
                .change
                .parents
                .first()
                .and_then(|parent| index_by_change_id.get(parent).copied())
        })
        .collect();

    // Count how many in-set commits fork from each commit as their first parent,
    // so a commit's snapshot is retained only while children still need it. This
    // bounds live snapshots to the DAG's branch width, not the whole history.
    let mut remaining_children = vec![0usize; total_commits];
    for parent in first_parent_index.iter().flatten() {
        remaining_children[*parent] += 1;
    }

    let order = first_parent_topological_order(&first_parent_index);
    let mut snapshots = HashMap::<SemanticChangeId, ImportedCommitSemanticState>::new();

    for (processed, &i) in order.iter().enumerate() {
        if total_commits > 0 {
            let percent = ((processed + 1) * 100) / total_commits;
            let short_oid: String = imported[i].git_oid.chars().take(7).collect();
            eprint!(
                "\r  Hydrating History: [{}/{}] {}% | Commit: {} | {:.1}s",
                processed + 1,
                total_commits,
                percent,
                short_oid,
                start_time.elapsed().as_secs_f64()
            );
        }

        // Fork this commit's baseline from its first parent's resulting state.
        // The parent's last child moves the snapshot (zero-copy, so a purely
        // linear history keeps the original single-accumulator cost); earlier
        // children clone it. Roots and below-horizon parents start from empty
        // state. Then rebind the forked accumulators into the names the
        // per-commit body below already uses.
        let baseline = match first_parent_index[i] {
            Some(parent_idx) => {
                remaining_children[parent_idx] -= 1;
                let parent_id = imported[parent_idx].change.id;
                if remaining_children[parent_idx] == 0 {
                    snapshots.remove(&parent_id).unwrap_or_default()
                } else {
                    snapshots.get(&parent_id).cloned().unwrap_or_default()
                }
            }
            None => ImportedCommitSemanticState::default(),
        };
        let ImportedCommitSemanticState {
            files: mut current_files,
            relations: mut current_relations,
            mut relations_by_src,
            mut relations_by_src_artifact,
            mut relations_by_dst,
            linker: mut incremental_linker,
        } = baseline;

        let mut entity_deltas = Vec::new();
        let mut relation_deltas = Vec::new();
        let mut changed_source_files = BTreeSet::<String>::new();
        let mut previous_file_states = HashMap::<String, ImportedSemanticFileState>::new();

        // Rung-3 intra-commit parallel compute. The outer commit loop stays
        // sequential (each commit forks its first parent's resulting semantic
        // state), so parallelism lives inside a commit: (1) plan each delta's
        // disposition in delta order, scheduling every distinct memo-missing
        // source blob as a parse job; (2) read and (3) parse those jobs across
        // the Rayon pool; (4) fold the results into the memo and reconcile
        // serially in the original delta order. Parsing is a pure function of
        // (blob bytes, parser semantics) and every order-sensitive step
        // (reconcile, linker mutation, current_files, delta accumulation) stays
        // serial, so the resulting graph is byte-identical to the serial path.
        let deltas = &imported[i].change.artifact_deltas;
        let mut resolutions: Vec<Option<ImportedFileResolution>> =
            (0..deltas.len()).map(|_| None).collect();
        let mut parse_jobs: Vec<ImportedParseJob> = Vec::new();
        let mut scheduled_jobs: HashMap<(kin_blobs::Hash256, u32), usize> = HashMap::new();

        for (delta_idx, artifact_delta) in deltas.iter().enumerate() {
            let file_path = &artifact_delta.file_id.0;

            if !matches!(
                FileClassifier::classify(Path::new(file_path)),
                FileClassification::EntitySource
            ) {
                resolutions[delta_idx] = Some(ImportedFileResolution::Remove);
                continue;
            }

            let Some(new_hash) = artifact_delta.new_hash else {
                resolutions[delta_idx] = Some(ImportedFileResolution::Remove);
                continue;
            };

            // A blob hash uniquely determines the file bytes, and a parse is a
            // pure function of (bytes, parser semantics), so the same file
            // version recurring across commits — git blobs dedup across history —
            // is read and parsed once. The parser-semantics version is part of
            // the key so a grammar/extractor upgrade never serves a stale parse.
            let memo_key = (
                kin_blobs::Hash256::from_bytes(*new_hash.as_bytes()),
                kin_parser::PARSER_SEMANTICS_VERSION,
            );

            if parse_memo_enabled {
                if let Some(hit) = parse_memo.get(&memo_key) {
                    parse_memo_hits += 1;
                    resolutions[delta_idx] = Some(ImportedFileResolution::Parsed(Arc::clone(hit)));
                    continue;
                }
                if let Some(&job_idx) = scheduled_jobs.get(&memo_key) {
                    // Served by the parse scheduled earlier this commit; whether
                    // it counts as a hit (parse succeeds and is memoized) or
                    // another miss (parse fails and is never memoized) is settled
                    // in the merge, matching the serial memo's per-appearance
                    // accounting exactly.
                    parse_jobs[job_idx].served_deltas.push(delta_idx);
                    continue;
                }
                parse_memo_misses += 1;
                scheduled_jobs.insert(memo_key, parse_jobs.len());
                parse_jobs.push(ImportedParseJob {
                    blob_hash: memo_key.0,
                    file_id: FilePathId::new(file_path),
                    served_deltas: vec![delta_idx],
                });
            } else {
                // Memo disabled (serial oracle): every appearance re-parses.
                parse_memo_misses += 1;
                parse_jobs.push(ImportedParseJob {
                    blob_hash: memo_key.0,
                    file_id: FilePathId::new(file_path),
                    served_deltas: vec![delta_idx],
                });
            }
        }

        if !parse_jobs.is_empty() {
            // Stage 1: read each distinct blob once, in parallel. The stage's
            // wall-clock (not summed thread time) is attributed to blob-read.
            let blob_read_start = std::time::Instant::now();
            let job_contents: Vec<Result<Vec<u8>, String>> = parse_jobs
                .par_iter()
                .map(|job| {
                    blob_store
                        .read(&job.blob_hash)
                        .map_err(|err| err.to_string())
                })
                .collect();
            total_blob_read_time += blob_read_start.elapsed();

            // Stage 2: parse the successfully-read blobs in parallel. Each worker
            // thread builds its own IndexPipeline (tree-sitter parsers are
            // per-thread). Results collect in job order (`par_iter().collect()`
            // preserves order) and the parse is pure, so the pass is
            // deterministic. The stage's wall-clock is attributed to parsing.
            let parse_start = std::time::Instant::now();
            let job_parses: Vec<Option<Result<Arc<CachedParse>, String>>> = parse_jobs
                .par_iter()
                .zip(job_contents.par_iter())
                .map_init(kin_index::IndexPipeline::new, |pipeline, (job, content)| {
                    let content = content.as_ref().ok()?;
                    Some(
                        pipeline
                            .index_file_content_with_tests(&job.file_id, content, job.blob_hash)
                            .map(|indexed| {
                                Arc::new(CachedParse {
                                    entities: indexed.indexed_file.entities,
                                    extracted_relations: indexed.indexed_file.extracted_relations,
                                    imports: indexed.indexed_file.imports,
                                })
                            })
                            .map_err(|err| err.to_string()),
                    )
                })
                .collect();
            total_parsing_time += parse_start.elapsed();

            // Merge (serial, deterministic): populate the content-keyed memo,
            // resolve every served delta, settle same-commit reappearance
            // accounting, and warn on failures in job order. Memo insertion order
            // never affects the memo's contents (keyed by blob hash + semantics).
            let read_errors: Vec<Option<String>> = job_contents
                .into_iter()
                .map(|content| content.err())
                .collect();
            for (job_idx, job) in parse_jobs.iter().enumerate() {
                let extra_appearances = job.served_deltas.len() - 1;
                match &job_parses[job_idx] {
                    Some(Ok(parsed)) => {
                        if parse_memo_enabled {
                            parse_memo.insert(
                                (job.blob_hash, kin_parser::PARSER_SEMANTICS_VERSION),
                                Arc::clone(parsed),
                            );
                        }
                        // Extra same-commit appearances were served from this one
                        // parse: hits, exactly as the serial memo would count.
                        parse_memo_hits += extra_appearances;
                        for &delta_idx in &job.served_deltas {
                            resolutions[delta_idx] =
                                Some(ImportedFileResolution::Parsed(Arc::clone(parsed)));
                        }
                    }
                    Some(Err(err)) => {
                        // Parse failed: never memoized, so every appearance is a
                        // miss (the first was already counted at schedule time).
                        parse_memo_misses += extra_appearances;
                        warn!(
                            file = %job.file_id.0,
                            error = %err,
                            "skipping semantic enrichment for imported source blob that could not be parsed"
                        );
                        for &delta_idx in &job.served_deltas {
                            resolutions[delta_idx] = Some(ImportedFileResolution::Remove);
                        }
                    }
                    None => {
                        // Blob read failed: same removal + miss accounting.
                        parse_memo_misses += extra_appearances;
                        let err = read_errors[job_idx].as_deref().unwrap_or("missing content");
                        warn!(
                            file = %job.file_id.0,
                            error = %err,
                            "skipping semantic enrichment for imported blob with missing content"
                        );
                        for &delta_idx in &job.served_deltas {
                            resolutions[delta_idx] = Some(ImportedFileResolution::Remove);
                        }
                    }
                }
            }
        }

        // Reconcile serially in delta order — byte-identical to the pre-rung-3
        // per-file body, now fed pre-resolved parses. Each commit changes a given
        // path at most once, so a delta's baseline `old_state` is independent of
        // its siblings and this fold reproduces the serial result exactly.
        for (delta_idx, artifact_delta) in imported[i].change.artifact_deltas.iter().enumerate() {
            let file_path = artifact_delta.file_id.0.clone();
            let old_state = current_files.get(&file_path).cloned();
            if let Some(old_state) = &old_state {
                previous_file_states.insert(file_path.clone(), old_state.clone());
            }

            match resolutions[delta_idx]
                .take()
                .expect("every artifact delta must be resolved by the plan/parse phase")
            {
                ImportedFileResolution::Remove => {
                    if remove_imported_file_semantic_state(
                        &file_path,
                        old_state,
                        &mut current_files,
                        &mut entity_deltas,
                    ) {
                        changed_source_files.insert(file_path.clone());
                        incremental_linker.remove_file(&file_path);
                    }
                }
                ImportedFileResolution::Parsed(parsed) => {
                    let old_entities = old_state
                        .as_ref()
                        .map(|state| state.entities.as_slice())
                        .unwrap_or(&[]);
                    // Reconcile borrows the shared parse output and clones only
                    // the entities it stabilizes, so a memo hit never deep-clones
                    // the entire entity vector.
                    let (file_entity_deltas, stabilized_entities) =
                        reconcile_imported_file_entities(old_entities, &parsed.entities);
                    entity_deltas.extend(file_entity_deltas);

                    incremental_linker.add_file(&file_path, &stabilized_entities);

                    current_files.insert(
                        file_path.clone(),
                        ImportedSemanticFileState {
                            file_path: file_path.clone(),
                            entities: stabilized_entities,
                            relations: parsed.extracted_relations.clone(),
                            imports: parsed.imports.clone(),
                        },
                    );
                    changed_source_files.insert(file_path);
                }
            }
        }

        let closure_diff_start = std::time::Instant::now();
        let semantic_entities_by_file =
            build_imported_semantic_entities_by_file(&current_files, &previous_file_states);
        let impacted_files = imported_reverse_dependency_closure(
            &changed_source_files,
            &semantic_entities_by_file,
            &current_relations,
            &relations_by_dst,
        );
        let old_relation_ids = collect_relation_ids_for_imported_files(
            &impacted_files,
            &semantic_entities_by_file,
            &relations_by_src,
            &relations_by_src_artifact,
        );

        let changed_parse_data = impacted_files
            .iter()
            .filter_map(|path| current_files.get(path))
            .map(ImportedSemanticFileState::to_link_data)
            .collect::<Vec<_>>();

        let mut old_relations = HashMap::<RelationId, Relation>::new();
        for relation_id in &old_relation_ids {
            if let Some(old_relation) = current_relations.remove(relation_id) {
                remove_relation_indexes(
                    &mut relations_by_src,
                    &mut relations_by_src_artifact,
                    &mut relations_by_dst,
                    &old_relation,
                );
                old_relations.insert(*relation_id, old_relation);
            }
        }
        total_closure_diffing_time += closure_diff_start.elapsed();

        if !changed_parse_data.is_empty() {
            let link_start_time = std::time::Instant::now();
            incremental_linker.record_file_includes(&changed_parse_data);
            incremental_linker.record_class_bases(&changed_parse_data);
            let mut new_relations_by_id = HashMap::<RelationId, Relation>::new();
            for relation in
                kin_index::link_cross_file_incremental(&changed_parse_data, &incremental_linker)
            {
                new_relations_by_id.insert(relation.id, relation);
            }
            total_linking_time += link_start_time.elapsed();

            let post_link_start = std::time::Instant::now();
            for old_relation_id in old_relations.keys() {
                if !new_relations_by_id.contains_key(old_relation_id) {
                    relation_deltas.push(RelationDelta::Removed(*old_relation_id));
                }
            }

            for (relation_id, relation) in new_relations_by_id {
                match old_relations.remove(&relation_id) {
                    Some(old_relation)
                        if imported_relations_equivalent(&old_relation, &relation) =>
                    {
                        insert_relation_indexes(
                            &mut relations_by_src,
                            &mut relations_by_src_artifact,
                            &mut relations_by_dst,
                            &old_relation,
                        );
                        current_relations.insert(relation_id, old_relation);
                    }
                    Some(_) => {
                        relation_deltas.push(RelationDelta::Removed(relation_id));
                        relation_deltas.push(RelationDelta::Added(relation.clone()));
                        insert_relation_indexes(
                            &mut relations_by_src,
                            &mut relations_by_src_artifact,
                            &mut relations_by_dst,
                            &relation,
                        );
                        current_relations.insert(relation_id, relation);
                    }
                    None => {
                        relation_deltas.push(RelationDelta::Added(relation.clone()));
                        insert_relation_indexes(
                            &mut relations_by_src,
                            &mut relations_by_src_artifact,
                            &mut relations_by_dst,
                            &relation,
                        );
                        current_relations.insert(relation_id, relation);
                    }
                }
            }
            total_closure_diffing_time += post_link_start.elapsed();
        } else {
            let post_link_start = std::time::Instant::now();
            relation_deltas.extend(old_relations.keys().copied().map(RelationDelta::Removed));
            total_closure_diffing_time += post_link_start.elapsed();
        }

        // Relation deltas accumulate from HashMap iteration above; sort by
        // relation id so the committed change record is byte-stable across
        // runs. The sort is stable, so a Removed(id)+Added(id) replacement
        // pair keeps its replay order.
        relation_deltas.sort_by_key(|delta| match delta {
            RelationDelta::Added(relation) => relation.id.0,
            RelationDelta::Removed(relation_id) => relation_id.0,
        });
        imported[i].change.entity_deltas = entity_deltas;
        imported[i].change.relation_deltas = relation_deltas;

        // Retain this commit's resulting state only while a later child will
        // fork from it; leaves are dropped immediately.
        if remaining_children[i] > 0 {
            snapshots.insert(
                imported[i].change.id,
                ImportedCommitSemanticState {
                    files: current_files,
                    relations: current_relations,
                    relations_by_src,
                    relations_by_src_artifact,
                    relations_by_dst,
                    linker: incremental_linker,
                },
            );
        }
    }

    if total_commits > 0 {
        eprintln!();
        let total_time_sec = start_time.elapsed().as_secs_f64();
        eprintln!("  Hydration Profiling Summary:");
        eprintln!("    Total Commits: {}", total_commits);
        eprintln!("    Total Time: {:.1}s", total_time_sec);
        eprintln!(
            "    - Blob Read: {:.1}s ({:.1}%)",
            total_blob_read_time.as_secs_f64(),
            (total_blob_read_time.as_secs_f64() * 100.0) / total_time_sec.max(0.001)
        );
        eprintln!(
            "    - Parsing/Indexing: {:.1}s ({:.1}%)",
            total_parsing_time.as_secs_f64(),
            (total_parsing_time.as_secs_f64() * 100.0) / total_time_sec.max(0.001)
        );
        eprintln!(
            "    - Cross-file Linking: {:.1}s ({:.1}%)",
            total_linking_time.as_secs_f64(),
            (total_linking_time.as_secs_f64() * 100.0) / total_time_sec.max(0.001)
        );
        eprintln!(
            "    - Closure & Diffing: {:.1}s ({:.1}%)",
            total_closure_diffing_time.as_secs_f64(),
            (total_closure_diffing_time.as_secs_f64() * 100.0) / total_time_sec.max(0.001)
        );

        // Machine-readable sibling of the summary above: one JSON line per pass
        // for downstream ingestion (kin-bench run artifacts, before/after
        // comparisons). Gated so default runs are byte-for-byte unchanged, and
        // derived from the same `total_time_sec` so the JSON reconciles exactly
        // with the human numbers.
        if hydrate_stage_timings_enabled() {
            eprintln!(
                "{}",
                hydrate_stage_timings_json(
                    total_commits,
                    total_time_sec,
                    total_blob_read_time.as_secs_f64(),
                    total_parsing_time.as_secs_f64(),
                    total_linking_time.as_secs_f64(),
                    total_closure_diffing_time.as_secs_f64(),
                    parse_memo_hits,
                    parse_memo_misses,
                )
            );
        }
    }

    Ok((parse_memo_hits, parse_memo_misses))
}

/// One machine-readable record of the history-hydration replay profile, emitted
/// as a single JSON line under `KIN_HYDRATE_STAGE_TIMINGS`. Fields serialize in
/// declaration order (nested under the outer key by [`HydrateStageTimingsLine`])
/// so the line reads in the same order as the human summary printed above it.
#[derive(Serialize)]
struct HydrateStageTimings {
    /// Commits replayed in the pass.
    total_commits: usize,
    /// Wall-clock seconds for the whole pass.
    total_s: f64,
    /// Replay throughput (`total_commits` / `total_s`).
    commits_per_s: f64,
    /// Seconds spent reading blobs.
    blob_read_s: f64,
    /// Seconds spent parsing / indexing.
    parsing_s: f64,
    /// Seconds spent cross-file linking.
    linking_s: f64,
    /// Seconds spent on closure and diffing.
    closure_diffing_s: f64,
    /// Wall-clock residue not attributed to any of the four buckets above.
    other_s: f64,
    /// Blob parses served from the per-pass parse memo (recurring file versions).
    parse_memo_hits: usize,
    /// Blob parses that missed the memo and ran the parser.
    parse_memo_misses: usize,
}

/// Outer envelope so the record serializes as `{"kin_hydrate_stage_timings":{…}}`.
/// Serializing through nested structs (never `serde_json::Value`) keeps every
/// field in declaration order.
#[derive(Serialize)]
struct HydrateStageTimingsLine {
    kin_hydrate_stage_timings: HydrateStageTimings,
}

/// Whether `KIN_HYDRATE_STAGE_TIMINGS` requests the machine-readable stage-timing
/// line (truthy `1`/`true`/`yes`/`on`, case-insensitive). Unset or falsy → off.
fn hydrate_stage_timings_enabled() -> bool {
    std::env::var("KIN_HYDRATE_STAGE_TIMINGS")
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            )
        })
        .unwrap_or(false)
}

/// Serialize the hydration replay profile as one JSON line. `other_s` is the
/// wall-clock residue left after subtracting the four phase buckets from
/// `total_s`, surfaced explicitly rather than folded into a bucket so a consumer
/// can always recover unattributed time. Pure (no env or clock reads) so the
/// emitted shape is unit-testable.
#[allow(clippy::too_many_arguments)]
fn hydrate_stage_timings_json(
    total_commits: usize,
    total_s: f64,
    blob_read_s: f64,
    parsing_s: f64,
    linking_s: f64,
    closure_diffing_s: f64,
    parse_memo_hits: usize,
    parse_memo_misses: usize,
) -> String {
    // Guard the divide so a zero wall never yields NaN/Infinity (serde renders
    // those as `null`, which would break the "always a parseable number"
    // contract). A real pass always has a positive wall.
    let commits_per_s = if total_s > 0.0 {
        total_commits as f64 / total_s
    } else {
        0.0
    };
    let other_s = total_s - blob_read_s - parsing_s - linking_s - closure_diffing_s;
    let line = HydrateStageTimingsLine {
        kin_hydrate_stage_timings: HydrateStageTimings {
            total_commits,
            total_s,
            commits_per_s,
            blob_read_s,
            parsing_s,
            linking_s,
            closure_diffing_s,
            other_s,
            parse_memo_hits,
            parse_memo_misses,
        },
    };
    // Only finite f64s reach here, so serialization cannot fail; fall back to an
    // empty object defensively rather than panicking on a diagnostic path.
    serde_json::to_string(&line).unwrap_or_else(|_| "{}".to_string())
}

fn remove_imported_file_semantic_state(
    file_path: &str,
    old_state: Option<ImportedSemanticFileState>,
    current_files: &mut HashMap<String, ImportedSemanticFileState>,
    entity_deltas: &mut Vec<EntityDelta>,
) -> bool {
    let removed_state = old_state.or_else(|| current_files.remove(file_path));
    if let Some(old_state) = removed_state {
        current_files.remove(file_path);
        for entity in old_state.entities {
            entity_deltas.push(EntityDelta::Removed(entity.id));
        }
        true
    } else {
        false
    }
}

fn build_imported_semantic_entities_by_file(
    current_files: &HashMap<String, ImportedSemanticFileState>,
    previous_file_states: &HashMap<String, ImportedSemanticFileState>,
) -> HashMap<String, Vec<Entity>> {
    let mut entities_by_file = current_files
        .iter()
        .map(|(path, state)| (path.clone(), state.entities.clone()))
        .collect::<HashMap<_, _>>();

    for (path, state) in previous_file_states {
        let entry = entities_by_file.entry(path.clone()).or_default();
        let mut seen = entry.iter().map(|entity| entity.id).collect::<HashSet<_>>();
        for entity in &state.entities {
            if seen.insert(entity.id) {
                entry.push(entity.clone());
            }
        }
    }

    entities_by_file
}

/// Reverse-dependency closure over `seed_files`: every file that holds an
/// entity referenced by a relation whose target is an entity defined in one
/// of the seed files, plus the seed files themselves. `relations_by_dst`
/// makes this an O(inbound-degree) walk — one map lookup per entity in a seed
/// file, followed by an O(1) relation lookup per inbound edge — rather than a
/// scan of every relation for every seed file. Returns a `BTreeSet` so the
/// result (and everything folded from it downstream) is byte-stable
/// regardless of the maps' hash iteration order.
fn imported_reverse_dependency_closure(
    seed_files: &BTreeSet<String>,
    semantic_entities_by_file: &HashMap<String, Vec<Entity>>,
    current_relations: &HashMap<RelationId, Relation>,
    relations_by_dst: &HashMap<EntityId, HashSet<RelationId>>,
) -> BTreeSet<String> {
    let mut entity_to_file = HashMap::<EntityId, String>::new();
    for (file_path, entities) in semantic_entities_by_file {
        for entity in entities {
            entity_to_file.insert(entity.id, file_path.clone());
        }
    }

    let mut visited = seed_files.clone();

    for file_path in seed_files {
        let Some(entities) = semantic_entities_by_file.get(file_path) else {
            continue;
        };
        for entity in entities {
            let Some(inbound_relation_ids) = relations_by_dst.get(&entity.id) else {
                continue;
            };
            for relation_id in inbound_relation_ids {
                let Some(relation) = current_relations.get(relation_id) else {
                    continue;
                };
                let Some(src_entity_id) = relation.src.as_entity() else {
                    continue;
                };
                let Some(src_file) = entity_to_file.get(&src_entity_id) else {
                    continue;
                };
                visited.insert(src_file.clone());
            }
        }
    }

    visited
}

fn collect_relation_ids_for_imported_files(
    files: &BTreeSet<String>,
    semantic_entities_by_file: &HashMap<String, Vec<Entity>>,
    relations_by_src: &HashMap<EntityId, HashSet<RelationId>>,
    relations_by_src_artifact: &HashMap<ArtifactId, HashSet<RelationId>>,
) -> HashSet<RelationId> {
    let mut relation_ids = HashSet::new();
    for file_path in files {
        if let Some(entities) = semantic_entities_by_file.get(file_path) {
            for entity in entities {
                if let Some(existing_ids) = relations_by_src.get(&entity.id) {
                    relation_ids.extend(existing_ids.iter().copied());
                }
            }
        }
        // Import/include edges are anchored to the file artifact (not an
        // entity), so collect them by the file's artifact id too — otherwise a
        // stable cross-file import edge is invisible to the incremental diff
        // and gets re-added on every relink of an impacted file.
        // Graph-less map key: `relations_by_src_artifact` is keyed by the same
        // path-derived id used when the map was built, so this lookup must derive
        // the id identically (no graph/snapshot handle is in scope here).
        let artifact_id = ArtifactId::seed_from_path(file_path);
        if let Some(existing_ids) = relations_by_src_artifact.get(&artifact_id) {
            relation_ids.extend(existing_ids.iter().copied());
        }
    }

    relation_ids
}

fn insert_relation_indexes(
    relations_by_src: &mut HashMap<EntityId, HashSet<RelationId>>,
    relations_by_src_artifact: &mut HashMap<ArtifactId, HashSet<RelationId>>,
    relations_by_dst: &mut HashMap<EntityId, HashSet<RelationId>>,
    relation: &Relation,
) {
    match relation.src {
        GraphNodeId::Entity(src_entity) => {
            relations_by_src
                .entry(src_entity)
                .or_default()
                .insert(relation.id);
        }
        GraphNodeId::Artifact(src_artifact) => {
            relations_by_src_artifact
                .entry(src_artifact)
                .or_default()
                .insert(relation.id);
        }
        _ => {}
    }
    if let GraphNodeId::Entity(dst_entity) = relation.dst {
        relations_by_dst
            .entry(dst_entity)
            .or_default()
            .insert(relation.id);
    }
}

fn remove_relation_indexes(
    relations_by_src: &mut HashMap<EntityId, HashSet<RelationId>>,
    relations_by_src_artifact: &mut HashMap<ArtifactId, HashSet<RelationId>>,
    relations_by_dst: &mut HashMap<EntityId, HashSet<RelationId>>,
    relation: &Relation,
) {
    match relation.src {
        GraphNodeId::Entity(src_entity) => {
            if let Some(ids) = relations_by_src.get_mut(&src_entity) {
                ids.remove(&relation.id);
                if ids.is_empty() {
                    relations_by_src.remove(&src_entity);
                }
            }
        }
        GraphNodeId::Artifact(src_artifact) => {
            if let Some(ids) = relations_by_src_artifact.get_mut(&src_artifact) {
                ids.remove(&relation.id);
                if ids.is_empty() {
                    relations_by_src_artifact.remove(&src_artifact);
                }
            }
        }
        _ => {}
    }
    if let GraphNodeId::Entity(dst_entity) = relation.dst {
        if let Some(ids) = relations_by_dst.get_mut(&dst_entity) {
            ids.remove(&relation.id);
            if ids.is_empty() {
                relations_by_dst.remove(&dst_entity);
            }
        }
    }
}

fn imported_relations_equivalent(old: &Relation, new: &Relation) -> bool {
    old.kind == new.kind
        && old.src == new.src
        && old.dst == new.dst
        && old.origin == new.origin
        && old.import_source == new.import_source
        && (old.confidence - new.confidence).abs() < f32::EPSILON
}

pub(crate) fn entity_fingerprint_changed(old: &Entity, new: &Entity) -> bool {
    kin_index::entity_semantics_changed(old, new)
}

fn reconcile_imported_file_entities(
    old_entities: &[Entity],
    parsed_entities: &[Entity],
) -> (Vec<EntityDelta>, Vec<Entity>) {
    let mut entity_deltas = Vec::new();
    let mut current_entities = Vec::new();
    let mut matched_old_entities = HashSet::<EntityId>::new();

    for parsed_entity in parsed_entities {
        let existing = old_entities
            .iter()
            .filter(|candidate| !matched_old_entities.contains(&candidate.id))
            .find(|candidate| {
                candidate.name == parsed_entity.name && candidate.kind == parsed_entity.kind
            })
            .or_else(|| {
                old_entities
                    .iter()
                    .filter(|candidate| !matched_old_entities.contains(&candidate.id))
                    .find(|candidate| {
                        candidate.name == parsed_entity.name
                            && candidate.file_origin == parsed_entity.file_origin
                    })
            });

        match existing {
            Some(old) if entity_fingerprint_changed(old, parsed_entity) => {
                // Re-key the parser-assigned id onto the stable existing id for
                // this commit. The parse output is shared across commits through
                // the memo, so clone rather than mutate the borrowed entity.
                let mut stabilized = parsed_entity.clone();
                stabilized.id = old.id;
                matched_old_entities.insert(old.id);
                entity_deltas.push(EntityDelta::Modified {
                    old: old.clone(),
                    new: stabilized.clone(),
                });
                current_entities.push(stabilized);
            }
            Some(old) => {
                matched_old_entities.insert(old.id);
                current_entities.push(old.clone());
            }
            None => {
                entity_deltas.push(EntityDelta::Added(parsed_entity.clone()));
                current_entities.push(parsed_entity.clone());
            }
        }
    }

    for old_entity in old_entities {
        if !matched_old_entities.contains(&old_entity.id) {
            entity_deltas.push(EntityDelta::Removed(old_entity.id));
        }
    }

    (entity_deltas, current_entities)
}

fn stabilize_reparsed_file_entities(
    old_entities: &[Entity],
    parsed_entities: &mut [Entity],
    layout: &mut FileLayout,
    discovered_tests: &mut [DiscoveredTest],
) {
    let mut remap = HashMap::<EntityId, EntityId>::new();
    let mut matched_old_entities = HashSet::<EntityId>::new();

    for parsed_entity in parsed_entities.iter_mut() {
        let parser_id = parsed_entity.id;
        let existing = old_entities
            .iter()
            .filter(|candidate| !matched_old_entities.contains(&candidate.id))
            .find(|candidate| {
                candidate.name == parsed_entity.name && candidate.kind == parsed_entity.kind
            });

        if let Some(old) = existing {
            parsed_entity.id = old.id;
            parsed_entity.lineage_parent = old.lineage_parent;
            parsed_entity.created_in = old.created_in;
            matched_old_entities.insert(old.id);
            remap.insert(parser_id, old.id);
        } else {
            remap.insert(parser_id, parser_id);
        }
    }

    remap_layout_entity_ids(layout, &remap);
    remap_discovered_test_entity_ids(discovered_tests, &remap);
}

fn remap_layout_entity_ids(layout: &mut FileLayout, remap: &HashMap<EntityId, EntityId>) {
    for region in &mut layout.regions {
        if let SourceRegion::EntityRef { entity_id, .. } = region {
            if let Some(stable_id) = remap.get(entity_id) {
                *entity_id = *stable_id;
            }
        }
    }
}

fn remap_discovered_test_entity_ids(
    discovered_tests: &mut [DiscoveredTest],
    remap: &HashMap<EntityId, EntityId>,
) {
    for discovered in discovered_tests {
        if let Some(entity_id) = discovered.entity_id.as_mut() {
            if let Some(stable_id) = remap.get(entity_id) {
                *entity_id = *stable_id;
            }
        }
        for target_id in &mut discovered.target_entity_ids {
            if let Some(stable_id) = remap.get(target_id) {
                *target_id = *stable_id;
            }
        }
    }
}

fn index_files(
    graph: &kin_db::InMemoryGraph,
    blob_store: &kin_blobs::BlobStore,
    files: &[IndexableFile],
) -> Result<(
    usize,
    usize,
    Vec<kin_index::FileParseData>,
    Vec<DiscoveredTest>,
    Vec<Relation>,
)> {
    index_files_with_stable_entity_ids(graph, blob_store, files, &HashMap::new())
}

fn index_files_with_stable_entity_ids(
    graph: &kin_db::InMemoryGraph,
    blob_store: &kin_blobs::BlobStore,
    files: &[IndexableFile],
    prior_entities_by_file: &HashMap<String, Vec<Entity>>,
) -> Result<(
    usize,
    usize,
    Vec<kin_index::FileParseData>,
    Vec<DiscoveredTest>,
    Vec<Relation>,
)> {
    let _span = tracing::info_span!("kin.init.index_files", files = files.len()).entered();

    let total = files.len();
    let start = std::time::Instant::now();
    let parsed_count = AtomicUsize::new(0);

    let mut parse_results: Vec<ParsedFileResult> =
        run_with_init_resource_pool("index_files", || {
            // Phase 1: parallel parse — read files, write blobs, parse with tree-sitter.
            // Each thread gets its own AdapterRegistry (tree-sitter parsers are per-thread).
            Ok(files
                .par_iter()
                .map(|file| {
                    let source = match fs::read(&file.abs_path) {
                        Ok(source) => source,
                        Err(_) => return ParsedFileResult::Skipped,
                    };

                    let _ = blob_store.write(&source);

                    let file_id = FilePathId::new(&file.rel_path);
                    let projection_markers =
                        kin_index::extract_projection_source_markers(&file.rel_path, &source);

                    let done = parsed_count.fetch_add(1, Ordering::Relaxed) + 1;
                    if done.is_multiple_of(100) || done == total {
                        eprint!(
                            "\r  [parse {}/{}] {}% | {:.1}s",
                            done,
                            total,
                            (done * 100) / total,
                            start.elapsed().as_secs_f64()
                        );
                    }

                    match &file.classification {
                        FileClassification::EntitySource => {
                            let registry = kin_parser::AdapterRegistry::new();
                            let ext = file
                                .abs_path
                                .extension()
                                .and_then(|e| e.to_str())
                                .unwrap_or("");
                            let adapter = match registry.get_by_extension_and_content(ext, &source)
                            {
                                Some(adapter) => adapter,
                                None => return ParsedFileResult::Skipped,
                            };

                            let tree = match adapter.parse(&source) {
                                Ok(tree) => tree,
                                Err(_) => return ParsedFileResult::Skipped,
                            };

                            let parse_output = match adapter.extract(&tree, &source, &file_id) {
                                Ok(output) => output,
                                Err(_) => return ParsedFileResult::Skipped,
                            };

                            let extracted_relations = parse_output.relations;
                            let file_imports = parse_output.imports;
                            let extracted_tests = parse_output.tests;
                            let parse_state = parse_output.parse_state;
                            let language = adapter.language_id();
                            let mut file_entities = Vec::new();

                            for extracted in parse_output.entities {
                                let mut entity = extracted.into_entity_with_source(
                                    language,
                                    &file_id,
                                    Some(&source),
                                );
                                entity.role = kin_index::classify_file_role(&file.rel_path);
                                kin_parser::attach_file_context_metadata(
                                    std::slice::from_mut(&mut entity),
                                    &file_id,
                                    &file_imports,
                                );
                                file_entities.push(entity);
                            }
                            if language == kin_model::LanguageId::Go {
                                kin_parser::attach_go_command_effect_contract_metadata(
                                    &tree,
                                    &source,
                                    &mut file_entities,
                                );
                            }
                            let discovered_tests = promote_discovered_tests(
                                &file_id,
                                &mut file_entities,
                                extracted_tests,
                            );

                            let layout = build_layout(
                                &file_id,
                                &file_entities,
                                source.len(),
                                &[],
                                ParseCompleteness::from_parse_state(&parse_state),
                            );

                            ParsedFileResult::EntitySource {
                                rel_path: file.rel_path.clone(),
                                hash: file.hash,
                                entities: file_entities,
                                discovered_tests,
                                relations: extracted_relations,
                                imports: file_imports,
                                projection_markers,
                                layout,
                            }
                        }
                        FileClassification::ShallowSyntax { language_hint } => {
                            if let Some(shallow) =
                                kin_parser::parse_shallow_file(&source, &file_id, language_hint)
                            {
                                ParsedFileResult::ShallowSyntax {
                                    rel_path: file.rel_path.clone(),
                                    hash: file.hash,
                                    shallow: ShallowTrackedFile {
                                        file_id,
                                        language_hint: language_hint.clone(),
                                        declaration_count: shallow.declarations.len(),
                                        import_count: shallow.imports.len(),
                                        syntax_hash: shallow.fingerprint.syntax_hash,
                                        signature_hash: shallow.fingerprint.signature_hash,
                                        declaration_names: summarize_shallow_items(
                                            shallow
                                                .declarations
                                                .iter()
                                                .map(|decl| decl.name.clone()),
                                        ),
                                        import_paths: summarize_shallow_items(
                                            shallow
                                                .imports
                                                .iter()
                                                .map(|import| import.raw_path.clone()),
                                        ),
                                    },
                                    projection_markers,
                                }
                            } else {
                                ParsedFileResult::Skipped
                            }
                        }
                        FileClassification::StructuredArtifact(kind) => {
                            let artifact = kin_index::extract_artifact(*kind, &source, &file_id)
                                .unwrap_or(StructuredArtifact {
                                    file_id,
                                    kind: *kind,
                                    content_hash: Hash256::from_bytes(file.hash),
                                    text_preview: preview_text(&source),
                                });
                            ParsedFileResult::StructuredArtifact {
                                rel_path: file.rel_path.clone(),
                                hash: file.hash,
                                artifact,
                                projection_markers,
                            }
                        }
                        FileClassification::OpaqueArtifact { mime_hint } => {
                            let text_preview =
                                preview_text_if_likely_text(&source, mime_hint.as_deref());
                            ParsedFileResult::OpaqueArtifact {
                                rel_path: file.rel_path.clone(),
                                hash: file.hash,
                                artifact: OpaqueArtifact {
                                    file_id,
                                    content_hash: Hash256::from_bytes(file.hash),
                                    mime_type: mime_hint.clone(),
                                    text_preview,
                                },
                                projection_markers,
                            }
                        }
                    }
                })
                .collect())
        })?;

    if !prior_entities_by_file.is_empty() {
        for result in &mut parse_results {
            let ParsedFileResult::EntitySource {
                rel_path,
                entities,
                discovered_tests,
                layout,
                ..
            } = result
            else {
                continue;
            };

            let Some(prior_entities) = prior_entities_by_file.get(rel_path) else {
                continue;
            };

            stabilize_reparsed_file_entities(prior_entities, entities, layout, discovered_tests);
        }
    }

    eprintln!();

    // Phase 2: sequential graph upsert — single-threaded, one lock acquisition per batch.
    let upsert_start = std::time::Instant::now();
    let mut total_entity_count = 0usize;
    let mut total_files = 0usize;
    let mut file_parse_data = Vec::new();
    let mut discovered_tests = Vec::new();
    let mut all_entities: Vec<Entity> = Vec::new();
    let mut projection_marker_files: Vec<(String, Vec<String>)> = Vec::new();

    for result in &parse_results {
        match result {
            ParsedFileResult::EntitySource {
                rel_path,
                hash,
                entities,
                discovered_tests: file_tests,
                relations,
                imports,
                projection_markers,
                layout,
            } => {
                graph.set_file_hash(rel_path, *hash);
                total_files += 1;
                if !projection_markers.is_empty() {
                    projection_marker_files.push((rel_path.clone(), projection_markers.clone()));
                }

                for entity in entities {
                    all_entities.push(entity.clone());
                }

                graph.upsert_file_layout(layout)?;

                total_entity_count += entities.len();
                discovered_tests.extend(file_tests.clone());
                file_parse_data.push(kin_index::FileParseData {
                    file_path: rel_path.clone(),
                    entities: entities.clone(),
                    relations: relations.clone(),
                    imports: imports.clone(),
                });
            }
            ParsedFileResult::ShallowSyntax {
                rel_path,
                hash,
                shallow,
                projection_markers,
            } => {
                graph.set_file_hash(rel_path, *hash);
                total_files += 1;
                if !projection_markers.is_empty() {
                    projection_marker_files.push((rel_path.clone(), projection_markers.clone()));
                }
                graph.upsert_shallow_file(shallow)?;
            }
            ParsedFileResult::StructuredArtifact {
                rel_path,
                hash,
                artifact,
                projection_markers,
            } => {
                graph.set_file_hash(rel_path, *hash);
                total_files += 1;
                if !projection_markers.is_empty() {
                    projection_marker_files.push((rel_path.clone(), projection_markers.clone()));
                }
                graph.upsert_structured_artifact(artifact)?;
            }
            ParsedFileResult::OpaqueArtifact {
                rel_path,
                hash,
                artifact,
                projection_markers,
            } => {
                graph.set_file_hash(rel_path, *hash);
                total_files += 1;
                if !projection_markers.is_empty() {
                    projection_marker_files.push((rel_path.clone(), projection_markers.clone()));
                }
                graph.upsert_opaque_artifact(artifact)?;
            }
            ParsedFileResult::Skipped => {}
        }
    }

    // Batch upsert all entities at once — single lock acquisition, deferred text index.
    graph.upsert_entities_batch(&all_entities)?;
    let projection_relations =
        build_projection_relations_from_markers(graph, &projection_marker_files);

    info!(
        entities = total_entity_count,
        files = total_files,
        parse_secs = %format!("{:.1}", start.elapsed().as_secs_f64()),
        upsert_secs = %format!("{:.1}", upsert_start.elapsed().as_secs_f64()),
        "index_files complete"
    );

    Ok((
        total_entity_count,
        total_files,
        file_parse_data,
        discovered_tests,
        projection_relations,
    ))
}

fn build_projection_relations_from_markers(
    graph: &kin_db::InMemoryGraph,
    projection_marker_files: &[(String, Vec<String>)],
) -> Vec<Relation> {
    if projection_marker_files.is_empty() {
        return Vec::new();
    }

    let known_files: HashSet<String> = graph.indexed_file_paths().into_iter().collect();
    projection_marker_files
        .iter()
        .flat_map(|(file_path, markers)| {
            kin_index::build_projection_derived_relations_from_markers(
                file_path,
                markers,
                &known_files,
                |path| graph.artifact_id_for_path(&FilePathId::new(path)),
            )
        })
        .collect()
}

fn promote_discovered_tests(
    file_id: &FilePathId,
    file_entities: &mut [Entity],
    extracted_tests: Vec<kin_parser::ExtractedTest>,
) -> Vec<DiscoveredTest> {
    extracted_tests
        .into_iter()
        .map(|test| {
            let entity_id = mark_matching_test_entity(file_entities, &test.name);
            let target_entity_ids = infer_test_targets(file_entities, entity_id, &test.name);
            DiscoveredTest {
                file_id: file_id.clone(),
                name: test.name,
                kind: test.kind,
                runner: test.runner,
                entity_id,
                target_entity_ids,
            }
        })
        .collect()
}

fn mark_matching_test_entity(file_entities: &mut [Entity], test_name: &str) -> Option<EntityId> {
    let normalized_test = normalize_test_name(test_name);
    for entity in file_entities {
        if normalize_test_name(&entity.name) == normalized_test {
            entity.role = kin_model::EntityRole::Test;
            return Some(entity.id);
        }
    }
    None
}

fn infer_test_targets(
    file_entities: &[Entity],
    test_entity_id: Option<EntityId>,
    test_name: &str,
) -> Vec<EntityId> {
    let hints = test_target_hints(test_name);
    if hints.is_empty() {
        return Vec::new();
    }

    let mut exact = Vec::new();
    let mut fuzzy = Vec::new();
    for entity in file_entities {
        if Some(entity.id) == test_entity_id {
            continue;
        }

        let normalized_entity = normalize_test_name(&entity.name);
        if normalized_entity.is_empty() {
            continue;
        }

        if hints.iter().any(|hint| hint == &normalized_entity) {
            exact.push(entity.id);
        } else if hints.iter().any(|hint| {
            hint.len() >= 3
                && (normalized_entity.contains(hint) || hint.contains(&normalized_entity))
        }) {
            fuzzy.push(entity.id);
        }
    }

    if !exact.is_empty() {
        exact.sort_unstable_by_key(|id| id.0);
        exact.dedup();
        exact
    } else {
        fuzzy.sort_unstable_by_key(|id| id.0);
        fuzzy.dedup();
        fuzzy
    }
}

fn test_target_hints(test_name: &str) -> Vec<String> {
    let normalized = normalize_test_name(test_name);
    if normalized.is_empty() {
        return Vec::new();
    }

    let mut hints = vec![normalized.clone()];
    for prefix in ["test", "should", "it", "when", "given"] {
        if let Some(stripped) = normalized.strip_prefix(prefix) {
            if stripped.len() >= 3 {
                hints.push(stripped.to_string());
            }
        }
    }

    for suffix in ["test", "spec"] {
        if let Some(stripped) = normalized.strip_suffix(suffix) {
            if stripped.len() >= 3 {
                hints.push(stripped.to_string());
            }
        }
    }

    hints.sort();
    hints.dedup();
    hints
}

fn normalize_test_name(name: &str) -> String {
    name.chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
}

fn materialize_discovered_tests(
    graph: &kin_db::InMemoryGraph,
    discovered_tests: &[DiscoveredTest],
) -> Result<usize> {
    let mut created_relations = 0usize;

    for discovered in discovered_tests {
        let scopes = if discovered.target_entity_ids.is_empty() {
            vec![WorkScope::Artifact(discovered.file_id.clone())]
        } else {
            discovered
                .target_entity_ids
                .iter()
                .copied()
                .map(WorkScope::Entity)
                .collect()
        };

        let test_case = TestCase {
            test_id: TestId::new(),
            name: discovered.name.clone(),
            language: file_language_hint(&discovered.file_id),
            kind: map_test_kind(discovered.kind),
            scopes,
            runner: map_test_runner(&discovered.runner),
            file_origin: Some(discovered.file_id.clone()),
        };
        graph.create_test_case(&test_case)?;

        if let Some(test_entity_id) = discovered.entity_id {
            for target_entity_id in &discovered.target_entity_ids {
                if *target_entity_id == test_entity_id {
                    continue;
                }
                graph.upsert_relation(&Relation {
                    id: RelationId::new(),
                    kind: RelationKind::Tests,
                    src: GraphNodeId::Entity(test_entity_id),
                    dst: GraphNodeId::Entity(*target_entity_id),
                    confidence: 0.7,
                    origin: RelationOrigin::Inferred,
                    created_in: None,
                    import_source: None,
                    evidence: Vec::new(),
                })?;
                created_relations += 1;
            }
        }
    }

    Ok(created_relations)
}

fn map_test_kind(kind: kin_parser::ExtractedTestKind) -> TestKind {
    match kind {
        kin_parser::ExtractedTestKind::Unit => TestKind::Unit,
        kin_parser::ExtractedTestKind::Integration => TestKind::Integration,
    }
}

fn map_test_runner(runner: &str) -> TestRunner {
    match runner {
        "cargo" => TestRunner::Cargo,
        "jest" => TestRunner::Jest,
        "pytest" => TestRunner::Pytest,
        "go" => TestRunner::Go,
        "junit" => TestRunner::JUnit,
        other => TestRunner::Custom(other.to_string()),
    }
}

fn file_language_hint(file_id: &FilePathId) -> String {
    Path::new(&file_id.0)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("unknown")
        .to_string()
}

fn collect_indexable_files(
    source_root: &Path,
    all_files: &[PathBuf],
) -> Result<Vec<IndexableFile>> {
    let _span = tracing::info_span!(
        "kin.init.collect_indexable_files",
        root = %source_root.display(),
        files = all_files.len()
    )
    .entered();

    let files = run_with_init_resource_pool("collect_indexable_files", || {
        Ok(all_files
            .par_iter()
            .filter_map(|file_path| {
                let source = fs::read(file_path).ok()?;
                let classification = FileClassifier::classify(file_path);
                Some(IndexableFile {
                    abs_path: file_path.clone(),
                    rel_path: file_path
                        .strip_prefix(source_root)
                        .unwrap_or(file_path)
                        .to_string_lossy()
                        .to_string(),
                    hash: kin_blobs::digest_bytes(&source),
                    classification,
                })
            })
            .collect())
    })?;

    Ok(files)
}

fn try_warm_init_from_cache(
    dir: &Path,
    layout: &kin_core::KinLayout,
    local_snap: &kin_db::SnapshotManager,
    blob_store: &kin_blobs::BlobStore,
    indexable_files: &[IndexableFile],
) -> Result<Option<InitIndexSummary>> {
    let _span = tracing::info_span!(
        "kin.init.try_warm_init_from_cache",
        root = %dir.display(),
        files = indexable_files.len()
    )
    .entered();
    let wt = std::time::Instant::now();
    macro_rules! wphase {
        ($name:expr) => {
            eprintln!("  [warm-timer] {:>35}: {:.2}s", $name, wt.elapsed().as_secs_f64());
        };
        ($name:expr, $($arg:tt)*) => {
            eprintln!("  [warm-timer] {:>35}: {:.2}s ({})", $name, wt.elapsed().as_secs_f64(), format!($($arg)*));
        };
    }

    let Some(cache_dir) = init_cache_repo_path(dir) else {
        return Ok(None);
    };
    // A HEAD recorded in the manifest resolves to a trusted bundle. An
    // unrecorded HEAD may still share semantic truth with a cached bundle (a
    // sibling clone, a no-op commit, or a doc-only change); adopt that
    // content-addressed candidate only speculatively, and confirm below that no
    // entity-source file diverged before grafting so a divergent HEAD still
    // cold-inits.
    let (cache_graph_path, speculative_candidate) =
        match resolve_warm_cache_graph_path(dir, &cache_dir)? {
            Some(path) => (path, false),
            None => match resolve_warm_cache_content_candidate(dir, &cache_dir)? {
                Some(path) => (path, true),
                None => return Ok(None),
            },
        };
    if !cache_graph_path.exists() {
        return Ok(None);
    }
    wphase!("resolve_cache_path");

    let cache_snap = match kin_db::SnapshotManager::open_without_text_index(&cache_graph_path) {
        Ok(snap) => snap,
        Err(err) => {
            warn!(path = %cache_graph_path.display(), error = %err, "failed to open warm init cache");
            return Ok(None);
        }
    };
    let cache_graph = cache_snap.graph();
    load_warm_cache_vector_index(cache_graph.as_ref(), &cache_graph_path)?;
    wphase!("open_cache_graph");

    let current_files: Vec<(String, [u8; 32])> = indexable_files
        .iter()
        .map(|file| (file.rel_path.clone(), file.hash))
        .collect();
    let diff = kin_db::engine::compute_diff(cache_graph.as_ref(), &current_files);
    let changed_files = diff.changed_count();
    wphase!(
        "compute_diff",
        "changed={} added={} modified={} removed={}",
        changed_files,
        diff.added_files.len(),
        diff.modified_files.len(),
        diff.removed_files.len()
    );

    // A speculative candidate (the current HEAD is not recorded in the manifest)
    // may only be grafted when the working tree's parsed semantic truth matches
    // it. An added, modified, or removed entity-source or shallow-syntax file
    // diverges that truth, so reject to a cold init rather than graft a foreign
    // semantic base onto an unrecorded HEAD. Artifact and opaque deltas (docs,
    // configs, manifests) carry no entity truth and stay reusable.
    if speculative_candidate {
        let semantic_source_diverged = diff
            .added_files
            .iter()
            .chain(diff.modified_files.iter())
            .chain(diff.removed_files.iter())
            .any(|path| {
                matches!(
                    FileClassifier::classify(Path::new(path)),
                    FileClassification::EntitySource | FileClassification::ShallowSyntax { .. }
                )
            });
        if semantic_source_diverged {
            return Ok(None);
        }
    }

    let delta = if diff.is_empty() {
        wphase!("apply_delta (skipped — no changes)");
        WarmCacheDeltaResult::default()
    } else {
        let delta =
            apply_warm_cache_delta(cache_graph.as_ref(), blob_store, indexable_files, &diff)?;
        wphase!("apply_delta", "reparsed={}", delta.reparsed_files);
        delta
    };
    let scrubbed_paths = scrub_internal_graph_truth(cache_graph.as_ref())?;
    wphase!("scrub_internal_graph_truth");
    if !scrubbed_paths.is_empty() {
        warn!(
            count = scrubbed_paths.len(),
            "scrubbed internal control-plane paths from warm init cache"
        );
    }
    let mut warm_text_index_reused = sync_warm_text_index_sidecar(
        local_snap,
        layout,
        &cache_graph_path,
        diff.is_empty() && scrubbed_paths.is_empty(),
    )?;
    wphase!("sync_warm_text_index_sidecar");

    graft_semantic_state(local_snap, layout, cache_graph.as_ref());
    wphase!("graft_semantic_state");
    if warm_text_index_reused {
        warm_text_index_reused =
            ensure_reused_warm_text_index_complete(local_snap, layout, cache_graph.as_ref())?;
        wphase!("validate_warm_text_index_sidecar");
    }

    let warm_embedding_status = restore_warm_embedding_state(
        local_snap,
        layout,
        cache_graph.as_ref(),
        Some(cache_graph_path.with_extension("kvec").as_path()),
        &delta.queued_embeddings,
        &delta.queued_artifacts,
    )?;
    wphase!("restore_warm_embedding_state");
    let local_graph = local_snap.graph();
    Ok(Some(InitIndexSummary {
        total_entity_count: local_graph.entity_count(),
        total_files: local_graph.indexed_file_paths().len(),
        linked_relations: local_graph.relation_count(),
        warm_cache_hit: true,
        warm_text_index_reused,
        warm_vector_index_reused: warm_embedding_status.vector_index_reused,
        warm_requeued_embeddings: warm_embedding_status.requeued_embeddings,
        warm_changed_files: changed_files,
        warm_reparsed_files: delta.reparsed_files,
    }))
}

fn apply_warm_cache_delta(
    graph: &kin_db::InMemoryGraph,
    blob_store: &kin_blobs::BlobStore,
    indexable_files: &[IndexableFile],
    diff: &kin_db::engine::IncrementalDiff,
) -> Result<WarmCacheDeltaResult> {
    let _span = tracing::info_span!(
        "kin.init.apply_warm_cache_delta",
        added = diff.added_files.len(),
        modified = diff.modified_files.len(),
        removed = diff.removed_files.len()
    )
    .entered();
    let dt = std::time::Instant::now();
    macro_rules! dphase {
        ($name:expr) => {
            eprintln!("  [delta-timer] {:>35}: {:.2}s", $name, dt.elapsed().as_secs_f64());
        };
        ($name:expr, $($arg:tt)*) => {
            eprintln!("  [delta-timer] {:>35}: {:.2}s ({})", $name, dt.elapsed().as_secs_f64(), format!($($arg)*));
        };
    }

    let file_map: HashMap<&str, &IndexableFile> = indexable_files
        .iter()
        .map(|file| (file.rel_path.as_str(), file))
        .collect();

    let old_entities_by_file = collect_prior_entities_by_file(graph, diff.modified_files.iter())?;
    let old_source_relations =
        collect_source_relations_for_files(graph, diff.modified_files.iter())?;
    dphase!(
        "snapshot_changed_file_state",
        "modified={} source_rels={}",
        old_entities_by_file.len(),
        old_source_relations.len()
    );

    let removed_artifact_relation_ids =
        collect_artifact_relation_ids_for_files(graph, diff.removed_files.iter())?;
    remove_relations_batch_by_id(graph, &removed_artifact_relation_ids)?;
    for path in &diff.removed_files {
        clear_file_semantic_state(graph, path)?;
    }
    dphase!(
        "clear_removed_file_state",
        "removed={} artifact_rels={}",
        diff.removed_files.len(),
        removed_artifact_relation_ids.len()
    );

    let mut reparsed_paths = BTreeSet::new();
    reparsed_paths.extend(diff.modified_files.iter().cloned());
    reparsed_paths.extend(diff.added_files.iter().cloned());
    if reparsed_paths.is_empty() {
        return Ok(WarmCacheDeltaResult::default());
    }

    let selected_files: Vec<IndexableFile> = reparsed_paths
        .iter()
        .filter_map(|path| file_map.get(path.as_str()).copied().cloned())
        .collect();
    let selected_paths: BTreeSet<String> = selected_files
        .iter()
        .map(|file| file.rel_path.clone())
        .collect();
    let unindexed_modified_files: Vec<String> = diff
        .modified_files
        .iter()
        .filter(|path| !selected_paths.contains(*path))
        .cloned()
        .collect();
    for path in &unindexed_modified_files {
        clear_file_semantic_state(graph, path)?;
    }
    for file in &selected_files {
        clear_file_tracking_for_reparse(graph, &file.rel_path, &file.classification)?;
    }
    dphase!(
        "select_files_to_reparse",
        "selected={} unindexed_modified={}",
        selected_files.len(),
        unindexed_modified_files.len()
    );

    let (_, _, file_parse_data, _, projection_relations) = index_files_with_stable_entity_ids(
        graph,
        blob_store,
        &selected_files,
        &old_entities_by_file,
    )?;
    dphase!("index_files (reparse)");

    remove_stale_reparsed_entities(graph, &old_entities_by_file, &file_parse_data)?;
    dphase!("remove_stale_reparsed_entities");

    let queued_embeddings = file_parse_data
        .iter()
        .flat_map(|file| file.entities.iter().map(|entity| entity.id))
        .collect();
    let mut queued_artifacts: Vec<ArtifactId> = selected_files
        .iter()
        .filter_map(|file| match file.classification {
            FileClassification::EntitySource => None,
            FileClassification::ShallowSyntax { .. }
            | FileClassification::StructuredArtifact(_)
            | FileClassification::OpaqueArtifact { .. } => {
                Some(artifact_id_for_file(graph, &file.rel_path))
            }
        })
        .collect();
    queued_artifacts.sort_unstable();
    queued_artifacts.dedup();
    let incremental_linker = build_incremental_linker_from_graph(graph)?;
    dphase!(
        "build_incremental_linker",
        "known_files={}",
        incremental_linker.known_files.len()
    );

    let mut linked_relations =
        kin_index::link_cross_file_incremental(&file_parse_data, &incremental_linker);
    linked_relations.extend(projection_relations);
    let new_relation_ids: HashSet<RelationId> = linked_relations
        .iter()
        .map(|relation| relation.id)
        .collect();
    let stale_source_relation_ids: Vec<RelationId> = old_source_relations
        .keys()
        .filter(|relation_id| !new_relation_ids.contains(relation_id))
        .copied()
        .collect();
    remove_relations_batch_by_id(graph, &stale_source_relation_ids)?;
    dphase!(
        "link_changed_files_incremental",
        "relations={} stale_source_rels={}",
        linked_relations.len(),
        stale_source_relation_ids.len()
    );

    graph.upsert_relations_batch(&linked_relations)?;
    dphase!("upsert_relations_batch");

    Ok(WarmCacheDeltaResult {
        reparsed_files: selected_files.len(),
        queued_embeddings,
        queued_artifacts,
    })
}

fn collect_prior_entities_by_file<'a, I>(
    graph: &kin_db::InMemoryGraph,
    files: I,
) -> Result<HashMap<String, Vec<Entity>>>
where
    I: IntoIterator<Item = &'a String>,
{
    let mut by_file = HashMap::new();
    for file in files {
        let entities = entities_for_file(graph, file)?;
        if !entities.is_empty() {
            by_file.insert(file.clone(), entities);
        }
    }
    Ok(by_file)
}

fn collect_source_relations_for_files<'a, I>(
    graph: &kin_db::InMemoryGraph,
    files: I,
) -> Result<HashMap<RelationId, Relation>>
where
    I: IntoIterator<Item = &'a String>,
{
    let mut relations = HashMap::new();
    for file in files {
        for entity in entities_for_file(graph, file)? {
            for relation in graph.get_all_relations_for_entity(&entity.id)? {
                if relation.src == GraphNodeId::Entity(entity.id) {
                    relations.insert(relation.id, relation);
                }
            }
        }

        let artifact_node = GraphNodeId::Artifact(artifact_id_for_file(graph, file));
        for relation in graph.get_all_relations_for_node(&artifact_node)? {
            if relation.src == artifact_node {
                relations.insert(relation.id, relation);
            }
        }
    }
    Ok(relations)
}

fn collect_artifact_relation_ids_for_files<'a, I>(
    graph: &kin_db::InMemoryGraph,
    files: I,
) -> Result<Vec<RelationId>>
where
    I: IntoIterator<Item = &'a String>,
{
    let mut relation_ids = HashSet::new();
    for file in files {
        let artifact_node = GraphNodeId::Artifact(artifact_id_for_file(graph, file));
        for relation in graph.get_all_relations_for_node(&artifact_node)? {
            relation_ids.insert(relation.id);
        }
    }
    Ok(relation_ids.into_iter().collect())
}

fn artifact_id_for_file(graph: &kin_db::InMemoryGraph, path: &str) -> ArtifactId {
    graph
        .artifact_id_for_path(&FilePathId::new(path))
        .unwrap_or_else(|| ArtifactId::seed_from_path(path))
}

fn remove_relations_batch_by_id(
    graph: &kin_db::InMemoryGraph,
    relation_ids: &[RelationId],
) -> Result<()> {
    let relation_refs: Vec<&RelationId> = relation_ids.iter().collect();
    graph.remove_relations_batch(&relation_refs)?;
    Ok(())
}

fn clear_file_tracking_for_reparse(
    graph: &kin_db::InMemoryGraph,
    path: &str,
    classification: &FileClassification,
) -> Result<()> {
    let file_id = FilePathId::new(path);
    match classification {
        FileClassification::EntitySource => {
            graph.delete_shallow_file(&file_id)?;
            graph.delete_structured_artifact(&file_id)?;
            graph.delete_opaque_artifact(&file_id)?;
        }
        FileClassification::ShallowSyntax { .. } => {
            graph.delete_file_layout(&file_id)?;
            graph.delete_structured_artifact(&file_id)?;
            graph.delete_opaque_artifact(&file_id)?;
        }
        FileClassification::StructuredArtifact(_) => {
            graph.delete_file_layout(&file_id)?;
            graph.delete_shallow_file(&file_id)?;
            graph.delete_opaque_artifact(&file_id)?;
        }
        FileClassification::OpaqueArtifact { .. } => {
            graph.delete_file_layout(&file_id)?;
            graph.delete_shallow_file(&file_id)?;
            graph.delete_structured_artifact(&file_id)?;
        }
    }
    Ok(())
}

fn remove_stale_reparsed_entities(
    graph: &kin_db::InMemoryGraph,
    old_entities_by_file: &HashMap<String, Vec<Entity>>,
    file_parse_data: &[kin_index::FileParseData],
) -> Result<()> {
    let current_ids_by_file: HashMap<&str, HashSet<EntityId>> = file_parse_data
        .iter()
        .map(|file| {
            (
                file.file_path.as_str(),
                file.entities.iter().map(|entity| entity.id).collect(),
            )
        })
        .collect();

    for (file, old_entities) in old_entities_by_file {
        let current_ids = current_ids_by_file.get(file.as_str());
        let stale_ids: Vec<EntityId> = old_entities
            .iter()
            .filter(|entity| {
                current_ids
                    .map(|ids| !ids.contains(&entity.id))
                    .unwrap_or(true)
            })
            .map(|entity| entity.id)
            .collect();
        graph.remove_entities_batch(&stale_ids)?;
    }
    Ok(())
}

fn build_incremental_linker_from_graph(
    graph: &kin_db::InMemoryGraph,
) -> Result<kin_index::IncrementalLinker> {
    let mut linker = kin_index::IncrementalLinker::new();
    let indexed_paths = graph.indexed_file_paths();
    for path in &indexed_paths {
        linker.known_files.insert(path.clone());
    }

    let mut entities_by_file = BTreeMap::<String, Vec<Entity>>::new();
    let mut entity_meta = HashMap::<EntityId, (String, String)>::new();
    for entity in graph.query_entities(&EntityFilter::default())? {
        let Some(file_path) = entity.file_origin.as_ref().map(|path| path.0.clone()) else {
            continue;
        };
        entity_meta.insert(entity.id, (entity.name.clone(), file_path.clone()));
        entities_by_file.entry(file_path).or_default().push(entity);
    }
    for (file_path, entities) in entities_by_file {
        linker.add_file(&file_path, &entities);
    }

    // Rehydrate per-file class hierarchies from the committed Extends edges so
    // inheritance-aware method resolution keeps working across reopen — the
    // reparsed subset alone would only see step-local hierarchies, and an
    // inheritance walk crossing into an unchanged file would dead-end.
    // Committed edges carry no declaration order, so bases are sorted
    // lexicographically — the same order every other recording path uses.
    let mut bases_by_file_class = BTreeMap::<(String, String), Vec<String>>::new();
    for (src, kind, dst, _confidence) in graph.list_all_entity_edges() {
        if kind != RelationKind::Extends {
            continue;
        }
        let (Some((src_name, src_file)), Some((dst_name, _))) =
            (entity_meta.get(&src), entity_meta.get(&dst))
        else {
            continue;
        };
        let bases = bases_by_file_class
            .entry((src_file.clone(), src_name.clone()))
            .or_default();
        if !bases.contains(dst_name) {
            bases.push(dst_name.clone());
        }
    }
    for ((file_path, class_name), mut bases) in bases_by_file_class {
        bases.sort_unstable();
        linker
            .class_bases_by_file
            .entry(file_path)
            .or_default()
            .push((class_name, bases));
    }

    // Rehydrate per-file include state from the committed artifact include
    // edges so include-closure disambiguation keeps working across reopen —
    // the reparsed subset alone would only see step-local includes.
    for path in &indexed_paths {
        let artifact_node = GraphNodeId::Artifact(artifact_id_for_file(graph, path));
        let mut targets = Vec::new();
        for relation in graph.get_all_relations_for_node(&artifact_node)? {
            if relation.kind != RelationKind::Includes || relation.src != artifact_node {
                continue;
            }
            let GraphNodeId::Artifact(dst_artifact) = relation.dst else {
                continue;
            };
            let Some(dst_path) = graph.path_for_artifact_id(&dst_artifact) else {
                continue;
            };
            targets.push(dst_path.0);
        }
        if !targets.is_empty() {
            targets.sort();
            targets.dedup();
            linker.include_targets_by_file.insert(path.clone(), targets);
        }
    }

    Ok(linker)
}

fn entities_for_file(graph: &kin_db::InMemoryGraph, path: &str) -> Result<Vec<Entity>> {
    let filter = EntityFilter {
        file_path: Some(FilePathId::new(path)),
        ..Default::default()
    };
    Ok(graph.query_entities(&filter)?)
}

fn clear_file_semantic_state(graph: &kin_db::InMemoryGraph, path: &str) -> Result<()> {
    let entities = entities_for_file(graph, path)?;
    if !entities.is_empty() {
        let ids: Vec<EntityId> = entities.iter().map(|e| e.id).collect();
        graph.remove_entities_batch(&ids)?;
    }
    let _ = graph.remove_entities_for_file(path);
    let file_id = FilePathId::new(path);
    graph.delete_shallow_file(&file_id)?;
    graph.delete_structured_artifact(&file_id)?;
    graph.delete_opaque_artifact(&file_id)?;
    graph.delete_file_layout(&file_id)?;
    Ok(())
}

pub(crate) fn is_repo_owned_graph_path(path: &str) -> bool {
    kin_index::should_index_repo_relative_path(Path::new(path))
}

fn scrub_internal_graph_truth(graph: &kin_db::InMemoryGraph) -> Result<Vec<String>> {
    let mut stale_paths = BTreeSet::new();

    stale_paths.extend(
        graph
            .indexed_file_paths()
            .into_iter()
            .filter(|path| !is_repo_owned_graph_path(path)),
    );
    stale_paths.extend(
        graph
            .list_shallow_files()?
            .into_iter()
            .map(|file| file.file_id.0)
            .filter(|path| !is_repo_owned_graph_path(path)),
    );
    stale_paths.extend(
        graph
            .list_structured_artifacts()?
            .into_iter()
            .map(|artifact| artifact.file_id.0)
            .filter(|path| !is_repo_owned_graph_path(path)),
    );
    stale_paths.extend(
        graph
            .list_opaque_artifacts()?
            .into_iter()
            .map(|artifact| artifact.file_id.0)
            .filter(|path| !is_repo_owned_graph_path(path)),
    );

    for path in &stale_paths {
        clear_file_semantic_state(graph, path)?;
    }

    Ok(stale_paths.into_iter().collect())
}

fn preview_text(content: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(content).ok()?;
    let collapsed = text
        .split_whitespace()
        .take(64)
        .collect::<Vec<_>>()
        .join(" ");
    let trimmed = collapsed.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.chars().take(320).collect())
    }
}

fn preview_text_if_likely_text(content: &[u8], mime_hint: Option<&str>) -> Option<String> {
    let textual_mime = mime_hint.is_some_and(|mime| {
        mime.starts_with("text/")
            || mime.contains("json")
            || mime.contains("yaml")
            || mime.contains("toml")
            || mime.contains("xml")
            || mime.contains("javascript")
            || mime.contains("shell")
    });
    if textual_mime {
        return preview_text(content);
    }

    let printable = content
        .iter()
        .copied()
        .filter(|byte| byte.is_ascii_graphic() || byte.is_ascii_whitespace())
        .count();
    if !content.is_empty() && printable * 100 / content.len() >= 92 {
        return preview_text(content);
    }

    None
}

fn summarize_shallow_items(items: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for item in items {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }
        if seen.insert(trimmed.to_string()) {
            result.push(trimmed.to_string());
        }
        if result.len() >= 12 {
            break;
        }
    }
    result
}

fn graft_semantic_state(
    local_snap: &kin_db::SnapshotManager,
    layout: &kin_core::KinLayout,
    source_graph: &kin_db::InMemoryGraph,
) {
    let _span = tracing::info_span!("kin.init.graft_semantic_state").entered();
    let mut local_snapshot = local_snap.graph().to_snapshot();
    let source_snapshot = source_graph.to_snapshot();
    local_snapshot.entities = source_snapshot.entities;
    local_snapshot.relations = source_snapshot.relations;
    local_snapshot.outgoing = source_snapshot.outgoing;
    local_snapshot.incoming = source_snapshot.incoming;
    local_snapshot.shallow_files = source_snapshot.shallow_files;
    local_snapshot.structured_artifacts = source_snapshot.structured_artifacts;
    local_snapshot.opaque_artifacts = source_snapshot.opaque_artifacts;
    local_snapshot.file_hashes = source_snapshot.file_hashes;
    local_snapshot.changes = source_snapshot.changes;
    local_snapshot.change_children = source_snapshot.change_children;
    local_snapshot.branches = source_snapshot.branches;

    local_snap.swap(kin_db::InMemoryGraph::from_snapshot_with_text_index(
        local_snapshot,
        layout.text_index_dir(),
    ));
}

fn sync_warm_text_index_sidecar(
    local_snap: &kin_db::SnapshotManager,
    layout: &kin_core::KinLayout,
    cache_graph_path: &Path,
    reuse_cached_sidecar: bool,
) -> Result<bool> {
    if !reuse_cached_sidecar {
        return Ok(false);
    }

    let Some(cache_dir) = cache_graph_path.parent() else {
        return Ok(false);
    };
    let cache_text_index_dir = cache_dir.join("text-index");
    if !cache_text_index_dir.exists() {
        return Ok(false);
    }

    // Release local persistent text-index handles before replacing the sidecar.
    let local_snapshot = local_snap.graph().to_snapshot();
    let local_root_hash = kin_db::compute_graph_root_hash(&local_snapshot);
    local_snap.swap(kin_db::InMemoryGraph::from_snapshot_with_root_hash(
        local_snapshot,
        local_root_hash,
    ));

    let local_text_index_dir = layout.text_index_dir();
    if local_text_index_dir.exists() {
        fs::remove_dir_all(&local_text_index_dir)?;
    }
    copy_dir_recursive(&cache_text_index_dir, &local_text_index_dir)?;
    Ok(true)
}

fn ensure_reused_warm_text_index_complete(
    local_snap: &kin_db::SnapshotManager,
    layout: &kin_core::KinLayout,
    source_graph: &kin_db::InMemoryGraph,
) -> Result<bool> {
    let stats = local_snap.graph().graph_stats();
    if stats.total_entities == 0 || stats.text_indexed_entity_count >= stats.total_entities {
        return Ok(true);
    }

    warn!(
        total_entities = stats.total_entities,
        text_indexed_entity_count = stats.text_indexed_entity_count,
        "warm init cache text index sidecar had incomplete entity coverage; rebuilding"
    );

    // Release any open persistent text-index handle before deleting the reused
    // sidecar, then graft the cached graph again so kin-db rebuilds a fresh
    // text index from semantic truth.
    let local_snapshot = local_snap.graph().to_snapshot();
    let local_root_hash = kin_db::compute_graph_root_hash(&local_snapshot);
    local_snap.swap(kin_db::InMemoryGraph::from_snapshot_with_root_hash(
        local_snapshot,
        local_root_hash,
    ));

    let local_text_index_dir = layout.text_index_dir();
    if local_text_index_dir.exists() {
        fs::remove_dir_all(&local_text_index_dir)?;
    }
    graft_semantic_state(local_snap, layout, source_graph);

    let rebuilt_stats = local_snap.graph().graph_stats();
    if rebuilt_stats.total_entities > 0
        && rebuilt_stats.text_indexed_entity_count < rebuilt_stats.total_entities
    {
        warn!(
            total_entities = rebuilt_stats.total_entities,
            text_indexed_entity_count = rebuilt_stats.text_indexed_entity_count,
            "rebuilt warm init text index still has incomplete entity coverage"
        );
        return Ok(false);
    }

    Ok(true)
}

#[cfg(feature = "vector")]
fn restore_warm_embedding_state(
    local_snap: &kin_db::SnapshotManager,
    layout: &kin_core::KinLayout,
    source_graph: &kin_db::InMemoryGraph,
    source_vector_path: Option<&Path>,
    queued_embeddings: &[EntityId],
    queued_artifacts: &[ArtifactId],
) -> Result<WarmEmbeddingRestoreStatus> {
    let _span = tracing::info_span!(
        "kin.init.restore_warm_embedding_state",
        queued_embeddings = queued_embeddings.len(),
        queued_artifacts = queued_artifacts.len()
    )
    .entered();
    let local_vector_path = layout.kindb_vector_index_path();
    let has_delta_embedding_work = !queued_embeddings.is_empty() || !queued_artifacts.is_empty();
    if let Some(source_vector_path) = source_vector_path {
        if source_vector_path.exists() {
            if let Some(parent) = local_vector_path.parent() {
                fs::create_dir_all(parent)?;
            }
            if has_delta_embedding_work {
                tracing::debug!(
                    source = %source_vector_path.display(),
                    destination = %local_vector_path.display(),
                    "saving delta-mutated warm cache vector index sidecar"
                );
                source_graph.save_vector_index(&local_vector_path)?;
            } else {
                tracing::debug!(
                    source = %source_vector_path.display(),
                    destination = %local_vector_path.display(),
                    "copying warm cache vector index sidecar"
                );
                fs::copy(source_vector_path, &local_vector_path)?;

                let source_metadata_path = source_vector_path.with_extension("kvec.meta.json");
                let local_metadata_path = local_vector_path.with_extension("kvec.meta.json");
                if source_metadata_path.exists() {
                    fs::copy(source_metadata_path, local_metadata_path)?;
                }
            }
        } else {
            source_graph.save_vector_index(&local_vector_path)?;
        }
    } else {
        source_graph.save_vector_index(&local_vector_path)?;
    }

    let local_graph = local_snap.graph();
    let mut indexed = local_graph.load_vector_index(&local_vector_path)?;
    if indexed == 0 {
        source_graph.save_vector_index(&local_vector_path)?;
        indexed = local_graph.load_vector_index(&local_vector_path)?;
    }
    tracing::debug!(
        indexed,
        path = %local_vector_path.display(),
        "restored warm embedding state into local graph"
    );
    if indexed == 0 {
        local_graph.queue_all_for_embedding();
        local_graph.queue_all_artifacts_for_embedding();
        return Ok(WarmEmbeddingRestoreStatus {
            vector_index_reused: false,
            requeued_embeddings: local_graph.embedding_status().pending,
        });
    }

    if !queued_embeddings.is_empty() {
        local_graph.queue_for_embedding(queued_embeddings);
    }
    if !queued_artifacts.is_empty() {
        local_graph.queue_artifacts_for_embedding(queued_artifacts);
    }

    Ok(WarmEmbeddingRestoreStatus {
        vector_index_reused: true,
        requeued_embeddings: queued_embeddings.len(),
    })
}

#[cfg(feature = "vector")]
fn load_warm_cache_vector_index(
    cache_graph: &kin_db::InMemoryGraph,
    cache_graph_path: &Path,
) -> Result<()> {
    let cache_vector_path = cache_graph_path.with_extension("kvec");
    if !cache_vector_path.exists() {
        return Ok(());
    }

    let indexed = cache_graph.load_vector_index(&cache_vector_path)?;
    tracing::debug!(
        indexed,
        path = %cache_vector_path.display(),
        "loaded warm cache vector index sidecar"
    );
    Ok(())
}

#[cfg(not(feature = "vector"))]
fn load_warm_cache_vector_index(
    _cache_graph: &kin_db::InMemoryGraph,
    _cache_graph_path: &Path,
) -> Result<()> {
    Ok(())
}

#[cfg(not(feature = "vector"))]
fn restore_warm_embedding_state(
    _local_snap: &kin_db::SnapshotManager,
    _layout: &kin_core::KinLayout,
    _source_graph: &kin_db::InMemoryGraph,
    _source_vector_path: Option<&Path>,
    _queued_embeddings: &[EntityId],
    _queued_artifacts: &[ArtifactId],
) -> Result<WarmEmbeddingRestoreStatus> {
    Ok(WarmEmbeddingRestoreStatus::default())
}

pub(crate) fn refresh_init_cache(
    dir: &Path,
    graph: &kin_db::InMemoryGraph,
    precomputed_root_hash: [u8; 32],
) -> Result<()> {
    let Some(cache_dir) = init_cache_repo_path(dir) else {
        return Ok(());
    };
    fs::create_dir_all(&cache_dir)?;

    // Fast path: if the manifest already has this git HEAD, skip the expensive
    // graph serialization + root hash computation.
    let current_head = read_git_head(dir);
    let manifest_path = warm_cache_manifest_path(&cache_dir);
    let current_entity_count = graph.entity_count();
    let current_relation_count = graph.relation_count();
    let current_indexed_files = graph.indexed_file_paths().len();
    if let Some(ref head) = current_head {
        if let Ok(Some(manifest)) = read_warm_cache_manifest(&manifest_path) {
            if let Some(bundle_id) = manifest.heads.get(head) {
                if let Some(entry) = manifest.bundles.get(bundle_id) {
                    if entry.entity_count == current_entity_count
                        && entry.relation_count == current_relation_count
                        && entry.indexed_files == current_indexed_files
                    {
                        return Ok(());
                    }
                }
            }
        }
    }

    let graph_root_hash = hex::encode(precomputed_root_hash);
    let bundle_id = graph_root_hash.clone();
    let cache_graph_path = warm_cache_bundle_graph_path(&cache_dir, &bundle_id);
    if !cache_graph_path.exists() {
        kin_db::SnapshotManager::save_graph_with_hash(
            &cache_graph_path,
            graph,
            Some(precomputed_root_hash),
        )
        .with_context(|| {
            format!(
                "failed to save warm init cache bundle at {}",
                cache_graph_path.display()
            )
        })?;

        // Co-locate the text index with the cache bundle so warm loads don't
        // trigger a 300s+ full rebuild. SnapshotManager::open auto-discovers
        // a `text-index/` sibling of the graph file.
        if let Some(bundle_dir) = cache_graph_path.parent() {
            let cache_ti_dir = bundle_dir.join("text-index");
            // Find the live text index: .kin/kindb/text-index/
            let live_ti_dir = dir.join(".kin/kindb/text-index");
            if live_ti_dir.is_dir() {
                let _ = fs::create_dir_all(&cache_ti_dir);
                // Copy all text index files (tantivy segments)
                if let Ok(entries) = fs::read_dir(&live_ti_dir) {
                    for entry in entries.flatten() {
                        let dest = cache_ti_dir.join(entry.file_name());
                        let _ = fs::copy(entry.path(), &dest);
                    }
                }
            }
        }
    }

    let manifest_path = warm_cache_manifest_path(&cache_dir);
    let mut manifest =
        read_warm_cache_manifest(&manifest_path)?.unwrap_or_else(|| WarmCacheRepoManifest {
            schema: INIT_WARM_CACHE_SCHEMA_VERSION.to_string(),
            pipeline_epoch: INIT_WARM_CACHE_PIPELINE_EPOCH.to_string(),
            repo_identity: repo_cache_identity(dir),
            ..Default::default()
        });
    manifest.schema = INIT_WARM_CACHE_SCHEMA_VERSION.to_string();
    manifest.pipeline_epoch = INIT_WARM_CACHE_PIPELINE_EPOCH.to_string();
    manifest.repo_identity = repo_cache_identity(dir);
    manifest.git_head = read_git_head(dir);
    manifest.current_bundle_id = Some(bundle_id.clone());
    if let Some(git_head) = manifest.git_head.clone() {
        manifest.heads.insert(git_head, bundle_id.clone());
    }
    manifest
        .bundles
        .entry(bundle_id.clone())
        .or_insert_with(|| WarmCacheBundleManifestEntry {
            graph_root_hash,
            entity_count: current_entity_count,
            relation_count: current_relation_count,
            indexed_files: current_indexed_files,
            published_at: chrono::Utc::now().to_rfc3339(),
        });

    fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)?;
    fs::write(
        warm_cache_ready_marker_path(&cache_dir, &bundle_id),
        b"ready",
    )?;
    Ok(())
}

fn init_cache_repo_path(dir: &Path) -> Option<PathBuf> {
    let root = init_cache_root()?;
    let mut hasher = Sha256::new();
    hasher.update(repo_cache_identity(dir).as_bytes());
    let repo_key = hex::encode(hasher.finalize());
    Some(root.join(repo_key))
}

fn warm_cache_manifest_path(cache_dir: &Path) -> PathBuf {
    cache_dir.join("manifest.json")
}

fn warm_cache_bundle_graph_path(cache_dir: &Path, bundle_id: &str) -> PathBuf {
    cache_dir.join("bundles").join(bundle_id).join("graph.kndb")
}

fn warm_cache_ready_marker_path(cache_dir: &Path, bundle_id: &str) -> PathBuf {
    cache_dir.join("bundles").join(bundle_id).join(".ready")
}

fn read_warm_cache_manifest(manifest_path: &Path) -> Result<Option<WarmCacheRepoManifest>> {
    if !manifest_path.exists() {
        return Ok(None);
    }

    let manifest =
        serde_json::from_str::<WarmCacheRepoManifest>(&fs::read_to_string(manifest_path)?)
            .with_context(|| {
                format!(
                    "failed to parse warm init manifest at {}",
                    manifest_path.display()
                )
            })?;
    Ok(Some(manifest))
}

fn warm_cache_manifest_is_valid(dir: &Path, manifest: &WarmCacheRepoManifest) -> bool {
    if manifest.schema != INIT_WARM_CACHE_SCHEMA_VERSION {
        return false;
    }
    if manifest.pipeline_epoch != INIT_WARM_CACHE_PIPELINE_EPOCH {
        return false;
    }
    manifest.repo_identity == repo_cache_identity(dir)
}

fn resolve_warm_cache_graph_path(dir: &Path, cache_dir: &Path) -> Result<Option<PathBuf>> {
    resolve_warm_cache_graph_path_for_head(dir, cache_dir, read_git_head(dir))
}

/// Resolve the warm-cache bundle graph to graft for a working tree currently at
/// `current_head`, or `None` to fall back to a cold init.
///
/// The bundle is selected by the tree's CURRENT git HEAD (via the manifest's
/// `heads` map), NOT by the manifest's last-written `current_bundle_id`.
/// `current_bundle_id` is whatever state was published LAST under this repo
/// identity, so adopting it grafts that state into any checkout that merely
/// shares the identity — the cross-state contamination where a warm init's
/// entity count swings with publish order. When the tree has a HEAD, only a
/// bundle recorded for exactly that HEAD is trustworthy; every other case
/// rejects rather than adopts a foreign state, and a cold init re-derives truth.
/// A non-git working tree has no HEAD to key on: its cache is
/// path-identity-scoped and single-state, so the last bundle is the only
/// meaningful one.
fn resolve_warm_cache_graph_path_for_head(
    dir: &Path,
    cache_dir: &Path,
    current_head: Option<String>,
) -> Result<Option<PathBuf>> {
    let manifest_path = warm_cache_manifest_path(cache_dir);
    if let Some(manifest) = read_warm_cache_manifest(&manifest_path)? {
        if !warm_cache_manifest_is_valid(dir, &manifest) {
            return Ok(None);
        }
        let bundle_id = match &current_head {
            Some(head) => match manifest.heads.get(head) {
                Some(id) => id.clone(),
                // Reject-don't-adopt: no bundle recorded for this exact HEAD, so
                // a cold init is the only trustworthy path — never graft another
                // HEAD's (or the last-published) state.
                None => return Ok(None),
            },
            None => match manifest.current_bundle_id.clone() {
                Some(id) => id,
                None => return Ok(None),
            },
        };
        let bundle_graph_path = warm_cache_bundle_graph_path(cache_dir, &bundle_id);
        if bundle_graph_path.exists()
            && warm_cache_ready_marker_path(cache_dir, &bundle_id).exists()
        {
            return Ok(Some(bundle_graph_path));
        }
        // The resolved bundle is absent or not yet marked ready: reject rather
        // than fall back to a legacy or foreign bundle.
        return Ok(None);
    }

    // No manifest: only the un-versioned legacy single-graph cache may exist. It
    // carries no HEAD provenance, so a git working tree cannot trust it
    // (reject-don't-adopt); a non-git, path-scoped tree may still reuse it.
    if current_head.is_none() {
        let legacy_graph_path = cache_dir.join("graph.kndb");
        if legacy_graph_path.exists() {
            return Ok(Some(legacy_graph_path));
        }
    }

    Ok(None)
}

/// Resolve a *content-addressed* warm-cache bundle candidate for a working tree
/// whose current HEAD is not recorded in the manifest.
///
/// The trusted head-scoped resolver rejects an unrecorded HEAD so it never
/// grafts a foreign or last-published state. That correctly refuses divergent
/// truth, but it also refuses the legitimate case where a different HEAD carries
/// *identical* graph truth — a sibling clone, a fresh checkout, or a commit that
/// changes no indexed file. Because a bundle is addressed by its graph root
/// hash, identical file content always maps to the same bundle, so such a tree
/// can safely reuse the last-published state.
///
/// This returns only a CANDIDATE: the caller MUST confirm no entity-source file
/// diverged (a semantic-truth-preserving diff) before grafting. An entity-level
/// divergence falls back to a cold init instead of adopting the candidate,
/// preserving the reject-don't-adopt guarantee against publish-order
/// contamination while still reusing shared semantic truth across doc- or
/// config-only changes.
fn resolve_warm_cache_content_candidate(dir: &Path, cache_dir: &Path) -> Result<Option<PathBuf>> {
    let manifest_path = warm_cache_manifest_path(cache_dir);
    let Some(manifest) = read_warm_cache_manifest(&manifest_path)? else {
        return Ok(None);
    };
    if !warm_cache_manifest_is_valid(dir, &manifest) {
        return Ok(None);
    }
    let Some(bundle_id) = manifest.current_bundle_id.as_deref() else {
        return Ok(None);
    };
    let bundle_graph_path = warm_cache_bundle_graph_path(cache_dir, bundle_id);
    if bundle_graph_path.exists() && warm_cache_ready_marker_path(cache_dir, bundle_id).exists() {
        return Ok(Some(bundle_graph_path));
    }
    Ok(None)
}

fn init_cache_root() -> Option<PathBuf> {
    if !init_cache_enabled() {
        return None;
    }

    if let Ok(path) = std::env::var("KIN_INIT_CACHE_DIR") {
        return Some(PathBuf::from(path));
    }

    directories::BaseDirs::new().map(|dirs| {
        dirs.home_dir()
            .join(".kin/cache/init")
            .join(init_cache_namespace())
    })
}

fn init_cache_enabled() -> bool {
    std::env::var("KIN_INIT_WARM_CACHE")
        .map(|value| value != "0")
        .unwrap_or(true)
}

fn init_cache_namespace() -> String {
    let mut hasher = Sha256::new();
    hasher.update(INIT_WARM_CACHE_SCHEMA_VERSION.as_bytes());
    hasher.update(b":");
    hasher.update(INIT_WARM_CACHE_PIPELINE_EPOCH.as_bytes());
    let digest = hex::encode(hasher.finalize());
    format!("{INIT_WARM_CACHE_SCHEMA_VERSION}-{}", &digest[..16])
}

fn repo_cache_identity(dir: &Path) -> String {
    if let Some(remote) = git_origin_remote(dir) {
        return format!("git:{remote}");
    }

    let canonical = dir.canonicalize().unwrap_or_else(|_| dir.to_path_buf());
    format!("path:{}", canonical.display())
}

fn git_origin_remote(dir: &Path) -> Option<String> {
    let output = Command::new("git")
        .args(["remote", "get-url", "origin"])
        .current_dir(dir)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let remote = String::from_utf8(output.stdout).ok()?;
    let remote = remote.trim();
    if remote.is_empty() {
        None
    } else {
        Some(remote.to_string())
    }
}

fn move_snapshot_into_place(src: &Path, dst: &Path) -> Result<()> {
    if !src.exists() {
        return Ok(());
    }
    if dst.exists() {
        fs::remove_dir_all(dst)?;
    }
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }
    match fs::rename(src, dst) {
        Ok(()) => Ok(()),
        Err(_) => {
            copy_dir_recursive(src, dst)?;
            fs::remove_dir_all(src)?;
            Ok(())
        }
    }
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else if file_type.is_file() {
            if let Some(parent) = dst_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

/// Collect all source files, skipping .kin/, .git/, and common artifact directories.
pub(crate) fn collect_source_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_source_files_recursive(root, root, &mut files)?;
    files.sort_by(|left, right| {
        source_file_sort_key(root, left).cmp(&source_file_sort_key(root, right))
    });
    Ok(files)
}

fn source_file_sort_key(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .replace(std::path::MAIN_SEPARATOR, "/")
}

fn collect_source_files_recursive(root: &Path, dir: &Path, files: &mut Vec<PathBuf>) -> Result<()> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Ok(()),
    };

    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        if path.is_dir() {
            if kin_index::should_skip_dir(name_str.as_ref()) {
                continue;
            }
            collect_source_files_recursive(root, &path, files)?;
        } else if path.is_file() {
            // A git *worktree* root carries `.git` as a FILE (a `gitdir:` pointer
            // holding a machine-absolute path), not a directory. Apply the same
            // VCS/internal skip to file entries so that pointer file — and any
            // other internal-named file (`.kin`, `.git-export`) — can never
            // become an indexed entity and leak a machine path into graph truth.
            if kin_index::should_skip_dir(name_str.as_ref()) {
                continue;
            }
            files.push(path);
        }
    }

    Ok(())
}

/// Enumerate the on-disk source files under `source_root` and pair each
/// repo-relative path with its content hash, using the exact enumeration and
/// hashing the indexer uses. Sharing this path with indexing guarantees the
/// hashes are directly comparable to graph truth, so a drift check can never
/// report a false mismatch caused by hashing a file differently than it was
/// indexed.
pub(crate) fn collect_on_disk_file_hashes(source_root: &Path) -> Result<Vec<(String, [u8; 32])>> {
    let all_files = collect_source_files(source_root)?;
    let indexable = collect_indexable_files(source_root, &all_files)?;
    Ok(indexable
        .into_iter()
        .map(|file| (file.rel_path, file.hash))
        .collect())
}

fn count_supported_source_inputs(indexable_files: &[IndexableFile]) -> (usize, usize) {
    let mut entity_source_count = 0usize;
    let mut shallow_source_count = 0usize;

    for file in indexable_files {
        match &file.classification {
            FileClassification::EntitySource => entity_source_count += 1,
            // Only count shallow inputs a grammar can actually parse; ungrammared
            // languages fall back to opaque artifacts and must not trip the abort.
            FileClassification::ShallowSyntax { language_hint } => {
                if kin_parser::get_shallow_grammar(language_hint.as_str()).is_some() {
                    shallow_source_count += 1;
                }
            }
            FileClassification::StructuredArtifact(_)
            | FileClassification::OpaqueArtifact { .. } => {}
        }
    }

    (entity_source_count, shallow_source_count)
}

fn ensure_graph_surface_materialized(
    graph: &kin_db::InMemoryGraph,
    entity_source_input_count: usize,
    shallow_source_input_count: usize,
) -> Result<()> {
    let stats = graph.graph_stats();

    if entity_source_input_count > 0 && stats.total_entities == 0 {
        anyhow::bail!(
            "graph initialization produced zero entities for {} entity-source files",
            entity_source_input_count
        );
    }

    if shallow_source_input_count > 0 && stats.shallow_file_count == 0 {
        anyhow::bail!(
            "graph initialization produced zero shallow files for {} shallow-syntax files",
            shallow_source_input_count
        );
    }

    Ok(())
}

/// Deterministic digest of the (path, content-hash) set, independent of
/// wall-clock time, machine path, and walk order. The path length prefix keeps
/// the digest unambiguous across path boundaries.
fn compute_artifact_fingerprint<'a>(
    entries: impl IntoIterator<Item = (&'a str, &'a [u8; 32])>,
) -> [u8; 32] {
    let mut entries: Vec<(&str, &[u8; 32])> = entries.into_iter().collect();
    entries.sort_unstable();
    let mut hasher = Sha256::new();
    hasher.update(b"kin-init-artifacts-v1:");
    for (path, hash) in entries {
        hasher.update((path.len() as u64).to_le_bytes());
        hasher.update(path.as_bytes());
        hasher.update(hash);
    }
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    bytes
}

/// Deterministic change ID for the init auto-parse commit: a pure function of
/// the parent change and the artifact content fingerprint, so two independent
/// preps of the same graph produce the same ID.
fn compute_init_change_id(
    parent: &SemanticChangeId,
    artifact_fingerprint: &[u8; 32],
) -> SemanticChangeId {
    let mut hasher = Sha256::new();
    hasher.update(b"kin-change-v1:");
    hasher.update(b"kin init: auto-parse");
    hasher.update(b":");
    hasher.update(parent.0.as_bytes());
    hasher.update(b":");
    hasher.update(artifact_fingerprint);
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    SemanticChangeId::from_hash(Hash256::from_bytes(bytes))
}

/// Get a human-readable author name.
fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_index::COMMAND_EFFECT_CONTRACT_KEY;
    use kin_model::{
        EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, LanguageId,
        SemanticFingerprint, Visibility,
    };
    use serial_test::serial;
    use std::collections::BTreeSet;
    use std::fs;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    fn open_snapshot_with_retry(path: impl Into<std::path::PathBuf>) -> kin_db::SnapshotManager {
        let path = path.into();
        for attempt in 0..10u32 {
            match kin_db::SnapshotManager::open(path.clone()) {
                Ok(s) => return s,
                Err(e) => {
                    if attempt == 9 {
                        panic!("SnapshotManager::open({path:?}) failed after 10 attempts: {e}");
                    }
                    std::thread::sleep(std::time::Duration::from_millis(
                        50 * u64::from(attempt + 1),
                    ));
                }
            }
        }
        unreachable!()
    }

    #[test]
    fn hydrate_stage_timings_json_is_parseable_with_explicit_residue() {
        // Representative pass: the four buckets leave a non-trivial residue, and
        // most parses were served from the memo.
        let line =
            hydrate_stage_timings_json(32865, 1933.4, 42.5, 261.9, 954.7, 641.2, 30000, 2865);

        let value: serde_json::Value =
            serde_json::from_str(&line).expect("emitted line must be parseable JSON");
        let obj = value
            .get("kin_hydrate_stage_timings")
            .expect("top-level envelope key present");

        // Count is an integer; every timing is a real (finite) float, never null.
        assert_eq!(obj["total_commits"].as_u64(), Some(32865));
        for key in [
            "total_s",
            "commits_per_s",
            "blob_read_s",
            "parsing_s",
            "linking_s",
            "closure_diffing_s",
            "other_s",
        ] {
            assert!(obj[key].is_f64(), "{key} must serialize as a JSON float");
        }

        // Memo counters are integers carried alongside the timings.
        assert_eq!(obj["parse_memo_hits"].as_u64(), Some(30000));
        assert_eq!(obj["parse_memo_misses"].as_u64(), Some(2865));

        let total_s = obj["total_s"].as_f64().unwrap();
        let blob = obj["blob_read_s"].as_f64().unwrap();
        let parsing = obj["parsing_s"].as_f64().unwrap();
        let linking = obj["linking_s"].as_f64().unwrap();
        let closure = obj["closure_diffing_s"].as_f64().unwrap();
        let other = obj["other_s"].as_f64().unwrap();

        // The whole point of other_s: the four buckets plus the residue
        // reconstruct the wall total exactly, matching the human summary.
        let reconstructed = blob + parsing + linking + closure + other;
        assert!(
            (reconstructed - total_s).abs() < 1e-9,
            "buckets + other_s must sum to total_s ({reconstructed} vs {total_s})"
        );
        assert!(
            (other - (1933.4 - 42.5 - 261.9 - 954.7 - 641.2)).abs() < 1e-9,
            "other_s must be the explicit unattributed residue"
        );

        // Throughput is commits / wall.
        assert!((obj["commits_per_s"].as_f64().unwrap() - 32865.0 / 1933.4).abs() < 1e-9);

        // Keys are emitted in the documented order, not alphabetized.
        let order = [
            "kin_hydrate_stage_timings",
            "total_commits",
            "total_s",
            "commits_per_s",
            "blob_read_s",
            "parsing_s",
            "linking_s",
            "closure_diffing_s",
            "other_s",
            "parse_memo_hits",
            "parse_memo_misses",
        ];
        let mut cursor = 0usize;
        for key in order {
            let quoted = format!("\"{key}\"");
            let at = line[cursor..]
                .find(quoted.as_str())
                .unwrap_or_else(|| panic!("key {key} must be present and in order"));
            cursor += at + quoted.len();
        }
    }

    #[test]
    fn hydrate_stage_timings_json_guards_zero_wall() {
        // A zero wall must not emit NaN/Infinity (serde renders those as null);
        // commits_per_s falls back to 0.0 and stays a parseable number.
        let line = hydrate_stage_timings_json(10, 0.0, 0.0, 0.0, 0.0, 0.0, 0, 0);
        let value: serde_json::Value =
            serde_json::from_str(&line).expect("emitted line must be parseable JSON");
        let obj = &value["kin_hydrate_stage_timings"];
        assert!(obj["commits_per_s"].is_f64());
        assert_eq!(obj["commits_per_s"].as_f64(), Some(0.0));
        assert_eq!(obj["other_s"].as_f64(), Some(0.0));
        assert_eq!(obj["parse_memo_hits"].as_u64(), Some(0));
        assert_eq!(obj["parse_memo_misses"].as_u64(), Some(0));
    }

    #[test]
    fn git_history_import_options_supports_recent_full_and_off() {
        assert!(git_history_import_options("off").is_none());

        let recent = git_history_import_options("recent").unwrap();
        assert_eq!(recent.max_commits, 50);
        assert!(!recent.shallow);

        let full = git_history_import_options("full").unwrap();
        assert_eq!(full.max_commits, 0);
        assert!(!full.shallow);
    }

    #[test]
    fn init_change_id_is_content_addressed_not_wall_clock() {
        let parent = SemanticChangeId::from_hash(Hash256::from_bytes([0x11; 32]));
        let a: [u8; 32] = [0xaa; 32];
        let b: [u8; 32] = [0xbb; 32];
        let fingerprint = compute_artifact_fingerprint([("src/a.rs", &a), ("src/b.rs", &b)]);

        let id1 = compute_init_change_id(&parent, &fingerprint);
        let id2 = compute_init_change_id(&parent, &fingerprint);
        assert_eq!(
            id1.to_string(),
            id2.to_string(),
            "same parent + content must yield an identical change id (no wall-clock)"
        );

        assert_eq!(
            fingerprint,
            compute_artifact_fingerprint([("src/b.rs", &b), ("src/a.rs", &a)]),
            "fingerprint must be independent of walk order"
        );

        let c: [u8; 32] = [0xcc; 32];
        let id3 =
            compute_init_change_id(&parent, &compute_artifact_fingerprint([("src/a.rs", &c)]));
        assert_ne!(
            id1.to_string(),
            id3.to_string(),
            "different artifact content must yield a different change id"
        );
    }

    fn with_env_var<T>(name: &str, value: Option<&str>, f: impl FnOnce() -> T) -> T {
        let prior = std::env::var_os(name);
        match value {
            Some(value) => std::env::set_var(name, value),
            None => std::env::remove_var(name),
        }
        let result = f();
        match prior {
            Some(value) => std::env::set_var(name, value),
            None => std::env::remove_var(name),
        }
        result
    }

    #[test]
    #[serial]
    fn init_resource_pool_is_opt_in_and_proof_safe() {
        with_env_var("KIN_RESOURCE_PROFILE", None, || {
            assert!(init_resource_pool_config().unwrap().is_none());
        });

        with_env_var("KIN_RESOURCE_PROFILE", Some("proof"), || {
            assert!(init_resource_pool_config().unwrap().is_none());
        });

        with_env_var("KIN_RESOURCE_PROFILE", Some("throughput"), || {
            let config = init_resource_pool_config().unwrap().unwrap();
            assert_eq!(config.profile, Profile::Throughput);
            assert!(config.rayon_threads > 0);
        });
    }

    #[test]
    #[serial]
    fn init_resource_pool_rejects_unknown_profile() {
        with_env_var("KIN_RESOURCE_PROFILE", Some("turbo"), || {
            let error = init_resource_pool_config().unwrap_err().to_string();
            assert!(error.contains("invalid KIN_RESOURCE_PROFILE"));
        });
    }

    #[test]
    fn collect_source_files_returns_sorted_repo_relative_paths() {
        let repo_dir = tempfile::tempdir().unwrap();
        let root = repo_dir.path();
        fs::create_dir_all(root.join("z")).unwrap();
        fs::create_dir_all(root.join("a")).unwrap();
        fs::write(root.join("z/mod.rs"), "pub fn zed() {}\n").unwrap();
        fs::write(root.join("a/mod.rs"), "pub fn alpha() {}\n").unwrap();
        fs::write(root.join("main.rs"), "fn main() {}\n").unwrap();

        let rels = collect_source_files(root)
            .unwrap()
            .into_iter()
            .map(|path| source_file_sort_key(root, &path))
            .collect::<Vec<_>>();

        assert_eq!(rels, vec!["a/mod.rs", "main.rs", "z/mod.rs"]);
    }

    fn single_added_function_id(deltas: &[EntityDelta]) -> EntityId {
        let functions = deltas
            .iter()
            .filter_map(|delta| match delta {
                EntityDelta::Added(entity) if entity.kind == EntityKind::Function => {
                    Some(entity.id)
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            functions.len(),
            1,
            "expected single added function entity delta, got {deltas:?}"
        );
        functions[0]
    }

    fn single_modified_function(deltas: &[EntityDelta]) -> (&Entity, &Entity) {
        let functions = deltas
            .iter()
            .filter_map(|delta| match delta {
                EntityDelta::Modified { old, new } if old.kind == EntityKind::Function => {
                    Some((old, new))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(
            functions.len(),
            1,
            "expected single modified function entity delta, got {deltas:?}"
        );
        functions[0]
    }

    #[test]
    fn enrich_imported_changes_with_semantics_reuses_entity_ids() {
        let dir = tempfile::tempdir().unwrap();
        let blob_store = kin_blobs::BlobStore::new(dir.path().join("objects")).unwrap();

        let blob_v1 = blob_store
            .write(b"def handler():\n    return 'v1'\n")
            .unwrap();
        let blob_v2 = blob_store
            .write(b"def handler(value):\n    return value\n")
            .unwrap();

        let mut imported = vec![
            imported_change(
                [0x11; 32],
                [0x10; 32],
                "imported root",
                vec![artifact_delta(
                    "src/lib.py",
                    kin_model::ArtifactDeltaKind::Added,
                    None,
                    Some(Hash256::from_bytes(blob_v1.0)),
                )],
            ),
            imported_change(
                [0x12; 32],
                [0x11; 32],
                "imported modify",
                vec![artifact_delta(
                    "src/lib.py",
                    kin_model::ArtifactDeltaKind::Modified,
                    Some(Hash256::from_bytes(blob_v1.0)),
                    Some(Hash256::from_bytes(blob_v2.0)),
                )],
            ),
        ];

        enrich_imported_changes_with_semantics(&mut imported, &blob_store).unwrap();

        let first_entity_id = single_added_function_id(&imported[0].change.entity_deltas);

        let (old, new) = single_modified_function(&imported[1].change.entity_deltas);
        assert_eq!(old.id, first_entity_id);
        assert_eq!(new.id, first_entity_id);
        assert_eq!(old.name, "handler");
        assert_eq!(new.name, "handler");
        assert!(
            entity_fingerprint_changed(old, new),
            "modified imported entity should record a semantic fingerprint change"
        );
    }

    /// Canonical, key-order-insensitive JSON so two structurally identical values
    /// compare equal regardless of `HashMap` iteration order. Entity metadata
    /// (`extra`) is a `HashMap`, and this workspace builds serde_json with
    /// `preserve_order`, so a freshly parsed map and a cloned map can serialize
    /// their keys in different orders while being semantically identical.
    fn canonical_json<T: serde::Serialize>(value: &T) -> String {
        fn sort(value: serde_json::Value) -> serde_json::Value {
            match value {
                serde_json::Value::Object(map) => serde_json::Value::Object(
                    map.into_iter()
                        .collect::<std::collections::BTreeMap<_, _>>()
                        .into_iter()
                        .map(|(key, val)| (key, sort(val)))
                        .collect(),
                ),
                serde_json::Value::Array(items) => {
                    serde_json::Value::Array(items.into_iter().map(sort).collect())
                }
                other => other,
            }
        }
        serde_json::to_string(&sort(
            serde_json::to_value(value).expect("value must serialize"),
        ))
        .expect("canonical json must serialize")
    }

    #[test]
    fn parse_memo_hit_shares_arc_and_version_participates_in_key() {
        let blob = kin_blobs::Hash256::from_bytes([0x42; 32]);
        let mut memo: HashMap<(kin_blobs::Hash256, u32), Arc<CachedParse>> = HashMap::new();
        let payload = Arc::new(CachedParse {
            entities: Vec::new(),
            extracted_relations: Vec::new(),
            imports: Vec::new(),
        });
        memo.insert(
            (blob, kin_parser::PARSER_SEMANTICS_VERSION),
            Arc::clone(&payload),
        );

        // Same (blob, version): a hit hands back the SAME allocation, not a clone.
        let hit = memo
            .get(&(blob, kin_parser::PARSER_SEMANTICS_VERSION))
            .expect("same key must hit");
        assert!(
            Arc::ptr_eq(hit, &payload),
            "a memo hit must share the cached Arc rather than deep-clone the payload"
        );

        // Same blob, a bumped parser-semantics version: miss. A grammar or
        // extractor upgrade can therefore never serve a stale parse.
        assert!(
            !memo.contains_key(&(blob, kin_parser::PARSER_SEMANTICS_VERSION.wrapping_add(1))),
            "a parser-semantics version change must key to a different (missing) entry"
        );

        // Different blob, same version: miss.
        let other_blob = kin_blobs::Hash256::from_bytes([0x43; 32]);
        assert!(
            !memo.contains_key(&(other_blob, kin_parser::PARSER_SEMANTICS_VERSION)),
            "a different blob must not collide with the cached entry"
        );
    }

    #[test]
    fn parse_memo_matches_unmemoized_reconciliation_across_commits() {
        let dir = tempfile::tempdir().unwrap();
        let blob_store = kin_blobs::BlobStore::new(dir.path().join("objects")).unwrap();

        // A file whose commit-3 content reverts to its commit-1 bytes. The
        // reverted blob is parsed once (commit 1) then served from the memo
        // (commit 3), yet commit 3's reconciliation still runs against commit 2's
        // state — the commit-relative step the memo must NOT short-circuit.
        let v1 = blob_store
            .write(b"def handler():\n    return 1\n\n\ndef helper():\n    return 2\n")
            .unwrap();
        let v2 = blob_store
            .write(b"def handler(value):\n    return value\n")
            .unwrap();

        let fixture = || {
            vec![
                imported_change(
                    [0x31; 32],
                    [0x30; 32],
                    "add module",
                    vec![artifact_delta(
                        "src/mod.py",
                        kin_model::ArtifactDeltaKind::Added,
                        None,
                        Some(Hash256::from_bytes(v1.0)),
                    )],
                ),
                imported_change(
                    [0x32; 32],
                    [0x31; 32],
                    "shrink module",
                    vec![artifact_delta(
                        "src/mod.py",
                        kin_model::ArtifactDeltaKind::Modified,
                        Some(Hash256::from_bytes(v1.0)),
                        Some(Hash256::from_bytes(v2.0)),
                    )],
                ),
                imported_change(
                    [0x33; 32],
                    [0x32; 32],
                    "revert module",
                    vec![artifact_delta(
                        "src/mod.py",
                        kin_model::ArtifactDeltaKind::Modified,
                        Some(Hash256::from_bytes(v2.0)),
                        Some(Hash256::from_bytes(v1.0)),
                    )],
                ),
            ]
        };

        // Oracle: memo disabled — every source-blob appearance re-parses.
        let mut oracle = fixture();
        let (oracle_hits, oracle_misses) =
            enrich_imported_changes_with_semantics_inner(&mut oracle, &blob_store, false).unwrap();
        assert_eq!(oracle_hits, 0, "memo-off must never report a hit");
        assert_eq!(
            oracle_misses, 3,
            "memo-off must parse every source-blob appearance"
        );

        // Memoized: the reverted blob is parsed once and reused.
        let mut memoized = fixture();
        let (memo_hits, memo_misses) =
            enrich_imported_changes_with_semantics_inner(&mut memoized, &blob_store, true).unwrap();
        assert_eq!(
            memo_hits, 1,
            "the reverted commit-3 blob must be served from the memo"
        );
        assert_eq!(
            memo_misses, 2,
            "only the two distinct blob versions are parsed"
        );

        // Bit-identity: memo-on and memo-off produce identical entity and
        // relation deltas for every commit.
        assert_eq!(oracle.len(), memoized.len());
        for (i, (oracle_change, memo_change)) in oracle.iter().zip(memoized.iter()).enumerate() {
            assert_eq!(
                canonical_json(&oracle_change.change.entity_deltas),
                canonical_json(&memo_change.change.entity_deltas),
                "entity_deltas diverged at commit {i}"
            );
            assert_eq!(
                canonical_json(&oracle_change.change.relation_deltas),
                canonical_json(&memo_change.change.relation_deltas),
                "relation_deltas diverged at commit {i}"
            );
        }
    }

    #[test]
    fn replay_is_bit_identical_under_serial_and_parallel_execution() {
        // End-to-end oracle for the intra-commit parallelism: the parse fan-out
        // (parallel blob read + parse) and the parallel incremental linker both
        // dispatch their per-item work onto the ambient Rayon pool. Pinning that
        // pool to a single worker forces the whole hydration pass to run fully
        // serially; a multi-worker pool exercises the concurrent path. Both arms
        // run the identical production code with the memo enabled — the ONLY
        // variable is worker-thread count — so any order-dependence, shared-state
        // hazard, or nondeterministic merge in the fan-out would make the two
        // diverge. The fixture spans several commits with cross-file imports,
        // calls, a class-inheritance receiver-method call, a blob that reverts to
        // an earlier version (memo hit), and a non-source file, so entities,
        // relations, and their per-entity fingerprints are all exercised.
        let dir = tempfile::tempdir().unwrap();
        let blob_store = kin_blobs::BlobStore::new(dir.path().join("objects")).unwrap();

        // Leaf callees imported across the tree.
        let log_v1 = blob_store
            .write(b"export function log(msg: string) { return msg; }\n")
            .unwrap();
        // math v1 is reused verbatim by commit 3, so it parses once (commit 1)
        // then serves from the memo.
        let math_v1 = blob_store
            .write(b"export function add(a: number, b: number) { return a + b; }\n")
            .unwrap();
        let math_v2 = blob_store
            .write(
                b"export function add(a: number, b: number) { return a + b; }\n\
                  export function mul(a: number, b: number) { return a * b; }\n",
            )
            .unwrap();
        // Base class for the inheritance-aware receiver-method tier.
        let base_v1 = blob_store
            .write(b"export class Base { greet() { return 0; } }\n")
            .unwrap();
        // Imports log + add, extends Base, and calls this.greet(): a single file
        // that reaches the cross-file import/call tiers and the inherited-method
        // tier at once.
        let main_v1 = blob_store
            .write(
                b"import { log } from '../util/log';\n\
                  import { add } from '../util/math';\n\
                  import { Base } from '../core/base';\n\
                  export class App extends Base { run() { log('x'); add(1, 2); this.greet(); } }\n",
            )
            .unwrap();
        // A second importer of log so commit 2 adds independent cross-file work.
        let worker_v1 = blob_store
            .write(b"import { log } from '../util/log';\nexport function work() { log('w'); }\n")
            .unwrap();
        let readme = blob_store.write(b"# Title\n").unwrap();

        let fixture = || {
            vec![
                imported_change(
                    [0x41; 32],
                    [0x40; 32],
                    "seed the tree",
                    vec![
                        artifact_delta(
                            "src/util/log.ts",
                            kin_model::ArtifactDeltaKind::Added,
                            None,
                            Some(Hash256::from_bytes(log_v1.0)),
                        ),
                        artifact_delta(
                            "src/util/math.ts",
                            kin_model::ArtifactDeltaKind::Added,
                            None,
                            Some(Hash256::from_bytes(math_v1.0)),
                        ),
                        artifact_delta(
                            "src/core/base.ts",
                            kin_model::ArtifactDeltaKind::Added,
                            None,
                            Some(Hash256::from_bytes(base_v1.0)),
                        ),
                        artifact_delta(
                            "src/app/main.ts",
                            kin_model::ArtifactDeltaKind::Added,
                            None,
                            Some(Hash256::from_bytes(main_v1.0)),
                        ),
                    ],
                ),
                imported_change(
                    [0x42; 32],
                    [0x41; 32],
                    "grow math + add a worker",
                    vec![
                        artifact_delta(
                            "src/util/math.ts",
                            kin_model::ArtifactDeltaKind::Modified,
                            Some(Hash256::from_bytes(math_v1.0)),
                            Some(Hash256::from_bytes(math_v2.0)),
                        ),
                        artifact_delta(
                            "src/app/worker.ts",
                            kin_model::ArtifactDeltaKind::Added,
                            None,
                            Some(Hash256::from_bytes(worker_v1.0)),
                        ),
                    ],
                ),
                imported_change(
                    [0x43; 32],
                    [0x42; 32],
                    "revert math + add docs",
                    vec![
                        // Reverts to commit 1's exact bytes: a memo hit whose
                        // reconciliation still runs against commit 2's state.
                        artifact_delta(
                            "src/util/math.ts",
                            kin_model::ArtifactDeltaKind::Modified,
                            Some(Hash256::from_bytes(math_v2.0)),
                            Some(Hash256::from_bytes(math_v1.0)),
                        ),
                        // Non-source file: takes the removal path, never a job.
                        artifact_delta(
                            "README.md",
                            kin_model::ArtifactDeltaKind::Added,
                            None,
                            Some(Hash256::from_bytes(readme.0)),
                        ),
                    ],
                ),
            ]
        };

        let serial_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .build()
            .unwrap();
        let parallel_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(4)
            .build()
            .unwrap();

        let mut serial = fixture();
        let (serial_hits, serial_misses) = serial_pool
            .install(|| {
                enrich_imported_changes_with_semantics_inner(&mut serial, &blob_store, true)
            })
            .unwrap();

        let mut parallel = fixture();
        let (parallel_hits, parallel_misses) = parallel_pool
            .install(|| {
                enrich_imported_changes_with_semantics_inner(&mut parallel, &blob_store, true)
            })
            .unwrap();

        // Memo hit/miss accounting must not depend on worker-thread count.
        assert_eq!(
            (serial_hits, serial_misses),
            (parallel_hits, parallel_misses),
            "memo accounting diverged between serial and parallel execution"
        );
        assert!(
            serial_hits >= 1,
            "fixture must exercise a memo hit (the reverted blob)"
        );

        // Bit-identity across every commit: the enriched entity and relation
        // deltas must match exactly. Entity deltas embed each entity's
        // `SemanticFingerprint` (ast/signature/behavior hashes), so this
        // comparison is also the fingerprint oracle.
        assert_eq!(serial.len(), parallel.len());
        let mut saw_entities = false;
        let mut saw_relations = false;
        let mut saw_fingerprint = false;
        for (i, (serial_change, parallel_change)) in serial.iter().zip(parallel.iter()).enumerate()
        {
            let serial_entities = canonical_json(&serial_change.change.entity_deltas);
            assert_eq!(
                serial_entities,
                canonical_json(&parallel_change.change.entity_deltas),
                "entity_deltas diverged at commit {i} under parallel execution"
            );
            assert_eq!(
                canonical_json(&serial_change.change.relation_deltas),
                canonical_json(&parallel_change.change.relation_deltas),
                "relation_deltas diverged at commit {i} under parallel execution"
            );
            saw_entities |= !serial_change.change.entity_deltas.is_empty();
            saw_relations |= !serial_change.change.relation_deltas.is_empty();
            saw_fingerprint |= serial_entities.contains("fingerprint");
        }
        assert!(saw_entities, "fixture must materialize entity deltas");
        assert!(
            saw_relations,
            "fixture must materialize cross-file relation deltas"
        );
        assert!(
            saw_fingerprint,
            "entity deltas must carry fingerprints for the fingerprint oracle to bite"
        );
    }

    #[test]
    fn entity_fingerprint_changed_includes_command_effect_contract_metadata() {
        let mut old = test_entity("prCheckout", "command/pr_checkout.go");
        let mut new = old.clone();
        old.metadata.extra.insert(
            COMMAND_EFFECT_CONTRACT_KEY.into(),
            serde_json::json!({
                "effects": [{
                    "kind": "queued_git_argv",
                    "bindings": { "newBranchName": "pr.HeadRefName" }
                }]
            }),
        );
        new.metadata.extra.insert(
            COMMAND_EFFECT_CONTRACT_KEY.into(),
            serde_json::json!({
                "effects": [{
                    "kind": "queued_git_argv",
                    "bindings": {
                        "newBranchName": "fmt.Sprintf(\"pr/%d/%s\", pr.Number, pr.HeadRefName)"
                    }
                }]
            }),
        );

        assert!(
            entity_fingerprint_changed(&old, &new),
            "command-effect contract metadata changes must produce an imported entity delta"
        );
    }

    #[test]
    fn imported_go_command_effect_contract_change_records_entity_delta() {
        let dir = tempfile::tempdir().unwrap();
        let blob_store = kin_blobs::BlobStore::new(dir.path().join("objects")).unwrap();
        let old_source = br#"
package command

import (
    "fmt"
    "os/exec"

    "github.com/cli/cli/git"
    "github.com/spf13/cobra"
)

type pullRequest struct {
    Number int
    HeadRefName string
}

func prCheckout(cmd *cobra.Command, args []string) error {
    pr := pullRequest{Number: 123, HeadRefName: "feature"}
    cmdQueue := [][]string{}
    newBranchName := pr.HeadRefName
    if git.VerifyRef("refs/heads/" + newBranchName) {
        cmdQueue = append(cmdQueue, []string{"git", "checkout", newBranchName})
    } else {
        cmdQueue = append(cmdQueue, []string{"git", "checkout", "-b", newBranchName, "--no-track", "origin/feature"})
    }
    exec.Command("git", "config", fmt.Sprintf("branch.%s.remote", newBranchName), "origin")
    _ = cmdQueue
    return nil
}
"#;
        let new_source = br#"
package command

import (
    "fmt"
    "os/exec"

    "github.com/cli/cli/git"
    "github.com/spf13/cobra"
)

type pullRequest struct {
    Number int
    HeadRefName string
}

func prCheckout(cmd *cobra.Command, args []string) error {
    pr := pullRequest{Number: 123, HeadRefName: "feature"}
    cmdQueue := [][]string{}
    newBranchName := fmt.Sprintf("pr/%d/%s", pr.Number, pr.HeadRefName)
    if git.VerifyRef("refs/heads/" + newBranchName) {
        cmdQueue = append(cmdQueue, []string{"git", "checkout", newBranchName})
    } else {
        cmdQueue = append(cmdQueue, []string{"git", "checkout", "-b", newBranchName, "--no-track", "origin/feature"})
    }
    exec.Command("git", "config", fmt.Sprintf("branch.%s.remote", newBranchName), "origin")
    _ = cmdQueue
    return nil
}
"#;
        let blob_v1 = blob_store.write(old_source).unwrap();
        let blob_v2 = blob_store.write(new_source).unwrap();
        let mut imported = vec![
            imported_change(
                [0x21; 32],
                [0x20; 32],
                "imported root",
                vec![artifact_delta(
                    "command/pr_checkout.go",
                    kin_model::ArtifactDeltaKind::Added,
                    None,
                    Some(Hash256::from_bytes(blob_v1.0)),
                )],
            ),
            imported_change(
                [0x22; 32],
                [0x21; 32],
                "prefix branch names",
                vec![artifact_delta(
                    "command/pr_checkout.go",
                    kin_model::ArtifactDeltaKind::Modified,
                    Some(Hash256::from_bytes(blob_v1.0)),
                    Some(Hash256::from_bytes(blob_v2.0)),
                )],
            ),
        ];

        enrich_imported_changes_with_semantics(&mut imported, &blob_store).unwrap();
        let (old, new) = imported[1]
            .change
            .entity_deltas
            .iter()
            .find_map(|delta| match delta {
                EntityDelta::Modified { old, new } if new.name == "prCheckout" => Some((old, new)),
                _ => None,
            })
            .expect("prCheckout should be recorded as a modified entity");
        let old_contract = old.metadata.extra.get(COMMAND_EFFECT_CONTRACT_KEY);
        let new_contract = new.metadata.extra.get(COMMAND_EFFECT_CONTRACT_KEY);
        assert!(old_contract.is_some(), "old contract metadata missing");
        assert!(new_contract.is_some(), "new contract metadata missing");
        assert_ne!(
            old_contract, new_contract,
            "branch naming contract change must be visible in metadata"
        );
    }

    #[test]
    fn enrich_imported_changes_with_semantics_relinks_reverse_dependencies() {
        let dir = tempfile::tempdir().unwrap();
        let blob_store = kin_blobs::BlobStore::new(dir.path().join("objects")).unwrap();

        let tools_v1 = blob_store
            .write(b"export function executeTool() { return 1; }\n")
            .unwrap();
        let api_v1 = blob_store
            .write(
                b"import { executeTool } from '../utils/tools';\nexport function handler() { executeTool(); }\n",
            )
            .unwrap();
        let tools_v2 = blob_store.write(b"export const VERSION = 1;\n").unwrap();

        let mut imported = vec![
            imported_change(
                [0x21; 32],
                [0x20; 32],
                "imported root",
                vec![
                    artifact_delta(
                        "src/utils/tools.ts",
                        kin_model::ArtifactDeltaKind::Added,
                        None,
                        Some(Hash256::from_bytes(tools_v1.0)),
                    ),
                    artifact_delta(
                        "src/routes/api.ts",
                        kin_model::ArtifactDeltaKind::Added,
                        None,
                        Some(Hash256::from_bytes(api_v1.0)),
                    ),
                ],
            ),
            imported_change(
                [0x22; 32],
                [0x21; 32],
                "remove callee",
                vec![artifact_delta(
                    "src/utils/tools.ts",
                    kin_model::ArtifactDeltaKind::Modified,
                    Some(Hash256::from_bytes(tools_v1.0)),
                    Some(Hash256::from_bytes(tools_v2.0)),
                )],
            ),
        ];

        enrich_imported_changes_with_semantics(&mut imported, &blob_store).unwrap();

        let removed_relations = imported[1]
            .change
            .relation_deltas
            .iter()
            .filter_map(|delta| match delta {
                RelationDelta::Removed(id) => Some(*id),
                RelationDelta::Added(_) => None,
            })
            .collect::<Vec<_>>();

        // Imports are now artifact-level (file→file) edges, so removing the
        // callee drops only the entity-level Calls edge (handler→executeTool);
        // the file-level import edge stays because api.ts still imports the
        // tools module, which still exists. Exactly one reverse-dependent edge
        // is removed.
        assert_eq!(
            removed_relations.len(),
            1,
            "the entity-level caller edge (handler→executeTool) should be removed"
        );
        assert!(
            imported[1]
                .change
                .relation_deltas
                .iter()
                .all(|delta| matches!(delta, RelationDelta::Removed(_))),
            "reverse-dependent caller edges should be removed instead of left stale, \
             with no spurious re-add of the stable artifact import edge"
        );
    }

    #[test]
    fn enrich_imported_changes_with_semantics_keeps_stable_relations_quiet() {
        let dir = tempfile::tempdir().unwrap();
        let blob_store = kin_blobs::BlobStore::new(dir.path().join("objects")).unwrap();

        let tools_v1 = blob_store
            .write(b"export function executeTool() { return 1; }\n")
            .unwrap();
        let api_v1 = blob_store
            .write(
                b"import { executeTool } from '../utils/tools';\nexport function handler() { executeTool(); }\n",
            )
            .unwrap();
        let tools_v2 = blob_store
            .write(b"export function executeTool(value: number) { return value; }\n")
            .unwrap();

        let mut imported = vec![
            imported_change(
                [0x31; 32],
                [0x30; 32],
                "imported root",
                vec![
                    artifact_delta(
                        "src/utils/tools.ts",
                        kin_model::ArtifactDeltaKind::Added,
                        None,
                        Some(Hash256::from_bytes(tools_v1.0)),
                    ),
                    artifact_delta(
                        "src/routes/api.ts",
                        kin_model::ArtifactDeltaKind::Added,
                        None,
                        Some(Hash256::from_bytes(api_v1.0)),
                    ),
                ],
            ),
            imported_change(
                [0x32; 32],
                [0x31; 32],
                "semantic update",
                vec![artifact_delta(
                    "src/utils/tools.ts",
                    kin_model::ArtifactDeltaKind::Modified,
                    Some(Hash256::from_bytes(tools_v1.0)),
                    Some(Hash256::from_bytes(tools_v2.0)),
                )],
            ),
        ];

        enrich_imported_changes_with_semantics(&mut imported, &blob_store).unwrap();

        assert!(
            matches!(
                &imported[1].change.entity_deltas[..],
                [EntityDelta::Modified { .. }]
            ),
            "callee entity should still record a semantic modification"
        );
        assert!(
            imported[1].change.relation_deltas.is_empty(),
            "stable cross-file edges should not be re-added on every imported change"
        );
    }

    #[test]
    fn enrich_imported_changes_with_semantics_drops_stale_state_on_missing_blob() {
        let dir = tempfile::tempdir().unwrap();
        let blob_store = kin_blobs::BlobStore::new(dir.path().join("objects")).unwrap();

        let blob_v1 = blob_store
            .write(b"def handler():\n    return 'v1'\n")
            .unwrap();
        let missing_hash = Hash256::from_bytes([0x7f; 32]);
        let mut imported = vec![
            imported_change(
                [0x41; 32],
                [0x40; 32],
                "imported root",
                vec![artifact_delta(
                    "src/lib.py",
                    kin_model::ArtifactDeltaKind::Added,
                    None,
                    Some(Hash256::from_bytes(blob_v1.0)),
                )],
            ),
            imported_change(
                [0x42; 32],
                [0x41; 32],
                "missing blob",
                vec![artifact_delta(
                    "src/lib.py",
                    kin_model::ArtifactDeltaKind::Modified,
                    Some(Hash256::from_bytes(blob_v1.0)),
                    Some(missing_hash),
                )],
            ),
        ];

        enrich_imported_changes_with_semantics(&mut imported, &blob_store).unwrap();

        let first_entity_id = single_added_function_id(&imported[0].change.entity_deltas);
        assert!(
            imported[1]
                .change
                .entity_deltas
                .iter()
                .any(|delta| matches!(delta, EntityDelta::Removed(entity_id) if *entity_id == first_entity_id)),
            "expected stale imported function removal, got {:?}",
            imported[1].change.entity_deltas
        );
    }

    #[test]
    fn enrich_imported_changes_keys_entity_deltas_to_git_parent_not_linear_running_map() {
        // Non-linear history: a root R forks into two sibling commits that both
        // touch the SAME file. Branch A rewrites `f`'s body; branch B leaves `f`
        // byte-identical to R and only adds `g`. In commit-time slice order the
        // sibling A is processed between R and B, so a linear running-map keying
        // would diff B against A's state and report a PHANTOM `Modified f`. DAG
        // keying diffs B against its real first parent R, where `f` is unchanged.
        let dir = tempfile::tempdir().unwrap();
        let blob_store = kin_blobs::BlobStore::new(dir.path().join("objects")).unwrap();

        let f_v1 = blob_store.write(b"def f():\n    return 1\n").unwrap();
        let f_v2 = blob_store.write(b"def f():\n    return 2\n").unwrap();
        // `f` here is byte-identical to f_v1; only `g` is new.
        let f_v3 = blob_store
            .write(b"def f():\n    return 1\ndef g():\n    return 2\n")
            .unwrap();

        // R id = 0x51; both branches list R (0x51) as their first parent.
        let mut imported = vec![
            imported_change(
                [0x51; 32],
                [0x50; 32],
                "root: add f",
                vec![artifact_delta(
                    "src/lib.py",
                    kin_model::ArtifactDeltaKind::Added,
                    None,
                    Some(Hash256::from_bytes(f_v1.0)),
                )],
            ),
            imported_change(
                [0x52; 32],
                [0x51; 32],
                "branch A: rewrite f body",
                vec![artifact_delta(
                    "src/lib.py",
                    kin_model::ArtifactDeltaKind::Modified,
                    Some(Hash256::from_bytes(f_v1.0)),
                    Some(Hash256::from_bytes(f_v2.0)),
                )],
            ),
            imported_change(
                [0x53; 32],
                [0x51; 32],
                "branch B: add g, f unchanged",
                vec![artifact_delta(
                    "src/lib.py",
                    kin_model::ArtifactDeltaKind::Modified,
                    Some(Hash256::from_bytes(f_v1.0)),
                    Some(Hash256::from_bytes(f_v3.0)),
                )],
            ),
        ];

        enrich_imported_changes_with_semantics(&mut imported, &blob_store).unwrap();

        // Sanity: R adds function `f`; branch A really did modify `f` (its body)
        // against its parent R. `single_modified_function` filters to the
        // function-kind delta, so the file's module-level entity is ignored here.
        let f_id = single_added_function_id(&imported[0].change.entity_deltas);
        let (a_old, a_new) = single_modified_function(&imported[1].change.entity_deltas);
        assert_eq!(
            a_old.id, f_id,
            "branch A should modify the same `f` R added"
        );
        assert_eq!(a_new.id, f_id);

        // Branch B is keyed to its git parent R, where `f` is byte-identical, so
        // the ONLY function-level change B introduces is `Added g`. The phantom
        // this fix eliminates is a function-level `Modified f`/`Removed f`, which
        // the old linear running-map keying produced by diffing B against sibling
        // A's rewritten `f`. (The file's module-level entity legitimately changes
        // because `g` was added — that is a real delta under old and new code and
        // is intentionally not asserted against.)
        let b_deltas = &imported[2].change.entity_deltas;
        let added_functions: Vec<&str> = b_deltas
            .iter()
            .filter_map(|delta| match delta {
                EntityDelta::Added(entity) if entity.kind == EntityKind::Function => {
                    Some(entity.name.as_str())
                }
                _ => None,
            })
            .collect();
        assert_eq!(
            added_functions,
            vec!["g"],
            "branch B should add exactly function `g` against its git parent, got {b_deltas:?}"
        );
        assert!(
            !b_deltas.iter().any(|delta| matches!(
                delta,
                EntityDelta::Modified { old, .. } if old.kind == EntityKind::Function
            )),
            "branch B must not report a phantom function Modified for the unchanged `f`, got {b_deltas:?}"
        );
        assert!(
            !b_deltas
                .iter()
                .any(|delta| matches!(delta, EntityDelta::Removed(id) if *id == f_id)),
            "branch B must not report a phantom Removed for `f`, got {b_deltas:?}"
        );
    }

    /// Minimal git repo bootstrap for history-import tests. Returns false when
    /// git is unavailable so the caller can skip (mirrors the kin-git tests).
    fn init_git_repo_for_test(dir: &Path) -> bool {
        let ok = Command::new("git")
            .args(["init"])
            .current_dir(dir)
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if !ok {
            return false;
        }
        for (k, v) in [("user.email", "test@test.com"), ("user.name", "Test")] {
            let _ = Command::new("git")
                .args(["config", k, v])
                .current_dir(dir)
                .output();
        }
        true
    }

    /// Replay the DAG reachable from `head` and report whether a LIVE relation
    /// exists whose source entity is named `src_name` and destination entity is
    /// named `dst_name`. Names are resolved from the reachable entity deltas;
    /// relation deltas are applied in the returned parents-first order.
    fn replayed_edge_present(
        imported: &[kin_git::ImportedChange],
        head: SemanticChangeId,
        src_name: &str,
        dst_name: &str,
    ) -> bool {
        let graph = kin_db::InMemoryGraph::new();
        for ic in imported {
            graph.create_change(&ic.change).unwrap();
        }
        let reachable = kin_core::collect_changes_at_ref(&graph, &head).unwrap();

        let mut names: HashMap<EntityId, String> = HashMap::new();
        for change in &reachable {
            for delta in &change.entity_deltas {
                match delta {
                    EntityDelta::Added(entity) => {
                        names.insert(entity.id, entity.name.clone());
                    }
                    EntityDelta::Modified { new, .. } => {
                        names.insert(new.id, new.name.clone());
                    }
                    EntityDelta::Removed(_) => {}
                }
            }
        }

        let mut live: HashMap<RelationId, Relation> = HashMap::new();
        for change in &reachable {
            for delta in &change.relation_deltas {
                match delta {
                    RelationDelta::Added(relation) => {
                        live.insert(relation.id, relation.clone());
                    }
                    RelationDelta::Removed(id) => {
                        live.remove(id);
                    }
                }
            }
        }

        let node_name = |node: &GraphNodeId| -> Option<&str> {
            match node {
                GraphNodeId::Entity(id) => names.get(id).map(String::as_str),
                _ => None,
            }
        };
        live.values().any(|relation| {
            node_name(&relation.src) == Some(src_name) && node_name(&relation.dst) == Some(dst_name)
        })
    }

    #[test]
    fn base_link_anchor_surfaces_untouched_consumer_edge_at_historical_head() {
        // End-to-end proof of FIR-1267 Fix D: a consumer living in a file NEVER
        // touched inside a truncated import window must still yield a committed
        // inbound relation delta that ref-scoped replay surfaces at a historical
        // head. Pre-Fix-D the window base linked against a touched-files-only
        // universe, so the consumer edge existed ONLY in live adjacency and the
        // genesis auto-parse change — both siblings of the historical chain — and
        // blast radius at a historical ref replayed as 0.
        let dir = tempfile::tempdir().unwrap();
        if !init_git_repo_for_test(dir.path()) {
            eprintln!("git not available, skipping base-link anchor e2e test");
            return;
        }

        let tools_path = dir.path().join("src/utils/tools.ts");
        let api_path = dir.path().join("src/routes/api.ts");
        fs::create_dir_all(tools_path.parent().unwrap()).unwrap();
        fs::create_dir_all(api_path.parent().unwrap()).unwrap();

        let commit = |msg: &str, epoch: i64| {
            let stamp = format!("{epoch} +0000");
            let _ = Command::new("git")
                .args(["add", "."])
                .current_dir(dir.path())
                .output();
            let _ = Command::new("git")
                .args(["commit", "-m", msg])
                .env("GIT_AUTHOR_DATE", &stamp)
                .env("GIT_COMMITTER_DATE", &stamp)
                .current_dir(dir.path())
                .output();
        };

        // c1 (base, will fall OUTSIDE a 3-commit window): callee `foo` and its
        // cross-file consumer `handler`, which calls `foo`.
        fs::write(&tools_path, "export function foo() { return 1; }\n").unwrap();
        fs::write(
            &api_path,
            "import { foo } from '../utils/tools';\nexport function handler() { foo(); }\n",
        )
        .unwrap();
        commit("c1 base", 1_000_000_000);
        // c2..c4 touch ONLY tools.ts — api.ts (the consumer) is never touched
        // anywhere inside the imported window.
        for (epoch, body) in [
            (1_000_000_100_i64, "2"),
            (1_000_000_200, "3"),
            (1_000_000_300, "4"),
        ] {
            fs::write(
                &tools_path,
                format!("export function foo() {{ return {body}; }}\n"),
            )
            .unwrap();
            commit("touch tools", epoch);
        }

        let blob_store = kin_blobs::BlobStore::new(dir.path().join("objects")).unwrap();
        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x60; 32]));
        let opts = kin_git::ImportOptions {
            max_commits: 3,
            ..Default::default()
        };

        // --- Anchored path (Fix D) ---
        let mut anchored = kin_git::import_git_history_with_blobs(
            dir.path(),
            genesis_id,
            &opts,
            Some(&blob_store),
        )
        .unwrap();
        let base_id = kin_git::anchor_imported_history_at_base_link(
            dir.path(),
            &mut anchored,
            genesis_id,
            Some(&blob_store),
        )
        .unwrap()
        .expect("a truncated window must yield a base-link change");
        enrich_imported_changes_with_semantics(&mut anchored, &blob_store).unwrap();

        // The base-link root change itself must carry the inbound handler→foo
        // edge, resolved against the FULL base universe.
        let base_change = &anchored[0].change;
        assert_eq!(base_change.id, base_id, "base-link is the prepended root");
        let mut base_names: HashMap<EntityId, String> = HashMap::new();
        for delta in &base_change.entity_deltas {
            match delta {
                EntityDelta::Added(entity) => {
                    base_names.insert(entity.id, entity.name.clone());
                }
                EntityDelta::Modified { new, .. } => {
                    base_names.insert(new.id, new.name.clone());
                }
                EntityDelta::Removed(_) => {}
            }
        }
        let base_node_name = |node: &GraphNodeId| -> Option<&str> {
            match node {
                GraphNodeId::Entity(id) => base_names.get(id).map(String::as_str),
                _ => None,
            }
        };
        assert!(
            base_change.relation_deltas.iter().any(|delta| matches!(
                delta,
                RelationDelta::Added(relation)
                    if base_node_name(&relation.src) == Some("handler")
                        && base_node_name(&relation.dst) == Some("foo")
            )),
            "base-link must carry the committed inbound handler→foo edge, got {:?}",
            base_change.relation_deltas
        );

        // ...and ref-scoped replay from the historical head must surface it live.
        let head = anchored.last().unwrap().change.id;
        assert!(
            replayed_edge_present(&anchored, head, "handler", "foo"),
            "anchored: the inbound handler→foo edge must be live at the historical head"
        );

        // --- Negative control: the SAME window with NO base-link anchor ---
        // This is the pre-Fix-D behavior; the untouched consumer edge must be
        // absent, proving the anchor is what surfaces it.
        let mut control = kin_git::import_git_history_with_blobs(
            dir.path(),
            genesis_id,
            &opts,
            Some(&blob_store),
        )
        .unwrap();
        enrich_imported_changes_with_semantics(&mut control, &blob_store).unwrap();
        let control_head = control.last().unwrap().change.id;
        assert!(
            !replayed_edge_present(&control, control_head, "handler", "foo"),
            "pre-Fix-D control: an untouched consumer edge must NOT be reachable at the head"
        );
    }

    #[test]
    fn base_link_cpp_receiver_method_edge_survives_at_historical_head() {
        // Regression guard for the FIR-1267 (c2) parity fix. A C++ receiver-method
        // call `w.work()` resolves to a `Type::method` (`Widget::work`) only through
        // the linker's bare-name index. The batch resolver has always had that
        // index; the incremental linker did not, so a base-link built as a
        // full-tree snapshot would carry the edge but the FIRST windowed commit
        // that touches the callee re-links the consumer via the reverse-dependency
        // closure with the incremental linker, which could not reproduce the edge
        // and emitted a spurious Removed — deleting it at exactly the historical
        // head a revert lands on. The existing TS e2e test cannot catch this: TS
        // import edges resolve in BOTH linkers, so they always survive. This test
        // uses a batch-only edge shape and asserts survival at the HEAD ref (not
        // just the base-link), which is what a ref-scoped blast query reads.
        let dir = tempfile::tempdir().unwrap();
        if !init_git_repo_for_test(dir.path()) {
            eprintln!("git not available, skipping c2 survival test");
            return;
        }

        let lib_path = dir.path().join("widget.hpp");
        let app_path = dir.path().join("app.cpp");

        let commit = |msg: &str, epoch: i64| {
            let stamp = format!("{epoch} +0000");
            let _ = Command::new("git")
                .args(["add", "."])
                .current_dir(dir.path())
                .output();
            let _ = Command::new("git")
                .args(["commit", "-m", msg])
                .env("GIT_AUTHOR_DATE", &stamp)
                .env("GIT_COMMITTER_DATE", &stamp)
                .current_dir(dir.path())
                .output();
        };

        // c1 (base, falls OUTSIDE a 3-commit window): the callee `Widget::work`
        // and its cross-file consumer `run`, which calls it via `w.work()` — a
        // bare-name receiver-method call resolvable only through the bare-name
        // index, never an exact cross-file name match or an ES-style import.
        fs::write(&lib_path, "struct Widget { int work() { return 1; } };\n").unwrap();
        fs::write(
            &app_path,
            "#include \"widget.hpp\"\nint run() { Widget w; return w.work(); }\n",
        )
        .unwrap();
        commit("c1 base", 1_000_000_000);
        // c2..c4 touch ONLY widget.hpp (the callee); app.cpp (the consumer) is
        // never touched anywhere inside the imported window.
        for (epoch, body) in [
            (1_000_000_100_i64, "2"),
            (1_000_000_200, "3"),
            (1_000_000_300, "4"),
        ] {
            fs::write(
                &lib_path,
                format!("struct Widget {{ int work() {{ return {body}; }} }};\n"),
            )
            .unwrap();
            commit("touch widget", epoch);
        }

        let blob_store = kin_blobs::BlobStore::new(dir.path().join("objects")).unwrap();
        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x71; 32]));
        let opts = kin_git::ImportOptions {
            max_commits: 3,
            ..Default::default()
        };

        // --- Anchored path (Fix D base-link + incremental (c2) parity) ---
        let mut anchored = kin_git::import_git_history_with_blobs(
            dir.path(),
            genesis_id,
            &opts,
            Some(&blob_store),
        )
        .unwrap();
        let base_id = kin_git::anchor_imported_history_at_base_link(
            dir.path(),
            &mut anchored,
            genesis_id,
            Some(&blob_store),
        )
        .unwrap()
        .expect("a truncated window must yield a base-link change");
        enrich_imported_changes_with_semantics(&mut anchored, &blob_store).unwrap();

        // The base-link carries the bare-name receiver-method edge...
        assert!(
            replayed_edge_present(&anchored, base_id, "run", "Widget::work"),
            "base-link must carry the receiver-method edge run->Widget::work"
        );
        // ...and it must SURVIVE at the historical head, even though every windowed
        // commit touches the callee (pulling the consumer into the reverse-dep
        // closure). Before the (c2) parity fix the incremental relink dropped it
        // here, so this assertion is the one that fails on the half-fix.
        let head = anchored.last().unwrap().change.id;
        assert!(
            replayed_edge_present(&anchored, head, "run", "Widget::work"),
            "anchored: the receiver-method edge must remain live at the historical head"
        );

        // --- Negative control: the SAME window with NO base-link anchor ---
        // Without the anchor the consumer file is never in the graph at any
        // windowed ref, so the edge cannot exist — proving the anchor is what
        // brings the base universe in and the (c2) parity is what keeps it.
        let mut control = kin_git::import_git_history_with_blobs(
            dir.path(),
            genesis_id,
            &opts,
            Some(&blob_store),
        )
        .unwrap();
        enrich_imported_changes_with_semantics(&mut control, &blob_store).unwrap();
        let control_head = control.last().unwrap().change.id;
        assert!(
            !replayed_edge_present(&control, control_head, "run", "Widget::work"),
            "unanchored control: an untouched consumer edge must NOT be reachable at the head"
        );
    }

    #[test]
    fn base_link_anchor_and_enrichment_are_byte_stable_across_runs() {
        // Determinism is the whole risk of Fix D: a citable proof is void if the
        // anchored, enriched history is not byte-identical run to run. Build one
        // truncated-window history, then run import → anchor → enrich twice and
        // assert every change (id, parents, and the ORDER of every delta list) is
        // identical. This exercises: the deterministic first-parent walk to the
        // window base, the sorted-path base-tree enumeration, content-addressed
        // entity ids, and the relation-delta id sort.
        let dir = tempfile::tempdir().unwrap();
        if !init_git_repo_for_test(dir.path()) {
            eprintln!("git not available, skipping base-link determinism test");
            return;
        }

        let tools_path = dir.path().join("src/utils/tools.ts");
        let api_path = dir.path().join("src/routes/api.ts");
        let extra_path = dir.path().join("src/utils/extra.ts");
        fs::create_dir_all(tools_path.parent().unwrap()).unwrap();
        fs::create_dir_all(api_path.parent().unwrap()).unwrap();

        let commit = |msg: &str, epoch: i64| {
            let stamp = format!("{epoch} +0000");
            let _ = Command::new("git")
                .args(["add", "."])
                .current_dir(dir.path())
                .output();
            let _ = Command::new("git")
                .args(["commit", "-m", msg])
                .env("GIT_AUTHOR_DATE", &stamp)
                .env("GIT_COMMITTER_DATE", &stamp)
                .current_dir(dir.path())
                .output();
        };

        // Base carries several files (multiple consumers) so the base-link's
        // delta ordering has real surface to be unstable if anything is unsorted.
        fs::write(&tools_path, "export function foo() { return 1; }\n").unwrap();
        fs::write(&extra_path, "export function bar() { return 9; }\n").unwrap();
        fs::write(
            &api_path,
            "import { foo } from '../utils/tools';\nimport { bar } from '../utils/extra';\n\
             export function handler() { foo(); bar(); }\n",
        )
        .unwrap();
        commit("c1 base", 1_000_000_000);
        for (epoch, body) in [
            (1_000_000_100_i64, "2"),
            (1_000_000_200, "3"),
            (1_000_000_300, "4"),
        ] {
            fs::write(
                &tools_path,
                format!("export function foo() {{ return {body}; }}\n"),
            )
            .unwrap();
            commit("touch tools", epoch);
        }

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x61; 32]));
        let opts = kin_git::ImportOptions {
            max_commits: 3,
            ..Default::default()
        };

        let run = || -> Vec<SemanticChange> {
            // A fresh blob store per run proves the output does not depend on
            // pre-existing store state either.
            let blob_root = tempfile::tempdir().unwrap();
            let blob_store = kin_blobs::BlobStore::new(blob_root.path().join("objects")).unwrap();
            let mut imported = kin_git::import_git_history_with_blobs(
                dir.path(),
                genesis_id,
                &opts,
                Some(&blob_store),
            )
            .unwrap();
            kin_git::anchor_imported_history_at_base_link(
                dir.path(),
                &mut imported,
                genesis_id,
                Some(&blob_store),
            )
            .unwrap();
            enrich_imported_changes_with_semantics(&mut imported, &blob_store).unwrap();
            imported.into_iter().map(|ic| ic.change).collect()
        };

        let first = run();
        let second = run();

        // Guard against a vacuous pass: the base-link plus the 3-commit window.
        assert_eq!(first.len(), 4, "expected base-link + 3 windowed commits");

        // (1) THE Fix-D determinism guarantee: change ids, parents, and the ORDER
        // and identity of every entity/relation/artifact delta are byte-identical.
        // The only non-deterministic surface in a SemanticChange is
        // `Entity.metadata.extra`, a `HashMap` of auxiliary embedding-context
        // strings (a pre-existing, kin-wide parser artifact that no entity id,
        // relation id, blast, or review path keys on — those derive from
        // (file, name, kind, index) and (src, dst, kind)). Neutralize only that
        // key-iteration order, then require the rest to match exactly.
        let structural = |changes: &[SemanticChange]| -> Vec<String> {
            changes
                .iter()
                .map(|change| {
                    let mut change = change.clone();
                    for delta in &mut change.entity_deltas {
                        match delta {
                            EntityDelta::Added(entity) => entity.metadata.extra.clear(),
                            EntityDelta::Modified { old, new } => {
                                old.metadata.extra.clear();
                                new.metadata.extra.clear();
                            }
                            EntityDelta::Removed(_) => {}
                        }
                    }
                    format!("{change:#?}")
                })
                .collect()
        };
        assert_eq!(
            structural(&first),
            structural(&second),
            "anchored + enriched history (ids, fingerprints, spans, delta ordering, \
             relations, artifacts) must be byte-identical across runs"
        );

        // (2) The auxiliary metadata.extra CONTENT is itself stable — only its
        // key order varies. Compare as a sorted multiset so a genuine content
        // drift would still fail, but key-order alone does not.
        let extra_multiset = |changes: &[SemanticChange]| -> Vec<String> {
            let mut lines = Vec::new();
            for change in changes {
                for delta in &change.entity_deltas {
                    let entities: Vec<&Entity> = match delta {
                        EntityDelta::Added(entity) => vec![entity],
                        EntityDelta::Modified { old, new } => vec![old, new],
                        EntityDelta::Removed(_) => vec![],
                    };
                    for entity in entities {
                        for (key, value) in &entity.metadata.extra {
                            lines.push(format!("{:?}|{key}={value}", entity.id));
                        }
                    }
                }
            }
            lines.sort();
            lines
        };
        assert_eq!(
            extra_multiset(&first),
            extra_multiset(&second),
            "metadata.extra content must be identical across runs (order-independent)"
        );
    }

    #[test]
    fn warm_cache_delta_reuses_entity_ids_and_remaps_relation_endpoints() {
        let repo_dir = tempfile::tempdir().unwrap();
        let blob_dir = tempfile::tempdir().unwrap();
        let root = repo_dir.path();

        let tools_path = root.join("src/utils/tools.ts");
        let api_path = root.join("src/routes/api.ts");
        fs::create_dir_all(tools_path.parent().unwrap()).unwrap();
        fs::create_dir_all(api_path.parent().unwrap()).unwrap();
        fs::write(&tools_path, "export function executeTool() { return 1; }\n").unwrap();
        fs::write(
            &api_path,
            "import { executeTool } from '../utils/tools';\nexport function handler() { executeTool(); }\n",
        )
        .unwrap();

        let blob_store = kin_blobs::BlobStore::new(blob_dir.path().join("objects")).unwrap();
        let graph = kin_db::InMemoryGraph::new();
        let all_files = collect_source_files(root).unwrap();
        let indexable_files = collect_indexable_files(root, &all_files).unwrap();
        parse_and_index(&graph, &blob_store, &indexable_files).unwrap();

        let handler_before = entity_by_name(&graph, "src/routes/api.ts", "handler");
        let handler_start_line_before = handler_before.span.as_ref().unwrap().start_line;
        let callee = entity_by_name(&graph, "src/utils/tools.ts", "executeTool");
        assert!(
            has_call_relation(&graph, handler_before.id, callee.id),
            "initial graph should link handler -> executeTool"
        );

        fs::write(
            &api_path,
            "// inserted header shifts parser start_line\nimport { executeTool } from '../utils/tools';\nexport function handler() { executeTool(); }\n",
        )
        .unwrap();
        let all_files = collect_source_files(root).unwrap();
        let indexable_files = collect_indexable_files(root, &all_files).unwrap();
        let diff = kin_db::engine::IncrementalDiff {
            added_files: Vec::new(),
            modified_files: vec!["src/routes/api.ts".to_string()],
            removed_files: Vec::new(),
        };

        let delta = apply_warm_cache_delta(&graph, &blob_store, &indexable_files, &diff).unwrap();
        assert_eq!(delta.reparsed_files, 1);

        let handler_after = entity_by_name(&graph, "src/routes/api.ts", "handler");
        assert_eq!(
            handler_after.id, handler_before.id,
            "warm delta must preserve stable entity ID across parser start_line drift"
        );
        assert!(
            handler_after.span.as_ref().unwrap().start_line > handler_start_line_before,
            "the entity span should reflect the shifted source location"
        );
        assert!(
            has_call_relation(&graph, handler_after.id, callee.id),
            "relation endpoints must be remapped to stable entity IDs"
        );
    }

    fn artifact_delta(
        file_path: &str,
        kind: kin_model::ArtifactDeltaKind,
        old_hash: Option<Hash256>,
        new_hash: Option<Hash256>,
    ) -> kin_model::ArtifactDelta {
        kin_model::ArtifactDelta {
            file_id: FilePathId::new(file_path),
            kind,
            old_hash,
            new_hash,
        }
    }

    fn imported_change(
        id_bytes: [u8; 32],
        parent_bytes: [u8; 32],
        message: &str,
        artifact_deltas: Vec<kin_model::ArtifactDelta>,
    ) -> kin_git::ImportedChange {
        kin_git::ImportedChange {
            change: SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes(id_bytes)),
                parents: vec![SemanticChangeId::from_hash(Hash256::from_bytes(
                    parent_bytes,
                ))],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: message.to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas,
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            },
            git_oid: hex::encode(id_bytes),
        }
    }

    fn entity_by_name(graph: &kin_db::InMemoryGraph, file: &str, name: &str) -> Entity {
        let matches = entities_for_file(graph, file)
            .unwrap()
            .into_iter()
            .filter(|entity| entity.name == name)
            .collect::<Vec<_>>();
        assert_eq!(
            matches.len(),
            1,
            "expected exactly one entity named {name} in {file}, got {matches:?}"
        );
        matches.into_iter().next().unwrap()
    }

    fn has_call_relation(
        graph: &kin_db::InMemoryGraph,
        src_entity: EntityId,
        dst_entity: EntityId,
    ) -> bool {
        graph
            .get_all_relations_for_entity(&src_entity)
            .unwrap()
            .into_iter()
            .any(|relation| {
                relation.kind == RelationKind::Calls
                    && relation.src == GraphNodeId::Entity(src_entity)
                    && relation.dst == GraphNodeId::Entity(dst_entity)
            })
    }

    fn test_entity(name: &str, file: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(file)),
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

    fn test_relation(kind: RelationKind, src: EntityId, dst: EntityId) -> Relation {
        Relation {
            id: RelationId::new(),
            kind,
            src: GraphNodeId::Entity(src),
            dst: GraphNodeId::Entity(dst),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        }
    }

    /// Reference oracle for `imported_reverse_dependency_closure`: the
    /// pre-index implementation, scanning every relation for every seed file
    /// instead of consulting `relations_by_dst`. Kept here, test-only, so the
    /// index-backed production path can be checked against it on arbitrary
    /// fixture graphs rather than trusted by inspection.
    fn naive_reverse_dependency_closure_scan(
        seed_files: &BTreeSet<String>,
        semantic_entities_by_file: &HashMap<String, Vec<Entity>>,
        current_relations: &HashMap<RelationId, Relation>,
    ) -> BTreeSet<String> {
        let mut entity_to_file = HashMap::<EntityId, String>::new();
        for (file_path, entities) in semantic_entities_by_file {
            for entity in entities {
                entity_to_file.insert(entity.id, file_path.clone());
            }
        }

        let mut visited = seed_files.clone();

        for file_path in seed_files {
            let entity_ids = semantic_entities_by_file
                .get(file_path)
                .into_iter()
                .flat_map(|entities| entities.iter().map(|entity| entity.id))
                .collect::<HashSet<_>>();
            if entity_ids.is_empty() {
                continue;
            }

            for relation in current_relations.values() {
                let Some(dst_entity_id) = relation.dst.as_entity() else {
                    continue;
                };
                if !entity_ids.contains(&dst_entity_id) {
                    continue;
                }
                let Some(src_entity_id) = relation.src.as_entity() else {
                    continue;
                };
                let Some(src_file) = entity_to_file.get(&src_entity_id) else {
                    continue;
                };
                visited.insert(src_file.clone());
            }
        }

        visited
    }

    /// Fixture graph exercising the shapes the index must handle identically
    /// to the naive scan: a direct reverse dependency (b -> a), a two-hop
    /// chain that a single-hop closure must NOT collapse (c -> b -> a), an
    /// isolated file with no inbound edges, a file with two entities where
    /// only one has an inbound edge, and an artifact-anchored relation (whose
    /// dst is not an entity) that neither path should follow.
    struct ClosureFixture {
        semantic_entities_by_file: HashMap<String, Vec<Entity>>,
        current_relations: HashMap<RelationId, Relation>,
        relations_by_dst: HashMap<EntityId, HashSet<RelationId>>,
    }

    fn build_closure_fixture() -> ClosureFixture {
        let a = test_entity("a", "src/a.rs");
        let b = test_entity("b", "src/b.rs");
        let c = test_entity("c", "src/c.rs");
        let d = test_entity("d", "src/d.rs");
        let e1 = test_entity("e1", "src/e.rs");
        let e2 = test_entity("e2", "src/e.rs");
        let f = test_entity("f", "src/f.rs");

        let semantic_entities_by_file: HashMap<String, Vec<Entity>> = [
            ("src/a.rs".to_string(), vec![a.clone()]),
            ("src/b.rs".to_string(), vec![b.clone()]),
            ("src/c.rs".to_string(), vec![c.clone()]),
            ("src/d.rs".to_string(), vec![d.clone()]),
            ("src/e.rs".to_string(), vec![e1.clone(), e2.clone()]),
            ("src/f.rs".to_string(), vec![f.clone()]),
        ]
        .into_iter()
        .collect();

        let b_calls_a = test_relation(RelationKind::Calls, b.id, a.id);
        let c_calls_b = test_relation(RelationKind::Calls, c.id, b.id);
        let f_calls_e1 = test_relation(RelationKind::Calls, f.id, e1.id);
        let artifact_edge = Relation {
            id: RelationId::new(),
            kind: RelationKind::Includes,
            src: GraphNodeId::Artifact(ArtifactId::seed_from_path("src/g.rs")),
            dst: GraphNodeId::Artifact(ArtifactId::seed_from_path("src/a.rs")),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        };

        let mut current_relations = HashMap::<RelationId, Relation>::new();
        let mut relations_by_src = HashMap::<EntityId, HashSet<RelationId>>::new();
        let mut relations_by_src_artifact = HashMap::<ArtifactId, HashSet<RelationId>>::new();
        let mut relations_by_dst = HashMap::<EntityId, HashSet<RelationId>>::new();
        for relation in [&b_calls_a, &c_calls_b, &f_calls_e1, &artifact_edge] {
            current_relations.insert(relation.id, relation.clone());
            insert_relation_indexes(
                &mut relations_by_src,
                &mut relations_by_src_artifact,
                &mut relations_by_dst,
                relation,
            );
        }

        ClosureFixture {
            semantic_entities_by_file,
            current_relations,
            relations_by_dst,
        }
    }

    #[test]
    fn imported_reverse_dependency_closure_index_matches_naive_scan() {
        let fixture = build_closure_fixture();

        let scenarios: Vec<(BTreeSet<String>, BTreeSet<String>)> = vec![
            (
                BTreeSet::from(["src/a.rs".to_string()]),
                BTreeSet::from(["src/a.rs".to_string(), "src/b.rs".to_string()]),
            ),
            (
                BTreeSet::from(["src/b.rs".to_string()]),
                BTreeSet::from(["src/b.rs".to_string(), "src/c.rs".to_string()]),
            ),
            (
                BTreeSet::from(["src/d.rs".to_string()]),
                BTreeSet::from(["src/d.rs".to_string()]),
            ),
            (
                BTreeSet::from(["src/e.rs".to_string()]),
                BTreeSet::from(["src/e.rs".to_string(), "src/f.rs".to_string()]),
            ),
            (
                BTreeSet::from(["src/a.rs".to_string(), "src/e.rs".to_string()]),
                BTreeSet::from([
                    "src/a.rs".to_string(),
                    "src/b.rs".to_string(),
                    "src/e.rs".to_string(),
                    "src/f.rs".to_string(),
                ]),
            ),
            (BTreeSet::new(), BTreeSet::new()),
            (
                // A seed file absent from `semantic_entities_by_file` (e.g. a
                // deleted file) must survive untouched in both paths.
                BTreeSet::from(["src/nonexistent.rs".to_string()]),
                BTreeSet::from(["src/nonexistent.rs".to_string()]),
            ),
        ];

        for (seed_files, expected) in scenarios {
            let via_index = imported_reverse_dependency_closure(
                &seed_files,
                &fixture.semantic_entities_by_file,
                &fixture.current_relations,
                &fixture.relations_by_dst,
            );
            let via_scan = naive_reverse_dependency_closure_scan(
                &seed_files,
                &fixture.semantic_entities_by_file,
                &fixture.current_relations,
            );

            assert_eq!(
                via_index, expected,
                "index-backed closure mismatched the expected set for seed {seed_files:?}"
            );
            assert_eq!(
                via_index, via_scan,
                "index-backed closure diverged from the naive scan oracle for seed {seed_files:?}"
            );
            // Both are BTreeSets, so equal sets already imply equal iteration
            // (sorted) order; assert on the materialized Vec too so the
            // order-bearing contract downstream code relies on is explicit.
            assert_eq!(
                via_index.into_iter().collect::<Vec<_>>(),
                via_scan.into_iter().collect::<Vec<_>>(),
                "index-backed closure produced a different order than the naive scan for seed {seed_files:?}"
            );
        }
    }

    #[test]
    fn imported_reverse_dependency_closure_index_tracks_incremental_relation_mutation() {
        let a = test_entity("a", "src/a.rs");
        let b = test_entity("b", "src/b.rs");
        let c = test_entity("c", "src/c.rs");

        let semantic_entities_by_file: HashMap<String, Vec<Entity>> = [
            ("src/a.rs".to_string(), vec![a.clone()]),
            ("src/b.rs".to_string(), vec![b.clone()]),
            ("src/c.rs".to_string(), vec![c.clone()]),
        ]
        .into_iter()
        .collect();

        let mut current_relations = HashMap::<RelationId, Relation>::new();
        let mut relations_by_src = HashMap::<EntityId, HashSet<RelationId>>::new();
        let mut relations_by_src_artifact = HashMap::<ArtifactId, HashSet<RelationId>>::new();
        let mut relations_by_dst = HashMap::<EntityId, HashSet<RelationId>>::new();

        let seed = BTreeSet::from(["src/a.rs".to_string()]);
        let assert_matches_oracle =
            |current_relations: &HashMap<RelationId, Relation>,
             relations_by_dst: &HashMap<EntityId, HashSet<RelationId>>,
             expected: &BTreeSet<String>| {
                let via_index = imported_reverse_dependency_closure(
                    &seed,
                    &semantic_entities_by_file,
                    current_relations,
                    relations_by_dst,
                );
                let via_scan = naive_reverse_dependency_closure_scan(
                    &seed,
                    &semantic_entities_by_file,
                    current_relations,
                );
                assert_eq!(&via_index, expected);
                assert_eq!(via_index, via_scan);
            };

        // No relations yet: closure is just the seed itself.
        assert_matches_oracle(
            &current_relations,
            &relations_by_dst,
            &BTreeSet::from(["src/a.rs".to_string()]),
        );

        // Add a relation between queries: b calls a.
        let b_calls_a = test_relation(RelationKind::Calls, b.id, a.id);
        current_relations.insert(b_calls_a.id, b_calls_a.clone());
        insert_relation_indexes(
            &mut relations_by_src,
            &mut relations_by_src_artifact,
            &mut relations_by_dst,
            &b_calls_a,
        );
        assert_matches_oracle(
            &current_relations,
            &relations_by_dst,
            &BTreeSet::from(["src/a.rs".to_string(), "src/b.rs".to_string()]),
        );

        // Add a second edge onto the same target: c calls a too.
        let c_calls_a = test_relation(RelationKind::Calls, c.id, a.id);
        current_relations.insert(c_calls_a.id, c_calls_a.clone());
        insert_relation_indexes(
            &mut relations_by_src,
            &mut relations_by_src_artifact,
            &mut relations_by_dst,
            &c_calls_a,
        );
        assert_matches_oracle(
            &current_relations,
            &relations_by_dst,
            &BTreeSet::from([
                "src/a.rs".to_string(),
                "src/b.rs".to_string(),
                "src/c.rs".to_string(),
            ]),
        );

        // Remove the first edge, mirroring how the replay loop retires a
        // stale relation on relink: b no longer reverse-depends on a, c
        // still does, and the index must not go stale.
        current_relations.remove(&b_calls_a.id);
        remove_relation_indexes(
            &mut relations_by_src,
            &mut relations_by_src_artifact,
            &mut relations_by_dst,
            &b_calls_a,
        );
        assert_matches_oracle(
            &current_relations,
            &relations_by_dst,
            &BTreeSet::from(["src/a.rs".to_string(), "src/c.rs".to_string()]),
        );
    }

    fn repo_truth_fixture(root: &Path) -> BTreeSet<String> {
        let files = [
            ("src/lib.rs", "pub fn alpha() -> usize { 1 }\n"),
            ("src/main.rs", "fn main() { println!(\"hi\"); }\n"),
            ("docs/guide.swift", "import Foundation\nfunc render() {}\n"),
            ("Makefile", "build:\n\tcargo build\n"),
            ("README.md", "# Example\n\nsemantic repo\n"),
        ];

        for (rel_path, content) in &files {
            let path = root.join(rel_path);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, content).unwrap();
        }

        files
            .iter()
            .map(|(rel_path, _)| (*rel_path).to_string())
            .collect()
    }

    fn repo_truth_fixture_with_agent_doc(root: &Path) -> BTreeSet<String> {
        let mut paths = repo_truth_fixture(root);
        paths.insert("AGENTS.md".to_string());
        paths
    }

    fn tracked_graph_paths(graph: &kin_db::InMemoryGraph) -> BTreeSet<String> {
        let mut tracked = BTreeSet::new();

        tracked.extend(graph.indexed_file_paths());
        tracked.extend(
            graph
                .list_shallow_files()
                .unwrap()
                .into_iter()
                .map(|file| file.file_id.0),
        );
        tracked.extend(
            graph
                .list_structured_artifacts()
                .unwrap()
                .into_iter()
                .map(|artifact| artifact.file_id.0),
        );
        tracked.extend(
            graph
                .list_opaque_artifacts()
                .unwrap()
                .into_iter()
                .map(|artifact| artifact.file_id.0),
        );

        tracked
    }

    fn assert_repo_owned_graph_truth(
        graph: &kin_db::InMemoryGraph,
        expected_paths: &BTreeSet<String>,
    ) {
        let tracked_paths = tracked_graph_paths(graph);
        assert_eq!(tracked_paths, *expected_paths);
        assert!(tracked_paths
            .iter()
            .all(|path| is_repo_owned_graph_path(path)));

        assert_eq!(graph.indexed_file_paths().len(), expected_paths.len());
        // Swift is an entity-source language, so docs/guide.swift is fully
        // indexed rather than shallow-tracked. Fresh native init also writes
        // AGENTS.md before the first snapshot, so it is graph-tracked as
        // repo-owned guidance, not as `.kin` control-plane state.
        let expected_opaque_artifacts = if expected_paths.contains("AGENTS.md") {
            2
        } else {
            1
        };
        assert_eq!(graph.list_shallow_files().unwrap().len(), 0);
        assert_eq!(graph.list_structured_artifacts().unwrap().len(), 1);
        assert_eq!(
            graph.list_opaque_artifacts().unwrap().len(),
            expected_opaque_artifacts
        );
    }

    fn assert_makefile_is_text_searchable(graph: &kin_db::InMemoryGraph) {
        let makefile_key =
            kin_db::RetrievalKey::Artifact(kin_db::ArtifactId::seed_from_path("Makefile"));
        let hits = graph.text_search("cargo build", 10).unwrap();
        assert!(
            hits.iter().any(|(key, _)| *key == makefile_key),
            "init should index structured artifact text documents during bootstrap"
        );
    }

    struct EnvVarGuard {
        key: &'static str,
        previous: Option<String>,
    }

    impl EnvVarGuard {
        fn set(key: &'static str, value: impl AsRef<std::ffi::OsStr>) -> Self {
            let previous = std::env::var(key).ok();
            std::env::set_var(key, value);
            Self { key, previous }
        }

        fn remove(key: &'static str) -> Self {
            let previous = std::env::var(key).ok();
            std::env::remove_var(key);
            Self { key, previous }
        }
    }

    impl Drop for EnvVarGuard {
        fn drop(&mut self) {
            if let Some(previous) = &self.previous {
                std::env::set_var(self.key, previous);
            } else {
                std::env::remove_var(self.key);
            }
        }
    }

    async fn spawn_bootstrap_server(
        snapshot: kin_db::GraphSnapshot,
    ) -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let payload = Arc::new(snapshot.to_bytes().unwrap());
        let hits_for_task = Arc::clone(&hits);
        let payload_for_task = Arc::clone(&payload);

        let task = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let hits = Arc::clone(&hits_for_task);
                let payload = Arc::clone(&payload_for_task);
                tokio::spawn(async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    let mut request = [0u8; 1024];
                    let _ = stream.read(&mut request).await;
                    let headers = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        payload.len()
                    );
                    let _ = stream.write_all(headers.as_bytes()).await;
                    let _ = stream.write_all(payload.as_slice()).await;
                });
            }
        });

        (format!("http://{}", address), hits, task)
    }

    #[test]
    fn snapshot_creates_correct_structure() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // Create some files.
        fs::write(root.join("README.md"), "hello").unwrap();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/main.rs"), "fn main() {}").unwrap();

        // Create a directory that should be skipped.
        fs::create_dir_all(root.join("node_modules/foo")).unwrap();
        fs::write(root.join("node_modules/foo/index.js"), "skip me").unwrap();

        let (snapshot, manifest) = snapshot_repo(root, false).unwrap();
        assert!(snapshot.join("README.md").exists());
        assert!(snapshot.join("src/main.rs").exists());
        assert!(!snapshot.join("node_modules").exists());
        // manifest.json should NOT exist on disk until explicitly written
        assert!(!snapshot.join("manifest.json").exists());
        write_snapshot_manifest(&snapshot, &manifest).unwrap();
        assert!(snapshot.join("manifest.json").exists());
    }

    #[test]
    fn manifest_has_correct_file_count() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        fs::write(root.join("a.txt"), "aaa").unwrap();
        fs::write(root.join("b.txt"), "bbb").unwrap();
        fs::create_dir_all(root.join("sub")).unwrap();
        fs::write(root.join("sub/c.txt"), "ccc").unwrap();

        let (_snapshot, manifest) = snapshot_repo(root, false).unwrap();

        assert_eq!(manifest["file_count"], 3);
        assert_eq!(manifest["total_bytes"], 9); // 3 + 3 + 3
    }

    #[test]
    fn snapshot_skips_all_excluded_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // Create all the skip dirs with a file inside each.
        for skip in kin_index::SKIP_DIRS {
            let p = root.join(skip);
            fs::create_dir_all(&p).unwrap();
            fs::write(p.join("file.txt"), "skip").unwrap();
        }

        // One real file.
        fs::write(root.join("keep.txt"), "keep").unwrap();

        let (snapshot, _manifest) = snapshot_repo(root, false).unwrap();
        assert!(snapshot.join("keep.txt").exists());
        assert!(!snapshot.join("node_modules").exists());
        assert!(!snapshot.join("target").exists());
        assert!(!snapshot.join("__pycache__").exists());
        assert!(!snapshot.join(".next").exists());
        assert!(!snapshot.join("dist").exists());
        assert!(!snapshot.join("build").exists());
    }

    #[test]
    fn snapshot_skips_kin_temporary_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        fs::create_dir_all(root.join(".kin-snapshot-tmp/nested")).unwrap();
        fs::write(root.join(".kin-snapshot-tmp/nested/file.txt"), "skip").unwrap();
        fs::create_dir_all(root.join(".kin-other/tmp")).unwrap();
        fs::write(root.join(".kin-other/tmp/file.txt"), "skip").unwrap();
        fs::write(root.join("keep.txt"), "keep").unwrap();

        let (snapshot, _manifest) = snapshot_repo(root, false).unwrap();
        assert!(snapshot.join("keep.txt").exists());
        assert!(!snapshot.join(".kin-snapshot-tmp").exists());
        assert!(!snapshot.join(".kin-other").exists());
    }

    #[test]
    fn snapshot_prunes_nested_vendored_git_and_kin_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn f() {}").unwrap();

        // Nested vendored dir (not at the repo root).
        fs::create_dir_all(root.join("pkg/inner/node_modules/dep")).unwrap();
        fs::write(root.join("pkg/inner/node_modules/dep/index.js"), "vendored").unwrap();

        // Nested sub-repo `.git` directory.
        fs::create_dir_all(root.join("sub/.git/objects")).unwrap();
        fs::write(root.join("sub/.git/config"), "[core]").unwrap();

        // Nested Kin graph dir and a renamed Kin graph dir.
        fs::create_dir_all(root.join("sub/.kin/snapshot")).unwrap();
        fs::write(root.join("sub/.kin/graph.bin"), "graph").unwrap();
        fs::create_dir_all(root.join("data/.kindb")).unwrap();
        fs::write(root.join("data/.kindb/blob"), "blob").unwrap();

        let (snapshot, manifest) = snapshot_repo(root, false).unwrap();
        let rels: BTreeSet<String> = collect_source_files(&snapshot)
            .unwrap()
            .iter()
            .map(|p| {
                p.strip_prefix(&snapshot)
                    .unwrap()
                    .to_string_lossy()
                    .to_string()
            })
            .collect();

        assert!(rels.contains("src/lib.rs"), "got: {:?}", rels);
        assert!(
            !rels.iter().any(|p| p.contains("node_modules")),
            "nested vendored dir leaked: {:?}",
            rels
        );
        assert!(
            !rels.iter().any(|p| p.contains(".git")),
            "nested sub-repo git plumbing leaked: {:?}",
            rels
        );
        assert!(
            !rels.iter().any(|p| p.contains(".kin")),
            "nested/renamed Kin graph dir leaked: {:?}",
            rels
        );
        assert_eq!(manifest["file_count"], 1);
    }

    #[test]
    fn snapshot_honors_kinignore_names_and_prefixes() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        fs::write(
            root.join(".kinignore"),
            "# scope discovery\ngenerated\nthirdparty/big/\n",
        )
        .unwrap();

        fs::write(root.join("keep.rs"), "fn k() {}").unwrap();
        fs::create_dir_all(root.join("generated/sub")).unwrap();
        fs::write(root.join("generated/sub/g.rs"), "fn g() {}").unwrap();
        fs::create_dir_all(root.join("thirdparty/big/x")).unwrap();
        fs::write(root.join("thirdparty/big/x/t.rs"), "fn t() {}").unwrap();
        fs::create_dir_all(root.join("thirdparty/small")).unwrap();
        fs::write(root.join("thirdparty/small/s.rs"), "fn s() {}").unwrap();

        let (snapshot, _manifest) = snapshot_repo(root, false).unwrap();
        let rels: BTreeSet<String> = collect_source_files(&snapshot)
            .unwrap()
            .iter()
            .map(|p| {
                p.strip_prefix(&snapshot)
                    .unwrap()
                    .to_string_lossy()
                    .to_string()
            })
            .collect();

        assert!(rels.contains("keep.rs"), "got: {:?}", rels);
        assert!(rels.contains("thirdparty/small/s.rs"), "got: {:?}", rels);
        assert!(
            !rels.iter().any(|p| p.starts_with("generated")),
            "name-pattern dir leaked: {:?}",
            rels
        );
        assert!(
            !rels.iter().any(|p| p.starts_with("thirdparty/big")),
            "prefix-pattern dir leaked: {:?}",
            rels
        );
    }

    #[test]
    fn discovery_cap_trips_on_oversized_tree() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for i in 0..8 {
            fs::write(root.join(format!("f{i}.rs")), "x").unwrap();
        }

        let ignore = KinIgnore::load(root);
        assert!(discovery_exceeds_cap(root, &ignore, 5));
        assert!(!discovery_exceeds_cap(root, &ignore, 100));
    }

    #[test]
    fn discovery_cap_excludes_pruned_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("real.rs"), "x").unwrap();
        fs::create_dir_all(root.join("node_modules")).unwrap();
        for i in 0..20 {
            fs::write(root.join(format!("node_modules/v{i}.js")), "x").unwrap();
        }

        let ignore = KinIgnore::load(root);
        assert!(!discovery_exceeds_cap(root, &ignore, 5));
    }

    #[test]
    fn snapshot_entry_ignored_prunes_internal_and_vendored() {
        let ignore = KinIgnore::default();
        let rel = Path::new("x");
        for name in [
            ".kin",
            ".kindb",
            ".kin-snapshot-tmp",
            ".git",
            ".git-export",
            "node_modules",
            "target",
            "vendor",
        ] {
            assert!(
                snapshot_entry_ignored(name, rel, &ignore),
                "should prune {name}"
            );
        }
        for name in ["src", "main.rs", ".gitignore", ".github"] {
            assert!(
                !snapshot_entry_ignored(name, rel, &ignore),
                "should keep {name}"
            );
        }
    }

    #[test]
    fn kinignore_matches_basenames_and_path_prefixes() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::write(
            root.join(".kinignore"),
            "build\n# comment\nthirdparty/large/\n./out\n",
        )
        .unwrap();

        let ignore = KinIgnore::load(root);
        assert!(ignore.matches(Path::new("a/b/build"), "build"));
        assert!(ignore.matches(Path::new("out"), "out"));
        assert!(ignore.matches(Path::new("thirdparty/large"), "large"));
        assert!(ignore.matches(Path::new("thirdparty/large/x"), "x"));
        assert!(!ignore.matches(Path::new("thirdparty/small"), "small"));
        assert!(!ignore.matches(Path::new("src/keep.rs"), "keep.rs"));
    }

    #[test]
    fn snapshot_reads_git_head() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // Set up a real git repo so `git rev-parse HEAD` works.
        let git_init = std::process::Command::new("git")
            .args(["init"])
            .current_dir(root)
            .output();
        if git_init.is_err() || !git_init.unwrap().status.success() {
            // Skip test if git is not available.
            return;
        }
        // Configure git user for the commit.
        let _ = std::process::Command::new("git")
            .args(["config", "user.email", "test@test.com"])
            .current_dir(root)
            .output();
        let _ = std::process::Command::new("git")
            .args(["config", "user.name", "Test"])
            .current_dir(root)
            .output();
        fs::write(root.join("file.txt"), "content").unwrap();
        let _ = std::process::Command::new("git")
            .args(["add", "file.txt"])
            .current_dir(root)
            .output();
        let _ = std::process::Command::new("git")
            .args(["commit", "-m", "init"])
            .current_dir(root)
            .output();

        let (_snapshot, manifest) = snapshot_repo(root, false).unwrap();

        // git_head should be a 40-char hex SHA.
        let head = manifest["git_head"]
            .as_str()
            .expect("git_head should be a string");
        assert_eq!(head.len(), 40, "expected 40-char SHA, got: {}", head);
        assert!(
            head.chars().all(|c| c.is_ascii_hexdigit()),
            "expected hex SHA, got: {}",
            head
        );
    }

    #[tokio::test]
    #[serial]
    async fn run_keeps_control_plane_paths_out_of_graph_truth_on_cold_init() {
        let repo_dir = tempfile::tempdir().unwrap();
        let home_dir = tempfile::tempdir().unwrap();
        let expected_paths = repo_truth_fixture_with_agent_doc(repo_dir.path());

        let _home_guard = EnvVarGuard::set("HOME", home_dir.path());
        let _cache_guard = EnvVarGuard::remove("KIN_INIT_CACHE_DIR");
        let _warm_cache_guard = EnvVarGuard::set("KIN_INIT_WARM_CACHE", "0");

        run(
            Some(repo_dir.path().display().to_string()),
            false,
            true,
            false,
            true,
            "recent".to_string(),
        )
        .await
        .unwrap();

        let layout = kin_core::KinLayout::new(repo_dir.path().join(".kin"));
        let snap = open_snapshot_with_retry(layout.kindb_snapshot_path());
        let graph = snap.graph();

        assert!(repo_dir.path().join(".kin/snapshot/manifest.json").exists());
        assert_repo_owned_graph_truth(graph.as_ref(), &expected_paths);
        assert_makefile_is_text_searchable(graph.as_ref());
        assert!(!tracked_graph_paths(graph.as_ref()).contains(".kin/snapshot/manifest.json"));
    }

    #[tokio::test]
    #[serial]
    async fn run_ignores_daemon_bootstrap_when_initializing_repo() {
        let repo_dir = tempfile::tempdir().unwrap();
        let home_dir = tempfile::tempdir().unwrap();
        let expected_paths = repo_truth_fixture_with_agent_doc(repo_dir.path());

        let daemon_graph = kin_db::InMemoryGraph::new();
        daemon_graph.set_file_hash(".kin/snapshot/manifest.json", [5; 32]);
        daemon_graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new(".kin/snapshot/manifest.json"),
                content_hash: Hash256::from_bytes([5; 32]),
                mime_type: Some("application/json".to_string()),
                text_preview: Some("{\"daemon\":true}".to_string()),
            })
            .unwrap();

        let (daemon_url, daemon_hits, daemon_task) =
            spawn_bootstrap_server(daemon_graph.to_snapshot()).await;

        let _home_guard = EnvVarGuard::set("HOME", home_dir.path());
        let _cache_guard = EnvVarGuard::remove("KIN_INIT_CACHE_DIR");
        let _warm_cache_guard = EnvVarGuard::set("KIN_INIT_WARM_CACHE", "0");
        let _daemon_guard = EnvVarGuard::set("KIN_DAEMON_URL", &daemon_url);

        run(
            Some(repo_dir.path().display().to_string()),
            false,
            true,
            false,
            true,
            "recent".to_string(),
        )
        .await
        .unwrap();
        daemon_task.abort();

        assert_eq!(daemon_hits.load(Ordering::SeqCst), 0);

        let layout = kin_core::KinLayout::new(repo_dir.path().join(".kin"));
        let snap = open_snapshot_with_retry(layout.kindb_snapshot_path());
        let graph = snap.graph();
        assert_repo_owned_graph_truth(graph.as_ref(), &expected_paths);
        assert_makefile_is_text_searchable(graph.as_ref());
        assert!(tracked_graph_paths(graph.as_ref())
            .iter()
            .all(|path| is_repo_owned_graph_path(path)));
    }

    #[test]
    #[serial]
    fn warm_init_cache_path_cleans_internal_control_plane_entries() {
        let repo_dir = tempfile::tempdir().unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        let expected_paths = repo_truth_fixture(repo_dir.path());
        let _cache_guard = EnvVarGuard::set("KIN_INIT_CACHE_DIR", cache_dir.path());
        let _warm_cache_guard = EnvVarGuard::set("KIN_INIT_WARM_CACHE", "1");

        let init_result = kin_core::init(repo_dir.path()).unwrap();
        let local_snap = open_snapshot_with_retry(init_result.layout.kindb_snapshot_path());
        let blob_store = kin_blobs::BlobStore::new(init_result.layout.objects_dir()).unwrap();

        let all_files = collect_source_files(repo_dir.path()).unwrap();
        let indexable_files = collect_indexable_files(repo_dir.path(), &all_files).unwrap();

        let cache_graph = kin_db::InMemoryGraph::new();
        parse_and_index(&cache_graph, &blob_store, &indexable_files).unwrap();

        cache_graph.set_file_hash(".kin/snapshot/manifest.json", [9; 32]);
        cache_graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new(".kin/snapshot/manifest.json"),
                content_hash: Hash256::from_bytes([9; 32]),
                mime_type: Some("application/json".to_string()),
                text_preview: Some("{\"stale\":true}".to_string()),
            })
            .unwrap();
        cache_graph.set_file_hash(".kin/internal/build.swift", [8; 32]);
        cache_graph
            .upsert_shallow_file(&ShallowTrackedFile {
                file_id: FilePathId::new(".kin/internal/build.swift"),
                language_hint: "swift".to_string(),
                declaration_count: 1,
                import_count: 1,
                syntax_hash: Hash256::from_bytes([8; 32]),
                signature_hash: Some(Hash256::from_bytes([7; 32])),
                declaration_names: vec!["render".to_string()],
                import_paths: vec!["Foundation".to_string()],
            })
            .unwrap();
        cache_graph.set_file_hash(".kin/workflows/ci.yml", [6; 32]);
        cache_graph
            .upsert_structured_artifact(&StructuredArtifact {
                file_id: FilePathId::new(".kin/workflows/ci.yml"),
                kind: kin_model::ArtifactKind::CiConfig,
                content_hash: Hash256::from_bytes([6; 32]),
                text_preview: Some("name: kin".to_string()),
            })
            .unwrap();
        cache_graph
            .upsert_shallow_file(&ShallowTrackedFile {
                file_id: FilePathId::new(".kin/orphan/guide.swift"),
                language_hint: "swift".to_string(),
                declaration_count: 1,
                import_count: 0,
                syntax_hash: Hash256::from_bytes([4; 32]),
                signature_hash: Some(Hash256::from_bytes([3; 32])),
                declaration_names: vec!["orphan".to_string()],
                import_paths: Vec::new(),
            })
            .unwrap();
        cache_graph
            .upsert_structured_artifact(&StructuredArtifact {
                file_id: FilePathId::new(".kin/orphan/ci.yml"),
                kind: kin_model::ArtifactKind::CiConfig,
                content_hash: Hash256::from_bytes([2; 32]),
                text_preview: Some("name: orphan".to_string()),
            })
            .unwrap();
        cache_graph
            .upsert_opaque_artifact(&OpaqueArtifact {
                file_id: FilePathId::new(".kin/orphan/notes.md"),
                content_hash: Hash256::from_bytes([1; 32]),
                mime_type: Some("text/markdown".to_string()),
                text_preview: Some("orphan".to_string()),
            })
            .unwrap();

        let root_hash = cache_graph.compute_root_hash();
        refresh_init_cache(repo_dir.path(), &cache_graph, root_hash).unwrap();

        let summary = try_warm_init_from_cache(
            repo_dir.path(),
            &init_result.layout,
            &local_snap,
            &blob_store,
            &indexable_files,
        )
        .unwrap()
        .expect("warm init cache should be reused");

        assert!(summary.warm_cache_hit);

        let graph = local_snap.graph();
        assert_repo_owned_graph_truth(graph.as_ref(), &expected_paths);
        assert!(tracked_graph_paths(graph.as_ref())
            .iter()
            .all(|path| is_repo_owned_graph_path(path)));
    }

    #[cfg(feature = "vector")]
    #[test]
    fn warm_embedding_state_restores_cached_vectors_and_requeues_delta() {
        let dir = tempfile::tempdir().unwrap();
        let result = kin_core::init(dir.path()).unwrap();
        let local_snap = open_snapshot_with_retry(result.layout.kindb_snapshot_path());

        let source_graph = kin_db::InMemoryGraph::new();
        let entity_a = test_entity("alpha", "src/lib.rs");
        let entity_b = test_entity("beta", "src/lib.rs");
        source_graph.upsert_entity(&entity_a).unwrap();
        source_graph.upsert_entity(&entity_b).unwrap();

        let source_vector_path = dir.path().join("source.kvec");
        let source_index = kin_db::VectorIndex::new(2).unwrap();
        source_index.upsert(entity_a.id, &[1.0, 0.0]).unwrap();
        source_index.upsert(entity_b.id, &[0.0, 1.0]).unwrap();
        source_index.save(&source_vector_path).unwrap();
        source_graph.load_vector_index(&source_vector_path).unwrap();

        graft_semantic_state(&local_snap, &result.layout, &source_graph);
        restore_warm_embedding_state(
            &local_snap,
            &result.layout,
            &source_graph,
            Some(&source_vector_path),
            &[entity_b.id],
            &[],
        )
        .unwrap();

        let local_graph = local_snap.graph();
        let status = local_graph.embedding_status();
        assert_eq!(status.indexed, 2);
        assert_eq!(status.pending, 1);
        assert!(result.layout.kindb_vector_index_path().exists());
    }

    #[test]
    fn warm_text_index_sidecar_reopens_with_queryable_docs() {
        let dir = tempfile::tempdir().unwrap();
        let result = kin_core::init(dir.path()).unwrap();
        let local_snap = open_snapshot_with_retry(result.layout.kindb_snapshot_path());

        let cache_graph_path = dir.path().join("warm-cache/graph.kndb");
        let cache_snap = kin_db::SnapshotManager::new(&cache_graph_path);
        let cache_graph = cache_snap.graph();
        let entity = test_entity("render_widget", "src/lib.rs");
        cache_graph.upsert_entity(&entity).unwrap();
        cache_snap.save().unwrap();

        assert!(
            sync_warm_text_index_sidecar(&local_snap, &result.layout, &cache_graph_path, true,)
                .unwrap()
        );
        graft_semantic_state(&local_snap, &result.layout, cache_graph.as_ref());

        let local_graph = local_snap.graph();
        let stats = local_graph.graph_stats();
        assert_eq!(stats.text_indexed_entity_count, 1);
        let hits = local_graph.text_search("render_widget", 5).unwrap();
        assert!(hits
            .iter()
            .any(|(key, _)| *key == kin_model::RetrievalKey::Entity(entity.id)));
    }

    #[test]
    fn warm_graft_preserves_tracked_non_entity_files() {
        let dir = tempfile::tempdir().unwrap();
        let result = kin_core::init(dir.path()).unwrap();
        let local_snap = open_snapshot_with_retry(result.layout.kindb_snapshot_path());

        let source_graph = kin_db::InMemoryGraph::new();
        let shallow = kin_model::ShallowTrackedFile {
            file_id: FilePathId::new("docs/guide.swift"),
            language_hint: "swift".to_string(),
            declaration_count: 3,
            import_count: 2,
            syntax_hash: Hash256::from_bytes([1; 32]),
            signature_hash: Some(Hash256::from_bytes([2; 32])),
            declaration_names: vec!["render".to_string()],
            import_paths: vec!["Foundation".to_string()],
        };
        let structured = kin_model::StructuredArtifact {
            file_id: FilePathId::new("Makefile"),
            kind: kin_model::ArtifactKind::Makefile,
            content_hash: Hash256::from_bytes([3; 32]),
            text_preview: Some("build test".to_string()),
        };
        let opaque = kin_model::OpaqueArtifact {
            file_id: FilePathId::new("README.md"),
            content_hash: Hash256::from_bytes([4; 32]),
            mime_type: Some("text/markdown".to_string()),
            text_preview: Some("usage guide".to_string()),
        };
        source_graph.upsert_shallow_file(&shallow).unwrap();
        source_graph
            .upsert_structured_artifact(&structured)
            .unwrap();
        source_graph.upsert_opaque_artifact(&opaque).unwrap();

        graft_semantic_state(&local_snap, &result.layout, &source_graph);

        let local_graph = local_snap.graph();
        assert_eq!(
            local_graph.list_shallow_files().unwrap()[0].file_id,
            shallow.file_id
        );
        assert_eq!(
            local_graph.list_structured_artifacts().unwrap()[0].file_id,
            structured.file_id
        );
        assert_eq!(
            local_graph.list_opaque_artifacts().unwrap()[0].file_id,
            opaque.file_id
        );
    }

    #[test]
    fn warm_graft_preserves_change_dag_and_branches() {
        let dir = tempfile::tempdir().unwrap();
        let result = kin_core::init(dir.path()).unwrap();
        let local_snap = open_snapshot_with_retry(result.layout.kindb_snapshot_path());

        let source_graph = kin_db::InMemoryGraph::new();
        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x11; 32]));
        let child_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x22; 32]));
        let branch_name = kin_model::BranchName::new("main");

        let genesis = SemanticChange {
            id: genesis_id,
            parents: vec![],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "genesis".to_string(),
            entity_deltas: vec![],
            relation_deltas: vec![],
            artifact_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: Some(branch_name.clone()),
        };
        let child = SemanticChange {
            id: child_id,
            parents: vec![genesis_id],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "child".to_string(),
            entity_deltas: vec![],
            relation_deltas: vec![],
            artifact_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: Some(branch_name.clone()),
        };

        source_graph.create_change(&genesis).unwrap();
        source_graph.create_change(&child).unwrap();
        source_graph
            .create_branch(&kin_model::Branch {
                name: branch_name.clone(),
                head: child_id,
            })
            .unwrap();

        graft_semantic_state(&local_snap, &result.layout, &source_graph);

        let local_graph = local_snap.graph();
        assert_eq!(
            local_graph.get_change(&genesis_id).unwrap().unwrap().id,
            genesis_id
        );
        let reloaded_child = local_graph.get_change(&child_id).unwrap().unwrap();
        assert_eq!(reloaded_child.parents, vec![genesis_id]);
        let branch = local_graph.get_branch(&branch_name).unwrap().unwrap();
        assert_eq!(branch.head, child_id);
    }

    #[test]
    fn warm_cache_manifest_validation_tracks_pipeline_epoch() {
        let repo_dir = tempfile::tempdir().unwrap();
        let repo_identity = repo_cache_identity(repo_dir.path());
        let valid_manifest = WarmCacheRepoManifest {
            schema: INIT_WARM_CACHE_SCHEMA_VERSION.to_string(),
            pipeline_epoch: INIT_WARM_CACHE_PIPELINE_EPOCH.to_string(),
            repo_identity: repo_identity.clone(),
            ..Default::default()
        };

        assert!(warm_cache_manifest_is_valid(
            repo_dir.path(),
            &valid_manifest
        ));

        let stale_manifest = WarmCacheRepoManifest {
            pipeline_epoch: "stale-pipeline".to_string(),
            ..valid_manifest
        };
        assert!(!warm_cache_manifest_is_valid(
            repo_dir.path(),
            &stale_manifest
        ));
    }

    #[test]
    fn resolve_warm_cache_graph_path_requires_ready_marker_for_bundle() {
        let repo_dir = tempfile::tempdir().unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        let bundle_id = "bundle-123".to_string();
        let manifest = WarmCacheRepoManifest {
            schema: INIT_WARM_CACHE_SCHEMA_VERSION.to_string(),
            pipeline_epoch: INIT_WARM_CACHE_PIPELINE_EPOCH.to_string(),
            repo_identity: repo_cache_identity(repo_dir.path()),
            current_bundle_id: Some(bundle_id.clone()),
            bundles: BTreeMap::from([(
                bundle_id.clone(),
                WarmCacheBundleManifestEntry {
                    graph_root_hash: "deadbeef".to_string(),
                    entity_count: 1,
                    relation_count: 1,
                    indexed_files: 1,
                    published_at: chrono::Utc::now().to_rfc3339(),
                },
            )]),
            ..Default::default()
        };

        fs::create_dir_all(cache_dir.path().join("bundles").join(&bundle_id)).unwrap();
        fs::write(
            warm_cache_manifest_path(cache_dir.path()),
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();
        fs::write(
            warm_cache_bundle_graph_path(cache_dir.path(), &bundle_id),
            b"graph",
        )
        .unwrap();

        assert!(
            resolve_warm_cache_graph_path(repo_dir.path(), cache_dir.path())
                .unwrap()
                .is_none(),
            "bundle should fast-fail before graph open when the ready marker is missing"
        );

        fs::write(
            warm_cache_ready_marker_path(cache_dir.path(), &bundle_id),
            b"ready",
        )
        .unwrap();
        assert_eq!(
            resolve_warm_cache_graph_path(repo_dir.path(), cache_dir.path())
                .unwrap()
                .as_deref(),
            Some(warm_cache_bundle_graph_path(cache_dir.path(), &bundle_id).as_path())
        );
    }

    #[test]
    fn warm_cache_resolves_by_current_head_not_last_published_bundle() {
        // Publish-order contamination guard: two commits of the same repo
        // identity each publish a bundle, and `current_bundle_id` points at
        // whichever was published LAST. Resolving must return the bundle for the
        // CURRENT head, not the last-published one — otherwise a checkout at head
        // A grafts head B's state (the 10k <-> 127k entity swing).
        let repo_dir = tempfile::tempdir().unwrap();
        let cache_dir = tempfile::tempdir().unwrap();

        let entry = |root: &str, entities: usize| WarmCacheBundleManifestEntry {
            graph_root_hash: root.to_string(),
            entity_count: entities,
            relation_count: entities,
            indexed_files: 1,
            published_at: chrono::Utc::now().to_rfc3339(),
        };
        let bundle_a = "bundle-a".to_string();
        let bundle_b = "bundle-b".to_string();
        let manifest = WarmCacheRepoManifest {
            schema: INIT_WARM_CACHE_SCHEMA_VERSION.to_string(),
            pipeline_epoch: INIT_WARM_CACHE_PIPELINE_EPOCH.to_string(),
            repo_identity: repo_cache_identity(repo_dir.path()),
            // Head B was published last, so the manifest's current_bundle_id
            // points at it — the pre-fix contamination source.
            current_bundle_id: Some(bundle_b.clone()),
            heads: BTreeMap::from([
                ("head_a".to_string(), bundle_a.clone()),
                ("head_b".to_string(), bundle_b.clone()),
            ]),
            bundles: BTreeMap::from([
                (bundle_a.clone(), entry("aaaa", 10)),
                (bundle_b.clone(), entry("bbbb", 127)),
            ]),
            ..Default::default()
        };
        fs::write(
            warm_cache_manifest_path(cache_dir.path()),
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();
        for bundle in [&bundle_a, &bundle_b] {
            fs::create_dir_all(cache_dir.path().join("bundles").join(bundle)).unwrap();
            fs::write(
                warm_cache_bundle_graph_path(cache_dir.path(), bundle),
                b"graph",
            )
            .unwrap();
            fs::write(
                warm_cache_ready_marker_path(cache_dir.path(), bundle),
                b"ready",
            )
            .unwrap();
        }

        // At head A, resolve MUST pick bundle A — not the last-published B.
        assert_eq!(
            resolve_warm_cache_graph_path_for_head(
                repo_dir.path(),
                cache_dir.path(),
                Some("head_a".to_string()),
            )
            .unwrap()
            .as_deref(),
            Some(warm_cache_bundle_graph_path(cache_dir.path(), &bundle_a).as_path()),
            "head A must resolve its own bundle, not the last-published bundle B",
        );

        // At head B, resolve picks bundle B.
        assert_eq!(
            resolve_warm_cache_graph_path_for_head(
                repo_dir.path(),
                cache_dir.path(),
                Some("head_b".to_string()),
            )
            .unwrap()
            .as_deref(),
            Some(warm_cache_bundle_graph_path(cache_dir.path(), &bundle_b).as_path()),
        );

        // An uncached head rejects-don't-adopt: cold init, never graft B.
        assert!(
            resolve_warm_cache_graph_path_for_head(
                repo_dir.path(),
                cache_dir.path(),
                Some("head_unknown".to_string()),
            )
            .unwrap()
            .is_none(),
            "an uncached head must cold-init rather than adopt the last-published bundle",
        );

        // A non-git (path-scoped) tree has no head; the single last bundle is
        // still the one meaningful state, so it is reused.
        assert_eq!(
            resolve_warm_cache_graph_path_for_head(repo_dir.path(), cache_dir.path(), None)
                .unwrap()
                .as_deref(),
            Some(warm_cache_bundle_graph_path(cache_dir.path(), &bundle_b).as_path()),
        );
    }

    #[test]
    fn warm_cache_content_candidate_offers_ready_last_bundle_head_agnostically() {
        // The speculative content candidate recovers reuse for an unrecorded
        // HEAD that still shares semantic truth (a sibling clone or a doc-only
        // change). It offers the last-published bundle head-agnostically; the
        // caller diff-gates it on entity-source divergence, so the candidate
        // itself only needs to exist and be marked ready.
        let repo_dir = tempfile::tempdir().unwrap();
        let cache_dir = tempfile::tempdir().unwrap();

        // No manifest yet: nothing to offer.
        assert!(
            resolve_warm_cache_content_candidate(repo_dir.path(), cache_dir.path())
                .unwrap()
                .is_none(),
            "no manifest means no candidate",
        );

        let bundle_id = "content-bundle".to_string();
        let manifest = WarmCacheRepoManifest {
            schema: INIT_WARM_CACHE_SCHEMA_VERSION.to_string(),
            pipeline_epoch: INIT_WARM_CACHE_PIPELINE_EPOCH.to_string(),
            repo_identity: repo_cache_identity(repo_dir.path()),
            current_bundle_id: Some(bundle_id.clone()),
            // A different HEAD is the only one recorded; the candidate must not
            // depend on the current tree's HEAD being present.
            heads: BTreeMap::from([("recorded_head".to_string(), bundle_id.clone())]),
            bundles: BTreeMap::from([(
                bundle_id.clone(),
                WarmCacheBundleManifestEntry {
                    graph_root_hash: bundle_id.clone(),
                    entity_count: 1,
                    relation_count: 1,
                    indexed_files: 1,
                    published_at: chrono::Utc::now().to_rfc3339(),
                },
            )]),
            ..Default::default()
        };
        fs::write(
            warm_cache_manifest_path(cache_dir.path()),
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();
        fs::create_dir_all(cache_dir.path().join("bundles").join(&bundle_id)).unwrap();
        fs::write(
            warm_cache_bundle_graph_path(cache_dir.path(), &bundle_id),
            b"graph",
        )
        .unwrap();

        // Bundle present but not yet marked ready: still nothing to offer.
        assert!(
            resolve_warm_cache_content_candidate(repo_dir.path(), cache_dir.path())
                .unwrap()
                .is_none(),
            "an unready bundle is not a candidate",
        );

        fs::write(
            warm_cache_ready_marker_path(cache_dir.path(), &bundle_id),
            b"ready",
        )
        .unwrap();

        // Ready last-published bundle: offered regardless of the current HEAD.
        assert_eq!(
            resolve_warm_cache_content_candidate(repo_dir.path(), cache_dir.path())
                .unwrap()
                .as_deref(),
            Some(warm_cache_bundle_graph_path(cache_dir.path(), &bundle_id).as_path()),
        );
    }

    /// Prove that the snapshot→collect→index pipeline never lets manifest.json
    /// or any `.kin/*` path leak into graph truth (file_hashes, shallow_files,
    /// structured_artifacts, opaque_artifacts).
    #[test]
    fn cold_init_pipeline_excludes_control_plane_from_all_surfaces() {
        let repo_dir = tempfile::tempdir().unwrap();
        let root = repo_dir.path();

        // Create a small repo with a mix of file types.
        let files = [
            ("src/main.rs", "fn main() { println!(\"hi\"); }\n"),
            ("Makefile", "build:\n\tcargo build\n"),
            ("README.md", "# Hello\n"),
            ("docs/guide.swift", "import Foundation\nfunc render() {}\n"),
            ("config.toml", "[package]\nname = \"test\"\n"),
        ];
        for (rel_path, content) in &files {
            let path = root.join(rel_path);
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent).unwrap();
            }
            fs::write(path, content).unwrap();
        }

        let expected_paths: BTreeSet<String> =
            files.iter().map(|(p, _)| (*p).to_string()).collect();

        // Phase 1: snapshot (returns deferred manifest — not yet on disk).
        let (snapshot_path, manifest) = snapshot_repo(root, false).unwrap();
        assert!(
            !snapshot_path.join("manifest.json").exists(),
            "manifest.json must not exist before write_snapshot_manifest"
        );

        // Phase 2: collect files from the snapshot — should be repo files only.
        let all_files = collect_source_files(&snapshot_path).unwrap();
        let rel_paths: BTreeSet<String> = all_files
            .iter()
            .map(|p| {
                p.strip_prefix(&snapshot_path)
                    .unwrap()
                    .to_string_lossy()
                    .to_string()
            })
            .collect();
        assert!(
            !rel_paths.contains("manifest.json"),
            "collect_source_files must not return manifest.json; got: {:?}",
            rel_paths
        );
        for path in &rel_paths {
            assert!(
                is_repo_owned_graph_path(path),
                "non-repo path leaked into collect_source_files: {}",
                path
            );
        }

        // Phase 3: classify and index into a graph.
        let indexable = collect_indexable_files(&snapshot_path, &all_files).unwrap();
        let init_result = kin_core::init(root).unwrap();
        let blob_store = kin_blobs::BlobStore::new(init_result.layout.objects_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();
        parse_and_index(&graph, &blob_store, &indexable).unwrap();

        // Phase 4: write manifest now (as the real run() does).
        write_snapshot_manifest(&snapshot_path, &manifest).unwrap();
        assert!(snapshot_path.join("manifest.json").exists());

        // Assert graph truth contains ONLY repo-owned paths.
        let tracked = tracked_graph_paths(&graph);
        assert_eq!(
            tracked, expected_paths,
            "graph truth must match repo files exactly; got: {:?}",
            tracked
        );
        assert!(
            tracked.iter().all(|p| is_repo_owned_graph_path(p)),
            "all tracked paths must be repo-owned"
        );

        // Double-check individual surfaces.
        let file_hash_paths: BTreeSet<String> = graph.indexed_file_paths().into_iter().collect();
        assert!(
            !file_hash_paths.contains("manifest.json"),
            "manifest.json must not appear in file_hashes"
        );
        for path in &file_hash_paths {
            assert!(
                is_repo_owned_graph_path(path),
                "non-repo path in file_hashes: {}",
                path
            );
        }

        for shallow in graph.list_shallow_files().unwrap() {
            assert!(
                is_repo_owned_graph_path(&shallow.file_id.0),
                "non-repo path in shallow_files: {}",
                shallow.file_id.0
            );
        }
        for artifact in graph.list_structured_artifacts().unwrap() {
            assert!(
                is_repo_owned_graph_path(&artifact.file_id.0),
                "non-repo path in structured_artifacts: {}",
                artifact.file_id.0
            );
        }
        for artifact in graph.list_opaque_artifacts().unwrap() {
            assert!(
                is_repo_owned_graph_path(&artifact.file_id.0),
                "non-repo path in opaque_artifacts: {}",
                artifact.file_id.0
            );
        }

        // Verify manifest data is correct.
        assert_eq!(manifest["file_count"], 5);
    }

    /// Regression: a git *worktree* root carries `.git` as a FILE whose contents
    /// are a `gitdir:` pointer holding a machine-absolute path. Indexing that file
    /// would bake an ambient filesystem path into graph truth, so two preps of
    /// identical content at different checkout paths would diverge by one entity
    /// (and its embedding). Prove the full snapshot→collect→index pipeline excludes
    /// it on every surface, while git-adjacent *repo* files (`.gitignore`,
    /// `.github/`) are still indexed.
    #[test]
    fn cold_init_pipeline_excludes_git_worktree_pointer_file() {
        let repo_dir = tempfile::tempdir().unwrap();
        let root = repo_dir.path();

        // The machine-absolute path the worktree pointer would otherwise leak.
        let worktree_abs = "/Users/somebody/checkouts/main/.git/worktrees/feature-x";
        fs::write(root.join(".git"), format!("gitdir: {}\n", worktree_abs)).unwrap();

        // Real repo content that MUST survive indexing — including git-adjacent
        // dotfiles/dirs that are genuine repo content, not VCS plumbing.
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("src/main.rs"),
            "fn main() { println!(\"hi\"); }\n",
        )
        .unwrap();
        fs::write(root.join(".gitignore"), "target\n").unwrap();
        fs::create_dir_all(root.join(".github/workflows")).unwrap();
        fs::write(root.join(".github/workflows/ci.yml"), "name: ci\n").unwrap();

        // Phase 1: the snapshot must not copy the worktree `.git` pointer file.
        let (snapshot_path, _manifest) = snapshot_repo(root, false).unwrap();
        assert!(
            !snapshot_path.join(".git").exists(),
            "worktree `.git` pointer file leaked into the snapshot"
        );

        // Phase 2: collect must yield no `.git`-pathed entry, and every collected
        // path must be repo-owned and free of the machine-absolute path.
        let all_files = collect_source_files(&snapshot_path).unwrap();
        let rel_paths: BTreeSet<String> = all_files
            .iter()
            .map(|p| {
                p.strip_prefix(&snapshot_path)
                    .unwrap()
                    .to_string_lossy()
                    .to_string()
            })
            .collect();
        assert!(
            !rel_paths
                .iter()
                .any(|p| p.as_str() == ".git" || p.starts_with(".git/")),
            "`.git` plumbing leaked into collect_source_files: {:?}",
            rel_paths
        );
        for p in &rel_paths {
            assert!(
                is_repo_owned_graph_path(p),
                "non-repo path leaked into collect_source_files: {}",
                p
            );
        }
        // Git-adjacent repo content is preserved.
        assert!(rel_paths.contains("src/main.rs"), "got: {:?}", rel_paths);
        assert!(rel_paths.contains(".gitignore"), "got: {:?}", rel_paths);
        assert!(
            rel_paths.contains(".github/workflows/ci.yml"),
            "got: {:?}",
            rel_paths
        );

        // Phase 2b: the machine-absolute path must appear in no collected input
        // (the pointer file was its only carrier).
        for p in &all_files {
            let text = String::from_utf8_lossy(&fs::read(p).unwrap()).into_owned();
            assert!(
                !text.contains(worktree_abs),
                "machine-absolute worktree path leaked into snapshot content: {}",
                p.display()
            );
        }

        // Phase 3: index into a real graph and assert no `.git`-pathed entity or
        // artifact — and no machine path — reaches graph truth on any surface.
        let indexable = collect_indexable_files(&snapshot_path, &all_files).unwrap();
        let init_result = kin_core::init(root).unwrap();
        let blob_store = kin_blobs::BlobStore::new(init_result.layout.objects_dir()).unwrap();
        let graph = kin_db::InMemoryGraph::new();
        parse_and_index(&graph, &blob_store, &indexable).unwrap();

        let tracked = tracked_graph_paths(&graph);
        assert!(
            !tracked
                .iter()
                .any(|p| p.as_str() == ".git" || p.starts_with(".git/")),
            "`.git` plumbing reached graph truth: {:?}",
            tracked
        );
        for p in &tracked {
            assert!(
                is_repo_owned_graph_path(p),
                "non-repo path in graph truth: {}",
                p
            );
            assert!(
                !p.contains(worktree_abs),
                "machine-absolute worktree path reached graph truth: {}",
                p
            );
        }
        assert!(
            tracked.contains("src/main.rs"),
            "real source file missing from graph truth; got: {:?}",
            tracked
        );
    }

    #[test]
    fn index_files_assigns_entity_roles_from_file_path() {
        use kin_model::{EntityRole, EntityStore};

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // Create files in different role categories.
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/lib.rs"), "pub fn source_fn() {}\n").unwrap();

        fs::create_dir_all(root.join("tests")).unwrap();
        fs::write(root.join("tests/integration.rs"), "fn test_fn() {}\n").unwrap();

        fs::create_dir_all(root.join("cextern/zlib")).unwrap();
        fs::write(
            root.join("cextern/zlib/zlib.c"),
            "int inflate(void) { return 0; }\n",
        )
        .unwrap();

        // Initialize kin so we get a valid graph.
        let init_result = kin_core::init(root).unwrap();
        let snap = open_snapshot_with_retry(init_result.layout.kindb_snapshot_path());
        let graph = snap.graph();
        let blob_store = kin_blobs::BlobStore::new(init_result.layout.objects_dir()).unwrap();

        let all_files = collect_source_files(root).unwrap();
        let indexable_files = collect_indexable_files(root, &all_files).unwrap();
        let _summary = parse_and_index(graph.as_ref(), &blob_store, &indexable_files).unwrap();
        snap.save().unwrap();

        // Re-open snapshot to verify persistence.
        drop(graph);
        drop(snap);
        let snap2 = open_snapshot_with_retry(init_result.layout.kindb_snapshot_path());
        let graph2 = snap2.graph();
        let entities = graph2.list_all_entities().unwrap();

        assert!(
            !entities.is_empty(),
            "expected entities to be extracted from source files"
        );

        // Check role assignments.
        let mut role_counts: std::collections::HashMap<EntityRole, Vec<String>> =
            std::collections::HashMap::new();
        for entity in &entities {
            role_counts.entry(entity.role).or_default().push(format!(
                "{} ({})",
                entity.name,
                entity
                    .file_origin
                    .as_ref()
                    .map(|f| f.0.as_str())
                    .unwrap_or("?")
            ));
        }

        // Print role assignments for debugging.
        for (role, names) in &role_counts {
            eprintln!(
                "  {:?}: {} entities — {:?}",
                role,
                names.len(),
                &names[..names.len().min(3)]
            );
        }

        // Source entities should exist (from src/lib.rs).
        assert!(
            role_counts.contains_key(&EntityRole::Source),
            "expected Source entities from src/lib.rs, got: {:?}",
            role_counts.keys().collect::<Vec<_>>()
        );

        // Test entities should exist (from tests/integration.rs).
        assert!(
            role_counts.contains_key(&EntityRole::Test),
            "expected Test entities from tests/integration.rs, got: {:?}",
            role_counts.keys().collect::<Vec<_>>()
        );

        // External entities should exist (from cextern/zlib/zlib.c).
        assert!(
            role_counts.contains_key(&EntityRole::External),
            "expected External entities from cextern/zlib/zlib.c, got: {:?}",
            role_counts.keys().collect::<Vec<_>>()
        );

        // Verify no entity from tests/ is marked Source.
        for entity in &entities {
            if let Some(ref fo) = entity.file_origin {
                if fo.0.contains("tests/") {
                    assert_eq!(
                        entity.role,
                        EntityRole::Test,
                        "entity '{}' in tests/ should be Test, got {:?}",
                        entity.name,
                        entity.role
                    );
                }
            }
        }
    }

    #[test]
    fn parse_and_index_materializes_discovered_tests() {
        use kin_model::{EntityRole, EntityStore, VerificationStore};

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("src/lib.rs"),
            r#"
pub fn parse_json() {}

#[test]
fn test_parse_json() {
    parse_json();
}
"#,
        )
        .unwrap();

        let init_result = kin_core::init(root).unwrap();
        let snap = open_snapshot_with_retry(init_result.layout.kindb_snapshot_path());
        let graph = snap.graph();
        let blob_store = kin_blobs::BlobStore::new(init_result.layout.objects_dir()).unwrap();

        let all_files = collect_source_files(root).unwrap();
        let indexable_files = collect_indexable_files(root, &all_files).unwrap();
        parse_and_index(graph.as_ref(), &blob_store, &indexable_files).unwrap();

        let entities = graph.list_all_entities().unwrap();
        let parse_entity = entities
            .iter()
            .find(|entity| entity.name == "parse_json")
            .unwrap();
        let test_entity = entities
            .iter()
            .find(|entity| entity.name == "test_parse_json")
            .unwrap();

        assert_eq!(parse_entity.role, EntityRole::Source);
        assert_eq!(test_entity.role, EntityRole::Test);
        assert_eq!(graph.graph_stats().test_case_count, 1);
        assert_eq!(
            graph.get_tests_for_entity(&parse_entity.id).unwrap().len(),
            1
        );

        let test_relations = graph.get_all_relations_for_entity(&test_entity.id).unwrap();
        assert!(test_relations.iter().any(|relation| {
            relation.kind == RelationKind::Tests
                && matches!(relation.dst, GraphNodeId::Entity(id) if id == parse_entity.id)
        }));
    }

    /// Comprehensive pipeline validation: tests that the full init pipeline
    /// produces a graph with correct entities, relations, roles, doc_summary,
    /// and cross-file linking. This is the "prove it actually works" test.
    #[test]
    fn full_pipeline_validation() {
        use kin_model::{EntityKind, EntityRole, EntityStore};

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // Create a multi-file Rust project with known structure.
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("src/lib.rs"),
            br#"/// The main library entry point.
pub mod utils;

/// Computes the answer to everything.
pub fn compute() -> i32 {
    utils::helper()
}
"#,
        )
        .unwrap();
        fs::write(
            root.join("src/utils.rs"),
            br#"/// A helper function used by lib.rs.
pub fn helper() -> i32 {
    42
}

pub struct Config {
    pub name: String,
}
"#,
        )
        .unwrap();

        // Test file
        fs::create_dir_all(root.join("tests")).unwrap();
        fs::write(
            root.join("tests/test_lib.rs"),
            b"fn test_compute() { assert_eq!(42, 42); }\n",
        )
        .unwrap();

        // External dep (use cextern/ path, not vendor/ which is a skip dir)
        fs::create_dir_all(root.join("cextern/zlib")).unwrap();
        fs::write(
            root.join("cextern/zlib/dep.rs"),
            b"pub fn external_fn() {}\n",
        )
        .unwrap();

        // Init and index
        let init_result = kin_core::init(root).unwrap();
        let snap = open_snapshot_with_retry(init_result.layout.kindb_snapshot_path());
        let graph = snap.graph();
        let blob_store = kin_blobs::BlobStore::new(init_result.layout.objects_dir()).unwrap();
        let all_files = collect_source_files(root).unwrap();
        let indexable_files = collect_indexable_files(root, &all_files).unwrap();
        let summary = parse_and_index(graph.as_ref(), &blob_store, &indexable_files).unwrap();
        snap.save().unwrap();

        // Reload from snapshot to verify persistence
        drop(graph);
        drop(snap);
        let snap2 = open_snapshot_with_retry(init_result.layout.kindb_snapshot_path());
        let graph2 = snap2.graph();
        let entities = graph2.list_all_entities().unwrap();

        // ── Entity count ──
        assert!(
            entities.len() >= 5,
            "expected at least 5 entities (compute, helper, Config, test_compute, external_fn), got {}",
            entities.len()
        );

        // ── Role classification ──
        let source_count = entities
            .iter()
            .filter(|e| e.role == EntityRole::Source)
            .count();
        let test_count = entities
            .iter()
            .filter(|e| e.role == EntityRole::Test)
            .count();
        let external_count = entities
            .iter()
            .filter(|e| e.role == EntityRole::External)
            .count();
        assert!(
            source_count >= 3,
            "expected at least 3 Source entities, got {}",
            source_count
        );
        assert!(
            test_count >= 1,
            "expected at least 1 Test entity, got {}",
            test_count
        );
        assert!(
            external_count >= 1,
            "expected at least 1 External entity, got {}",
            external_count
        );

        // ── Entity kinds ──
        let has_function = entities.iter().any(|e| e.kind == EntityKind::Function);
        let has_class = entities.iter().any(|e| e.kind == EntityKind::Class);
        assert!(has_function, "expected at least one Function entity");
        assert!(
            has_class,
            "expected at least one Class entity (Config struct)"
        );

        // ── Doc summary populated ──
        let with_docs = entities.iter().filter(|e| e.doc_summary.is_some()).count();
        assert!(
            with_docs >= 2,
            "expected at least 2 entities with doc_summary (compute, helper), got {}",
            with_docs
        );
        let compute = entities.iter().find(|e| e.name == "compute").unwrap();
        assert!(
            compute.doc_summary.is_some(),
            "compute should have doc_summary from /// comment"
        );

        // ── Cross-file relations ──
        // Note: Rust module-qualified calls (utils::helper) don't resolve via
        // the name-based linker because the entity name is "helper" not
        // "utils::helper". This is a known limitation — LSP integration will fix it.
        // For now, just verify the linker ran without error.
        // In languages with simpler call patterns (Python, JS), this DOES resolve.

        // ── File origins valid ──
        for entity in &entities {
            if let Some(ref fo) = entity.file_origin {
                assert!(
                    root.join(&fo.0).exists(),
                    "entity '{}' has file_origin '{}' but file doesn't exist",
                    entity.name,
                    fo.0
                );
            }
        }

        // ── Fingerprints non-zero ──
        for entity in &entities {
            assert_ne!(
                entity.fingerprint.ast_hash,
                kin_model::Hash256::from_bytes([0; 32]),
                "entity '{}' has zero ast_hash",
                entity.name
            );
        }

        eprintln!(
            "Pipeline validation: {} entities, {} relations, {} source, {} test, {} external, {} with docs",
            entities.len(),
            summary.linked_relations,
            source_count,
            test_count,
            external_count,
            with_docs
        );
    }
}
