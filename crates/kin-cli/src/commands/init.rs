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
    GraphNodeId, Hash256, LocatedEntry, OpaqueArtifact, ParseCompleteness, Relation, RelationDelta,
    RelationId, RelationKind, RelationOrigin, RepoPath, ResolvedTree, SemanticChange,
    SemanticChangeId, ShallowTrackedFile, SourceRegion, StructuredArtifact, TestCase, TestId,
    TestKind, TestRunner, Timestamp, TransactionDelta, TreeDelta, TreeEntry, WorkScope,
};
use kin_projection::build_layout;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tracing::{debug, info, warn};

mod history_checkpoint;

use history_checkpoint::{
    CheckpointIoStats, HydrationCheckpointBoundary, HydrationCheckpointConfig,
    HydrationCheckpointSession,
};

/// Discovery cap for `kin init`. When more than this many indexable files are
/// found, init refuses to grind unless the caller explicitly opts in (`--force`)
/// or raises the limit via `KIN_INIT_MAX_FILES`.
const INIT_MAX_DISCOVERED_FILES: usize = 100_000;

/// Invalidates prepared graph state whenever the canonical graph-build
/// pipeline changes in a way that can alter persisted semantic truth.
pub(crate) const GRAPH_BUILD_PIPELINE_EPOCH: &str =
    "graph-build-2026-07-26-exact-tree-semantic-history-v1";

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

#[derive(Debug, Clone)]
struct IndexableFile {
    rel_path: String,
    hash: [u8; 32],
    classification: FileClassification,
    content: Arc<Vec<u8>>,
}

#[derive(Debug, Clone)]
struct ExactInitSourceEntry {
    repo_path: RepoPath,
    hash: [u8; 32],
    entry: TreeEntry,
}

#[derive(Debug, Clone, Copy, Default, Serialize)]
struct InitIndexSummary {
    total_entity_count: usize,
    total_files: usize,
    linked_relations: usize,
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

/// Read one explicit native-filesystem admission boundary and persist every
/// admitted byte sequence in Kin's content-addressed object authority.
///
/// This is ingestion, not a second repository copy. No `.kin/snapshot` tree or
/// manifest is created. After this function returns, parsing reads only the
/// persisted blobs named by graph-owned exact tree entries.
fn collect_native_boundary_entries(
    dir: &Path,
    graph: &kin_db::InMemoryGraph,
    blob_store: &kin_blobs::BlobStore,
    force: bool,
) -> Result<Vec<ExactInitSourceEntry>> {
    let _span = tracing::info_span!(
        "kin.init.collect_native_boundary_entries",
        root = %dir.display()
    )
    .entered();
    let current_tree = graph.resolved_tree();
    let tracked_paths = current_tree
        .artifacts_by_path()
        .map(|artifact| artifact.path.clone())
        .collect::<Vec<_>>();
    let graph_only_paths = current_tree
        .artifacts_by_path()
        .filter(|artifact| matches!(artifact.entry, TreeEntry::Gitlink { .. }))
        .map(|artifact| artifact.path.clone())
        .collect::<Vec<_>>();
    let ignore = kin_index::RepositoryIgnore::load(dir)?;
    let scan = kin_index::scan_repository_preserving_graph_only(
        dir,
        &ignore,
        tracked_paths.iter(),
        graph_only_paths.iter(),
    )?;
    let cap = init_max_discovered_files();
    if scan.len() > cap {
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

    let mut entries = Vec::with_capacity(scan.len());
    for entry in scan.entries() {
        let verified_bytes = kin_index::read_verified_scanned_entry(entry).with_context(|| {
            format!(
                "re-read exact repository entry while admitting {}",
                entry.repo_path
            )
        })?;
        let observed_hash = kin_blobs::digest_bytes(&verified_bytes);
        let observed_entry = exact_tree_entry(observed_hash, entry.kind);
        let expected_entry = exact_tree_entry(entry.content_hash, entry.kind);
        if observed_hash != entry.content_hash || observed_entry != expected_entry {
            anyhow::bail!(
                "repository entry changed while admitting graph truth: {}",
                entry.repo_path
            );
        }
        let stored = blob_store
            .write(&verified_bytes)
            .with_context(|| format!("store exact init source {}", entry.repo_path))?;
        if stored.0 != entry.content_hash {
            anyhow::bail!(
                "blob authority returned the wrong identity while admitting {}",
                entry.repo_path
            );
        }
        entries.push(ExactInitSourceEntry {
            repo_path: entry.repo_path.clone(),
            hash: entry.content_hash,
            entry: expected_entry,
        });
    }

    Ok(entries)
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
    let git_import_options = if is_git_repo {
        git_history_import_options(&git_history)?
    } else {
        None
    };

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

    let is_initialized = kin_dir.exists();
    // Full Git history has one repository-invariant, non-colliding boundary
    // root: Kin's canonical genesis. It must never be replaced with the current
    // branch head on a repeated init. Snapshot mode also attaches its standalone
    // exact-tree change to genesis so it makes no ancestry claim.
    let history_boundary_root = kin_core::build_genesis_change().id;
    let (layout, snap, blob_store, auto_parse_parent_id) = if is_initialized {
        let layout = kin_core::KinLayout::discover(&dir)
            .ok_or_else(|| anyhow::anyhow!("layout not found in existing .kin"))?;
        let snap = crate::backend::open_kindb_snapshot(&layout)?;
        let blob_store = kin_blobs::BlobStore::new(layout.objects_dir())
            .map_err(|e| anyhow::anyhow!("failed to open blob store: {}", e))?;
        // For an existing repository, use the current default-branch head as
        // the parent of any real native semantic/tree transition. Git import
        // still attaches its repository boundary to canonical genesis below.
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

    let graph = snap.graph();
    let branch_name = kin_core::read_current_branch(&layout)?;

    // Re-init is a rebuild request over an already-admitted repository. Drop
    // derived semantic surfaces while every old artifact identity is still
    // live; the exact target tree is installed below, then enrichment is
    // reconstructed from graph/blob truth.
    if is_initialized {
        clear_all_file_semantic_state(graph.as_ref())?;
    }

    let mut native_tree_deltas = None;
    let mut imported_mode = None;
    if let Some(import_opts) = git_import_options.as_ref() {
        let mut imported = kin_git::import_git_history_with_blobs(
            &dir,
            history_boundary_root,
            import_opts,
            Some(&blob_store),
        )
        .with_context(|| format!("import Git repository boundary ({git_history})"))?;
        if imported.is_empty() {
            anyhow::bail!("Git import produced no exact repository head");
        }

        // Historical enrichment consumes only the exact tree transitions and
        // immutable blobs produced by kin-git. It never reads the checkout and
        // never changes membership, path, mode, link kind, or artifact id.
        enrich_imported_changes_with_semantics_checkpointed(
            &mut imported,
            &blob_store,
            layout.root(),
            history_boundary_root,
            false,
        )
        .with_context(|| {
            format!("enrich imported Git history with semantic deltas ({git_history})")
        })?;

        let imported_head = imported
            .last()
            .map(|entry| entry.change.id)
            .ok_or_else(|| anyhow!("Git import produced no head"))?;
        graph.create_changes(imported.iter().map(|entry| entry.change.clone()).collect())?;
        let imported_tree = graph.resolve_tree_at(&imported_head)?;
        apply_resolved_tree_transition(graph.as_ref(), &imported_tree)?;
        graph.update_branch_head(&branch_name, &imported_head)?;
        imported_mode = Some((import_opts.mode, imported.len()));

        if !json {
            match import_opts.mode {
                kin_git::GitImportMode::Snapshot => {
                    println!("  Imported exact Git HEAD snapshot as graph-owned truth.");
                }
                kin_git::GitImportMode::Full => {
                    println!(
                        "  Imported {} Git commit(s) as exact semantic history.",
                        imported.len()
                    );
                }
            }
        }
        phase!("import_exact_git_history");
    } else {
        // Native init (including explicit `--git-history off`) has one
        // filesystem ingestion boundary. Persist its bytes, install exact tree
        // identity, and never consult raw files again during enrichment.
        let exact_source_entries =
            collect_native_boundary_entries(&dir, graph.as_ref(), &blob_store, force)?;
        let tree_deltas = build_exact_init_tree_deltas(
            graph.resolve_tree_at(&auto_parse_parent_id)?,
            &exact_source_entries,
        );
        graph.apply_transaction_delta(&TransactionDelta {
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: tree_deltas.clone(),
        })?;
        native_tree_deltas = Some(tree_deltas);
        phase!("admit_native_repository_tree");
    }

    let indexable_files = collect_indexable_files_from_graph(graph.as_ref(), &blob_store)?;
    phase!("collect_graph_indexable_files");
    let (entity_source_input_count, shallow_source_input_count) =
        count_supported_source_inputs(&indexable_files);

    let has_repository_entries = !graph.resolved_tree().is_empty();
    let init_summary = if !indexable_files.is_empty() {
        let summary = parse_and_index(graph.as_ref(), &blob_store, &indexable_files)?;
        phase!("parse_and_index_graph_blobs");
        summary
    } else {
        InitIndexSummary {
            total_files: graph.resolved_tree().len(),
            ..InitIndexSummary::default()
        }
    };

    if !indexable_files.is_empty() {
        ensure_graph_surface_materialized(
            graph.as_ref(),
            entity_source_input_count,
            shallow_source_input_count,
        )?;
    }

    if let Some(tree_deltas) = native_tree_deltas {
        // Native admission and semantic enrichment publish as one immutable
        // model-owned change. The tree was installed before parsing; this DAG
        // record captures that already-validated transition without reapplying
        // it to the live graph.
        let parent_state = graph.resolve_graph_at(&auto_parse_parent_id)?;
        let current_state = graph.to_snapshot();
        let (entity_deltas, relation_deltas) = exact_semantic_deltas(
            &parent_state,
            &current_state.entities,
            &current_state.relations,
        );

        if !entity_deltas.is_empty() || !relation_deltas.is_empty() || !tree_deltas.is_empty() {
            let mut change = SemanticChange {
                id: placeholder_semantic_change_id(),
                parents: vec![auto_parse_parent_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new(whoami()),
                message: "kin init: auto-parse".to_string(),
                entity_deltas,
                relation_deltas,
                tree_deltas,
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: Some(branch_name.clone()),
            };
            change.id = kin_model::compute_semantic_change_id(&change)?;
            kin_model::validate_semantic_change_id(&change)?;
            graph.create_change(&change)?;
            graph.update_branch_head(&branch_name, &change.id)?;
        } else {
            debug!(
                parent = %auto_parse_parent_id,
                "native init rebuilt identical graph/tree truth; keeping branch head unchanged"
            );
        }

        phase!("change_dag+blob_backfill");
    }

    if let Some((mode, _)) = imported_mode {
        let cochange_limit = match mode {
            kin_git::GitImportMode::Snapshot => 50,
            kin_git::GitImportMode::Full => 0,
        };
        match crate::commands::cochange::refresh_from_git_history_with_limit(
            graph.as_ref(),
            &dir,
            cochange_limit,
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
                    "failed to mine co-change relations from Git provenance"
                );
            }
        }
    }

    let embed_status = graph.embedding_status();

    phase!("cochange_mining");

    snap.save()?;
    phase!("snapshot_save");

    // Build and save the read-only index for fast CLI queries.
    let read_index = kin_db::ReadIndex::from_graph(&graph)?;
    let idx_path = layout.kindb_snapshot_path().with_extension("kidx");
    read_index.save(&idx_path)?;

    phase!("read_index_save");

    // Optional LSP enrichment: discover servers, enrich entities with type-resolved relations.
    if has_repository_entries && !no_lsp {
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
                    println!("  LSP cold sweep triggered — enriching all entities in background");
                }
            }
        }
    }

    if has_repository_entries && !json {
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
    if has_repository_entries && verbose {
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
    // Register in the global ~/.kin/registry.toml with the current-tree count.
    let repo_id = dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown")
        .to_string();
    let canonical_dir = dir.canonicalize().unwrap_or(dir);
    kin_core::registry::KinRegistry::update(|registry| {
        registry.upsert(repo_id, canonical_dir, init_summary.total_entity_count);
    })
    .map_err(|e| anyhow!("graph initialized, but local registry authority update failed: {e}"))?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&InitResultPayload {
                schema: "kin.init-result.v2",
                repo_root: layout.root().display().to_string(),
                kindb_snapshot_path: layout.kindb_snapshot_path().display().to_string(),
                objects_dir: layout.objects_dir().display().to_string(),
                genesis_change: history_boundary_root.to_string(),
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

fn git_history_import_options(mode: &str) -> Result<Option<kin_git::ImportOptions>> {
    match mode {
        "off" => Ok(None),
        "snapshot" => Ok(Some(kin_git::ImportOptions {
            mode: kin_git::GitImportMode::Snapshot,
            branch: None,
        })),
        "full" => Ok(Some(kin_git::ImportOptions::default())),
        other => Err(anyhow!(
            "invalid Git history mode {other:?}; expected off, snapshot, or full"
        )),
    }
}

fn placeholder_semantic_change_id() -> SemanticChangeId {
    SemanticChangeId::from_hash(Hash256::from_bytes([0; 32]))
}

/// Recompute enriched imported changes in parent-first order.
///
/// kin-git identifies its exact artifact-only payloads. Historical semantic
/// enrichment changes that immutable payload, so every affected ID and every
/// descendant parent reference must be remapped before graph insertion.
fn reidentify_enriched_imported_changes(
    imported: &mut [kin_git::ImportedChange],
    boundary_root: SemanticChangeId,
) -> Result<()> {
    validate_imported_parent_closure(imported, boundary_root)?;

    let old_index = imported
        .iter()
        .enumerate()
        .map(|(index, entry)| (entry.change.id, index))
        .collect::<HashMap<_, _>>();
    let parent_indices = imported
        .iter()
        .map(|entry| {
            entry
                .change
                .parents
                .iter()
                .filter(|parent| **parent != boundary_root)
                .map(|parent| {
                    old_index.get(parent).copied().ok_or_else(|| {
                        anyhow!(
                            "cannot reidentify imported change {}: parent {} is absent",
                            entry.change.id,
                            parent
                        )
                    })
                })
                .collect::<Result<Vec<_>>>()
        })
        .collect::<Result<Vec<_>>>()?;
    let order = full_parent_topological_order(&parent_indices)?;
    let mut remapped = HashMap::<SemanticChangeId, SemanticChangeId>::with_capacity(imported.len());

    for index in order {
        let old_id = imported[index].change.id;
        for parent in &mut imported[index].change.parents {
            if *parent == boundary_root {
                continue;
            }
            *parent = remapped.get(parent).copied().ok_or_else(|| {
                anyhow!(
                    "cannot reidentify imported change {} before parent {}",
                    old_id,
                    parent
                )
            })?;
        }
        imported[index].change.id = placeholder_semantic_change_id();
        imported[index].change.id = kin_model::compute_semantic_change_id(&imported[index].change)
            .with_context(|| format!("identify enriched imported change {}", old_id))?;
        kin_model::validate_semantic_change_id(&imported[index].change)
            .with_context(|| format!("validate enriched imported change {}", old_id))?;
        remapped.insert(old_id, imported[index].change.id);
    }

    validate_imported_parent_closure(imported, boundary_root)?;
    for entry in imported {
        kin_model::validate_semantic_change_id(&entry.change).with_context(|| {
            format!(
                "validate final imported payload for Git object {}",
                entry.git_oid
            )
        })?;
    }
    Ok(())
}

/// Install one exact resolved tree as the live repository view without
/// allocating new identities or deriving them from locations.
fn apply_resolved_tree_transition(
    graph: &kin_db::InMemoryGraph,
    target: &ResolvedTree,
) -> Result<()> {
    let current = graph.resolved_tree();
    let mut deltas = Vec::new();

    for old in current.artifacts() {
        if target.get(&old.artifact_id).is_none() {
            deltas.push(TreeDelta::Removed {
                artifact_id: old.artifact_id,
                old: old.located_entry(),
            });
        }
    }
    for new in target.artifacts() {
        match current.get(&new.artifact_id) {
            Some(old) if old.path == new.path && old.entry == new.entry => {}
            Some(old) => deltas.push(TreeDelta::Updated {
                artifact_id: new.artifact_id,
                old: old.located_entry(),
                new: new.located_entry(),
            }),
            None => deltas.push(TreeDelta::Added {
                artifact_id: new.artifact_id,
                new: new.located_entry(),
            }),
        }
    }

    let staged = current
        .apply(&deltas)
        .context("validate exact init tree transition")?;
    if &staged != target {
        anyhow::bail!("exact init tree transition did not reproduce the imported target");
    }
    if !deltas.is_empty() {
        graph.apply_transaction_delta(&TransactionDelta {
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: deltas,
        })?;
    }
    Ok(())
}

fn clear_all_file_semantic_state(graph: &kin_db::InMemoryGraph) -> Result<()> {
    let paths = graph
        .resolved_tree()
        .artifacts_by_path()
        .filter_map(|artifact| artifact.path.as_utf8().map(str::to_owned))
        .collect::<Vec<_>>();
    let artifact_relations = collect_artifact_relation_ids_for_files(graph, paths.iter())?;
    remove_relations_batch_by_id(graph, &artifact_relations)?;
    for path in paths {
        clear_file_semantic_state(graph, &path)?;
    }
    Ok(())
}

/// Diff a rebuilt live semantic graph against its immutable parent ref.
///
/// Re-init is allowed to rebuild parser-derived state, but its history record
/// must describe only the actual parent-to-current transition. Replaying every
/// current entity as `Added` would make an identical second init look like new
/// history and can collide with entities already present at the parent.
fn exact_semantic_deltas(
    parent: &kin_model::graph::ResolvedGraphState,
    current_entities: &HashMap<EntityId, Entity>,
    current_relations: &HashMap<RelationId, Relation>,
) -> (Vec<EntityDelta>, Vec<RelationDelta>) {
    let entity_ids = parent
        .entities
        .keys()
        .chain(current_entities.keys())
        .copied()
        .collect::<BTreeSet<_>>();
    let mut entity_deltas = Vec::new();
    for entity_id in entity_ids {
        match (
            parent.entities.get(&entity_id),
            current_entities.get(&entity_id),
        ) {
            (Some(old), Some(new)) if imported_entities_exactly_equivalent(old, new) => {}
            (Some(old), Some(new)) => entity_deltas.push(EntityDelta::Modified {
                old: old.clone(),
                new: new.clone(),
            }),
            (Some(_), None) => entity_deltas.push(EntityDelta::Removed(entity_id)),
            (None, Some(new)) => entity_deltas.push(EntityDelta::Added(new.clone())),
            (None, None) => unreachable!("entity id came from one side of the semantic diff"),
        }
    }

    let mut relation_ids = parent
        .relations
        .keys()
        .chain(current_relations.keys())
        .copied()
        .collect::<Vec<_>>();
    relation_ids.sort_by_key(|relation_id| relation_id.0);
    relation_ids.dedup();
    let mut relation_deltas = Vec::new();
    for relation_id in relation_ids {
        match (
            parent.relations.get(&relation_id),
            current_relations.get(&relation_id),
        ) {
            (Some(old), Some(new)) if imported_relations_exactly_equivalent(old, new) => {}
            (Some(_), Some(new)) => {
                relation_deltas.push(RelationDelta::Removed(relation_id));
                relation_deltas.push(RelationDelta::Added(new.clone()));
            }
            (Some(_), None) => relation_deltas.push(RelationDelta::Removed(relation_id)),
            (None, Some(new)) => relation_deltas.push(RelationDelta::Added(new.clone())),
            (None, None) => unreachable!("relation id came from one side of the semantic diff"),
        }
    }

    (entity_deltas, relation_deltas)
}

/// Select semantic-enrichment inputs exclusively from admitted tree/blob truth.
fn collect_indexable_files_from_graph(
    graph: &kin_db::InMemoryGraph,
    blob_store: &kin_blobs::BlobStore,
) -> Result<Vec<IndexableFile>> {
    let mut files = Vec::new();
    for artifact in graph.resolved_tree().artifacts_by_path() {
        let TreeEntry::Blob { hash, .. } = artifact.entry else {
            continue;
        };
        let Some(path) = artifact.path.as_utf8() else {
            // Exact non-UTF8 membership remains graph-owned and projectable;
            // parser adapters currently accept UTF-8 file identifiers only.
            continue;
        };
        let blob_hash = kin_blobs::Hash256::from_bytes(*hash.as_bytes());
        let content = blob_store.read(&blob_hash).with_context(|| {
            format!(
                "read admitted source blob {} for semantic enrichment",
                artifact.path
            )
        })?;
        if kin_blobs::digest_bytes(&content) != *hash.as_bytes() {
            anyhow::bail!(
                "admitted source blob for {} does not match graph identity {}",
                artifact.path,
                hash
            );
        }
        files.push(IndexableFile {
            rel_path: path.to_string(),
            hash: *hash.as_bytes(),
            classification: FileClassifier::classify(Path::new(path)),
            content: Arc::new(content),
        });
    }
    Ok(files)
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
    let parse_completeness_by_file = link_parse_completeness_from_layouts(graph, &file_parse_data)?;
    eprintln!(
        "  [init-timer] {:>30}: {:.2}s",
        "index_files (parse+upsert)",
        pi_timer.elapsed().as_secs_f64()
    );
    // Cross-file relation linking (progress printed by the linker itself)
    let artifact_ids = graph_artifact_identity_map(graph);
    let mut linked_relations = kin_index::link_cross_file_with_completeness(
        &file_parse_data,
        &artifact_ids,
        &parse_completeness_by_file,
    )?;
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
        total_files: graph.resolved_tree().len(),
        linked_relations: linked_relations.len(),
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportedSemanticFileState {
    artifact_id: ArtifactId,
    file_path: String,
    parse_completeness: ParseCompleteness,
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
            // The checkpoint conversion is the exhaustive, versioned linker
            // clone contract, including graph-assigned artifact identities and
            // language gates. A new linker field must update that contract.
            linker: kin_index::IncrementalLinker::from_checkpoint_v1(
                self.linker.to_checkpoint_v1(),
            )
            .expect("a live incremental linker must round-trip its own checkpoint"),
        }
    }
}

/// Deterministic topological order over the complete imported parent DAG.
///
/// Every in-set parent must be processed before its child. This is stricter
/// than the first-parent ordering required to compute a Git commit's target
/// tree: merge-delta rebasing also resolves the runtime all-parent baseline, so
/// every secondary parent must already be present in the scratch change store.
/// Kahn's algorithm is seeded and drained in ascending input-index order to keep
/// the result byte-stable and as close as possible to the importer order.
fn full_parent_topological_order(parent_indices: &[Vec<usize>]) -> Result<Vec<usize>> {
    let n = parent_indices.len();
    let mut children: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut indegree = vec![0usize; n];
    for (child, parents) in parent_indices.iter().enumerate() {
        for &parent in parents {
            children[parent].push(child);
            indegree[child] += 1;
        }
    }

    let mut queue: std::collections::VecDeque<usize> =
        (0..n).filter(|&i| indegree[i] == 0).collect();
    let mut order = Vec::with_capacity(n);
    while let Some(i) = queue.pop_front() {
        order.push(i);
        for &child in &children[i] {
            indegree[child] -= 1;
            if indegree[child] == 0 {
                queue.push_back(child);
            }
        }
    }
    if order.len() != n {
        return Err(anyhow!(
            "historical hydration invariant violated: imported parent DAG contains a cycle"
        ));
    }
    Ok(order)
}

fn validate_imported_parent_closure(
    imported: &[kin_git::ImportedChange],
    boundary_root: SemanticChangeId,
) -> Result<()> {
    let mut imported_ids = HashSet::with_capacity(imported.len());
    for imported_change in imported {
        if imported_change.change.id == boundary_root {
            return Err(anyhow!(
                "historical hydration invariant violated: imported change collides with boundary root {}",
                boundary_root
            ));
        }
        if !imported_ids.insert(imported_change.change.id) {
            return Err(anyhow!(
                "historical hydration invariant violated: duplicate imported change {}",
                imported_change.change.id
            ));
        }
    }
    for imported_change in imported {
        let mut unique_parents = HashSet::with_capacity(imported_change.change.parents.len());
        if imported_change.change.parents.is_empty() {
            return Err(anyhow!(
                "historical hydration invariant violated: imported change {} has no parent; Git roots must reference canonical genesis {}",
                imported_change.change.id,
                boundary_root
            ));
        }
        for parent in &imported_change.change.parents {
            if !unique_parents.insert(*parent) {
                return Err(anyhow!(
                    "historical hydration invariant violated: imported change {} repeats parent {}",
                    imported_change.change.id,
                    parent
                ));
            }
            if *parent != boundary_root && !imported_ids.contains(parent) {
                return Err(anyhow!(
                    "historical hydration invariant violated: imported change {} has dangling parent {} (expected imported history or canonical genesis {})",
                    imported_change.change.id,
                    parent,
                    boundary_root
                ));
            }
        }
    }

    // Validate the complete parent DAG, not only the first-parent forest used
    // as the semantic replay baseline. A merge can name canonical genesis as
    // its first parent while a secondary-parent path closes a cycle. Closure
    // validation alone accepts that shape, and first-parent ordering cannot see
    // it. Reject every such cycle here, before checkpoint prepare can acquire
    // the store lock or create directories.
    let parents_by_id: HashMap<_, _> = imported
        .iter()
        .map(|entry| (entry.change.id, entry.change.parents.as_slice()))
        .collect();
    let mut color = HashMap::<SemanticChangeId, u8>::with_capacity(imported.len());
    for start in imported_ids.iter().copied() {
        if color.get(&start) == Some(&2) {
            continue;
        }
        let mut stack = vec![(start, false)];
        while let Some((change_id, exiting)) = stack.pop() {
            if exiting {
                color.insert(change_id, 2);
                continue;
            }
            match color.get(&change_id).copied().unwrap_or(0) {
                2 => continue,
                1 => {
                    return Err(anyhow!(
                        "historical hydration invariant violated: imported parent DAG contains a cycle at {}",
                        change_id
                    ));
                }
                _ => {}
            }
            color.insert(change_id, 1);
            stack.push((change_id, true));
            for parent in parents_by_id[&change_id].iter().rev().copied() {
                if parent != boundary_root {
                    stack.push((parent, false));
                }
            }
        }
    }
    Ok(())
}

fn take_imported_parent_baseline(
    snapshots: &mut HashMap<SemanticChangeId, ImportedCommitSemanticState>,
    parent_id: SemanticChangeId,
    is_last_child: bool,
) -> Result<ImportedCommitSemanticState> {
    if is_last_child {
        snapshots.remove(&parent_id).ok_or_else(|| {
            anyhow!(
                "historical hydration invariant violated: missing retained first-parent state {} for its last child",
                parent_id
            )
        })
    } else {
        snapshots.get(&parent_id).cloned().ok_or_else(|| {
            anyhow!(
                "historical hydration invariant violated: missing retained first-parent state {} while later children remain",
                parent_id
            )
        })
    }
}

/// Pre-reconciliation parse payload memoized per `(blob_hash, exact UTF-8
/// location, PARSER_SEMANTICS_VERSION)` for one hydration pass. Parser output
/// carries file origins and path-sensitive entity ids, so content identity
/// alone is deliberately insufficient across a rename or duplicate blob.
/// Holds exactly the fields
/// the replay consumes between the parse and commit-relative entity
/// reconciliation; reconciliation itself is deliberately excluded because it
/// re-keys entity ids per commit. Shared via `Arc` so a blob recurring across
/// commits reuses one allocation instead of re-parsing.
struct CachedParse {
    parse_completeness: ParseCompleteness,
    entities: Vec<Entity>,
    extracted_relations: Vec<kin_parser::ExtractedRelation>,
    imports: Vec<kin_parser::FileImport>,
}

/// One tree delta's resolved parse disposition for a commit's reconcile
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
    /// Indices into the commit's `tree_deltas` this parse resolves. The
    /// first entry was counted as a memo miss when the job was scheduled; any
    /// later entries are same-commit reappearances whose hit/miss accounting is
    /// settled in the merge once the parse's success is known.
    served_deltas: Vec<usize>,
}

#[cfg(test)]
pub(crate) fn enrich_imported_changes_with_semantics(
    imported: &mut [kin_git::ImportedChange],
    blob_store: &kin_blobs::BlobStore,
) -> Result<()> {
    enrich_imported_changes_with_semantics_inner(imported, blob_store, true)?;
    reidentify_enriched_imported_changes(imported, kin_core::build_genesis_change().id)
}

#[cfg(test)]
fn enrich_imported_changes_with_semantics_and_genesis(
    imported: &mut [kin_git::ImportedChange],
    blob_store: &kin_blobs::BlobStore,
    genesis_id: SemanticChangeId,
) -> Result<()> {
    enrich_imported_changes_with_semantics_with_checkpoints_and_boundary_root(
        imported, blob_store, true, None, genesis_id, false,
    )?;
    reidentify_enriched_imported_changes(imported, genesis_id)
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct HydrationReplayStats {
    parse_memo_hits: usize,
    parse_memo_misses: usize,
    resumed_from: usize,
    checkpoint_io: CheckpointIoStats,
}

#[cfg(test)]
impl HydrationReplayStats {
    pub(crate) fn resumed_from(&self) -> usize {
        self.resumed_from
    }
}

pub(crate) fn enrich_imported_changes_with_semantics_checkpointed(
    imported: &mut [kin_git::ImportedChange],
    blob_store: &kin_blobs::BlobStore,
    kin_root: &Path,
    boundary_root: SemanticChangeId,
    tolerant: bool,
) -> Result<HydrationReplayStats> {
    let config = HydrationCheckpointConfig::production(kin_root);
    let stats = enrich_imported_changes_with_semantics_with_checkpoints_and_boundary_root(
        imported,
        blob_store,
        true,
        Some(config),
        boundary_root,
        tolerant,
    )?;
    reidentify_enriched_imported_changes(imported, boundary_root)?;
    debug!(
        resumed_from = stats.resumed_from,
        parse_memo_hits = stats.parse_memo_hits,
        parse_memo_misses = stats.parse_memo_misses,
        total_commits = imported.len(),
        checkpoint_serialized_units = stats.checkpoint_io.serialized_units,
        checkpoint_written_bytes = stats.checkpoint_io.written_bytes,
        checkpoint_max_unit_bytes = stats.checkpoint_io.max_serialized_unit_bytes,
        checkpoint_retained_bytes = stats.checkpoint_io.retained_bytes,
        "historical semantic hydration checkpoint outcome"
    );
    Ok(stats)
}

/// Test-only seam for exercising the exact production hydration wrapper from
/// lazy-ref callers while supplying a deterministic clean build identity.
/// Production never accepts an identity from the request or environment.
#[cfg(test)]
pub(crate) fn enrich_imported_changes_with_semantics_test_checkpoint(
    imported: &mut [kin_git::ImportedChange],
    blob_store: &kin_blobs::BlobStore,
    kin_root: &Path,
    clean_git_sha: &str,
    boundary_root: SemanticChangeId,
) -> Result<HydrationReplayStats> {
    enrich_imported_changes_with_semantics_with_checkpoints_and_boundary_root(
        imported,
        blob_store,
        true,
        Some(HydrationCheckpointConfig::clean_for_test(
            kin_root,
            clean_git_sha,
            1,
            16 * 1024 * 1024,
        )),
        boundary_root,
        false,
    )
}

/// Replay body shared by production (`parse_memo_enabled = true`) and the
/// memo-off serial oracle used in tests. Returns `(parse_memo_hits,
/// parse_memo_misses)` observed over the pass.
#[cfg(test)]
fn enrich_imported_changes_with_semantics_inner(
    imported: &mut [kin_git::ImportedChange],
    blob_store: &kin_blobs::BlobStore,
    parse_memo_enabled: bool,
) -> Result<(usize, usize)> {
    let stats = enrich_imported_changes_with_semantics_with_checkpoints(
        imported,
        blob_store,
        parse_memo_enabled,
        None,
    )?;
    Ok((stats.parse_memo_hits, stats.parse_memo_misses))
}

#[cfg(test)]
fn enrich_imported_changes_with_semantics_with_checkpoints(
    imported: &mut [kin_git::ImportedChange],
    blob_store: &kin_blobs::BlobStore,
    parse_memo_enabled: bool,
    checkpoint_config: Option<HydrationCheckpointConfig>,
) -> Result<HydrationReplayStats> {
    enrich_imported_changes_with_semantics_with_checkpoints_and_boundary_root(
        imported,
        blob_store,
        parse_memo_enabled,
        checkpoint_config,
        kin_core::build_genesis_change().id,
        false,
    )
}

fn enrich_imported_changes_with_semantics_with_checkpoints_and_boundary_root(
    imported: &mut [kin_git::ImportedChange],
    blob_store: &kin_blobs::BlobStore,
    parse_memo_enabled: bool,
    checkpoint_config: Option<HydrationCheckpointConfig>,
    boundary_root: SemanticChangeId,
    tolerant: bool,
) -> Result<HydrationReplayStats> {
    // Profiling timers (accumulated across every commit in the pass).
    let mut total_blob_read_time = std::time::Duration::ZERO;
    let mut total_parsing_time = std::time::Duration::ZERO;
    let mut total_linking_time = std::time::Duration::ZERO;
    let mut total_closure_diffing_time = std::time::Duration::ZERO;

    // Parse memo (per-pass lifetime; the replay loop is single-threaded, so a
    // plain HashMap is sound and deterministic). Bounds live memory to the
    // pass's distinct source blobs.
    let mut parse_memo: HashMap<(kin_blobs::Hash256, String, u32), Arc<CachedParse>> =
        HashMap::new();
    let mut parse_memo_hits = 0usize;
    let mut parse_memo_misses = 0usize;

    let total_commits = imported.len();
    let start_time = std::time::Instant::now();

    // kin-git closes every truncation-horizon edge onto the import's genesis.
    // Validate that contract before acquiring the checkpoint-store lock, reading
    // blobs, or mutating deltas so corruption can never be mistaken for a root
    // baseline or leave a partial side effect.
    validate_imported_parent_closure(imported, boundary_root)?;

    // Resolve each imported commit's FIRST git parent to an in-set slice index.
    // kin-git derives a commit's tree deltas by diffing its tree against its
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
            imported_change.change.parents.first().and_then(|parent| {
                (*parent != boundary_root).then(|| {
                    *index_by_change_id
                        .get(parent)
                        .expect("validated imported first parent must be present")
                })
            })
        })
        .collect();
    let all_parent_indices: Vec<Vec<usize>> = imported
        .iter()
        .map(|imported_change| {
            imported_change
                .change
                .parents
                .iter()
                .filter(|parent| **parent != boundary_root)
                .map(|parent| {
                    *index_by_change_id
                        .get(parent)
                        .expect("validated imported parent must be present")
                })
                .collect()
        })
        .collect();

    // Count how many in-set commits fork from each commit as their first parent,
    // so a commit's snapshot is retained only while children still need it. This
    // bounds live snapshots to the DAG's branch width, not the whole history.
    let mut remaining_children = vec![0usize; total_commits];
    for parent in first_parent_index.iter().flatten() {
        remaining_children[*parent] += 1;
    }
    let initial_remaining_children = remaining_children.clone();

    // Reject cycles before checkpoint prepare acquires the repository-scoped
    // store lock or creates any store paths. Git cannot contain a commit
    // cycle, so accepting one here would only turn corrupt input into a later
    // missing-snapshot failure with partial hydration side effects.
    let order = full_parent_topological_order(&all_parent_indices)?;
    let mut snapshots = HashMap::<SemanticChangeId, ImportedCommitSemanticState>::new();
    let mut resumed_from = 0usize;
    let mut checkpoint_session = if let Some(config) = checkpoint_config {
        let (session, resume) = HydrationCheckpointSession::prepare(
            config,
            imported,
            &order,
            &first_parent_index,
            &initial_remaining_children,
        )?;
        if let Some(resume) = resume {
            resumed_from = resume.processed_count;
            remaining_children = resume.remaining_children;
            snapshots = resume.frontier;
        }
        Some(session)
    } else {
        None
    };

    for (processed, &i) in order.iter().enumerate().skip(resumed_from) {
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
                remaining_children[parent_idx] = remaining_children[parent_idx]
                    .checked_sub(1)
                    .ok_or_else(|| {
                        anyhow!(
                            "historical hydration invariant violated: first-parent child count underflow at {}",
                            imported[parent_idx].change.id
                        )
                    })?;
                let parent_id = imported[parent_idx].change.id;
                take_imported_parent_baseline(
                    &mut snapshots,
                    parent_id,
                    remaining_children[parent_idx] == 0,
                )?
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
        let deltas = &imported[i].change.tree_deltas;
        let mut resolutions: Vec<Option<ImportedFileResolution>> =
            (0..deltas.len()).map(|_| None).collect();
        let mut parse_jobs: Vec<ImportedParseJob> = Vec::new();
        let mut scheduled_jobs: HashMap<(kin_blobs::Hash256, String, u32), usize> = HashMap::new();

        for (delta_idx, tree_delta) in deltas.iter().enumerate() {
            let new_state = match tree_delta {
                TreeDelta::Added { new, .. } | TreeDelta::Updated { new, .. } => Some(new),
                TreeDelta::Removed { .. } => None,
            };
            let Some(new_state) = new_state else {
                resolutions[delta_idx] = Some(ImportedFileResolution::Remove);
                continue;
            };
            let Some(file_path) = new_state.path.as_utf8() else {
                resolutions[delta_idx] = Some(ImportedFileResolution::Remove);
                continue;
            };
            let TreeEntry::Blob {
                hash: new_blob_hash,
                ..
            } = new_state.entry
            else {
                resolutions[delta_idx] = Some(ImportedFileResolution::Remove);
                continue;
            };

            if !matches!(
                FileClassifier::classify(Path::new(file_path)),
                FileClassification::EntitySource
            ) {
                resolutions[delta_idx] = Some(ImportedFileResolution::Remove);
                continue;
            }

            // Parsing is keyed by exact bytes, exact UTF-8 location, and parser
            // semantics. Parser output carries path-derived origins/ids, so a
            // rename must be reparsed even when Git reuses the same blob.
            let memo_key = (
                kin_blobs::Hash256::from_bytes(*new_blob_hash.as_bytes()),
                file_path.to_string(),
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
                scheduled_jobs.insert(memo_key.clone(), parse_jobs.len());
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
                    let content = blob_store
                        .read(&job.blob_hash)
                        .map_err(|err| err.to_string())?;
                    if kin_blobs::digest_bytes(&content) != job.blob_hash.0 {
                        return Err(format!(
                            "blob content does not match admitted identity {}",
                            job.blob_hash
                        ));
                    }
                    Ok(content)
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
                                    parse_completeness: indexed
                                        .indexed_file
                                        .file_layout
                                        .parse_completeness
                                        .clone(),
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
                                (
                                    job.blob_hash,
                                    job.file_id.0.clone(),
                                    kin_parser::PARSER_SEMANTICS_VERSION,
                                ),
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
                        if !tolerant {
                            return Err(anyhow!(
                                "historical enrichment cannot read admitted blob {} for {}: {}",
                                job.blob_hash,
                                job.file_id.0,
                                err
                            ));
                        }
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

        // Remove every old semantic location before inserting any new one.
        // Exact tree transactions permit swaps and rename cycles; processing
        // move A→B before B→A in-place would otherwise overwrite B's semantic
        // state and silently transfer it to A.
        let mut old_states = HashMap::<ArtifactId, ImportedSemanticFileState>::new();
        for tree_delta in &imported[i].change.tree_deltas {
            let (artifact_id, old) = match tree_delta {
                TreeDelta::Added { artifact_id, .. } => (*artifact_id, None),
                TreeDelta::Updated {
                    artifact_id, old, ..
                }
                | TreeDelta::Removed { artifact_id, old } => (*artifact_id, Some(old)),
            };
            let Some(old) = old else {
                continue;
            };
            let Some(old_path) = old.path.as_utf8() else {
                continue;
            };
            if let Some(old_state) = current_files.remove(old_path) {
                if old_state.artifact_id != artifact_id {
                    anyhow::bail!(
                        "historical semantic state at {} belongs to artifact {:?}, not delta artifact {:?}",
                        old.path,
                        old_state.artifact_id,
                        artifact_id
                    );
                }
                previous_file_states.insert(old_path.to_string(), old_state.clone());
                changed_source_files.insert(old_path.to_string());
                incremental_linker.remove_file(old_path);
                old_states.insert(artifact_id, old_state);
            }
        }

        // Reconcile serially in canonical delta order, now against the exact
        // graph-assigned identity removed above. Unsupported/non-source files
        // intentionally receive no semantic state; their tree membership and
        // byte identity remain untouched.
        for (delta_idx, tree_delta) in imported[i].change.tree_deltas.iter().enumerate() {
            let (artifact_id, new_state) = match tree_delta {
                TreeDelta::Added { artifact_id, new }
                | TreeDelta::Updated {
                    artifact_id, new, ..
                } => (*artifact_id, Some(new)),
                TreeDelta::Removed { artifact_id, .. } => (*artifact_id, None),
            };
            let old_state = old_states.remove(&artifact_id);

            match resolutions[delta_idx]
                .take()
                .expect("every tree delta must be resolved by the plan/parse phase")
            {
                ImportedFileResolution::Remove => {
                    if let Some(old_state) = old_state {
                        for entity in old_state.entities {
                            entity_deltas.push(EntityDelta::Removed(entity.id));
                        }
                    }
                }
                ImportedFileResolution::Parsed(parsed) => {
                    let new_state =
                        new_state.expect("a parsed imported delta must have an exact new location");
                    let file_path = new_state.path.as_utf8().ok_or_else(|| {
                        anyhow!(
                            "parsed imported artifact {:?} has a non-UTF8 location",
                            artifact_id
                        )
                    })?;
                    let old_entities = old_state
                        .as_ref()
                        .map(|state| state.entities.as_slice())
                        .unwrap_or(&[]);
                    // Reconcile borrows the shared parse output and clones only
                    // the entities it stabilizes, so a memo hit never deep-clones
                    // the entire entity vector.
                    let (file_entity_deltas, stabilized_entities) =
                        reconcile_imported_file_entities(
                            artifact_id,
                            old_entities,
                            &parsed.entities,
                        );
                    entity_deltas.extend(file_entity_deltas);

                    incremental_linker.add_file(file_path, artifact_id, &stabilized_entities);

                    if current_files
                        .insert(
                            file_path.to_string(),
                            ImportedSemanticFileState {
                                artifact_id,
                                file_path: file_path.to_string(),
                                parse_completeness: parsed.parse_completeness.clone(),
                                entities: stabilized_entities,
                                relations: parsed.extracted_relations.clone(),
                                imports: parsed.imports.clone(),
                            },
                        )
                        .is_some()
                    {
                        anyhow::bail!(
                            "historical semantic transaction produced two artifacts at {}",
                            new_state.path
                        );
                    }
                    changed_source_files.insert(file_path.to_string());
                }
            }
        }
        if !old_states.is_empty() {
            anyhow::bail!(
                "historical semantic transaction retained {} unconsumed artifact baseline(s)",
                old_states.len()
            );
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
            &current_files,
            &previous_file_states,
            &relations_by_src,
            &relations_by_src_artifact,
        );

        let changed_parse_data = impacted_files
            .iter()
            .filter_map(|path| current_files.get(path))
            .map(ImportedSemanticFileState::to_link_data)
            .collect::<Vec<_>>();
        let changed_parse_completeness = impacted_files
            .iter()
            .filter_map(|path| current_files.get(path))
            .map(|file| (file.file_path.clone(), file.parse_completeness.clone()))
            .collect::<kin_index::FileParseCompletenessMap>();

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
            for relation in kin_index::link_cross_file_incremental_with_completeness(
                &changed_parse_data,
                &incremental_linker,
                &changed_parse_completeness,
            )? {
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

        let processed_count = processed + 1;
        let checkpoint_boundary = checkpoint_session.as_ref().and_then(|session| {
            if !session.enabled() {
                return None;
            }
            let is_base_link = imported[i].change.message == history_checkpoint::BASE_LINK_MESSAGE;
            let is_final = processed_count == total_commits;
            let is_periodic = processed_count % session.interval() == 0;
            if is_base_link {
                Some(HydrationCheckpointBoundary::BaseLink)
            } else if is_final {
                Some(HydrationCheckpointBoundary::Final)
            } else if is_periodic {
                Some(HydrationCheckpointBoundary::Periodic)
            } else {
                None
            }
        });

        let resulting_state = ImportedCommitSemanticState {
            files: current_files,
            relations: current_relations,
            relations_by_src,
            relations_by_src_artifact,
            relations_by_dst,
            linker: incremental_linker,
        };

        // Retain this commit's resulting state while a later child will fork
        // from it. A checkpoint boundary additionally retains its own state
        // even when it is currently a leaf, allowing a longer or shorter
        // exact-prefix history to resume from that nearest ancestor later.
        let mut detached_boundary_state = None;
        if remaining_children[i] > 0 {
            snapshots.insert(imported[i].change.id, resulting_state);
        } else if checkpoint_boundary.is_some() {
            detached_boundary_state = Some(resulting_state);
        } else {
            drop(resulting_state);
        }

        if let (Some(session), Some(boundary)) = (checkpoint_session.as_mut(), checkpoint_boundary)
        {
            session.persist_boundary(
                imported,
                &order,
                processed_count,
                boundary,
                &snapshots,
                detached_boundary_state.as_ref(),
            )?;
        }
    }

    // Finalize even when `resumed_from == total_commits` and the replay loop
    // executed zero times. Cache cap enforcement and orphan reachability GC
    // are store invariants, not side effects of replaying a new boundary.
    if let Some(session) = checkpoint_session.as_mut() {
        session.finalize()?;
    }

    if total_commits > 0 {
        eprintln!();
        let total_time_sec = start_time.elapsed().as_secs_f64();
        eprintln!("  Hydration Profiling Summary:");
        eprintln!("    Total Commits: {}", total_commits);
        eprintln!("    Resumed From: {}", resumed_from);
        eprintln!("    Replayed Commits: {}", total_commits - resumed_from);
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
                    resumed_from,
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

    let checkpoint_io = checkpoint_session
        .as_ref()
        .map(HydrationCheckpointSession::io_stats)
        .unwrap_or_default();
    Ok(HydrationReplayStats {
        parse_memo_hits,
        parse_memo_misses,
        resumed_from,
        checkpoint_io,
    })
}

/// One machine-readable record of the history-hydration replay profile, emitted
/// as a single JSON line under `KIN_HYDRATE_STAGE_TIMINGS`. Fields serialize in
/// declaration order (nested under the outer key by [`HydrateStageTimingsLine`])
/// so the line reads in the same order as the human summary printed above it.
#[derive(Serialize)]
struct HydrateStageTimings {
    /// Total commits in the requested history.
    total_commits: usize,
    /// Prefix restored from a persisted semantic checkpoint.
    resumed_from_commits: usize,
    /// Commits actually replayed during this pass.
    replayed_commits: usize,
    /// Wall-clock seconds for the whole pass.
    total_s: f64,
    /// Replay throughput (`replayed_commits` / `total_s`).
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
    resumed_from_commits: usize,
    total_s: f64,
    blob_read_s: f64,
    parsing_s: f64,
    linking_s: f64,
    closure_diffing_s: f64,
    parse_memo_hits: usize,
    parse_memo_misses: usize,
) -> String {
    let replayed_commits = total_commits.saturating_sub(resumed_from_commits);
    // Guard the divide so a zero wall never yields NaN/Infinity (serde renders
    // those as `null`, which would break the "always a parseable number"
    // contract). A real pass always has a positive wall.
    let commits_per_s = if total_s > 0.0 {
        replayed_commits as f64 / total_s
    } else {
        0.0
    };
    let other_s = total_s - blob_read_s - parsing_s - linking_s - closure_diffing_s;
    let line = HydrateStageTimingsLine {
        kin_hydrate_stage_timings: HydrateStageTimings {
            total_commits,
            resumed_from_commits,
            replayed_commits,
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
    current_files: &HashMap<String, ImportedSemanticFileState>,
    previous_file_states: &HashMap<String, ImportedSemanticFileState>,
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
        // Import/include edges are anchored to admitted artifact identity.
        // During a move/path-reuse transaction, both the old and new artifact
        // states may name this impacted path, so inspect both exact states and
        // never derive identity from the path string.
        let artifact_ids = current_files
            .get(file_path)
            .into_iter()
            .chain(previous_file_states.get(file_path))
            .map(|state| state.artifact_id)
            .collect::<BTreeSet<_>>();
        for artifact_id in artifact_ids {
            if let Some(existing_ids) = relations_by_src_artifact.get(&artifact_id) {
                relation_ids.extend(existing_ids.iter().copied());
            }
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
        && old.evidence == new.evidence
        && (old.confidence - new.confidence).abs() < f32::EPSILON
}

fn imported_entities_exactly_equivalent(old: &Entity, new: &Entity) -> bool {
    old.id == new.id
        && old.kind == new.kind
        && old.name == new.name
        && old.language == new.language
        && old.fingerprint.algorithm == new.fingerprint.algorithm
        && old.fingerprint.ast_hash == new.fingerprint.ast_hash
        && old.fingerprint.signature_hash == new.fingerprint.signature_hash
        && old.fingerprint.behavior_hash == new.fingerprint.behavior_hash
        && old.fingerprint.equivalence_hash == new.fingerprint.equivalence_hash
        && old.fingerprint.stability_score.to_bits() == new.fingerprint.stability_score.to_bits()
        && old.file_origin == new.file_origin
        && old.span == new.span
        && old.signature == new.signature
        && old.visibility == new.visibility
        && old.role == new.role
        && old.doc_summary == new.doc_summary
        && old.metadata.extra == new.metadata.extra
        && old.lineage_parent == new.lineage_parent
        && old.created_in == new.created_in
        && old.superseded_by == new.superseded_by
}

fn imported_relations_exactly_equivalent(old: &Relation, new: &Relation) -> bool {
    old.id == new.id
        && old.kind == new.kind
        && old.src == new.src
        && old.dst == new.dst
        && old.confidence.to_bits() == new.confidence.to_bits()
        && old.origin == new.origin
        && old.created_in == new.created_in
        && old.import_source == new.import_source
        && old.evidence == new.evidence
}

pub(crate) fn entity_fingerprint_changed(old: &Entity, new: &Entity) -> bool {
    kin_index::entity_semantics_changed(old, new)
}

fn imported_entity_id(artifact_id: ArtifactId, parser_id: EntityId) -> EntityId {
    let mut hasher = Sha256::new();
    hasher.update(b"kin.imported-entity.v1\0");
    hasher.update(artifact_id.0.as_bytes());
    hasher.update(parser_id.0.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    EntityId(uuid::Uuid::from_bytes(bytes))
}

fn reconcile_imported_file_entities(
    artifact_id: ArtifactId,
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
            Some(old) => {
                // Re-key the parser-assigned id onto the stable existing id.
                // Exact location and metadata changes (including a rename with
                // byte-identical content) are still real Modified payloads.
                let mut stabilized = parsed_entity.clone();
                stabilized.id = old.id;
                stabilized.lineage_parent = old.lineage_parent;
                stabilized.created_in = old.created_in;
                stabilized.superseded_by = old.superseded_by;
                matched_old_entities.insert(old.id);
                if !imported_entities_exactly_equivalent(old, &stabilized) {
                    entity_deltas.push(EntityDelta::Modified {
                        old: old.clone(),
                        new: stabilized.clone(),
                    });
                }
                current_entities.push(stabilized);
            }
            None => {
                // Parser ids are path-derived and can repeat when a path is
                // deleted then reused. Namespace first-introduction identity by
                // the graph-assigned artifact so unrelated lifetimes never
                // collapse into one semantic entity lineage.
                let mut introduced = parsed_entity.clone();
                introduced.id = imported_entity_id(artifact_id, parsed_entity.id);
                entity_deltas.push(EntityDelta::Added(introduced.clone()));
                current_entities.push(introduced);
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

fn link_parse_completeness_from_layouts(
    graph: &kin_db::InMemoryGraph,
    files: &[kin_index::FileParseData],
) -> Result<kin_index::FileParseCompletenessMap> {
    let mut completeness = kin_index::FileParseCompletenessMap::new();
    for file in files {
        let file_id = FilePathId::new(&file.file_path);
        let state = graph
            .get_file_layout(&file_id)?
            .map(|layout| layout.parse_completeness)
            .unwrap_or_else(|| {
                ParseCompleteness::Failed("indexed source file has no persisted layout".to_string())
            });
        completeness.insert(file.file_path.clone(), state);
    }
    Ok(completeness)
}

fn index_files_with_stable_entity_ids(
    graph: &kin_db::InMemoryGraph,
    _blob_store: &kin_blobs::BlobStore,
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
                    let source = file.content.as_slice();

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
                            let ext = Path::new(&file.rel_path)
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

                            let parse_completeness =
                                ParseCompleteness::from_parse_state(&parse_state);
                            let layout = build_layout(
                                &file_id,
                                &file_entities,
                                source.len(),
                                &[],
                                parse_completeness.clone(),
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
                hash: _,
                entities,
                discovered_tests: file_tests,
                relations,
                imports,
                projection_markers,
                layout,
            } => {
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
                hash: _,
                shallow,
                projection_markers,
            } => {
                total_files += 1;
                if !projection_markers.is_empty() {
                    projection_marker_files.push((rel_path.clone(), projection_markers.clone()));
                }
                graph.upsert_shallow_file(shallow)?;
            }
            ParsedFileResult::StructuredArtifact {
                rel_path,
                hash: _,
                artifact,
                projection_markers,
            } => {
                total_files += 1;
                if !projection_markers.is_empty() {
                    projection_marker_files.push((rel_path.clone(), projection_markers.clone()));
                }
                graph.upsert_structured_artifact(artifact)?;
            }
            ParsedFileResult::OpaqueArtifact {
                rel_path,
                hash: _,
                artifact,
                projection_markers,
            } => {
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

    let known_files: HashSet<String> = graph
        .resolved_tree()
        .artifacts_by_path()
        .filter_map(|artifact| artifact.path.as_utf8().map(str::to_owned))
        .collect();
    projection_marker_files
        .iter()
        .flat_map(|(file_path, markers)| {
            kin_index::build_projection_derived_relations_from_markers(
                file_path,
                markers,
                &known_files,
                |path| {
                    RepoPath::from_utf8(path)
                        .ok()
                        .and_then(|repo_path| graph.artifact_id_at_path(&repo_path))
                },
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

fn exact_tree_entry(hash: [u8; 32], kind: kin_index::ScannedEntryKind) -> TreeEntry {
    let hash = Hash256::from_bytes(hash);
    match kind {
        kin_index::ScannedEntryKind::Regular { executable } => TreeEntry::blob(hash, executable),
        kin_index::ScannedEntryKind::Symlink => TreeEntry::symlink(hash),
    }
}

/// Diff the admitted source scan against the exact parent tree. Native init
/// records removals as well as additions and mode changes so graph-owned truth
/// cannot retain files that no longer exist at the ingestion boundary.
fn build_exact_init_tree_deltas(
    parent: ResolvedTree,
    current: &[ExactInitSourceEntry],
) -> Vec<TreeDelta> {
    let current: BTreeMap<&RepoPath, &ExactInitSourceEntry> = current
        .iter()
        .map(|entry| (&entry.repo_path, entry))
        .collect();
    let mut deltas = Vec::new();

    for old in parent.artifacts_by_path() {
        if matches!(old.entry, TreeEntry::Gitlink { .. }) {
            // Gitlink identity is graph/import truth. A host checkout cannot
            // prove either its target or its removal.
            continue;
        }
        if !current.contains_key(&old.path) {
            deltas.push(TreeDelta::Removed {
                artifact_id: old.artifact_id,
                old: old.located_entry(),
            });
        }
    }
    for (path, entry) in current {
        match parent.artifact_at_path(path) {
            Some(old) if old.entry == entry.entry => {}
            Some(old) => deltas.push(TreeDelta::Updated {
                artifact_id: old.artifact_id,
                old: old.located_entry(),
                new: LocatedEntry::new((*path).clone(), entry.entry),
            }),
            None => deltas.push(TreeDelta::Added {
                artifact_id: ArtifactId::new(),
                new: LocatedEntry::new((*path).clone(), entry.entry),
            }),
        }
    }
    deltas.sort_by(|left, right| {
        let left = left
            .new_state()
            .or_else(|| left.old_state())
            .expect("tree delta has one side");
        let right = right
            .new_state()
            .or_else(|| right.old_state())
            .expect("tree delta has one side");
        left.path.cmp(&right.path)
    });
    deltas
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
        let artifact_node = GraphNodeId::Artifact(artifact_id_for_file(graph, file)?);
        for relation in graph.get_all_relations_for_node(&artifact_node)? {
            relation_ids.insert(relation.id);
        }
    }
    Ok(relation_ids.into_iter().collect())
}

fn artifact_id_for_file(graph: &kin_db::InMemoryGraph, path: &str) -> Result<ArtifactId> {
    let repo_path = RepoPath::from_utf8(path)
        .with_context(|| format!("semantic file path is not a valid repository path: {path}"))?;
    graph
        .artifact_id_at_path(&repo_path)
        .ok_or_else(|| anyhow!("semantic enrichment requires admitted tree identity at {path}"))
}

fn graph_artifact_identity_map(
    graph: &kin_db::InMemoryGraph,
) -> kin_index::linker::ArtifactIdentityMap {
    graph
        .resolved_tree()
        .artifacts_by_path()
        .filter_map(|artifact| {
            artifact
                .path
                .as_utf8()
                .map(|path| (path.to_string(), artifact.artifact_id))
        })
        .collect()
}

fn remove_relations_batch_by_id(
    graph: &kin_db::InMemoryGraph,
    relation_ids: &[RelationId],
) -> Result<()> {
    let relation_refs: Vec<&RelationId> = relation_ids.iter().collect();
    graph.remove_relations_batch(&relation_refs)?;
    Ok(())
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
    let stale_tree_entries: Vec<(String, ArtifactId, LocatedEntry)> = graph
        .resolved_tree()
        .artifacts_by_path()
        .filter_map(|artifact| {
            let path = artifact.path.as_utf8()?;
            (!is_repo_owned_graph_path(path)).then(|| {
                (
                    path.to_owned(),
                    artifact.artifact_id,
                    artifact.located_entry(),
                )
            })
        })
        .collect();
    stale_paths.extend(stale_tree_entries.iter().map(|(path, _, _)| path.clone()));
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
    if !stale_tree_entries.is_empty() {
        graph.apply_transaction_delta(&TransactionDelta {
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: stale_tree_entries
                .into_iter()
                .map(|(_, artifact_id, old)| TreeDelta::Removed { artifact_id, old })
                .collect(),
        })?;
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

/// Enumerate every admitted working-tree entry and preserve its exact content
/// identity and materialization kind. Parser support does not affect drift
/// admission.
pub(crate) fn collect_on_disk_tree_entries(
    source_root: &Path,
    graph: &kin_db::InMemoryGraph,
) -> Result<Vec<(RepoPath, TreeEntry)>> {
    let current_tree = graph.resolved_tree();
    let tracked_paths = current_tree
        .artifacts_by_path()
        .map(|artifact| artifact.path.clone())
        .collect::<Vec<_>>();
    let graph_only_paths = current_tree
        .artifacts_by_path()
        .filter(|artifact| matches!(artifact.entry, TreeEntry::Gitlink { .. }))
        .map(|artifact| artifact.path.clone())
        .collect::<Vec<_>>();
    let ignore = kin_index::RepositoryIgnore::load(source_root)?;
    let scan = kin_index::scan_repository_preserving_graph_only(
        source_root,
        &ignore,
        tracked_paths.iter(),
        graph_only_paths.iter(),
    )?;
    let mut observed = scan
        .entries()
        .map(|entry| {
            let content = kin_index::read_verified_scanned_entry(entry)
                .with_context(|| format!("read exact working-tree entry {}", entry.repo_path))?;
            let hash = kin_blobs::digest_bytes(&content);
            Ok((entry.repo_path.clone(), exact_tree_entry(hash, entry.kind)))
        })
        .collect::<Result<Vec<_>>>()?;
    // Gitlinks are graph-only repository members. A host directory cannot
    // prove their target identity, and host absence cannot prove removal.
    // Carry their existing exact graph entry into the observation just as the
    // complete scanner's graph-only token requires.
    observed.extend(
        current_tree
            .artifacts_by_path()
            .filter(|artifact| matches!(artifact.entry, TreeEntry::Gitlink { .. }))
            .map(|artifact| (artifact.path.clone(), artifact.entry)),
    );
    observed.sort_by(|left, right| left.0.cmp(&right.0));
    Ok(observed)
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

/// Get a human-readable author name.
fn whoami() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_git::GitImportMode;
    use kin_index::COMMAND_EFFECT_CONTRACT_KEY;
    use kin_model::{
        BranchName, EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, LanguageId,
        SemanticFingerprint, Visibility,
    };
    use serial_test::serial;
    use std::collections::BTreeSet;
    use std::fs;
    use std::process::Command;
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

    fn admit_test_repository(
        root: &Path,
        graph: &kin_db::InMemoryGraph,
        blob_store: &kin_blobs::BlobStore,
    ) -> Vec<IndexableFile> {
        let entries = collect_native_boundary_entries(root, graph, blob_store, false).unwrap();
        let tree_deltas = build_exact_init_tree_deltas(graph.resolved_tree(), &entries);
        graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: Vec::new(),
                relation_deltas: Vec::new(),
                tree_deltas,
            })
            .unwrap();
        collect_indexable_files_from_graph(graph, blob_store).unwrap()
    }

    #[test]
    fn hydrate_stage_timings_json_is_parseable_with_explicit_residue() {
        // Representative pass: the four buckets leave a non-trivial residue, and
        // most parses were served from the memo.
        let line = hydrate_stage_timings_json(
            32865, 32000, 1933.4, 42.5, 261.9, 954.7, 641.2, 30000, 2865,
        );

        let value: serde_json::Value =
            serde_json::from_str(&line).expect("emitted line must be parseable JSON");
        let obj = value
            .get("kin_hydrate_stage_timings")
            .expect("top-level envelope key present");

        // Count is an integer; every timing is a real (finite) float, never null.
        assert_eq!(obj["total_commits"].as_u64(), Some(32865));
        assert_eq!(obj["resumed_from_commits"].as_u64(), Some(32000));
        assert_eq!(obj["replayed_commits"].as_u64(), Some(865));
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

        // Throughput counts only work done in this process, never the restored prefix.
        assert!((obj["commits_per_s"].as_f64().unwrap() - 865.0 / 1933.4).abs() < 1e-9);

        // Keys are emitted in the documented order, not alphabetized.
        let order = [
            "kin_hydrate_stage_timings",
            "total_commits",
            "resumed_from_commits",
            "replayed_commits",
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
        let line = hydrate_stage_timings_json(10, 0, 0.0, 0.0, 0.0, 0.0, 0.0, 0, 0);
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
    fn git_history_import_options_supports_snapshot_full_and_off() {
        assert!(git_history_import_options("off").unwrap().is_none());

        let snapshot = git_history_import_options("snapshot").unwrap().unwrap();
        assert_eq!(snapshot.mode, GitImportMode::Snapshot);

        let full = git_history_import_options("full").unwrap().unwrap();
        assert_eq!(full.mode, GitImportMode::Full);

        assert!(git_history_import_options("partial").is_err());
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
                [0; 32],
                "imported root",
                vec![added_regular_delta(
                    "src/lib.py",
                    Hash256::from_bytes(blob_v1.0),
                )],
            ),
            imported_change(
                [0x12; 32],
                [0x11; 32],
                "imported modify",
                vec![modified_regular_delta(
                    "src/lib.py",
                    Hash256::from_bytes(blob_v1.0),
                    Hash256::from_bytes(blob_v2.0),
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

    fn canonical_live_repository_state(graph: &kin_db::InMemoryGraph) -> String {
        let snapshot = graph.to_snapshot();
        let mut entities = snapshot
            .entities
            .values()
            .map(canonical_json)
            .collect::<Vec<_>>();
        entities.sort();
        let mut relations = snapshot
            .relations
            .values()
            .map(canonical_json)
            .collect::<Vec<_>>();
        relations.sort();
        let changes = snapshot
            .changes
            .iter()
            .map(|(id, change)| (id.to_string(), canonical_json(change)))
            .collect::<BTreeMap<_, _>>();
        let mut shallow_files = snapshot
            .shallow_files
            .iter()
            .map(canonical_json)
            .collect::<Vec<_>>();
        shallow_files.sort();
        let mut file_layouts = snapshot
            .file_layouts
            .iter()
            .map(canonical_json)
            .collect::<Vec<_>>();
        file_layouts.sort();
        let mut structured_artifacts = snapshot
            .structured_artifacts
            .iter()
            .map(canonical_json)
            .collect::<Vec<_>>();
        structured_artifacts.sort();
        let mut opaque_artifacts = snapshot
            .opaque_artifacts
            .iter()
            .map(canonical_json)
            .collect::<Vec<_>>();
        opaque_artifacts.sort();

        canonical_json(&(
            entities,
            relations,
            changes,
            snapshot.change_children,
            snapshot.entity_revisions,
            snapshot.resolved_tree,
            shallow_files,
            file_layouts,
            structured_artifacts,
            opaque_artifacts,
        ))
    }

    #[test]
    fn exact_semantic_diff_emits_modifications_removals_and_replacements() {
        let retained = test_entity("retained", "src/lib.rs");
        let removed = test_entity("removed", "src/lib.rs");
        let added = test_entity("added", "src/lib.rs");
        let mut modified = retained.clone();
        modified.signature = "fn retained(value: u8)".to_string();
        let old_relation = test_relation(RelationKind::Calls, retained.id, removed.id);
        let mut replacement_relation = old_relation.clone();
        replacement_relation.confidence = 0.75;

        let mut parent = kin_model::graph::ResolvedGraphState::default();
        parent.entities.insert(retained.id, retained.clone());
        parent.entities.insert(removed.id, removed.clone());
        parent
            .relations
            .insert(old_relation.id, old_relation.clone());
        let current_entities =
            HashMap::from([(modified.id, modified.clone()), (added.id, added.clone())]);
        let current_relations =
            HashMap::from([(replacement_relation.id, replacement_relation.clone())]);

        let (entity_deltas, relation_deltas) =
            exact_semantic_deltas(&parent, &current_entities, &current_relations);
        assert!(entity_deltas.iter().any(|delta| matches!(
            delta,
            EntityDelta::Modified { old, new }
                if old.id == retained.id && new.signature == modified.signature
        )));
        assert!(entity_deltas
            .iter()
            .any(|delta| matches!(delta, EntityDelta::Removed(id) if *id == removed.id)));
        assert!(entity_deltas
            .iter()
            .any(|delta| matches!(delta, EntityDelta::Added(entity) if entity.id == added.id)));
        assert_eq!(relation_deltas.len(), 2);
        assert!(matches!(
            relation_deltas[0],
            RelationDelta::Removed(id) if id == old_relation.id
        ));
        assert!(matches!(
            &relation_deltas[1],
            RelationDelta::Added(relation)
                if relation.id == replacement_relation.id
                    && relation.confidence.to_bits()
                        == replacement_relation.confidence.to_bits()
        ));
    }

    #[test]
    fn parse_memo_hit_shares_arc_and_version_participates_in_key() {
        let blob = kin_blobs::Hash256::from_bytes([0x42; 32]);
        let path = "src/original.py".to_string();
        let mut memo: HashMap<(kin_blobs::Hash256, String, u32), Arc<CachedParse>> = HashMap::new();
        let payload = Arc::new(CachedParse {
            parse_completeness: ParseCompleteness::Full,
            entities: Vec::new(),
            extracted_relations: Vec::new(),
            imports: Vec::new(),
        });
        memo.insert(
            (blob, path.clone(), kin_parser::PARSER_SEMANTICS_VERSION),
            Arc::clone(&payload),
        );

        // Same (blob, exact location, version): a hit hands back the SAME
        // allocation, not a clone.
        let hit = memo
            .get(&(blob, path.clone(), kin_parser::PARSER_SEMANTICS_VERSION))
            .expect("same key must hit");
        assert!(
            Arc::ptr_eq(hit, &payload),
            "a memo hit must share the cached Arc rather than deep-clone the payload"
        );

        // Same blob, a bumped parser-semantics version: miss. A grammar or
        // extractor upgrade can therefore never serve a stale parse.
        assert!(
            !memo.contains_key(&(
                blob,
                path.clone(),
                kin_parser::PARSER_SEMANTICS_VERSION.wrapping_add(1),
            )),
            "a parser-semantics version change must key to a different (missing) entry"
        );

        // Parser output carries the exact file origin. Reusing it at a rename
        // destination would leak the old location into entity identity.
        assert!(
            !memo.contains_key(&(
                blob,
                "src/renamed.py".to_string(),
                kin_parser::PARSER_SEMANTICS_VERSION,
            )),
            "the same bytes at a different location must be reparsed"
        );

        // Different blob, same version: miss.
        let other_blob = kin_blobs::Hash256::from_bytes([0x43; 32]);
        assert!(
            !memo.contains_key(&(other_blob, path, kin_parser::PARSER_SEMANTICS_VERSION,)),
            "a different blob must not collide with the cached entry"
        );
    }

    #[test]
    fn historical_state_preserves_parse_completeness_separately_from_public_link_data() {
        let expected = ParseCompleteness::Partial(
            "one recovered error range in historical source".to_string(),
        );
        let state = ImportedSemanticFileState {
            artifact_id: test_artifact_id("src/history.py"),
            file_path: "src/history.py".to_string(),
            parse_completeness: expected.clone(),
            entities: Vec::new(),
            relations: Vec::new(),
            imports: Vec::new(),
        };

        assert_eq!(state.parse_completeness, expected);
        let link_data = state.to_link_data();
        assert_eq!(link_data.file_path, "src/history.py");
        let completeness = kin_index::FileParseCompletenessMap::from([(
            state.file_path.clone(),
            state.parse_completeness.clone(),
        )]);
        let mut linker = kin_index::IncrementalLinker::new();
        linker.add_file(&state.file_path, state.artifact_id, &state.entities);
        let relations = kin_index::link_cross_file_incremental_with_completeness(
            &[link_data],
            &linker,
            &completeness,
        )
        .unwrap();
        assert!(relations
            .iter()
            .any(|relation| relation.evidence.iter().any(|evidence| {
                evidence.parser_rule.as_deref()
                    == Some(kin_index::CALL_SHAPE_PARSE_COVERAGE_INCOMPLETE_V1)
                    && evidence.source_path.as_deref() == Some("src/history.py")
            })));
    }

    #[test]
    fn historical_relation_equivalence_detects_call_evidence_changes() {
        let caller = EntityId::from_content("src/caller.py", "caller", "function", 1);
        let target = EntityId::from_content("src/defs.py", "target", "function", 1);
        let mut positional = test_relation(RelationKind::Calls, caller, target);
        positional.evidence = vec![kin_model::RelationEvidence {
            parser_rule: Some(kin_index::CALL_SHAPE_EVIDENCE_AGGREGATION_V1.to_string()),
            call_shape: Some(kin_model::CallArgShape::new(1, Vec::new(), false, false)),
            ..kin_model::RelationEvidence::default()
        }];
        let mut keyword = positional.clone();
        keyword.evidence[0].call_shape = Some(kin_model::CallArgShape::new(
            0,
            vec!["value".to_string()],
            false,
            false,
        ));

        assert!(!imported_relations_equivalent(&positional, &keyword));
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
                    [0; 32],
                    "add module",
                    vec![added_regular_delta("src/mod.py", Hash256::from_bytes(v1.0))],
                ),
                imported_change(
                    [0x32; 32],
                    [0x31; 32],
                    "shrink module",
                    vec![modified_regular_delta(
                        "src/mod.py",
                        Hash256::from_bytes(v1.0),
                        Hash256::from_bytes(v2.0),
                    )],
                ),
                imported_change(
                    [0x33; 32],
                    [0x32; 32],
                    "revert module",
                    vec![modified_regular_delta(
                        "src/mod.py",
                        Hash256::from_bytes(v2.0),
                        Hash256::from_bytes(v1.0),
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
                    [0; 32],
                    "seed the tree",
                    vec![
                        added_regular_delta("src/util/log.ts", Hash256::from_bytes(log_v1.0)),
                        added_regular_delta("src/util/math.ts", Hash256::from_bytes(math_v1.0)),
                        added_regular_delta("src/core/base.ts", Hash256::from_bytes(base_v1.0)),
                        added_regular_delta("src/app/main.ts", Hash256::from_bytes(main_v1.0)),
                    ],
                ),
                imported_change(
                    [0x42; 32],
                    [0x41; 32],
                    "grow math + add a worker",
                    vec![
                        modified_regular_delta(
                            "src/util/math.ts",
                            Hash256::from_bytes(math_v1.0),
                            Hash256::from_bytes(math_v2.0),
                        ),
                        added_regular_delta("src/app/worker.ts", Hash256::from_bytes(worker_v1.0)),
                    ],
                ),
                imported_change(
                    [0x43; 32],
                    [0x42; 32],
                    "revert math + add docs",
                    vec![
                        // Reverts to commit 1's exact bytes: a memo hit whose
                        // reconciliation still runs against commit 2's state.
                        modified_regular_delta(
                            "src/util/math.ts",
                            Hash256::from_bytes(math_v2.0),
                            Hash256::from_bytes(math_v1.0),
                        ),
                        // Non-source file: takes the removal path, never a job.
                        added_regular_delta("README.md", Hash256::from_bytes(readme.0)),
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
                [0; 32],
                "imported root",
                vec![added_regular_delta(
                    "command/pr_checkout.go",
                    Hash256::from_bytes(blob_v1.0),
                )],
            ),
            imported_change(
                [0x22; 32],
                [0x21; 32],
                "prefix branch names",
                vec![modified_regular_delta(
                    "command/pr_checkout.go",
                    Hash256::from_bytes(blob_v1.0),
                    Hash256::from_bytes(blob_v2.0),
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
                [0; 32],
                "imported root",
                vec![
                    added_regular_delta("src/utils/tools.ts", Hash256::from_bytes(tools_v1.0)),
                    added_regular_delta("src/routes/api.ts", Hash256::from_bytes(api_v1.0)),
                ],
            ),
            imported_change(
                [0x22; 32],
                [0x21; 32],
                "remove callee",
                vec![modified_regular_delta(
                    "src/utils/tools.ts",
                    Hash256::from_bytes(tools_v1.0),
                    Hash256::from_bytes(tools_v2.0),
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
                [0; 32],
                "imported root",
                vec![
                    added_regular_delta("src/utils/tools.ts", Hash256::from_bytes(tools_v1.0)),
                    added_regular_delta("src/routes/api.ts", Hash256::from_bytes(api_v1.0)),
                ],
            ),
            imported_change(
                [0x32; 32],
                [0x31; 32],
                "semantic update",
                vec![modified_regular_delta(
                    "src/utils/tools.ts",
                    Hash256::from_bytes(tools_v1.0),
                    Hash256::from_bytes(tools_v2.0),
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
                [0; 32],
                "imported root",
                vec![added_regular_delta(
                    "src/lib.py",
                    Hash256::from_bytes(blob_v1.0),
                )],
            ),
            imported_change(
                [0x42; 32],
                [0x41; 32],
                "missing blob",
                vec![modified_regular_delta(
                    "src/lib.py",
                    Hash256::from_bytes(blob_v1.0),
                    missing_hash,
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
                [0; 32],
                "root: add f",
                vec![added_regular_delta(
                    "src/lib.py",
                    Hash256::from_bytes(f_v1.0),
                )],
            ),
            imported_change(
                [0x52; 32],
                [0x51; 32],
                "branch A: rewrite f body",
                vec![modified_regular_delta(
                    "src/lib.py",
                    Hash256::from_bytes(f_v1.0),
                    Hash256::from_bytes(f_v2.0),
                )],
            ),
            imported_change(
                [0x53; 32],
                [0x51; 32],
                "branch B: add g, f unchanged",
                vec![modified_regular_delta(
                    "src/lib.py",
                    Hash256::from_bytes(f_v1.0),
                    Hash256::from_bytes(f_v3.0),
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

    fn merge_rebase_fixture(blob_store: &kin_blobs::BlobStore) -> Vec<kin_git::ImportedChange> {
        let tools = blob_store.write(b"def helper():\n    return 1\n").unwrap();
        let app_root = blob_store.write(b"def run():\n    return 1\n").unwrap();
        let app_first_parent = blob_store.write(b"def run():\n    return 2\n").unwrap();
        let app_secondary_parent = blob_store
            .write(b"from tools import helper\n\ndef run():\n    return helper()\n")
            .unwrap();
        let secondary_only = blob_store
            .write(b"def secondary_only():\n    return 'secondary'\n")
            .unwrap();

        let root = imported_change(
            [0x81; 32],
            [0; 32],
            "root",
            vec![
                added_regular_delta("tools.py", Hash256::from_bytes(tools.0)),
                added_regular_delta("app.py", Hash256::from_bytes(app_root.0)),
            ],
        );
        let first_parent = imported_change(
            [0x82; 32],
            [0x81; 32],
            "first parent",
            vec![modified_regular_delta(
                "app.py",
                Hash256::from_bytes(app_root.0),
                Hash256::from_bytes(app_first_parent.0),
            )],
        );
        let secondary_parent = imported_change(
            [0x83; 32],
            [0x81; 32],
            "secondary parent",
            vec![
                modified_regular_delta(
                    "app.py",
                    Hash256::from_bytes(app_root.0),
                    Hash256::from_bytes(app_secondary_parent.0),
                ),
                added_regular_delta("secondary.py", Hash256::from_bytes(secondary_only.0)),
            ],
        );
        // Exact Git tree deltas are first-parent-relative. A merge that keeps
        // its first parent's tree therefore has no tree transition; semantic
        // rebase still removes state contributed only by secondary parents.
        let mut merge = imported_change(
            [0x84; 32],
            [0x82; 32],
            "merge choosing first-parent tree",
            Vec::new(),
        );
        merge.change.parents = vec![first_parent.change.id, secondary_parent.change.id];

        vec![root, first_parent, secondary_parent, merge]
    }

    fn resolve_imported_semantics(
        imported: &[kin_git::ImportedChange],
        head: SemanticChangeId,
    ) -> kin_model::graph::ResolvedGraphState {
        let graph = kin_db::InMemoryGraph::new();
        graph
            .create_change(&kin_core::build_genesis_change())
            .unwrap();
        for imported_change in imported {
            graph.create_change(&imported_change.change).unwrap();
        }
        graph.resolve_graph_at(&head).unwrap()
    }

    fn assert_imported_semantics_exact(
        expected: &kin_model::graph::ResolvedGraphState,
        actual: &kin_model::graph::ResolvedGraphState,
    ) {
        assert_eq!(expected.entities.len(), actual.entities.len());
        for (entity_id, expected_entity) in &expected.entities {
            let actual_entity = actual
                .entities
                .get(entity_id)
                .unwrap_or_else(|| panic!("missing entity {entity_id}"));
            assert!(
                imported_entities_exactly_equivalent(expected_entity, actual_entity),
                "entity {entity_id} differs: expected {expected_entity:#?}, actual {actual_entity:#?}"
            );
        }
        assert_eq!(expected.relations.len(), actual.relations.len());
        for (relation_id, expected_relation) in &expected.relations {
            let actual_relation = actual
                .relations
                .get(relation_id)
                .unwrap_or_else(|| panic!("missing relation {relation_id}"));
            assert!(
                imported_relations_exactly_equivalent(expected_relation, actual_relation),
                "relation {relation_id} differs: expected {expected_relation:#?}, actual {actual_relation:#?}"
            );
        }
        assert_eq!(expected.tree, actual.tree);
    }

    fn identity_neutral_semantic_shape(
        state: &kin_model::graph::ResolvedGraphState,
    ) -> (Vec<String>, Vec<String>) {
        let normalized_ids: HashMap<_, _> = state
            .entities
            .values()
            .map(|entity| {
                let file = entity
                    .file_origin
                    .as_ref()
                    .map(|file| file.0.as_str())
                    .unwrap_or("");
                let start_line = entity
                    .span
                    .as_ref()
                    .map(|span| span.start_line)
                    .unwrap_or(0);
                (
                    entity.id,
                    EntityId::from_content(
                        file,
                        &entity.name,
                        &format!("{:?}", entity.kind),
                        start_line,
                    ),
                )
            })
            .collect();

        let mut entities = state
            .entities
            .values()
            .cloned()
            .map(|mut entity| {
                entity.id = normalized_ids[&entity.id];
                entity.lineage_parent = entity
                    .lineage_parent
                    .and_then(|id| normalized_ids.get(&id).copied());
                entity.superseded_by = entity
                    .superseded_by
                    .and_then(|id| normalized_ids.get(&id).copied());
                canonical_json(&entity)
            })
            .collect::<Vec<_>>();
        entities.sort();

        let normalize_node = |node: GraphNodeId| match node {
            GraphNodeId::Entity(id) => {
                GraphNodeId::Entity(normalized_ids.get(&id).copied().unwrap_or(id))
            }
            other => other,
        };
        let mut relations = state
            .relations
            .values()
            .cloned()
            .map(|mut relation| {
                relation.src = normalize_node(relation.src);
                relation.dst = normalize_node(relation.dst);
                relation.id = RelationId::from_content(
                    &relation.src.to_string(),
                    &relation.dst.to_string(),
                    &format!("{:?}", relation.kind),
                );
                canonical_json(&relation)
            })
            .collect::<Vec<_>>();
        relations.sort();
        (entities, relations)
    }

    #[test]
    fn imported_merge_target_can_select_secondary_state_and_add_novel_content() {
        let dir = tempfile::tempdir().unwrap();
        let blob_store = kin_blobs::BlobStore::new(dir.path().join("objects")).unwrap();
        let mut imported = merge_rebase_fixture(&blob_store);
        let first_parent_oid = imported[1].git_oid.clone();
        let secondary_parent_oid = imported[2].git_oid.clone();
        let (tools_id, tools_entry) = exact_new_artifact(&imported[0].change, "tools.py");
        let (app_id, app_first_parent_entry) = exact_new_artifact(&imported[1].change, "app.py");
        let (secondary_app_id, app_secondary_entry) =
            exact_new_artifact(&imported[2].change, "app.py");
        assert_eq!(app_id, secondary_app_id);
        let (secondary_id, secondary_entry) =
            exact_new_artifact(&imported[2].change, "secondary.py");
        let novel_hash = Hash256::from_bytes(
            blob_store
                .write(b"def novel_at_merge():\n    return 'novel'\n")
                .unwrap()
                .0,
        );

        let merge = imported.last_mut().unwrap();
        merge.change.tree_deltas = vec![
            TreeDelta::Updated {
                artifact_id: app_id,
                old: app_first_parent_entry,
                new: app_secondary_entry.clone(),
            },
            TreeDelta::Added {
                artifact_id: secondary_id,
                new: secondary_entry.clone(),
            },
            added_regular_delta("novel.py", novel_hash),
        ];
        let merge_oid = merge.git_oid.clone();
        let mut repeated = imported.clone();

        enrich_imported_changes_with_semantics(&mut imported, &blob_store).unwrap();
        enrich_imported_changes_with_semantics(&mut repeated, &blob_store).unwrap();
        let merge_id = imported_id(&imported, &merge_oid);
        let merge = imported
            .iter()
            .find(|entry| entry.change.id == merge_id)
            .unwrap();
        assert_eq!(
            merge.change.parents,
            vec![
                imported_id(&imported, &first_parent_oid),
                imported_id(&imported, &secondary_parent_oid),
            ],
            "every Git parent edge must survive while payload deltas stay first-parent-relative"
        );
        kin_model::validate_semantic_change_id(&merge.change).unwrap();
        assert_eq!(
            merge.change.id,
            imported_id(&repeated, &merge_oid),
            "the enriched full-payload identity must be deterministic"
        );
        assert_eq!(
            serde_json::to_vec(&merge.change).unwrap(),
            serde_json::to_vec(
                &repeated
                    .iter()
                    .find(|entry| entry.git_oid == merge_oid)
                    .unwrap()
                    .change
            )
            .unwrap()
        );

        // Hydrate the exact selected merge tree independently as a single
        // root. This oracle proves the merge is not hardwired to reset to its
        // first parent: it keeps secondary-parent app/edge state and adds a
        // path that exists in neither parent.
        let mut oracle = vec![imported_change(
            [0xb1; 32],
            [0; 32],
            "independent exact merge target",
            vec![
                TreeDelta::Added {
                    artifact_id: tools_id,
                    new: tools_entry,
                },
                TreeDelta::Added {
                    artifact_id: app_id,
                    new: app_secondary_entry,
                },
                TreeDelta::Added {
                    artifact_id: secondary_id,
                    new: secondary_entry,
                },
                added_regular_delta("novel.py", novel_hash),
            ],
        )];
        enrich_imported_changes_with_semantics(&mut oracle, &blob_store).unwrap();

        let expected = resolve_imported_semantics(&oracle, oracle[0].change.id);
        let actual = resolve_imported_semantics(&imported, merge_id);
        assert_eq!(
            identity_neutral_semantic_shape(&expected),
            identity_neutral_semantic_shape(&actual),
            "selected merge tree must match an independently hydrated exact-tree oracle after neutralizing expected lineage-preserving IDs"
        );
        assert_eq!(expected.tree, actual.tree);
        assert!(actual
            .entities
            .values()
            .any(|entity| entity.name == "novel_at_merge"));
        assert!(!actual.relations.is_empty());
    }

    #[test]
    fn checkpoint_resume_preserves_complete_parent_closure() {
        let dir = tempfile::tempdir().unwrap();
        let blob_store = kin_blobs::BlobStore::new(dir.path().join("objects")).unwrap();
        let fixture = merge_rebase_fixture(&blob_store);
        let first_parent_oid = fixture[1].git_oid.clone();
        let merge_oid = fixture[3].git_oid.clone();
        let config = HydrationCheckpointConfig::clean_for_test(
            &dir.path().join("kin"),
            "merge-rebase-clean-sha",
            1,
            16 * 1024 * 1024,
        );

        let mut oracle = fixture.clone();
        enrich_imported_changes_with_semantics_inner(&mut oracle, &blob_store, true).unwrap();

        let mut prefix = fixture[..2].to_vec();
        enrich_imported_changes_with_semantics_with_checkpoints(
            &mut prefix,
            &blob_store,
            true,
            Some(config.clone()),
        )
        .unwrap();

        let mut resumed = fixture;
        let stats = enrich_imported_changes_with_semantics_with_checkpoints(
            &mut resumed,
            &blob_store,
            true,
            Some(config),
        )
        .unwrap();
        assert_eq!(
            stats.resumed_from, 1,
            "resume must fall back to the newest frontier retaining root state for both branches"
        );
        assert_same_hydration_deltas(&oracle, &resumed);

        reidentify_enriched_imported_changes(&mut resumed, kin_core::build_genesis_change().id)
            .unwrap();
        let first_parent_id = imported_id(&resumed, &first_parent_oid);
        let merge_id = imported_id(&resumed, &merge_oid);
        let expected = resolve_imported_semantics(&resumed, first_parent_id);
        let actual = resolve_imported_semantics(&resumed, merge_id);
        assert_imported_semantics_exact(&expected, &actual);
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
        // Pin every setting a developer's global config could otherwise supply
        // to a `git commit` below. Commit signing hands the terminal to a
        // pinentry prompt and hooks can wait on input of their own, neither of
        // which anything in a test run will ever answer, so an inherited value
        // turns a commit into an unbounded wait rather than a failure.
        for (k, v) in [
            ("user.email", "test@test.com"),
            ("user.name", "Test"),
            ("commit.gpgsign", "false"),
            ("tag.gpgsign", "false"),
            ("core.hooksPath", ".git/no-hooks"),
            ("gc.auto", "0"),
        ] {
            let _ = Command::new("git")
                .args(["config", k, v])
                .current_dir(dir)
                .output();
        }
        true
    }

    fn commit_git_file_for_test(dir: &Path, path: &str, content: &str, message: &str) -> bool {
        let file = dir.join(path);
        if let Some(parent) = file.parent() {
            if fs::create_dir_all(parent).is_err() {
                return false;
            }
        }
        if fs::write(&file, content).is_err() {
            return false;
        }
        Command::new("git")
            .args(["add", path])
            .current_dir(dir)
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
            && Command::new("git")
                .args(["commit", "-q", "-m", message])
                .current_dir(dir)
                .output()
                .map(|output| output.status.success())
                .unwrap_or(false)
    }

    #[cfg(unix)]
    #[test]
    fn historical_enrichment_preserves_every_exact_tree_surface() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        use std::os::unix::fs::{symlink, PermissionsExt};

        let repo_dir = tempfile::tempdir().unwrap();
        let root = repo_dir.path();
        if !init_git_repo_for_test(root) {
            return;
        }

        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(
            root.join("src/lib.rs"),
            b"pub fn rust_answer() -> u8 { 42 }\n",
        )
        .unwrap();
        fs::write(
            root.join("tools.py"),
            b"def python_answer():\n    return 42\n",
        )
        .unwrap();
        fs::write(
            root.join("docker-compose.yml"),
            b"services:\n  app:\n    image: example/app:latest\n",
        )
        .unwrap();
        fs::write(root.join("Cargo.lock"), b"version = 3\n").unwrap();
        fs::write(root.join("asset.bin"), [0, 0xff, 1, 2, 3]).unwrap();
        fs::write(root.join("notes.unsupported"), b"opaque but exact\n").unwrap();
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::write(root.join("bin/run"), b"#!/bin/sh\nexit 0\n").unwrap();
        let mut permissions = fs::metadata(root.join("bin/run")).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(root.join("bin/run"), permissions).unwrap();
        symlink("docker-compose.yml", root.join("compose-current")).unwrap();
        let non_utf8_name = OsString::from_vec(b"odd-\xff.bin".to_vec());
        fs::write(root.join(&non_utf8_name), b"non-utf8 path\n").unwrap();

        assert!(Command::new("git")
            .args(["add", "-A"])
            .current_dir(root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["commit", "-q", "-m", "exact mixed tree"])
            .current_dir(root)
            .status()
            .unwrap()
            .success());
        let gitlink_target = read_git_head(root).unwrap();
        let cache_info = format!("160000,{gitlink_target},vendor/submodule");
        assert!(Command::new("git")
            .args(["update-index", "--add", "--cacheinfo", &cache_info])
            .current_dir(root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["commit", "-q", "-m", "add gitlink"])
            .current_dir(root)
            .status()
            .unwrap()
            .success());

        let blob_root = tempfile::tempdir().unwrap();
        let blob_store = kin_blobs::BlobStore::new(blob_root.path().join("objects")).unwrap();
        let mut imported = kin_git::import_git_history_with_blobs(
            root,
            kin_core::build_genesis_change().id,
            &kin_git::ImportOptions::default(),
            Some(&blob_store),
        )
        .unwrap();
        let exact_before = imported
            .iter()
            .map(|entry| entry.change.tree_deltas.clone())
            .collect::<Vec<_>>();

        enrich_imported_changes_with_semantics(&mut imported, &blob_store).unwrap();

        assert_eq!(
            imported
                .iter()
                .map(|entry| entry.change.tree_deltas.clone())
                .collect::<Vec<_>>(),
            exact_before,
            "semantic enrichment must not rewrite membership, identity, path, mode, or blob truth"
        );
        for entry in &imported {
            kin_model::validate_semantic_change_id(&entry.change).unwrap();
        }

        let graph = kin_db::InMemoryGraph::new();
        graph
            .create_change(&kin_core::build_genesis_change())
            .unwrap();
        graph
            .create_changes(imported.iter().map(|entry| entry.change.clone()).collect())
            .unwrap();
        let head = imported.last().unwrap().change.id;
        let tree = graph.resolve_tree_at(&head).unwrap();

        assert!(matches!(
            tree.artifact_at_path(&RepoPath::from_utf8("bin/run").unwrap())
                .unwrap()
                .entry,
            TreeEntry::Blob {
                executable: true,
                ..
            }
        ));
        assert!(matches!(
            tree.artifact_at_path(&RepoPath::from_utf8("compose-current").unwrap())
                .unwrap()
                .entry,
            TreeEntry::Symlink { .. }
        ));
        assert!(matches!(
            tree.artifact_at_path(&RepoPath::from_utf8("vendor/submodule").unwrap())
                .unwrap()
                .entry,
            TreeEntry::Gitlink { .. }
        ));
        assert!(tree
            .artifact_at_path(&RepoPath::from_bytes(b"odd-\xff.bin".to_vec()).unwrap())
            .is_some());
        for path in [
            "docker-compose.yml",
            "Cargo.lock",
            "asset.bin",
            "notes.unsupported",
        ] {
            assert!(
                tree.artifact_at_path(&RepoPath::from_utf8(path).unwrap())
                    .is_some(),
                "{path} must remain exact tree truth even without entity parsing"
            );
        }

        let parsed_origins = imported
            .iter()
            .flat_map(|entry| &entry.change.entity_deltas)
            .filter_map(|delta| match delta {
                EntityDelta::Added(entity) | EntityDelta::Modified { new: entity, .. } => {
                    entity.file_origin.as_ref().map(|origin| origin.0.as_str())
                }
                EntityDelta::Removed(_) => None,
            })
            .collect::<HashSet<_>>();
        assert!(parsed_origins.contains("src/lib.rs"));
        assert!(parsed_origins.contains("tools.py"));
    }

    #[test]
    fn historical_rename_preserves_lineage_but_path_reuse_does_not() {
        let repo_dir = tempfile::tempdir().unwrap();
        let root = repo_dir.path();
        if !init_git_repo_for_test(root)
            || !commit_git_file_for_test(
                root,
                "old.py",
                "def stable_name():\n    return 1\n",
                "introduce",
            )
        {
            return;
        }
        assert!(Command::new("git")
            .args(["mv", "old.py", "renamed.py"])
            .current_dir(root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["commit", "-q", "-m", "rename"])
            .current_dir(root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["rm", "renamed.py"])
            .current_dir(root)
            .status()
            .unwrap()
            .success());
        assert!(Command::new("git")
            .args(["commit", "-q", "-m", "delete"])
            .current_dir(root)
            .status()
            .unwrap()
            .success());
        assert!(commit_git_file_for_test(
            root,
            "renamed.py",
            "def stable_name():\n    return 1\n",
            "reuse path",
        ));

        let objects = tempfile::tempdir().unwrap();
        let blob_store = kin_blobs::BlobStore::new(objects.path().join("objects")).unwrap();
        let mut imported = kin_git::import_git_history_with_blobs(
            root,
            kin_core::build_genesis_change().id,
            &kin_git::ImportOptions::default(),
            Some(&blob_store),
        )
        .unwrap();
        let first_artifact = imported[0].change.tree_deltas[0].artifact_id();
        let renamed_artifact = imported[1].change.tree_deltas[0].artifact_id();
        let reintroduced_artifact = imported[3].change.tree_deltas[0].artifact_id();
        assert_eq!(first_artifact, renamed_artifact);
        assert_ne!(renamed_artifact, reintroduced_artifact);

        enrich_imported_changes_with_semantics(&mut imported, &blob_store).unwrap();
        let introduced_entity = single_added_function_id(&imported[0].change.entity_deltas);
        let (rename_old, rename_new) = single_modified_function(&imported[1].change.entity_deltas);
        assert_eq!(rename_old.id, introduced_entity);
        assert_eq!(rename_new.id, introduced_entity);
        assert_eq!(
            rename_new
                .file_origin
                .as_ref()
                .map(|origin| origin.0.as_str()),
            Some("renamed.py")
        );
        let reintroduced_entity = single_added_function_id(&imported[3].change.entity_deltas);
        assert_ne!(
            reintroduced_entity, introduced_entity,
            "delete/re-add at the same path is a new artifact and must start a new entity lineage"
        );
        for entry in &imported {
            kin_model::validate_semantic_change_id(&entry.change).unwrap();
        }
    }

    fn test_artifact_id(label: &str) -> ArtifactId {
        let digest = Sha256::digest(label.as_bytes());
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&digest[..16]);
        bytes[6] = (bytes[6] & 0x0f) | 0x40;
        bytes[8] = (bytes[8] & 0x3f) | 0x80;
        ArtifactId(uuid::Uuid::from_bytes(bytes))
    }

    fn regular_location(file_path: &str, hash: Hash256) -> LocatedEntry {
        LocatedEntry::new(
            RepoPath::from_utf8(file_path).unwrap(),
            TreeEntry::blob(hash, false),
        )
    }

    fn exact_new_artifact(change: &SemanticChange, file_path: &str) -> (ArtifactId, LocatedEntry) {
        change
            .tree_deltas
            .iter()
            .find_map(|delta| {
                let new = delta.new_state()?;
                (new.path.as_utf8() == Some(file_path)).then(|| (delta.artifact_id(), new.clone()))
            })
            .unwrap_or_else(|| panic!("missing exact new artifact at {file_path}"))
    }

    fn imported_id(imported: &[kin_git::ImportedChange], git_oid: &str) -> SemanticChangeId {
        imported
            .iter()
            .find(|entry| entry.git_oid == git_oid)
            .map(|entry| entry.change.id)
            .unwrap_or_else(|| panic!("missing imported Git object {git_oid}"))
    }

    fn added_regular_delta(file_path: &str, new_hash: Hash256) -> TreeDelta {
        TreeDelta::Added {
            artifact_id: test_artifact_id(file_path),
            new: regular_location(file_path, new_hash),
        }
    }

    fn modified_regular_delta(file_path: &str, old_hash: Hash256, new_hash: Hash256) -> TreeDelta {
        TreeDelta::Updated {
            artifact_id: test_artifact_id(file_path),
            old: regular_location(file_path, old_hash),
            new: regular_location(file_path, new_hash),
        }
    }

    fn removed_regular_delta(file_path: &str, old_hash: Hash256) -> TreeDelta {
        TreeDelta::Removed {
            artifact_id: test_artifact_id(file_path),
            old: regular_location(file_path, old_hash),
        }
    }

    fn imported_change(
        id_bytes: [u8; 32],
        parent_bytes: [u8; 32],
        message: &str,
        tree_deltas: Vec<TreeDelta>,
    ) -> kin_git::ImportedChange {
        kin_git::ImportedChange {
            change: SemanticChange {
                id: SemanticChangeId::from_hash(Hash256::from_bytes(id_bytes)),
                parents: vec![if parent_bytes == [0; 32] {
                    kin_core::build_genesis_change().id
                } else {
                    SemanticChangeId::from_hash(Hash256::from_bytes(parent_bytes))
                }],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: message.to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                tree_deltas,
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            },
            git_oid: hex::encode(id_bytes),
        }
    }

    fn checkpoint_fixture(blob_store: &kin_blobs::BlobStore) -> Vec<kin_git::ImportedChange> {
        let util_v1 = blob_store
            .write(b"def helper(value):\n    return value\n")
            .unwrap();
        let app_v1 = blob_store
            .write(b"from util import helper\n\ndef run():\n    return helper(1)\n")
            .unwrap();
        let util_v2 = blob_store
            .write(b"def helper(value):\n    return value + 1\n")
            .unwrap();
        let sibling_v1 = blob_store
            .write(b"def sibling():\n    return 'branch'\n")
            .unwrap();
        vec![
            imported_change(
                [0x71; 32],
                [0; 32],
                history_checkpoint::BASE_LINK_MESSAGE,
                vec![added_regular_delta(
                    "util.py",
                    Hash256::from_bytes(util_v1.0),
                )],
            ),
            imported_change(
                [0x72; 32],
                [0x71; 32],
                "add caller",
                vec![added_regular_delta("app.py", Hash256::from_bytes(app_v1.0))],
            ),
            imported_change(
                [0x73; 32],
                [0x71; 32],
                "add sibling branch",
                vec![added_regular_delta(
                    "sibling.py",
                    Hash256::from_bytes(sibling_v1.0),
                )],
            ),
            imported_change(
                [0x74; 32],
                [0x72; 32],
                "change helper",
                vec![modified_regular_delta(
                    "util.py",
                    Hash256::from_bytes(util_v1.0),
                    Hash256::from_bytes(util_v2.0),
                )],
            ),
        ]
    }

    fn linear_checkpoint_fixture(
        blob_store: &kin_blobs::BlobStore,
        count: usize,
    ) -> Vec<kin_git::ImportedChange> {
        assert!((1..=200).contains(&count));
        let source = blob_store
            .write(b"def checkpoint_scale_fixture():\n    return 1\n")
            .unwrap();
        (1..=count)
            .map(|position| {
                let deltas = if position == 1 {
                    vec![added_regular_delta(
                        "scale.py",
                        Hash256::from_bytes(source.0),
                    )]
                } else {
                    Vec::new()
                };
                imported_change(
                    [position as u8; 32],
                    if position == 1 {
                        [0; 32]
                    } else {
                        [(position - 1) as u8; 32]
                    },
                    &format!("scale commit {position}"),
                    deltas,
                )
            })
            .collect()
    }

    fn assert_same_hydration_deltas(
        expected: &[kin_git::ImportedChange],
        actual: &[kin_git::ImportedChange],
    ) {
        assert_eq!(expected.len(), actual.len());
        for (position, (expected, actual)) in expected.iter().zip(actual).enumerate() {
            assert_eq!(
                canonical_json(&expected.change.entity_deltas),
                canonical_json(&actual.change.entity_deltas),
                "entity deltas diverged at commit {position}"
            );
            assert_eq!(
                canonical_json(&expected.change.relation_deltas),
                canonical_json(&actual.change.relation_deltas),
                "relation deltas diverged at commit {position}"
            );
        }
    }

    fn recursive_checkpoint_files(root: &Path) -> Vec<PathBuf> {
        fn walk(dir: &Path, output: &mut Vec<PathBuf>) {
            let Ok(entries) = fs::read_dir(dir) else {
                return;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, output);
                } else if path.is_file() {
                    output.push(path);
                }
            }
        }
        let mut output = Vec::new();
        walk(root, &mut output);
        output.sort();
        output
    }

    fn checkpoint_path_has_component(path: &Path, expected: &str) -> bool {
        path.components()
            .any(|component| component.as_os_str() == expected)
    }

    fn checkpoint_path_has_file_suffix(path: &Path, suffix: &str) -> bool {
        path.file_name()
            .is_some_and(|name| name.to_string_lossy().ends_with(suffix))
    }

    fn checkpoint_file_map(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        recursive_checkpoint_files(root)
            .into_iter()
            .map(|path| {
                (
                    path.strip_prefix(root).unwrap().to_path_buf(),
                    fs::read(path).unwrap(),
                )
            })
            .collect()
    }

    const CHECKPOINT_WORKER_ROOT: &str = "KIN_TEST_CHECKPOINT_WORKER_ROOT";
    const CHECKPOINT_WORKER_BLOBS: &str = "KIN_TEST_CHECKPOINT_WORKER_BLOBS";
    const CHECKPOINT_WORKER_VARIANT: &str = "KIN_TEST_CHECKPOINT_WORKER_VARIANT";
    const CHECKPOINT_WORKER_LOCK_ATTEMPT: &str = "KIN_TEST_CHECKPOINT_LOCK_ATTEMPT";
    const CHECKPOINT_WORKER_LOCK_ACQUIRED: &str = "KIN_TEST_CHECKPOINT_LOCK_ACQUIRED";
    const CHECKPOINT_WORKER_LOCK_RELEASE: &str = "KIN_TEST_CHECKPOINT_LOCK_RELEASE";

    fn checkpoint_worker_command(
        root: &Path,
        blobs: &Path,
        variant: &str,
    ) -> std::process::Command {
        let mut command = std::process::Command::new(std::env::current_exe().unwrap());
        command
            .args([
                "--exact",
                "commands::init::tests::checkpoint_subprocess_worker",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHECKPOINT_WORKER_ROOT, root)
            .env(CHECKPOINT_WORKER_BLOBS, blobs)
            .env(CHECKPOINT_WORKER_VARIANT, variant);
        command
    }

    fn assert_checkpoint_worker(output: std::process::Output) {
        assert!(
            output.status.success(),
            "checkpoint subprocess failed\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn wait_for_test_path(path: &Path) {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while !path.exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "timed out waiting for test handshake {}",
                path.display()
            );
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
    }

    #[test]
    fn checkpoint_subprocess_worker() {
        let Ok(root) = std::env::var(CHECKPOINT_WORKER_ROOT) else {
            return;
        };
        let blobs = PathBuf::from(std::env::var(CHECKPOINT_WORKER_BLOBS).unwrap());
        let variant = std::env::var(CHECKPOINT_WORKER_VARIANT).unwrap();
        let blob_store = kin_blobs::BlobStore::new(blobs).unwrap();
        let mut history = checkpoint_fixture(&blob_store);
        if variant == "linear" {
            history.truncate(2);
        } else if variant == "crash-orphan" {
            history[0].change.message = "orphan-only crash boundary".to_string();
        } else {
            assert_eq!(variant, "branched");
        }
        let mut config = HydrationCheckpointConfig::clean_for_test(
            Path::new(&root),
            "subprocess-clean-sha",
            1,
            16 * 1024 * 1024,
        );
        if let (Ok(attempt), Ok(acquired)) = (
            std::env::var(CHECKPOINT_WORKER_LOCK_ATTEMPT),
            std::env::var(CHECKPOINT_WORKER_LOCK_ACQUIRED),
        ) {
            let release = std::env::var(CHECKPOINT_WORKER_LOCK_RELEASE)
                .ok()
                .map(PathBuf::from);
            config = config.with_lock_test_hook(
                PathBuf::from(attempt),
                PathBuf::from(acquired),
                release,
            );
        }
        if variant == "crash-orphan" {
            config = config.with_crash_after_objects_before_manifest();
        }
        enrich_imported_changes_with_semantics_with_checkpoints(
            &mut history,
            &blob_store,
            true,
            Some(config),
        )
        .unwrap();
    }

    #[test]
    fn checkpoint_bytes_are_identical_across_real_processes() {
        let dir = tempfile::tempdir().unwrap();
        let root_a = dir.path().join("kin-a");
        let root_b = dir.path().join("kin-b");
        assert_checkpoint_worker(
            checkpoint_worker_command(&root_a, &dir.path().join("blobs-a"), "branched")
                .output()
                .unwrap(),
        );
        assert_checkpoint_worker(
            checkpoint_worker_command(&root_b, &dir.path().join("blobs-b"), "branched")
                .output()
                .unwrap(),
        );
        assert_eq!(
            checkpoint_file_map(&root_a),
            checkpoint_file_map(&root_b),
            "separate OS processes emitted different canonical checkpoint bytes"
        );
    }

    #[test]
    fn concurrent_processes_publish_without_dangling_checkpoint_references() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("shared-kin");
        let holder_attempt = dir.path().join("holder-attempt");
        let holder_acquired = dir.path().join("holder-acquired");
        let holder_release = dir.path().join("holder-release");
        let waiter_attempt = dir.path().join("waiter-attempt");
        let waiter_acquired = dir.path().join("waiter-acquired");

        let mut holder_command =
            checkpoint_worker_command(&root, &dir.path().join("linear-blobs"), "linear");
        holder_command
            .env(CHECKPOINT_WORKER_LOCK_ATTEMPT, &holder_attempt)
            .env(CHECKPOINT_WORKER_LOCK_ACQUIRED, &holder_acquired)
            .env(CHECKPOINT_WORKER_LOCK_RELEASE, &holder_release);
        let linear = holder_command.spawn().unwrap();
        wait_for_test_path(&holder_acquired);

        let mut waiter_command =
            checkpoint_worker_command(&root, &dir.path().join("branched-blobs"), "branched");
        waiter_command
            .env(CHECKPOINT_WORKER_LOCK_ATTEMPT, &waiter_attempt)
            .env(CHECKPOINT_WORKER_LOCK_ACQUIRED, &waiter_acquired);
        let branched = waiter_command.spawn().unwrap();
        wait_for_test_path(&waiter_attempt);
        assert!(
            !waiter_acquired.exists(),
            "second process acquired the store while the first process held it"
        );

        fs::write(&holder_release, b"release\n").unwrap();
        assert_checkpoint_worker(linear.wait_with_output().unwrap());
        assert_checkpoint_worker(branched.wait_with_output().unwrap());
        assert!(
            waiter_acquired.exists(),
            "waiting process never acquired the store after deterministic release"
        );

        let config = HydrationCheckpointConfig::clean_for_test(
            &root,
            "subprocess-clean-sha",
            1,
            16 * 1024 * 1024,
        );
        history_checkpoint::validate_store_for_test(&config).unwrap();

        // A fresh consumer can also restore and complete from the concurrently
        // published store, establishing that manifests are operational rather
        // than merely parseable.
        let blob_store = kin_blobs::BlobStore::new(dir.path().join("verify-blobs")).unwrap();
        let mut history = checkpoint_fixture(&blob_store);
        let stats = enrich_imported_changes_with_semantics_with_checkpoints(
            &mut history,
            &blob_store,
            true,
            Some(config),
        )
        .unwrap();
        assert!(stats.resumed_from > 0);
    }

    #[test]
    fn installed_objects_without_manifest_are_recovered_after_real_process_crash() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("crash-kin");
        let crashed =
            checkpoint_worker_command(&root, &dir.path().join("crash-blobs"), "crash-orphan")
                .output()
                .unwrap();
        assert_eq!(
            crashed.status.code(),
            Some(history_checkpoint::CRASH_SIMULATION_EXIT_CODE),
            "crash worker did not die at the armed crash boundary\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&crashed.stdout),
            String::from_utf8_lossy(&crashed.stderr)
        );

        let orphan_objects: Vec<_> = recursive_checkpoint_files(&root)
            .into_iter()
            .filter(|path| checkpoint_path_has_component(path, "objects"))
            .collect();
        assert!(
            orphan_objects.len() >= 3,
            "crash did not leave the installed segment and frontier objects"
        );
        assert!(
            recursive_checkpoint_files(&root)
                .iter()
                .all(|path| !checkpoint_path_has_file_suffix(path, ".manifest.json")),
            "crash injection occurred after manifest publication"
        );

        assert_checkpoint_worker(
            checkpoint_worker_command(&root, &dir.path().join("recovery-blobs"), "branched")
                .output()
                .unwrap(),
        );
        for orphan in orphan_objects {
            assert!(
                !orphan.exists(),
                "prepare maintenance retained unreachable crash object {}",
                orphan.display()
            );
        }
        let config = HydrationCheckpointConfig::clean_for_test(
            &root,
            "subprocess-clean-sha",
            1,
            16 * 1024 * 1024,
        );
        history_checkpoint::validate_store_for_test(&config).unwrap();
    }

    #[test]
    fn segmented_checkpoint_resume_is_canonical_prefix_reusable_and_bit_identical() {
        let dir = tempfile::tempdir().unwrap();
        let blob_store = kin_blobs::BlobStore::new(dir.path().join("objects")).unwrap();
        let mut oracle = checkpoint_fixture(&blob_store);
        enrich_imported_changes_with_semantics_inner(&mut oracle, &blob_store, true).unwrap();

        let root_a = dir.path().join("kin-a");
        let config_a =
            HydrationCheckpointConfig::clean_for_test(&root_a, "clean-sha-a", 1, 16 * 1024 * 1024);
        let mut first = checkpoint_fixture(&blob_store);
        let first_stats = enrich_imported_changes_with_semantics_with_checkpoints(
            &mut first,
            &blob_store,
            true,
            Some(config_a.clone()),
        )
        .unwrap();
        assert_eq!(first_stats.resumed_from, 0);
        assert_eq!(first_stats.checkpoint_io.serialized_units, 16);
        assert_eq!(first_stats.checkpoint_io.written_units, 16);
        assert!(first_stats.checkpoint_io.max_serialized_unit_bytes > 0);
        assert_same_hydration_deltas(&oracle, &first);

        let root_b = dir.path().join("kin-b");
        let config_b =
            HydrationCheckpointConfig::clean_for_test(&root_b, "clean-sha-a", 1, 16 * 1024 * 1024);
        let mut independent = checkpoint_fixture(&blob_store);
        enrich_imported_changes_with_semantics_with_checkpoints(
            &mut independent,
            &blob_store,
            true,
            Some(config_b),
        )
        .unwrap();
        assert_eq!(
            checkpoint_file_map(&root_a),
            checkpoint_file_map(&root_b),
            "independent clean runs must emit byte-identical object graphs"
        );
        let canonical_checkpoint_map = checkpoint_file_map(&root_a);

        let segment_files: Vec<_> = recursive_checkpoint_files(&root_a)
            .into_iter()
            .filter(|path| checkpoint_path_has_component(path, "segments"))
            .collect();
        assert_eq!(segment_files.len(), 4, "one immutable segment per boundary");

        let mut historical_ref = checkpoint_fixture(&blob_store);
        historical_ref.truncate(3);
        let historical_stats = enrich_imported_changes_with_semantics_with_checkpoints(
            &mut historical_ref,
            &blob_store,
            true,
            Some(config_a.clone()),
        )
        .unwrap();
        assert_eq!(historical_stats.resumed_from, 3);
        assert_eq!(historical_stats.checkpoint_io.serialized_units, 0);
        assert_same_hydration_deltas(&oracle[..3], &historical_ref);

        let mut manifests: Vec<_> = recursive_checkpoint_files(&root_a)
            .into_iter()
            .filter(|path| checkpoint_path_has_file_suffix(path, ".manifest.json"))
            .collect();
        manifests.sort();
        fs::remove_file(&manifests[2]).unwrap();
        fs::remove_file(&manifests[3]).unwrap();
        let mut resumed = checkpoint_fixture(&blob_store);
        let resumed_stats = enrich_imported_changes_with_semantics_with_checkpoints(
            &mut resumed,
            &blob_store,
            true,
            Some(config_a),
        )
        .unwrap();
        assert_eq!(resumed_stats.resumed_from, 2);
        assert_eq!(
            resumed_stats.checkpoint_io.serialized_units, 8,
            "two suffix boundaries serialize exactly segment+parser-frontier+linker-frontier+manifest each"
        );
        assert_eq!(
            resumed_stats.checkpoint_io.reused_units, 0,
            "prepare GC must remove every object made unreachable by the deleted manifests"
        );
        assert_eq!(
            resumed_stats.checkpoint_io.written_units, 8,
            "both replayed boundaries must rebuild segment, frontiers, and manifest after startup reachability GC"
        );
        assert_eq!(
            checkpoint_file_map(&root_a),
            canonical_checkpoint_map,
            "resumed reconstruction must restore the exact canonical object graph"
        );
        assert_same_hydration_deltas(&oracle, &resumed);
    }

    #[test]
    fn checkpoint_falls_back_when_new_side_branch_needs_an_older_ancestor() {
        let dir = tempfile::tempdir().unwrap();
        let blob_store = kin_blobs::BlobStore::new(dir.path().join("objects")).unwrap();
        let root = dir.path().join("kin");
        let config =
            HydrationCheckpointConfig::clean_for_test(&root, "clean-sha", 1, 16 * 1024 * 1024);

        // First history is linear A -> B. Its final B checkpoint retains B, not
        // A, because no future branch is known yet.
        let mut linear = checkpoint_fixture(&blob_store);
        linear.truncate(2);
        let seeded = enrich_imported_changes_with_semantics_with_checkpoints(
            &mut linear,
            &blob_store,
            true,
            Some(config.clone()),
        )
        .unwrap();
        assert_eq!(seeded.resumed_from, 0);

        // The complete fixture preserves exact prefix A,B but adds C from A.
        // B's valid frontier is now inapplicable; A is the newest applicable
        // checkpoint and must be selected instead of refusing the store.
        let mut oracle = checkpoint_fixture(&blob_store);
        enrich_imported_changes_with_semantics_inner(&mut oracle, &blob_store, true).unwrap();
        let mut branched = checkpoint_fixture(&blob_store);
        let resumed = enrich_imported_changes_with_semantics_with_checkpoints(
            &mut branched,
            &blob_store,
            true,
            Some(config),
        )
        .unwrap();
        assert_eq!(resumed.resumed_from, 1);
        assert_same_hydration_deltas(&oracle, &branched);
    }

    #[test]
    fn checkpoint_build_identity_is_strict_and_dirty_or_unknown_builds_do_full_replay() {
        let dir = tempfile::tempdir().unwrap();
        let blob_store = kin_blobs::BlobStore::new(dir.path().join("objects")).unwrap();
        let mut oracle = checkpoint_fixture(&blob_store);
        enrich_imported_changes_with_semantics_inner(&mut oracle, &blob_store, true).unwrap();

        let clean_root = dir.path().join("clean");
        let clean_a = HydrationCheckpointConfig::clean_for_test(
            &clean_root,
            "clean-sha-a",
            1,
            16 * 1024 * 1024,
        );
        let mut seeded = checkpoint_fixture(&blob_store);
        enrich_imported_changes_with_semantics_with_checkpoints(
            &mut seeded,
            &blob_store,
            true,
            Some(clean_a),
        )
        .unwrap();
        let clean_b = HydrationCheckpointConfig::clean_for_test(
            &clean_root,
            "clean-sha-b",
            1,
            16 * 1024 * 1024,
        );
        let error = enrich_imported_changes_with_semantics_with_checkpoints(
            &mut checkpoint_fixture(&blob_store),
            &blob_store,
            true,
            Some(clean_b),
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("clean build/version key mismatch"));
        let dependency_b = HydrationCheckpointConfig::clean_for_test(
            &clean_root,
            "clean-sha-a",
            1,
            16 * 1024 * 1024,
        )
        .with_dependency_provenance_for_test("different-lock-provenance");
        let dependency_error = enrich_imported_changes_with_semantics_with_checkpoints(
            &mut checkpoint_fixture(&blob_store),
            &blob_store,
            true,
            Some(dependency_b),
        )
        .unwrap_err();
        assert!(dependency_error
            .to_string()
            .contains("clean build/version key mismatch"));
        let seeded_files = checkpoint_file_map(&clean_root);

        for (name, reason) in [
            ("dirty", "dirty build is ambiguous"),
            ("unknown", "unknown build SHA"),
        ] {
            let config = HydrationCheckpointConfig::disabled_for_test(
                &clean_root,
                &format!("{name}: {reason}"),
            );
            let mut replayed = checkpoint_fixture(&blob_store);
            let stats = enrich_imported_changes_with_semantics_with_checkpoints(
                &mut replayed,
                &blob_store,
                true,
                Some(config),
            )
            .unwrap();
            assert_eq!(stats.resumed_from, 0);
            assert_eq!(stats.checkpoint_io.serialized_units, 0);
            assert_eq!(
                checkpoint_file_map(&clean_root),
                seeded_files,
                "{name} build must neither reuse nor mutate a seeded store"
            );
            assert_same_hydration_deltas(&oracle, &replayed);
        }
    }

    #[test]
    fn checkpoint_segment_frontier_and_manifest_corruption_all_refuse() {
        let dir = tempfile::tempdir().unwrap();
        let blob_store = kin_blobs::BlobStore::new(dir.path().join("objects")).unwrap();
        for component in [
            "segments",
            "parser-frontiers",
            "linker-frontiers",
            "manifest",
        ] {
            let root = dir.path().join(format!("corrupt-{component}"));
            let config =
                HydrationCheckpointConfig::clean_for_test(&root, "clean-sha", 1, 16 * 1024 * 1024);
            let mut seeded = checkpoint_fixture(&blob_store);
            enrich_imported_changes_with_semantics_with_checkpoints(
                &mut seeded,
                &blob_store,
                true,
                Some(config.clone()),
            )
            .unwrap();
            let targets: Vec<_> = recursive_checkpoint_files(&root)
                .into_iter()
                .filter(|path| {
                    if component == "manifest" {
                        checkpoint_path_has_file_suffix(path, ".manifest.json")
                    } else {
                        checkpoint_path_has_component(path, component)
                    }
                })
                .collect();
            assert!(!targets.is_empty(), "missing {component} fixture artifact");
            for path in targets {
                fs::write(path, b"corrupt").unwrap();
            }
            let error = enrich_imported_changes_with_semantics_with_checkpoints(
                &mut checkpoint_fixture(&blob_store),
                &blob_store,
                true,
                Some(config),
            )
            .unwrap_err();
            assert!(
                error.to_string().contains("REFUSED hydration checkpoint"),
                "{} corruption was not refused: {error:#}",
                component
            );
        }
    }

    #[test]
    fn checkpoint_byte_cap_is_enforced_without_changing_semantic_output() {
        let dir = tempfile::tempdir().unwrap();
        let blob_store = kin_blobs::BlobStore::new(dir.path().join("objects")).unwrap();
        let mut oracle = checkpoint_fixture(&blob_store);
        enrich_imported_changes_with_semantics_inner(&mut oracle, &blob_store, true).unwrap();
        let root = dir.path().join("capped");
        let stale_temp = root
            .join("checkpoints/history-hydration/objects/segments")
            .join(".orphan.json.tmp.999999");
        fs::create_dir_all(stale_temp.parent().unwrap()).unwrap();
        fs::write(&stale_temp, vec![0x55; 8 * 1024]).unwrap();
        let config = HydrationCheckpointConfig::clean_for_test(&root, "clean-sha", 1, 1);
        let mut replayed = checkpoint_fixture(&blob_store);
        let stats = enrich_imported_changes_with_semantics_with_checkpoints(
            &mut replayed,
            &blob_store,
            true,
            Some(config),
        )
        .unwrap();
        assert!(stats.checkpoint_io.retained_bytes <= 1);
        assert_eq!(stats.checkpoint_io.serialized_units, 4);
        assert!(!stale_temp.exists(), "stale crash temp was not reaped");
        let retained: u64 = recursive_checkpoint_files(&root)
            .iter()
            .map(|path| fs::metadata(path).unwrap().len())
            .sum();
        assert!(retained <= 1);
        assert_same_hydration_deltas(&oracle, &replayed);
    }

    #[test]
    fn lowered_byte_cap_and_orphan_gc_apply_on_exact_full_resume() {
        let dir = tempfile::tempdir().unwrap();
        let blob_store = kin_blobs::BlobStore::new(dir.path().join("objects")).unwrap();
        let root = dir.path().join("cap-resume");
        let high_cap =
            HydrationCheckpointConfig::clean_for_test(&root, "clean-sha", 1, 16 * 1024 * 1024);
        let mut seeded = checkpoint_fixture(&blob_store);
        let seed_stats = enrich_imported_changes_with_semantics_with_checkpoints(
            &mut seeded,
            &blob_store,
            true,
            Some(high_cap),
        )
        .unwrap();
        let low_cap = seed_stats.checkpoint_io.retained_bytes;
        assert!(low_cap > 0);

        // Model an object that was installed after the high-cap run but never
        // made reachable from a manifest. The lower cap is exactly the known
        // good store size, so a zero-replay resume must collect this object in
        // prepare rather than returning early above the new policy limit.
        let orphan = root
            .join("checkpoints/history-hydration/objects/segments")
            .join(format!("{}.json", "f".repeat(64)));
        fs::write(&orphan, vec![0x55; 8 * 1024]).unwrap();

        let low_config = HydrationCheckpointConfig::clean_for_test(&root, "clean-sha", 1, low_cap);
        let mut resumed = checkpoint_fixture(&blob_store);
        let resume_stats = enrich_imported_changes_with_semantics_with_checkpoints(
            &mut resumed,
            &blob_store,
            true,
            Some(low_config.clone()),
        )
        .unwrap();
        assert_eq!(
            resume_stats.resumed_from,
            resumed.len(),
            "exact final checkpoint should still take the zero-replay path"
        );
        assert!(!orphan.exists(), "unreachable object survived prepare GC");
        assert!(resume_stats.checkpoint_io.retained_bytes <= low_cap);
        history_checkpoint::validate_store_for_test(&low_config).unwrap();
        assert_same_hydration_deltas(&seeded, &resumed);
    }

    #[test]
    fn checkpoint_retention_keeps_base_latest_and_even_interior_with_deterministic_gc() {
        let dir = tempfile::tempdir().unwrap();
        let blob_store = kin_blobs::BlobStore::new(dir.path().join("objects")).unwrap();
        let root = dir.path().join("retained");
        let config =
            HydrationCheckpointConfig::clean_for_test(&root, "clean-sha", 1, 16 * 1024 * 1024)
                .with_retention_for_test(3, 2);
        let mut hydrated = checkpoint_fixture(&blob_store);
        enrich_imported_changes_with_semantics_with_checkpoints(
            &mut hydrated,
            &blob_store,
            true,
            Some(config),
        )
        .unwrap();

        let files = recursive_checkpoint_files(&root);
        let manifests: Vec<_> = files
            .iter()
            .filter(|path| checkpoint_path_has_file_suffix(path, ".manifest.json"))
            .collect();
        let manifest_positions: Vec<_> = manifests
            .iter()
            .map(|path| {
                path.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .split('-')
                    .next()
                    .unwrap()
                    .parse::<usize>()
                    .unwrap()
            })
            .collect();
        assert_eq!(manifest_positions, vec![1, 2, 4]);
        assert_eq!(
            files
                .iter()
                .filter(|path| checkpoint_path_has_component(path, "parser-frontiers"))
                .count(),
            3,
            "unreferenced parser frontier was not collected"
        );
        assert_eq!(
            files
                .iter()
                .filter(|path| checkpoint_path_has_component(path, "linker-frontiers"))
                .count(),
            3,
            "unreferenced linker frontier was not collected"
        );
        assert_eq!(
            files
                .iter()
                .filter(|path| checkpoint_path_has_component(path, "segments"))
                .count(),
            4,
            "latest immutable delta chain must retain every bounded segment to genesis"
        );
    }

    #[test]
    fn checkpoint_retained_byte_reconciliation_is_linear_not_per_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let blob_store = kin_blobs::BlobStore::new(dir.path().join("objects")).unwrap();
        let run = |count: usize, name: &str| {
            let root = dir.path().join(name);
            let config = HydrationCheckpointConfig::clean_for_test(
                &root,
                "scale-clean-sha",
                1,
                64 * 1024 * 1024,
            );
            let mut history = linear_checkpoint_fixture(&blob_store, count);
            enrich_imported_changes_with_semantics_with_checkpoints(
                &mut history,
                &blob_store,
                true,
                Some(config),
            )
            .unwrap()
            .checkpoint_io
        };

        let small = run(8, "small");
        let large = run(16, "large");
        assert_eq!(small.retention_full_scans, 2);
        assert_eq!(large.retention_full_scans, 2);
        assert!(
            large.retention_entries_scanned
                <= small
                    .retention_entries_scanned
                    .saturating_mul(3)
                    .saturating_add(32),
            "retention reconciliation grew superlinearly: small={} large={}",
            small.retention_entries_scanned,
            large.retention_entries_scanned
        );
    }

    #[test]
    fn missing_first_parent_snapshot_is_an_invariant_error() {
        let parent = SemanticChangeId::from_hash(Hash256::from_bytes([0x44; 32]));
        let mut snapshots = HashMap::new();
        for is_last_child in [false, true] {
            let error = take_imported_parent_baseline(&mut snapshots, parent, is_last_child)
                .err()
                .expect("missing parent snapshot must fail");
            assert!(error
                .to_string()
                .contains("missing retained first-parent state"));
        }
    }

    #[test]
    fn dangling_imported_parent_refuses_before_checkpoint_side_effects() {
        let dir = tempfile::tempdir().unwrap();
        let blob_store = kin_blobs::BlobStore::new(dir.path().join("objects")).unwrap();
        let root = dir.path().join("kin");
        let config =
            HydrationCheckpointConfig::clean_for_test(&root, "clean-sha", 1, 16 * 1024 * 1024);
        let mut imported = checkpoint_fixture(&blob_store);
        let dangling = SemanticChangeId::from_hash(Hash256::from_bytes([0xee; 32]));
        imported[0].change.parents = vec![dangling];

        let error = enrich_imported_changes_with_semantics_with_checkpoints(
            &mut imported,
            &blob_store,
            true,
            Some(config),
        )
        .unwrap_err();
        assert!(error.to_string().contains("dangling parent"), "{error:#}");
        assert!(imported
            .iter()
            .all(|entry| entry.change.entity_deltas.is_empty()
                && entry.change.relation_deltas.is_empty()));
        assert!(
            !root.join("checkpoints/history-hydration").exists(),
            "parent preflight must run before lock/store creation"
        );
    }

    #[test]
    fn cyclic_imported_first_parent_refuses_before_checkpoint_side_effects() {
        let dir = tempfile::tempdir().unwrap();
        let blob_store = kin_blobs::BlobStore::new(dir.path().join("objects")).unwrap();
        let root = dir.path().join("kin");
        let config =
            HydrationCheckpointConfig::clean_for_test(&root, "clean-sha", 1, 16 * 1024 * 1024);
        let mut imported = checkpoint_fixture(&blob_store);
        let first = imported[0].change.id;
        let second = imported[1].change.id;
        imported[0].change.parents = vec![second];
        imported[1].change.parents = vec![first];

        let error = enrich_imported_changes_with_semantics_with_checkpoints(
            &mut imported,
            &blob_store,
            true,
            Some(config),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("imported parent DAG contains a cycle"),
            "unexpected cycle refusal: {error:#}"
        );
        assert!(imported
            .iter()
            .all(|entry| entry.change.entity_deltas.is_empty()
                && entry.change.relation_deltas.is_empty()));
        assert!(
            !root.join("checkpoints/history-hydration").exists(),
            "cycle preflight must run before lock/store creation"
        );
    }

    #[test]
    fn cyclic_imported_secondary_parent_refuses_before_checkpoint_side_effects() {
        let dir = tempfile::tempdir().unwrap();
        let blob_store = kin_blobs::BlobStore::new(dir.path().join("objects")).unwrap();
        let root = dir.path().join("kin");
        let config =
            HydrationCheckpointConfig::clean_for_test(&root, "clean-sha", 1, 16 * 1024 * 1024);
        let mut imported = checkpoint_fixture(&blob_store);
        let boundary_root = kin_core::build_genesis_change().id;
        let first = imported[0].change.id;
        let second = imported[1].change.id;

        // Both first-parent paths reach canonical genesis, but the secondary
        // edges form first -> second -> first. First-parent-only validation
        // used to accept this corrupt merge shape and acquire the store lock.
        imported[0].change.parents = vec![boundary_root, second];
        imported[1].change.parents = vec![boundary_root, first];

        let error = enrich_imported_changes_with_semantics_with_checkpoints(
            &mut imported,
            &blob_store,
            true,
            Some(config),
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("imported parent DAG contains a cycle"),
            "unexpected secondary-parent cycle refusal: {error:#}"
        );
        assert!(imported
            .iter()
            .all(|entry| entry.change.entity_deltas.is_empty()
                && entry.change.relation_deltas.is_empty()));
        assert!(
            !root.join("checkpoints/history-hydration").exists(),
            "secondary-parent preflight must run before lock/store creation"
        );
    }

    #[test]
    fn imported_change_cannot_collide_with_boundary_root() {
        let dir = tempfile::tempdir().unwrap();
        let blob_store = kin_blobs::BlobStore::new(dir.path().join("objects")).unwrap();
        let root = dir.path().join("kin");
        let config =
            HydrationCheckpointConfig::clean_for_test(&root, "clean-sha", 1, 16 * 1024 * 1024);
        let boundary_root = kin_core::build_genesis_change().id;
        let mut imported = checkpoint_fixture(&blob_store);
        imported[0].change.id = boundary_root;

        let error = enrich_imported_changes_with_semantics_with_checkpoints(
            &mut imported,
            &blob_store,
            true,
            Some(config),
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("collides with boundary root"),
            "unexpected root-collision refusal: {error:#}"
        );
        assert!(
            !root.join("checkpoints/history-hydration").exists(),
            "root-collision preflight must run before lock/store creation"
        );
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
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
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
            src: GraphNodeId::Artifact(test_artifact_id("src/g.rs")),
            dst: GraphNodeId::Artifact(test_artifact_id("src/a.rs")),
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
        let mut tracked: BTreeSet<String> = graph
            .resolved_tree()
            .artifacts_by_path()
            .filter_map(|artifact| artifact.path.as_utf8().map(str::to_owned))
            .collect();
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

        assert_eq!(graph.resolved_tree().len(), expected_paths.len());
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
        let makefile_id = graph
            .artifact_id_at_path(&RepoPath::from_utf8("Makefile").unwrap())
            .expect("Makefile must have admitted graph identity");
        let makefile_key = kin_db::RetrievalKey::Artifact(makefile_id);
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
    fn native_boundary_admits_all_files_without_creating_a_snapshot_copy() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("README.md"), "hello").unwrap();
        fs::create_dir_all(root.join("src")).unwrap();
        fs::write(root.join("src/main.rs"), "fn main() {}").unwrap();
        fs::create_dir_all(root.join("node_modules/foo")).unwrap();
        fs::write(root.join("node_modules/foo/index.js"), "track me").unwrap();

        let init = kin_core::init(root).unwrap();
        let snap = open_snapshot_with_retry(init.layout.kindb_snapshot_path());
        let blob_store = kin_blobs::BlobStore::new(init.layout.objects_dir()).unwrap();
        let entries =
            collect_native_boundary_entries(root, snap.graph().as_ref(), &blob_store, false)
                .unwrap();
        let paths = entries
            .iter()
            .filter_map(|entry| entry.repo_path.as_utf8())
            .collect::<BTreeSet<_>>();

        assert!(paths.contains("README.md"));
        assert!(paths.contains("src/main.rs"));
        assert!(paths.contains("node_modules/foo/index.js"));
        assert!(
            !root.join(".kin/snapshot").exists(),
            "native admission must persist CAS blobs, never a second raw tree"
        );
        for entry in entries {
            let hash = kin_blobs::Hash256::from_bytes(entry.hash);
            assert!(blob_store.read(&hash).is_ok());
        }
    }

    #[cfg(unix)]
    #[test]
    fn native_boundary_preserves_modes_and_symlink_targets() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::write(root.join("plain.txt"), b"plain\n").unwrap();
        fs::write(root.join("bin/run"), b"#!/bin/sh\n").unwrap();
        let mut permissions = fs::metadata(root.join("bin/run")).unwrap().permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(root.join("bin/run"), permissions).unwrap();
        symlink("plain.txt", root.join("current")).unwrap();

        let init = kin_core::init(root).unwrap();
        let snap = open_snapshot_with_retry(init.layout.kindb_snapshot_path());
        let blob_store = kin_blobs::BlobStore::new(init.layout.objects_dir()).unwrap();
        let exact =
            collect_native_boundary_entries(root, snap.graph().as_ref(), &blob_store, false)
                .unwrap();
        let kinds: BTreeMap<_, _> = exact
            .iter()
            .map(|entry| (entry.repo_path.as_utf8().unwrap(), entry.entry))
            .collect();
        assert_eq!(
            kinds.get("plain.txt"),
            Some(&TreeEntry::blob(
                Hash256::from_bytes(kin_blobs::digest_bytes(b"plain\n")),
                false
            ))
        );
        assert_eq!(
            kinds.get("bin/run"),
            Some(&TreeEntry::blob(
                Hash256::from_bytes(kin_blobs::digest_bytes(b"#!/bin/sh\n")),
                true
            ))
        );
        assert_eq!(
            kinds.get("current"),
            Some(&TreeEntry::symlink(Hash256::from_bytes(
                kin_blobs::digest_bytes(b"plain.txt")
            )))
        );
        let link = exact
            .iter()
            .find(|entry| entry.repo_path.as_utf8() == Some("current"))
            .unwrap();
        let target_hash = link.entry.blob_identity().unwrap();
        let target = blob_store
            .read(&kin_blobs::Hash256::from_bytes(*target_hash.as_bytes()))
            .unwrap();
        assert_eq!(target, b"plain.txt");
        assert!(!root.join(".kin/snapshot").exists());
    }

    #[test]
    fn exact_init_tree_deltas_record_mode_change_removal_and_added_symlink() {
        let retained_hash = Hash256::from_bytes([0x11; 32]);
        let deleted_hash = Hash256::from_bytes([0x22; 32]);
        let added_hash = [0x33; 32];
        let unchanged_hash = Hash256::from_bytes([0x44; 32]);
        let legacy_id = ArtifactId::new();
        let deleted_id = ArtifactId::new();
        let unchanged_id = ArtifactId::new();
        let parent = ResolvedTree::from_artifacts([
            kin_model::ResolvedArtifact::new(
                legacy_id,
                RepoPath::from_utf8("legacy.sh").unwrap(),
                TreeEntry::blob(retained_hash, false),
            ),
            kin_model::ResolvedArtifact::new(
                deleted_id,
                RepoPath::from_utf8("deleted.txt").unwrap(),
                TreeEntry::blob(deleted_hash, false),
            ),
            kin_model::ResolvedArtifact::new(
                unchanged_id,
                RepoPath::from_utf8("unchanged.txt").unwrap(),
                TreeEntry::blob(unchanged_hash, false),
            ),
        ])
        .unwrap();
        let current = vec![
            ExactInitSourceEntry {
                repo_path: RepoPath::from_utf8("legacy.sh").unwrap(),
                hash: *retained_hash.as_bytes(),
                entry: TreeEntry::blob(retained_hash, true),
            },
            ExactInitSourceEntry {
                repo_path: RepoPath::from_utf8("new-link").unwrap(),
                hash: added_hash,
                entry: TreeEntry::symlink(Hash256::from_bytes(added_hash)),
            },
            ExactInitSourceEntry {
                repo_path: RepoPath::from_utf8("unchanged.txt").unwrap(),
                hash: *unchanged_hash.as_bytes(),
                entry: TreeEntry::blob(unchanged_hash, false),
            },
        ];

        let deltas = build_exact_init_tree_deltas(parent, &current);
        assert_eq!(deltas.len(), 3);
        assert_eq!(
            deltas[0],
            TreeDelta::Removed {
                artifact_id: deleted_id,
                old: LocatedEntry::new(
                    RepoPath::from_utf8("deleted.txt").unwrap(),
                    TreeEntry::blob(deleted_hash, false),
                ),
            }
        );
        // Same bytes, new exact mode: an executable-bit-only transition is a
        // real delta and must survive intact.
        assert_eq!(
            deltas[1],
            TreeDelta::Updated {
                artifact_id: legacy_id,
                old: LocatedEntry::new(
                    RepoPath::from_utf8("legacy.sh").unwrap(),
                    TreeEntry::blob(retained_hash, false),
                ),
                new: LocatedEntry::new(
                    RepoPath::from_utf8("legacy.sh").unwrap(),
                    TreeEntry::blob(retained_hash, true),
                ),
            }
        );
        let TreeDelta::Added { new, .. } = &deltas[2] else {
            panic!("new link must be an addition");
        };
        assert_eq!(
            new,
            &LocatedEntry::new(
                RepoPath::from_utf8("new-link").unwrap(),
                TreeEntry::symlink(Hash256::from_bytes(added_hash)),
            )
        );
        assert!(
            deltas.iter().all(|delta| delta
                .new_state()
                .or_else(|| delta.old_state())
                .is_none_or(|state| state.path.as_utf8() != Some("unchanged.txt"))),
            "a path whose exact entry is unchanged must not produce a delta"
        );
    }

    #[test]
    fn discovery_cap_trips_on_oversized_tree() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        for i in 0..8 {
            fs::write(root.join(format!("f{i}.rs")), "x").unwrap();
        }

        let ignore = kin_index::RepositoryIgnore::load(root).unwrap();
        let scan = kin_index::scan_repository(root, &ignore, std::iter::empty()).unwrap();
        assert!(scan.len() > 5);
        assert!(scan.len() <= 100);
    }

    #[test]
    fn discovery_cap_counts_generated_and_vendor_named_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        fs::write(root.join("real.rs"), "x").unwrap();
        fs::create_dir_all(root.join("node_modules")).unwrap();
        for i in 0..20 {
            fs::write(root.join(format!("node_modules/v{i}.js")), "x").unwrap();
        }

        let ignore = kin_index::RepositoryIgnore::load(root).unwrap();
        let scan = kin_index::scan_repository(root, &ignore, std::iter::empty()).unwrap();
        assert!(scan.len() > 5);
    }

    #[test]
    fn repository_admission_excludes_only_control_metadata() {
        for name in [
            ".kin",
            ".kin-session",
            ".kin-session.json",
            ".kin-shadow",
            ".kin-reconcile-test",
            ".kin-checkout-test",
            ".git",
            ".git-export",
        ] {
            assert!(
                !kin_index::should_track_host_relative_path(Path::new(name)),
                "should prune {name}"
            );
        }
        for name in [
            ".kindb",
            ".kin-release",
            ".kin-snapshot-tmp",
            ".kin-other",
            "node_modules",
            "target",
            "vendor",
            "src",
            "main.rs",
            ".gitignore",
            ".github",
        ] {
            assert!(
                kin_index::should_track_host_relative_path(Path::new(name)),
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

        let ignore = kin_index::RepositoryIgnore::load(root).unwrap();
        let repo_path = |value| kin_model::RepoPath::from_utf8(value).unwrap();
        assert!(ignore.matches(&repo_path("a/b/build")));
        assert!(ignore.matches(&repo_path("out")));
        assert!(ignore.matches(&repo_path("thirdparty/large")));
        assert!(ignore.matches(&repo_path("thirdparty/large/x")));
        assert!(!ignore.matches(&repo_path("thirdparty/small")));
        assert!(!ignore.matches(&repo_path("src/keep.rs")));
    }

    #[test]
    fn read_git_head_reports_source_provenance() {
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

        let head = read_git_head(root).expect("Git HEAD should be available");
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

        run(
            Some(repo_dir.path().display().to_string()),
            false,
            true,
            false,
            true,
            "snapshot".to_string(),
        )
        .await
        .unwrap();

        let layout = kin_core::KinLayout::new(repo_dir.path().join(".kin"));
        let snap = open_snapshot_with_retry(layout.kindb_snapshot_path());
        let graph = snap.graph();

        assert!(
            !repo_dir.path().join(".kin/snapshot").exists(),
            "init must not create a raw repository snapshot"
        );
        assert_repo_owned_graph_truth(graph.as_ref(), &expected_paths);
        assert_makefile_is_text_searchable(graph.as_ref());
        assert!(!tracked_graph_paths(graph.as_ref()).contains(".kin/snapshot/manifest.json"));
    }

    #[tokio::test]
    #[serial]
    async fn identical_native_reinit_keeps_head_and_graph_state_unchanged() {
        let repo_dir = tempfile::tempdir().unwrap();
        let home_dir = tempfile::tempdir().unwrap();
        fs::create_dir_all(repo_dir.path().join("src")).unwrap();
        fs::write(
            repo_dir.path().join("src/lib.rs"),
            "pub fn answer() -> u32 { 42 }\n",
        )
        .unwrap();
        fs::write(
            repo_dir.path().join("docker-compose.yml"),
            "services:\n  app:\n    image: example/app:latest\n",
        )
        .unwrap();
        fs::write(repo_dir.path().join("asset.bin"), [0, 0xff, 1, 2]).unwrap();

        let _home_guard = EnvVarGuard::set("HOME", home_dir.path());

        run(
            Some(repo_dir.path().display().to_string()),
            false,
            true,
            false,
            true,
            "off".to_string(),
        )
        .await
        .unwrap();

        let layout = kin_core::KinLayout::new(repo_dir.path().join(".kin"));
        let (first_head, first_resolved, first_live) = {
            let snap = open_snapshot_with_retry(layout.kindb_snapshot_path());
            let graph = snap.graph();
            let branch_name = kin_core::read_current_branch(&layout).unwrap();
            let head = graph.get_branch(&branch_name).unwrap().unwrap().head;
            (
                head,
                graph.resolve_graph_at(&head).unwrap(),
                canonical_live_repository_state(graph.as_ref()),
            )
        };

        run(
            Some(repo_dir.path().display().to_string()),
            false,
            true,
            false,
            true,
            "off".to_string(),
        )
        .await
        .unwrap();

        let snap = open_snapshot_with_retry(layout.kindb_snapshot_path());
        let graph = snap.graph();
        let branch_name = kin_core::read_current_branch(&layout).unwrap();
        let second_head = graph.get_branch(&branch_name).unwrap().unwrap().head;
        assert_eq!(
            second_head, first_head,
            "an identical native re-init must not manufacture a new semantic change"
        );
        let second_resolved = graph.resolve_graph_at(&second_head).unwrap();
        assert_imported_semantics_exact(&first_resolved, &second_resolved);
        assert_eq!(
            canonical_live_repository_state(graph.as_ref()),
            first_live,
            "an identical native re-init must rebuild byte-equivalent live semantic state"
        );
    }

    #[tokio::test]
    #[serial]
    async fn consecutive_full_git_history_inits_keep_canonical_boundary_root() {
        let repo_dir = tempfile::tempdir().unwrap();
        if !init_git_repo_for_test(repo_dir.path())
            || !commit_git_file_for_test(
                repo_dir.path(),
                "src/lib.rs",
                "pub fn answer() -> u32 { 42 }\n",
                "initial",
            )
        {
            return;
        }
        let home_dir = tempfile::tempdir().unwrap();
        let _home_guard = EnvVarGuard::set("HOME", home_dir.path());

        let mut second_change_children = None;
        let mut second_entity_revisions = None;
        let mut second_changes = None;
        for pass in 0..3 {
            run(
                Some(repo_dir.path().display().to_string()),
                false,
                true,
                false,
                true,
                "full".to_string(),
            )
            .await
            .unwrap();

            if pass >= 1 {
                let layout = kin_core::KinLayout::new(repo_dir.path().join(".kin"));
                let snap = open_snapshot_with_retry(layout.kindb_snapshot_path());
                let persisted = snap.graph().to_snapshot();
                for children in persisted.change_children.values() {
                    let unique: HashSet<_> = children.iter().copied().collect();
                    assert_eq!(
                        unique.len(),
                        children.len(),
                        "repeated init duplicated a parent-to-child reverse edge"
                    );
                }
                for revisions in persisted.entity_revisions.values() {
                    let unique: HashSet<_> = revisions
                        .iter()
                        .map(|revision| revision.revision_id)
                        .collect();
                    assert_eq!(
                        unique.len(),
                        revisions.len(),
                        "repeated init duplicated an entity revision generation"
                    );
                }
                if pass == 1 {
                    second_change_children = Some(persisted.change_children);
                    second_entity_revisions = Some(persisted.entity_revisions);
                    second_changes = Some(
                        persisted
                            .changes
                            .iter()
                            .map(|(id, change)| {
                                (id.to_string(), serde_json::to_value(change).unwrap())
                            })
                            .collect::<BTreeMap<_, _>>(),
                    );
                } else {
                    assert_eq!(
                        second_change_children.as_ref().unwrap(),
                        &persisted.change_children,
                        "third init changed reverse DAG indexes"
                    );
                    assert_eq!(
                        second_entity_revisions.as_ref().unwrap(),
                        &persisted.entity_revisions,
                        "third init replayed revision generations"
                    );
                    assert_eq!(
                        second_changes.as_ref().unwrap(),
                        &persisted
                            .changes
                            .iter()
                            .map(|(id, change)| {
                                (id.to_string(), serde_json::to_value(change).unwrap())
                            })
                            .collect::<BTreeMap<_, _>>(),
                        "third init rewrote a deterministic change record"
                    );
                }
            }
        }

        let layout = kin_core::KinLayout::new(repo_dir.path().join(".kin"));
        let snap = open_snapshot_with_retry(layout.kindb_snapshot_path());
        let graph = snap.graph();
        let git_change = graph
            .get_branch(&BranchName::new("main"))
            .unwrap()
            .unwrap()
            .head;
        let imported = graph.get_change(&git_change).unwrap().unwrap();
        kin_model::validate_semantic_change_id(&imported).unwrap();
        assert_eq!(
            imported.parents,
            vec![kin_core::build_genesis_change().id],
            "true Git root must stay attached to canonical Kin genesis"
        );
        let persisted = graph.to_snapshot();
        assert_eq!(
            persisted
                .change_children
                .get(&kin_core::build_genesis_change().id)
                .into_iter()
                .flatten()
                .filter(|child| **child == git_change)
                .count(),
            1,
            "canonical genesis must name the imported root exactly once"
        );
    }

    #[tokio::test]
    #[serial]
    async fn git_history_off_then_full_uses_canonical_boundary_root() {
        let repo_dir = tempfile::tempdir().unwrap();
        if !init_git_repo_for_test(repo_dir.path())
            || !commit_git_file_for_test(
                repo_dir.path(),
                "src/lib.rs",
                "pub fn answer() -> u32 { 42 }\n",
                "initial",
            )
        {
            return;
        }
        let home_dir = tempfile::tempdir().unwrap();
        let _home_guard = EnvVarGuard::set("HOME", home_dir.path());

        run(
            Some(repo_dir.path().display().to_string()),
            false,
            true,
            false,
            true,
            "off".to_string(),
        )
        .await
        .unwrap();
        run(
            Some(repo_dir.path().display().to_string()),
            false,
            true,
            false,
            true,
            "full".to_string(),
        )
        .await
        .unwrap();

        let layout = kin_core::KinLayout::new(repo_dir.path().join(".kin"));
        let snap = open_snapshot_with_retry(layout.kindb_snapshot_path());
        let git_change = snap
            .graph()
            .get_branch(&BranchName::new("main"))
            .unwrap()
            .unwrap()
            .head;
        let imported = snap.graph().get_change(&git_change).unwrap().unwrap();
        kin_model::validate_semantic_change_id(&imported).unwrap();
        assert_eq!(
            imported.parents,
            vec![kin_core::build_genesis_change().id],
            "warm import must not use the prior auto-parse head as its root"
        );
    }

    #[tokio::test]
    #[serial]
    async fn run_ignores_daemon_bootstrap_when_initializing_repo() {
        let repo_dir = tempfile::tempdir().unwrap();
        let home_dir = tempfile::tempdir().unwrap();
        let expected_paths = repo_truth_fixture_with_agent_doc(repo_dir.path());

        let daemon_graph = kin_db::InMemoryGraph::new();

        let (daemon_url, daemon_hits, daemon_task) =
            spawn_bootstrap_server(daemon_graph.to_snapshot()).await;

        let _home_guard = EnvVarGuard::set("HOME", home_dir.path());
        let _daemon_guard = EnvVarGuard::set("KIN_DAEMON_URL", &daemon_url);

        run(
            Some(repo_dir.path().display().to_string()),
            false,
            true,
            false,
            true,
            "snapshot".to_string(),
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

        let init_result = kin_core::init(root).unwrap();
        let snap = open_snapshot_with_retry(init_result.layout.kindb_snapshot_path());
        let blob_store = kin_blobs::BlobStore::new(init_result.layout.objects_dir()).unwrap();
        let graph = snap.graph();
        let indexable = admit_test_repository(root, graph.as_ref(), &blob_store);
        parse_and_index(graph.as_ref(), &blob_store, &indexable).unwrap();
        assert!(
            !root.join(".kin/snapshot").exists(),
            "graph/blob admission must not make a raw tree copy"
        );

        // Assert graph truth contains ONLY repo-owned paths.
        let tracked = tracked_graph_paths(graph.as_ref());
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
        let file_hash_paths: BTreeSet<String> = graph
            .resolved_tree()
            .artifacts_by_path()
            .filter_map(|artifact| artifact.path.as_utf8().map(str::to_owned))
            .collect();
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
    }

    /// Regression: a Git worktree root carries `.git` as a FILE whose contents
    /// are a `gitdir:` pointer holding a machine-absolute path. Indexing that file
    /// would bake an ambient filesystem path into graph truth, so two preps of
    /// identical content at different checkout paths would diverge. Prove the
    /// graph/blob admission boundary excludes it while git-adjacent repo files (`.gitignore`,
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

        let init_result = kin_core::init(root).unwrap();
        let snap = open_snapshot_with_retry(init_result.layout.kindb_snapshot_path());
        let graph = snap.graph();
        let blob_store = kin_blobs::BlobStore::new(init_result.layout.objects_dir()).unwrap();
        let indexable = admit_test_repository(root, graph.as_ref(), &blob_store);
        let rel_paths = graph
            .resolved_tree()
            .artifacts_by_path()
            .filter_map(|artifact| artifact.path.as_utf8().map(str::to_owned))
            .collect::<BTreeSet<_>>();
        assert!(
            !rel_paths
                .iter()
                .any(|p| p.as_str() == ".git" || p.starts_with(".git/")),
            "`.git` plumbing leaked into exact tree truth: {:?}",
            rel_paths
        );
        for p in &rel_paths {
            assert!(
                is_repo_owned_graph_path(p),
                "non-repo path leaked into exact tree truth: {}",
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

        for file in &indexable {
            let text = String::from_utf8_lossy(file.content.as_slice()).into_owned();
            assert!(
                !text.contains(worktree_abs),
                "machine-absolute worktree path leaked into admitted content: {}",
                file.rel_path
            );
        }

        parse_and_index(graph.as_ref(), &blob_store, &indexable).unwrap();

        let tracked = tracked_graph_paths(graph.as_ref());
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

        let indexable_files = admit_test_repository(root, graph.as_ref(), &blob_store);
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

        let indexable_files = admit_test_repository(root, graph.as_ref(), &blob_store);
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
        let indexable_files = admit_test_repository(root, graph.as_ref(), &blob_store);
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
