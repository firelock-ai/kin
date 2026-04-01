// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_index::{FileClassification, FileClassifier, link_cross_file_against_entities};
use kin_model::ChangeStore;
use kin_model::EntityStore;
use kin_model::{
    AuthorId, Entity, EntityFilter, EntityId, FilePathId, GraphNodeId, Hash256, OpaqueArtifact,
    ParseCompleteness, SemanticChange, SemanticChangeId, ShallowTrackedFile, StructuredArtifact,
    Timestamp,
};
use kin_projection::build_layout;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use tracing::{info, warn};

/// Directories to skip during snapshot.
const SKIP_DIRS: &[&str] = &[
    ".kin",
    ".git/objects",
    ".git/pack",
    "node_modules",
    "target",
    "__pycache__",
    ".next",
    "dist",
    "build",
];

const INIT_WARM_CACHE_SCHEMA_VERSION: &str = "v1";
pub(crate) const INIT_WARM_CACHE_PIPELINE_EPOCH: &str = "init-warm-2026-03-29-truth-hygiene-v3";

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
fn snapshot_repo(dir: &Path) -> Result<(PathBuf, serde_json::Value)> {
    let _span = tracing::info_span!(
        "kin.init.snapshot_repo",
        root = %dir.display()
    )
    .entered();
    let tmp_snapshot = dir.join(".kin-snapshot-tmp");
    if tmp_snapshot.exists() {
        fs::remove_dir_all(&tmp_snapshot)?;
    }
    fs::create_dir_all(&tmp_snapshot)?;
    let snapshot_dir = &tmp_snapshot;

    let mut file_count: u64 = 0;
    let mut total_bytes: u64 = 0;

    walk_and_snapshot(dir, dir, &snapshot_dir, &mut file_count, &mut total_bytes)?;

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

        // Check if this path starts with any skipped directory.
        if should_skip(rel) {
            continue;
        }

        let ft = entry.file_type()?;
        if ft.is_dir() {
            walk_and_snapshot(root, &path, snapshot_dir, file_count, total_bytes)?;
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

fn should_skip(rel: &Path) -> bool {
    let rel_str = rel.to_string_lossy();
    if rel_str == ".kin-snapshot-tmp" || rel_str.starts_with(".kin-snapshot-tmp/") {
        return true;
    }
    if rel_str.starts_with(".kin-") {
        return true;
    }
    for skip in SKIP_DIRS {
        if rel_str == *skip || rel_str.starts_with(&format!("{}/", skip)) {
            return true;
        }
    }
    false
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

pub async fn run(path: Option<String>, json: bool) -> Result<()> {
    let _span = tracing::info_span!("kin.init").entered();
    let dir = path
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().expect("cannot determine current directory"));

    // Snapshot the working tree once and reuse that frozen view for indexing.
    let (tmp_snapshot, snapshot_manifest) = snapshot_repo(&dir)?;
    let result = kin_core::init(&dir)?;
    if !json {
        println!(
            "Initialized Kin repository at {}",
            result.layout.root().display()
        );
        println!("  KinDB: {}", result.layout.kindb_snapshot_path().display());
        println!("  Blobs: {}", result.layout.objects_dir().display());
        println!("  Genesis change: {}", result.genesis_id);
    }

    let layout = &result.layout;
    // Intentionally offline-only: `kin init` must seed repo truth from the
    // freshly created local snapshot, never from daemon bootstrap state owned
    // by some other repo/session. Do not replace with open_snapshot_daemon_first.
    let snap = crate::backend::open_kindb_snapshot(layout)?;
    let blob_store = kin_blobs::BlobStore::new(layout.objects_dir())
        .map_err(|e| anyhow::anyhow!("failed to open blob store: {}", e))?;

    let all_files = collect_source_files(&tmp_snapshot)?;
    let indexable_files = collect_indexable_files(&tmp_snapshot, &all_files)?;

    let init_summary = if !all_files.is_empty() {
        match try_warm_init_from_cache(&dir, layout, &snap, &blob_store, &indexable_files) {
            Ok(Some(summary)) => summary,
            Ok(None) => {
                let graph = snap.graph();
                parse_and_index(graph.as_ref(), &blob_store, &indexable_files)?
            }
            Err(err) => {
                warn!(error = %err, "warm init cache failed; falling back to full reindex");
                let graph = snap.graph();
                parse_and_index(graph.as_ref(), &blob_store, &indexable_files)?
            }
        }
    } else {
        InitIndexSummary::default()
    };

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
        // Build a semantic change for the initial parse
        let branch_name = kin_core::read_current_branch(layout)?;
        let parent_id = result.genesis_id;
        let change_id = compute_init_change_id(&parent_id);
        let change = SemanticChange {
            id: change_id,
            parents: vec![parent_id],
            timestamp: Timestamp::now(),
            author: AuthorId::new(whoami()),
            message: "kin init: auto-parse".to_string(),
            entity_deltas: vec![],
            relation_deltas: vec![],
            artifact_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: Some(branch_name.clone()),
        };
        graph.create_change(&change)?;
        graph.update_branch_head(&branch_name, &change_id)?;

        if dir.join(".git").exists() {
            match crate::commands::cochange::refresh_from_git_history(graph.as_ref(), &dir) {
                Ok(count) if count > 0 => {
                    if !json {
                        println!("  Mined {} co-change relation(s) from Git history.", count);
                    }
                }
                Ok(_) => {}
                Err(err) => {
                    warn!(error = %err, "failed to mine co-change relations from git history");
                }
            }
        }

        embed_status = graph.embedding_status();

        snap.save()?;

        // Build and save the read-only index for fast CLI queries.
        let read_index = kin_db::ReadIndex::from_graph(&graph)?;
        let idx_path = layout.kindb_snapshot_path().with_extension("kidx");
        read_index.save(&idx_path)?;

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
        if init_summary.warm_cache_hit {
            info!(
                changed_files = init_summary.warm_changed_files,
                reparsed_files = init_summary.warm_reparsed_files,
                indexed_files = init_summary.total_files,
                "warm init cache reused prior semantic snapshot"
            );
        }

        if let Err(err) = refresh_init_cache(&dir, graph.as_ref()) {
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
                repo_root: result.layout.root().display().to_string(),
                kindb_snapshot_path: result.layout.kindb_snapshot_path().display().to_string(),
                objects_dir: result.layout.objects_dir().display().to_string(),
                genesis_change: result.genesis_id.to_string(),
                indexed_embeddings: embed_status.indexed,
                pending_embeddings: embed_status.pending,
                summary: init_summary,
            })?
        );
    }

    Ok(())
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
    let (total_entity_count, _total_files, file_parse_data) =
        index_files(graph, blob_store, indexable_files)?;
    // Cross-file relation linking (progress printed by the linker itself)
    let linked_relations = kin_index::link_cross_file(&file_parse_data);
    for rel in &linked_relations {
        graph.upsert_relation(rel)?;
    }
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

fn index_files(
    graph: &kin_db::InMemoryGraph,
    blob_store: &kin_blobs::BlobStore,
    files: &[IndexableFile],
) -> Result<(usize, usize, Vec<kin_index::FileParseData>)> {
    let _span = tracing::info_span!("kin.init.index_files", files = files.len()).entered();
    let registry = kin_parser::AdapterRegistry::new();
    let mut total_entity_count = 0usize;
    let mut total_files = 0usize;
    let mut file_parse_data = Vec::new();

    let total = files.len();
    let progress_interval = std::cmp::max(total / 100, 10);
    let start = std::time::Instant::now();
    let mut progress = crate::progress::Progress::stderr();

    for (idx, file) in files.iter().enumerate() {
        if idx % progress_interval == 0 || idx + 1 == total {
            progress.update(format_args!(
                "[{}/{}] {}% | {} entities | {:.1}s",
                idx + 1,
                total,
                ((idx + 1) * 100) / total,
                total_entity_count,
                start.elapsed().as_secs_f64()
            ));
        }

        let source = match fs::read(&file.abs_path) {
            Ok(source) => source,
            Err(_) => continue,
        };

        graph.set_file_hash(&file.rel_path, file.hash);
        let _ = blob_store
            .write(&source)
            .map_err(|e| anyhow::anyhow!("blob write failed: {}", e))?;

        total_files += 1;
        let file_id = FilePathId::new(&file.rel_path);

        match &file.classification {
            FileClassification::EntitySource => {
                let ext = file
                    .abs_path
                    .extension()
                    .and_then(|e| e.to_str())
                    .unwrap_or("");
                let adapter = match registry.get_by_extension(ext) {
                    Some(adapter) => adapter,
                    None => continue,
                };

                let tree = match adapter.parse(&source) {
                    Ok(tree) => tree,
                    Err(_) => continue,
                };

                let parse_output = match adapter.extract(&tree, &source, &file_id) {
                    Ok(output) => output,
                    Err(_) => continue,
                };

                let extracted_relations = parse_output.relations;
                let file_imports = parse_output.imports;
                let parse_state = parse_output.parse_state;
                let language = adapter.language_id();
                let mut file_entities = Vec::new();

                for extracted in parse_output.entities {
                    let mut entity =
                        extracted.into_entity_with_source(language, &file_id, Some(&source));
                    kin_parser::attach_file_context_metadata(
                        std::slice::from_mut(&mut entity),
                        &file_id,
                        &file_imports,
                    );
                    graph.upsert_entity(&entity)?;
                    file_entities.push(entity);
                }

                let file_layout = build_layout(
                    &file_id,
                    &file_entities,
                    source.len(),
                    &[],
                    ParseCompleteness::from_parse_state(&parse_state),
                );
                graph.upsert_file_layout(&file_layout)?;

                total_entity_count += file_entities.len();
                file_parse_data.push(kin_index::FileParseData {
                    file_path: file.rel_path.clone(),
                    entities: file_entities,
                    relations: extracted_relations,
                    imports: file_imports,
                });
            }
            FileClassification::ShallowSyntax { language_hint } => {
                if let Some(shallow) =
                    kin_parser::parse_shallow_file(&source, &file_id, language_hint)
                {
                    graph.upsert_shallow_file(&ShallowTrackedFile {
                        file_id,
                        language_hint: language_hint.clone(),
                        declaration_count: shallow.declarations.len(),
                        import_count: shallow.imports.len(),
                        syntax_hash: shallow.fingerprint.syntax_hash,
                        signature_hash: shallow.fingerprint.signature_hash,
                        declaration_names: summarize_shallow_items(
                            shallow.declarations.iter().map(|decl| decl.name.clone()),
                        ),
                        import_paths: summarize_shallow_items(
                            shallow.imports.iter().map(|import| import.raw_path.clone()),
                        ),
                    })?;
                }
            }
            FileClassification::StructuredArtifact(kind) => {
                let artifact = kin_index::extract_artifact(*kind, &source, &file_id).unwrap_or(
                    StructuredArtifact {
                        file_id,
                        kind: *kind,
                        content_hash: Hash256::from_bytes(file.hash),
                        text_preview: preview_text(&source),
                    },
                );
                graph.upsert_structured_artifact(&artifact)?;
            }
            FileClassification::OpaqueArtifact { mime_hint } => {
                graph.upsert_opaque_artifact(&OpaqueArtifact {
                    file_id,
                    content_hash: Hash256::from_bytes(file.hash),
                    mime_type: mime_hint.clone(),
                    text_preview: preview_text_if_likely_text(&source, mime_hint.as_deref()),
                })?;
            }
        }
    }

    progress.finish();
    Ok((total_entity_count, total_files, file_parse_data))
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
    let mut files = Vec::new();

    for file_path in all_files {
        let source = match fs::read(file_path) {
            Ok(source) => source,
            Err(_) => continue,
        };
        let classification = FileClassifier::classify(file_path);

        files.push(IndexableFile {
            abs_path: file_path.clone(),
            rel_path: file_path
                .strip_prefix(source_root)
                .unwrap_or(file_path)
                .to_string_lossy()
                .to_string(),
            hash: kin_blobs::digest_bytes(&source),
            classification,
        });
    }

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
    let Some(cache_dir) = init_cache_repo_path(dir) else {
        return Ok(None);
    };
    let Some(cache_graph_path) = resolve_warm_cache_graph_path(dir, &cache_dir)? else {
        return Ok(None);
    };
    if !cache_graph_path.exists() {
        return Ok(None);
    }

    let cache_snap = match kin_db::SnapshotManager::open(&cache_graph_path) {
        Ok(snap) => snap,
        Err(err) => {
            warn!(path = %cache_graph_path.display(), error = %err, "failed to open warm init cache");
            return Ok(None);
        }
    };
    let cache_graph = cache_snap.graph();
    let current_files: Vec<(String, [u8; 32])> = indexable_files
        .iter()
        .map(|file| (file.rel_path.clone(), file.hash))
        .collect();
    let diff = kin_db::engine::compute_diff(cache_graph.as_ref(), &current_files);
    let changed_files = diff.changed_count();
    let delta = if diff.is_empty() {
        WarmCacheDeltaResult::default()
    } else {
        apply_warm_cache_delta(cache_graph.as_ref(), blob_store, indexable_files, &diff)?
    };
    let scrubbed_paths = scrub_internal_graph_truth(cache_graph.as_ref())?;
    if !scrubbed_paths.is_empty() {
        warn!(
            count = scrubbed_paths.len(),
            "scrubbed internal control-plane paths from warm init cache"
        );
    }
    let warm_text_index_reused =
        sync_warm_text_index_sidecar(local_snap, layout, &cache_graph_path, cache_graph.as_ref())?;

    graft_semantic_state(local_snap, layout, cache_graph.as_ref());
    let warm_embedding_status = restore_warm_embedding_state(
        local_snap,
        layout,
        cache_graph.as_ref(),
        &delta.queued_embeddings,
    )?;
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
    let mut impacted_files = reverse_dependency_closure(
        graph,
        diff.modified_files.iter().chain(diff.removed_files.iter()),
    )?;
    impacted_files.extend(diff.modified_files.iter().cloned());

    let mut files_to_clear = impacted_files.clone();
    files_to_clear.extend(diff.removed_files.iter().cloned());
    for path in &files_to_clear {
        clear_file_semantic_state(graph, path)?;
    }

    let mut reparsed_paths = impacted_files;
    reparsed_paths.extend(diff.added_files.iter().cloned());
    if reparsed_paths.is_empty() {
        return Ok(WarmCacheDeltaResult::default());
    }

    let file_map: HashMap<&str, &IndexableFile> = indexable_files
        .iter()
        .map(|file| (file.rel_path.as_str(), file))
        .collect();
    let selected_files: Vec<IndexableFile> = reparsed_paths
        .iter()
        .filter_map(|path| file_map.get(path.as_str()).copied().cloned())
        .collect();

    let (_, _, file_parse_data) = index_files(graph, blob_store, &selected_files)?;
    let queued_embeddings = file_parse_data
        .iter()
        .flat_map(|file| file.entities.iter().map(|entity| entity.id))
        .collect();
    let universe_entities = graph.query_entities(&EntityFilter::default())?;
    let linked_relations = link_cross_file_against_entities(&file_parse_data, &universe_entities);
    for rel in &linked_relations {
        graph.upsert_relation(rel)?;
    }

    Ok(WarmCacheDeltaResult {
        reparsed_files: selected_files.len(),
        queued_embeddings,
    })
}

fn reverse_dependency_closure<'a, I>(
    graph: &kin_db::InMemoryGraph,
    seed_files: I,
) -> Result<BTreeSet<String>>
where
    I: IntoIterator<Item = &'a String>,
{
    let _span = tracing::info_span!("kin.init.reverse_dependency_closure").entered();
    let mut visited = BTreeSet::new();
    let mut queue = VecDeque::new();

    for file in seed_files {
        if visited.insert(file.clone()) {
            queue.push_back(file.clone());
        }
    }

    while let Some(file_path) = queue.pop_front() {
        for entity in entities_for_file(graph, &file_path)? {
            for relation in graph.get_all_relations_for_entity(&entity.id)? {
                if relation.dst != GraphNodeId::Entity(entity.id) {
                    continue;
                }
                let Some(src_entity_id) = relation.src.as_entity() else {
                    continue;
                };
                let Some(src_entity) = graph.get_entity(&src_entity_id)? else {
                    continue;
                };
                let Some(src_file) = src_entity.file_origin.as_ref().map(|path| path.0.clone())
                else {
                    continue;
                };
                if visited.insert(src_file.clone()) {
                    queue.push_back(src_file);
                }
            }
        }
    }

    Ok(visited)
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
    for entity in entities {
        graph.remove_entity(&entity.id)?;
    }
    let _ = graph.remove_entities_for_file(path);
    let file_id = FilePathId::new(path);
    graph.delete_shallow_file(&file_id)?;
    graph.delete_structured_artifact(&file_id)?;
    graph.delete_opaque_artifact(&file_id)?;
    Ok(())
}

fn is_repo_owned_graph_path(path: &str) -> bool {
    let Some(first_component) = path.split('/').next() else {
        return true;
    };
    !matches!(first_component, ".kin" | ".git" | ".git-export")
        && !first_component.starts_with(".kin-")
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
    cache_graph: &kin_db::InMemoryGraph,
) -> Result<bool> {
    let Some(cache_dir) = cache_graph_path.parent() else {
        return Ok(false);
    };
    let cache_text_index_dir = cache_dir.join("text-index");
    let cache_root_hash = kin_db::compute_graph_root_hash(&cache_graph.to_snapshot());
    cache_graph.persist_text_index_with_root_hash(cache_root_hash)?;
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

#[cfg(feature = "vector")]
fn restore_warm_embedding_state(
    local_snap: &kin_db::SnapshotManager,
    layout: &kin_core::KinLayout,
    source_graph: &kin_db::InMemoryGraph,
    queued_embeddings: &[EntityId],
) -> Result<WarmEmbeddingRestoreStatus> {
    let _span = tracing::info_span!(
        "kin.init.restore_warm_embedding_state",
        queued_embeddings = queued_embeddings.len()
    )
    .entered();
    let local_vector_path = layout.kindb_vector_index_path();
    source_graph.save_vector_index(&local_vector_path)?;

    let local_graph = local_snap.graph();
    let indexed = local_graph.load_vector_index(&local_vector_path)?;
    if indexed == 0 {
        local_graph.queue_all_for_embedding();
        return Ok(WarmEmbeddingRestoreStatus {
            vector_index_reused: false,
            requeued_embeddings: local_graph.embedding_status().pending,
        });
    }

    if !queued_embeddings.is_empty() {
        local_graph.queue_for_embedding(queued_embeddings);
    }

    Ok(WarmEmbeddingRestoreStatus {
        vector_index_reused: true,
        requeued_embeddings: queued_embeddings.len(),
    })
}

#[cfg(not(feature = "vector"))]
fn restore_warm_embedding_state(
    _local_snap: &kin_db::SnapshotManager,
    _layout: &kin_core::KinLayout,
    _source_graph: &kin_db::InMemoryGraph,
    _queued_embeddings: &[EntityId],
) -> Result<WarmEmbeddingRestoreStatus> {
    Ok(WarmEmbeddingRestoreStatus::default())
}

pub(crate) fn refresh_init_cache(dir: &Path, graph: &kin_db::InMemoryGraph) -> Result<()> {
    let Some(cache_dir) = init_cache_repo_path(dir) else {
        return Ok(());
    };
    fs::create_dir_all(&cache_dir)?;

    // Fast path: if the manifest already has this git HEAD, skip the expensive
    // graph serialization + root hash computation.
    let current_head = read_git_head(dir);
    let manifest_path = warm_cache_manifest_path(&cache_dir);
    if let Some(ref head) = current_head {
        if let Ok(Some(manifest)) = read_warm_cache_manifest(&manifest_path) {
            if manifest.heads.contains_key(head) {
                return Ok(());
            }
        }
    }

    let graph_root_hash = hex::encode(kin_db::compute_graph_root_hash(&graph.to_snapshot()));
    let bundle_id = graph_root_hash.clone();
    let cache_graph_path = warm_cache_bundle_graph_path(&cache_dir, &bundle_id);
    if !cache_graph_path.exists() {
        kin_db::SnapshotManager::save_graph(&cache_graph_path, graph).with_context(|| {
            format!(
                "failed to save warm init cache bundle at {}",
                cache_graph_path.display()
            )
        })?;
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
            entity_count: graph.entity_count(),
            relation_count: graph.relation_count(),
            indexed_files: graph.indexed_file_paths().len(),
            published_at: chrono::Utc::now().to_rfc3339(),
        });

    fs::write(&manifest_path, serde_json::to_string_pretty(&manifest)?)?;
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
    let manifest_path = warm_cache_manifest_path(cache_dir);
    if let Some(manifest) = read_warm_cache_manifest(&manifest_path)? {
        if !warm_cache_manifest_is_valid(dir, &manifest) {
            return Ok(None);
        }
        if let Some(bundle_id) = manifest.current_bundle_id.as_deref() {
            let bundle_graph_path = warm_cache_bundle_graph_path(cache_dir, bundle_id);
            if bundle_graph_path.exists() {
                return Ok(Some(bundle_graph_path));
            }
        }
    }

    let legacy_graph_path = cache_dir.join("graph.kndb");
    if legacy_graph_path.exists() {
        return Ok(Some(legacy_graph_path));
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
fn collect_source_files(root: &Path) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    collect_source_files_recursive(root, root, &mut files)?;
    Ok(files)
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
            if matches!(name_str.as_ref(), ".kin" | ".git" | ".git-export")
                || name_str.starts_with(".kin-")
            {
                continue;
            }
            if matches!(
                name_str.as_ref(),
                "node_modules" | "target" | "build" | "dist" | "__pycache__" | "vendor"
            ) {
                continue;
            }
            collect_source_files_recursive(root, &path, files)?;
        } else if path.is_file() {
            files.push(path);
        }
    }

    Ok(())
}

/// Compute a unique change ID for the init auto-parse commit.
fn compute_init_change_id(parent: &SemanticChangeId) -> SemanticChangeId {
    let mut hasher = Sha256::new();
    hasher.update(b"kin-change-v1:");
    hasher.update(b"kin init: auto-parse");
    hasher.update(b":");
    hasher.update(parent.0.as_bytes());
    hasher.update(b":");
    hasher.update(chrono::Utc::now().to_rfc3339().as_bytes());
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
    use kin_model::{
        EntityKind, EntityMetadata, FingerprintAlgorithm, LanguageId, SemanticFingerprint,
        Visibility,
    };
    use serial_test::serial;
    use std::collections::BTreeSet;
    use std::fs;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

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
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
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
        assert!(
            tracked_paths
                .iter()
                .all(|path| is_repo_owned_graph_path(path))
        );

        assert_eq!(graph.indexed_file_paths().len(), expected_paths.len());
        assert_eq!(graph.list_shallow_files().unwrap().len(), 1);
        assert_eq!(graph.list_structured_artifacts().unwrap().len(), 1);
        assert_eq!(graph.list_opaque_artifacts().unwrap().len(), 1);
    }

    fn assert_makefile_is_text_searchable(graph: &kin_db::InMemoryGraph) {
        let makefile_key =
            kin_db::RetrievalKey::Artifact(kin_db::ArtifactId::from_path("Makefile"));
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

        let (snapshot, manifest) = snapshot_repo(root).unwrap();
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

        let (_snapshot, manifest) = snapshot_repo(root).unwrap();

        assert_eq!(manifest["file_count"], 3);
        assert_eq!(manifest["total_bytes"], 9); // 3 + 3 + 3
    }

    #[test]
    fn snapshot_skips_all_excluded_dirs() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // Create all the skip dirs with a file inside each.
        for skip in SKIP_DIRS {
            if *skip == ".kin" {
                continue; // we create .kin ourselves
            }
            let p = root.join(skip);
            fs::create_dir_all(&p).unwrap();
            fs::write(p.join("file.txt"), "skip").unwrap();
        }

        // One real file.
        fs::write(root.join("keep.txt"), "keep").unwrap();

        let (snapshot, _manifest) = snapshot_repo(root).unwrap();
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

        let (snapshot, _manifest) = snapshot_repo(root).unwrap();
        assert!(snapshot.join("keep.txt").exists());
        assert!(!snapshot.join(".kin-snapshot-tmp").exists());
        assert!(!snapshot.join(".kin-other").exists());
    }

    #[test]
    fn snapshot_reads_git_head() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // Set up a fake git repo with a resolved ref.
        fs::create_dir_all(root.join(".git/refs/heads")).unwrap();
        fs::write(root.join(".git/HEAD"), "ref: refs/heads/main\n").unwrap();
        fs::write(root.join(".git/refs/heads/main"), "abc123def456\n").unwrap();
        fs::write(root.join("file.txt"), "content").unwrap();

        let (_snapshot, manifest) = snapshot_repo(root).unwrap();

        assert_eq!(manifest["git_head"], "abc123def456");
    }

    #[tokio::test]
    #[serial]
    async fn run_keeps_control_plane_paths_out_of_graph_truth_on_cold_init() {
        let repo_dir = tempfile::tempdir().unwrap();
        let home_dir = tempfile::tempdir().unwrap();
        let expected_paths = repo_truth_fixture(repo_dir.path());

        let _home_guard = EnvVarGuard::set("HOME", home_dir.path());
        let _cache_guard = EnvVarGuard::remove("KIN_INIT_CACHE_DIR");
        let _warm_cache_guard = EnvVarGuard::set("KIN_INIT_WARM_CACHE", "0");

        run(Some(repo_dir.path().display().to_string()), false)
            .await
            .unwrap();

        let layout = kin_core::KinLayout::new(repo_dir.path().join(".kin"));
        let snap = kin_db::SnapshotManager::open(layout.kindb_snapshot_path()).unwrap();
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
        let expected_paths = repo_truth_fixture(repo_dir.path());

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

        run(Some(repo_dir.path().display().to_string()), false)
            .await
            .unwrap();
        daemon_task.abort();

        assert_eq!(daemon_hits.load(Ordering::SeqCst), 0);

        let layout = kin_core::KinLayout::new(repo_dir.path().join(".kin"));
        let snap = kin_db::SnapshotManager::open(layout.kindb_snapshot_path()).unwrap();
        let graph = snap.graph();
        assert_repo_owned_graph_truth(graph.as_ref(), &expected_paths);
        assert_makefile_is_text_searchable(graph.as_ref());
        assert!(
            tracked_graph_paths(graph.as_ref())
                .iter()
                .all(|path| is_repo_owned_graph_path(path))
        );
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
        let local_snap =
            kin_db::SnapshotManager::open(init_result.layout.kindb_snapshot_path()).unwrap();
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

        refresh_init_cache(repo_dir.path(), &cache_graph).unwrap();

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
        assert!(
            tracked_graph_paths(graph.as_ref())
                .iter()
                .all(|path| is_repo_owned_graph_path(path))
        );
    }

    #[cfg(feature = "vector")]
    #[test]
    fn warm_embedding_state_restores_cached_vectors_and_requeues_delta() {
        let dir = tempfile::tempdir().unwrap();
        let result = kin_core::init(dir.path()).unwrap();
        let local_snap =
            kin_db::SnapshotManager::open(result.layout.kindb_snapshot_path()).unwrap();

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
        restore_warm_embedding_state(&local_snap, &result.layout, &source_graph, &[entity_b.id])
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
        let local_snap =
            kin_db::SnapshotManager::open(result.layout.kindb_snapshot_path()).unwrap();

        let cache_graph_path = dir.path().join("warm-cache/graph.kndb");
        let cache_snap = kin_db::SnapshotManager::new(&cache_graph_path);
        let cache_graph = cache_snap.graph();
        let entity = test_entity("render_widget", "src/lib.rs");
        cache_graph.upsert_entity(&entity).unwrap();
        cache_snap.save().unwrap();

        assert!(
            sync_warm_text_index_sidecar(
                &local_snap,
                &result.layout,
                &cache_graph_path,
                cache_graph.as_ref(),
            )
            .unwrap()
        );
        graft_semantic_state(&local_snap, &result.layout, cache_graph.as_ref());

        let local_graph = local_snap.graph();
        let stats = local_graph.graph_stats();
        assert_eq!(stats.text_indexed_entity_count, 1);
        let hits = local_graph.text_search("render_widget", 5).unwrap();
        assert!(
            hits.iter()
                .any(|(key, _)| *key == kin_model::RetrievalKey::Entity(entity.id))
        );
    }

    #[test]
    fn warm_graft_preserves_tracked_non_entity_files() {
        let dir = tempfile::tempdir().unwrap();
        let result = kin_core::init(dir.path()).unwrap();
        let local_snap =
            kin_db::SnapshotManager::open(result.layout.kindb_snapshot_path()).unwrap();

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
        let local_snap =
            kin_db::SnapshotManager::open(result.layout.kindb_snapshot_path()).unwrap();

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
        let (snapshot_path, manifest) = snapshot_repo(root).unwrap();
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
}
