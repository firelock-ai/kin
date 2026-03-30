// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_index::{link_cross_file_against_entities, FileClassification, FileClassifier};
use kin_model::ChangeStore;
use kin_model::EntityStore;
use kin_model::{
    AuthorId, Entity, EntityFilter, EntityId, FilePathId, Hash256, OpaqueArtifact, SemanticChange,
    SemanticChangeId, ShallowTrackedFile, StructuredArtifact, Timestamp,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap, VecDeque};
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
const INIT_WARM_CACHE_PIPELINE_EPOCH: &str = "init-warm-2026-03-28-file-surfaces-v2";

#[derive(Debug, Clone)]
struct IndexableFile {
    abs_path: PathBuf,
    rel_path: String,
    hash: [u8; 32],
    classification: FileClassification,
}

#[derive(Debug, Clone, Copy, Default)]
struct InitIndexSummary {
    total_entity_count: usize,
    total_files: usize,
    linked_relations: usize,
    warm_cache_hit: bool,
    warm_changed_files: usize,
    warm_reparsed_files: usize,
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
fn snapshot_repo(dir: &Path) -> Result<PathBuf> {
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
    fs::write(
        snapshot_dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest)?,
    )?;

    println!("  Snapshot saved ({} files)", file_count);
    Ok(tmp_snapshot)
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
    let head_path = dir.join(".git/HEAD");
    let content = fs::read_to_string(head_path).ok()?;
    let content = content.trim();

    if let Some(ref_path) = content.strip_prefix("ref: ") {
        // Resolve the ref to a commit hash.
        let ref_file = dir.join(".git").join(ref_path);
        fs::read_to_string(ref_file)
            .ok()
            .map(|s| s.trim().to_string())
    } else {
        // Detached HEAD — already a commit hash.
        Some(content.to_string())
    }
}

pub async fn run(path: Option<String>) -> Result<()> {
    let _span = tracing::info_span!("kin.init").entered();
    let dir = path
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().expect("cannot determine current directory"));

    // Snapshot the working tree once and reuse that frozen view for indexing.
    let tmp_snapshot = snapshot_repo(&dir)?;
    let result = kin_core::init(&dir)?;
    println!(
        "Initialized Kin repository at {}",
        result.layout.root().display()
    );
    println!("  KinDB: {}", result.layout.kindb_snapshot_path().display());
    println!("  Blobs: {}", result.layout.objects_dir().display());
    println!("  Genesis change: {}", result.genesis_id);

    let layout = &result.layout;
    let snap = crate::backend::open_snapshot_daemon_first(layout).await?;
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

    move_snapshot_into_place(&tmp_snapshot, &dir.join(".kin/snapshot"))?;

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

        let embed_status = graph.embedding_status();

        snap.save()?;

        // Build and save the read-only index for fast CLI queries.
        let read_index = kin_db::ReadIndex::from_graph(&graph)?;
        let idx_path = layout.kindb_snapshot_path().with_extension("kidx");
        read_index.save(&idx_path)?;

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
    let (total_entity_count, total_files, file_parse_data) =
        index_files(graph, blob_store, indexable_files)?;
    // Cross-file relation linking
    let linked_relations = kin_index::link_cross_file(&file_parse_data);
    for rel in &linked_relations {
        graph.upsert_relation(rel)?;
    }

    Ok(InitIndexSummary {
        total_entity_count,
        total_files,
        linked_relations: linked_relations.len(),
        warm_cache_hit: false,
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

    for file in files {
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
                    })?;
                }
            }
            FileClassification::StructuredArtifact(kind) => {
                graph.upsert_structured_artifact(&StructuredArtifact {
                    file_id,
                    kind: *kind,
                    content_hash: Hash256::from_bytes(file.hash),
                })?;
            }
            FileClassification::OpaqueArtifact { mime_hint } => {
                graph.upsert_opaque_artifact(&OpaqueArtifact {
                    file_id,
                    content_hash: Hash256::from_bytes(file.hash),
                    mime_type: mime_hint.clone(),
                })?;
            }
        }
    }

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
    let Some(cache_graph_path) = init_cache_repo_path(dir).map(|path| path.join("graph.kndb"))
    else {
        return Ok(None);
    };
    if !cache_graph_path.exists() {
        return Ok(None);
    }
    if !warm_cache_manifest_is_valid(dir, &cache_graph_path)? {
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

    graft_semantic_state(local_snap, layout, cache_graph.as_ref());
    restore_warm_embedding_state(
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
                if relation.dst != entity.id {
                    continue;
                }
                let Some(src_entity) = graph.get_entity(&relation.src)? else {
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

    local_snap.swap(kin_db::InMemoryGraph::from_snapshot_with_text_index(
        local_snapshot,
        layout.text_index_dir(),
    ));
}

#[cfg(feature = "vector")]
fn restore_warm_embedding_state(
    local_snap: &kin_db::SnapshotManager,
    layout: &kin_core::KinLayout,
    source_graph: &kin_db::InMemoryGraph,
    queued_embeddings: &[EntityId],
) -> Result<()> {
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
    } else if !queued_embeddings.is_empty() {
        local_graph.queue_for_embedding(queued_embeddings);
    }

    Ok(())
}

#[cfg(not(feature = "vector"))]
fn restore_warm_embedding_state(
    _local_snap: &kin_db::SnapshotManager,
    _layout: &kin_core::KinLayout,
    _source_graph: &kin_db::InMemoryGraph,
    _queued_embeddings: &[EntityId],
) -> Result<()> {
    Ok(())
}

pub(crate) fn refresh_init_cache(dir: &Path, graph: &kin_db::InMemoryGraph) -> Result<()> {
    let Some(cache_dir) = init_cache_repo_path(dir) else {
        return Ok(());
    };
    let cache_graph_path = cache_dir.join("graph.kndb");
    kin_db::SnapshotManager::save_graph(&cache_graph_path, graph).with_context(|| {
        format!(
            "failed to save warm init cache at {}",
            cache_graph_path.display()
        )
    })?;

    fs::create_dir_all(&cache_dir)?;
    let manifest = serde_json::json!({
        "schema": INIT_WARM_CACHE_SCHEMA_VERSION,
        "pipeline_epoch": INIT_WARM_CACHE_PIPELINE_EPOCH,
        "repo_identity": repo_cache_identity(dir),
        "git_head": read_git_head(dir),
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "entity_count": graph.entity_count(),
        "relation_count": graph.relation_count(),
        "indexed_files": graph.indexed_file_paths().len(),
    });
    fs::write(
        cache_dir.join("manifest.json"),
        serde_json::to_string_pretty(&manifest)?,
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

fn warm_cache_manifest_is_valid(dir: &Path, cache_graph_path: &Path) -> Result<bool> {
    let Some(cache_dir) = cache_graph_path.parent() else {
        return Ok(false);
    };
    let manifest_path = cache_dir.join("manifest.json");
    if !manifest_path.exists() {
        return Ok(false);
    }

    let manifest = serde_json::from_str::<serde_json::Value>(&fs::read_to_string(&manifest_path)?)
        .with_context(|| {
            format!(
                "failed to parse warm init manifest at {}",
                manifest_path.display()
            )
        })?;

    let schema = manifest
        .get("schema")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    if schema != INIT_WARM_CACHE_SCHEMA_VERSION {
        return Ok(false);
    }

    let pipeline_epoch = manifest
        .get("pipeline_epoch")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    if pipeline_epoch != INIT_WARM_CACHE_PIPELINE_EPOCH {
        return Ok(false);
    }

    let repo_identity = manifest
        .get("repo_identity")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    Ok(repo_identity == repo_cache_identity(dir))
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
    use std::fs;

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

        let snapshot = snapshot_repo(root).unwrap();
        assert!(snapshot.join("README.md").exists());
        assert!(snapshot.join("src/main.rs").exists());
        assert!(!snapshot.join("node_modules").exists());
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

        let snapshot = snapshot_repo(root).unwrap();

        let manifest: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(snapshot.join("manifest.json")).unwrap())
                .unwrap();

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

        let snapshot = snapshot_repo(root).unwrap();
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

        let snapshot = snapshot_repo(root).unwrap();
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

        let snapshot = snapshot_repo(root).unwrap();

        let manifest: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(snapshot.join("manifest.json")).unwrap())
                .unwrap();

        assert_eq!(manifest["git_head"], "abc123def456");
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
        };
        let structured = kin_model::StructuredArtifact {
            file_id: FilePathId::new("Makefile"),
            kind: kin_model::ArtifactKind::Makefile,
            content_hash: Hash256::from_bytes([3; 32]),
        };
        let opaque = kin_model::OpaqueArtifact {
            file_id: FilePathId::new("README.md"),
            content_hash: Hash256::from_bytes([4; 32]),
            mime_type: Some("text/markdown".to_string()),
        };
        source_graph.upsert_shallow_file(&shallow).unwrap();
        source_graph.upsert_structured_artifact(&structured).unwrap();
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
    fn warm_cache_manifest_validation_tracks_pipeline_epoch() {
        let repo_dir = tempfile::tempdir().unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        let cache_graph_path = cache_dir.path().join("graph.kndb");
        fs::write(&cache_graph_path, []).unwrap();

        let repo_identity = repo_cache_identity(repo_dir.path());
        let manifest_path = cache_dir.path().join("manifest.json");
        fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&serde_json::json!({
                "schema": INIT_WARM_CACHE_SCHEMA_VERSION,
                "pipeline_epoch": INIT_WARM_CACHE_PIPELINE_EPOCH,
                "repo_identity": repo_identity,
            }))
            .unwrap(),
        )
        .unwrap();

        assert!(warm_cache_manifest_is_valid(repo_dir.path(), &cache_graph_path).unwrap());

        fs::write(
            &manifest_path,
            serde_json::to_string_pretty(&serde_json::json!({
                "schema": INIT_WARM_CACHE_SCHEMA_VERSION,
                "pipeline_epoch": "stale-pipeline",
                "repo_identity": repo_cache_identity(repo_dir.path()),
            }))
            .unwrap(),
        )
        .unwrap();

        assert!(!warm_cache_manifest_is_valid(repo_dir.path(), &cache_graph_path).unwrap());
    }
}
