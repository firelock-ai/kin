// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{HashMap, HashSet};
use std::ops::Range;
use std::path::Path;
use std::process::Command;

use kin_blobs::BlobStore;
use kin_db::{GraphSnapshot, InMemoryGraph};
use kin_index::{
    build_projection_derived_relations_for_file, extract_artifact,
    link_cross_file_against_entities, FileClassification, FileClassifier, FileParseData,
    IndexPipeline,
};
use kin_model::{
    ArtifactDeltaKind, ArtifactId, ChangeStore, EntityId, EntityKind, FileLayout, FilePathId,
    GraphStore, Hash256, ImportSection, OpaqueArtifact, ParseCompleteness, RelationKind,
    SemanticChange, SemanticChangeId, ShallowTrackedFile, SourceRegion, StructuredArtifact,
};
use kin_parser::extract::{EMBEDDING_BODY_PREVIEW_KEY, FILE_SURFACE_CONTEXT_KEY};

use crate::{KinError, Result};

/// Build a read-only graph view resolved at a specific semantic ref.
///
/// The returned graph contains:
/// - entities and relations replayed as of `head`
/// - only changes reachable from `head`
/// - entity-source file layouts derived from persisted historical entity spans
/// - non-entity tracked files rebuilt from historical blob content
/// - a fresh in-memory text index aligned with the historical view
///
/// When `repo_path` is provided and a blob is missing from the blob store,
/// the function repairs the gap by reading from the Git object database and
/// back-filling the blob store. This is a one-time migration path for repos
/// initialized before the import.rs fix (commit 244de43) that persists old
/// blob hashes. Once all repos have been re-initialized or repaired, this
/// code path becomes dead and can be removed.
///
/// Embedding/vector state is intentionally not reconstructed yet.
pub fn build_graph_at_ref(
    graph: &InMemoryGraph,
    blob_store: &BlobStore,
    head: &SemanticChangeId,
) -> Result<InMemoryGraph> {
    build_graph_at_ref_with_repo(graph, blob_store, head, None, None)
}

pub fn build_graph_at_ref_with_repo(
    graph: &InMemoryGraph,
    blob_store: &BlobStore,
    head: &SemanticChangeId,
    repo_path: Option<&Path>,
    oid_cache: Option<&ChangeOidCache>,
) -> Result<InMemoryGraph> {
    build_graph_at_ref_with_repo_inner(graph, blob_store, head, repo_path, oid_cache, None)
}

pub fn build_graph_at_git_ref_with_repo(
    graph: &InMemoryGraph,
    blob_store: &BlobStore,
    head: &SemanticChangeId,
    repo_path: &Path,
    git_oid_hint: &str,
    oid_cache: Option<&ChangeOidCache>,
) -> Result<InMemoryGraph> {
    build_graph_at_ref_with_repo_inner(
        graph,
        blob_store,
        head,
        Some(repo_path),
        oid_cache,
        Some(git_oid_hint),
    )
}

fn build_graph_at_ref_with_repo_inner(
    graph: &InMemoryGraph,
    blob_store: &BlobStore,
    head: &SemanticChangeId,
    repo_path: Option<&Path>,
    oid_cache: Option<&ChangeOidCache>,
    git_oid_hint: Option<&str>,
) -> Result<InMemoryGraph> {
    let build_start = std::time::Instant::now();
    let build_timeout_secs = std::env::var("KIN_BUILD_GRAPH_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<f64>().ok())
        .unwrap_or(60.0);

    let changes = collect_changes_at_ref(graph, head)?;
    let resolved = graph
        .resolve_graph_at(head)
        .map_err(|err| KinError::Graph(err.to_string()))?;

    let git_repair = repo_path.and_then(|path| {
        match GitBlobRepair::new(path, head, &changes, oid_cache, git_oid_hint) {
            Ok(repair) => Some(repair),
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    "failed to initialize git-backed historical ref repair"
                );
                None
            }
        }
    });
    let reader = BlobReader::new(blob_store, git_repair.as_ref(), repo_path);
    let ref_file_tree = match git_repair
        .as_ref()
        .map(|repair| repair.materialize_file_tree(blob_store))
    {
        Some(Ok(git_tree)) if !git_tree.is_empty() => {
            if git_tree != resolved.file_tree {
                tracing::warn!(
                    graph_files = resolved.file_tree.len(),
                    git_files = git_tree.len(),
                    "historical ref graph file tree differed from git tree; using git object tree for scoped source truth"
                );
            }
            git_tree
        }
        Some(Ok(_)) => resolved.file_tree.clone(),
        Some(Err(err)) => {
            tracing::warn!(
                error = %err,
                "failed to materialize git tree for historical ref; falling back to graph artifact deltas"
            );
            resolved.file_tree.clone()
        }
        None => resolved.file_tree.clone(),
    };

    let mut snapshot = GraphSnapshot::empty();
    snapshot.entities = resolved.entities;
    snapshot.relations = resolved.relations;
    snapshot.entity_revisions = resolved.entity_revisions;
    snapshot.entity_tombstones = resolved.entity_tombstones;
    snapshot.relation_tombstones = resolved.relation_tombstones;
    snapshot.changes = changes
        .iter()
        .map(|change| (change.id, change.clone()))
        .collect();
    snapshot.change_children = build_change_children(&changes);
    snapshot.file_hashes = ref_file_tree
        .iter()
        .map(|(file_id, hash)| (file_id.0.clone(), *hash.as_bytes()))
        .collect();
    let mut branches = HashMap::new();
    if let Ok(parent_branches) = graph.list_branches() {
        let reachable_ids: HashSet<SemanticChangeId> = changes.iter().map(|c| c.id).collect();
        for mut b in parent_branches {
            let mut curr = b.head;
            let mut found = false;
            let mut visited = HashSet::new();
            while !visited.contains(&curr) {
                visited.insert(curr);
                if reachable_ids.contains(&curr) {
                    b.head = curr;
                    found = true;
                    break;
                }
                if let Ok(Some(change)) = graph.get_change(&curr) {
                    if change.parents.is_empty() {
                        break;
                    }
                    curr = change.parents[0];
                } else {
                    break;
                }
            }
            if found {
                branches.insert(b.name.clone(), b);
            }
        }
    }
    snapshot.branches = branches;

    let lifecycle = RefLifecycle::from_changes(&changes);
    let path_resolver = HistoricalPathResolver::from_changes(&changes, &ref_file_tree);

    normalize_entity_file_origins_to_historical_tree(&mut snapshot, &ref_file_tree, &path_resolver);
    rebuild_entity_source_file_layouts(
        &mut snapshot,
        &ref_file_tree,
        &reader,
        &lifecycle,
        build_start,
        build_timeout_secs,
    )?;
    rebuild_non_entity_tracked_files(
        &mut snapshot,
        &ref_file_tree,
        &reader,
        build_start,
        build_timeout_secs,
    )?;
    filter_temporal_cochange_relations(&mut snapshot);

    Ok(InMemoryGraph::from_snapshot(snapshot))
}

/// Post-filter vector search results to retain only entities present in a
/// scoped entity set.
///
/// Vector indices are global (they index the full HEAD graph) and cannot be
/// cheaply rebuilt for each historical scope. This function compensates by
/// over-fetching from the global vector index and retaining only entity keys
/// whose entity is present in the scoped snapshot. Non-entity keys are dropped:
/// artifact/vector keys are built from HEAD content today, so keeping them for
/// a historical scope can inject evidence from files that changed after the
/// scoped ref.
///
/// # Usage
///
/// ```ignore
/// let raw = vector_index.search_similar(&embedding, limit * 3)?;
/// let scoped = filter_vector_results_to_scope(raw, &scoped_entity_ids, limit);
/// ```
pub fn filter_vector_results_to_scope(
    results: Vec<(kin_model::RetrievalKey, f32)>,
    scoped_entity_ids: &HashSet<EntityId>,
    limit: usize,
) -> Vec<(kin_model::RetrievalKey, f32)> {
    results
        .into_iter()
        .filter(|(key, _score)| {
            matches!(key, kin_model::RetrievalKey::Entity(eid) if scoped_entity_ids.contains(eid))
        })
        .take(limit)
        .collect()
}

/// Reads blob content, repairing from Git objects when the blob store misses.
///
/// Layered fallback for missing blobs (Kin's SHA-256 store -> Git tree by path
/// via gix -> `git cat-file blob`). All tiers verify the content hash matches
/// the requested Kin SHA-256 before back-filling the store.
///
/// Migration debt: the Git repair tiers exist for repos initialized before
/// import.rs persisted old blob hashes (commit 244de43), and for shallow
/// clones / integration branches where Kin's blob store hasn't been seeded
/// for every blob the change DAG references.
struct BlobReader<'a> {
    blob_store: &'a BlobStore,
    git_repair: Option<&'a GitBlobRepair>,
    repo_path: Option<&'a Path>,
}

impl<'a> BlobReader<'a> {
    fn new(
        blob_store: &'a BlobStore,
        git_repair: Option<&'a GitBlobRepair>,
        repo_path: Option<&'a Path>,
    ) -> Self {
        Self {
            blob_store,
            git_repair,
            repo_path,
        }
    }

    fn read(&self, hash: &kin_blobs::Hash256, file_path: &str) -> Option<Vec<u8>> {
        if let Ok(content) = self.blob_store.read(hash) {
            return Some(content);
        }
        if let Some(content) = self.repair_from_git_tree(hash, file_path) {
            return Some(content);
        }
        if let Some(content) = self.repair_from_git_object(hash, file_path) {
            return Some(content);
        }
        None
    }

    fn repair_from_git_tree(&self, hash: &kin_blobs::Hash256, file_path: &str) -> Option<Vec<u8>> {
        let repair = self.git_repair?;
        let content = repair.read_blob(file_path)?;
        self.accept_repaired_blob(hash, file_path, content, "git tree")
    }

    fn repair_from_git_object(
        &self,
        hash: &kin_blobs::Hash256,
        file_path: &str,
    ) -> Option<Vec<u8>> {
        let repo_path = self.repo_path?;
        let content = git_cat_file_blob(repo_path, &hash.to_string())?;
        self.accept_repaired_blob(hash, file_path, content, "git cat-file")
    }

    fn accept_repaired_blob(
        &self,
        expected: &kin_blobs::Hash256,
        file_path: &str,
        content: Vec<u8>,
        source: &str,
    ) -> Option<Vec<u8>> {
        let actual_hash = kin_blobs::digest(&content);
        if actual_hash != *expected {
            // Surface as warn (not debug) so silent-pass mode is observable:
            // caller sees `None` either way, but logs distinguish
            // "blob missing everywhere" from "blob retrieved but corrupted".
            tracing::warn!(
                file = %file_path,
                expected = %expected,
                actual = %actual_hash,
                source = source,
                "git blob hash mismatch during repair: retrieved blob content does not match expected hash, skipping repair"
            );
            return None;
        }
        tracing::warn!(
            file = %file_path,
            source = source,
            "repaired missing blob from git — re-init repo to eliminate migration debt"
        );
        if let Err(err) = self.blob_store.write(&content) {
            tracing::debug!(
                file = %file_path,
                error = %err,
                "failed to back-fill blob store during repair"
            );
        }
        Some(content)
    }
}

/// Final-tier blob repair: ask Git to dump the blob content for a hash.
///
/// Works when the repository is using SHA-256 object format (Git's optional
/// modern OID format). For SHA-1 repos this returns `None` because Kin's hash
/// won't address any Git object; that failure is expected and silent.
fn git_cat_file_blob(repo_path: &Path, hash_hex: &str) -> Option<Vec<u8>> {
    let output = Command::new("git")
        .arg("-C")
        .arg(repo_path)
        .arg("cat-file")
        .arg("blob")
        .arg(hash_hex)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    Some(output.stdout)
}

/// One-time blob repair from Git for repos with unpersisted old blob hashes.
///
/// Constructed once per `build_graph_at_ref` call when `repo_path` is provided
/// and the head change maps to an imported git commit. Reads blob content
/// from Git's object database and back-fills the blob store so subsequent
/// reads are served from the blob store directly.
///
/// Migration debt: remove once all active repos have been re-initialized
/// with the import.rs fix that persists old blob hashes (commit 244de43).
struct GitBlobRepair {
    repo: gix::Repository,
    repo_path: std::path::PathBuf,
    git_oid: gix::ObjectId,
    tree_id: gix::ObjectId,
}

fn open_repo(path: &Path) -> std::result::Result<gix::Repository, gix::open::Error> {
    let dot_git = path.join(".git");
    if dot_git.is_dir() {
        gix::open(dot_git)
    } else {
        gix::open(path)
    }
}

impl GitBlobRepair {
    fn new(
        repo_path: &Path,
        head: &SemanticChangeId,
        _changes: &[SemanticChange],
        oid_cache: Option<&ChangeOidCache>,
        git_oid_hint: Option<&str>,
    ) -> std::result::Result<Self, String> {
        let repo = open_repo(repo_path).map_err(|e| e.to_string())?;
        let git_oid = if let Some(git_oid) = git_oid_hint {
            let oid = gix::ObjectId::from_hex(git_oid.as_bytes())
                .map_err(|err| format!("invalid git oid hint '{git_oid}': {err}"))?;
            let hinted_change = change_id_from_git_oid_for_ref_view(&oid);
            if hinted_change != *head {
                return Err(format!(
                    "git oid hint {git_oid} maps to {hinted_change}, not requested change {head}"
                ));
            }
            oid
        } else {
            find_git_oid_for_change(&repo, head, oid_cache)?
        };
        let tree_id = {
            let commit = repo.find_commit(git_oid).map_err(|e| e.to_string())?;
            let tree = commit.tree().map_err(|e| e.to_string())?;
            tree.id
        };
        Ok(Self {
            repo,
            repo_path: repo_path.to_path_buf(),
            git_oid,
            tree_id,
        })
    }

    fn read_blob(&self, file_path: &str) -> Option<Vec<u8>> {
        let tree = self.repo.find_tree(self.tree_id).ok()?;
        let entry = tree.lookup_entry_by_path(file_path).ok()??;
        let object = entry.object().ok()?;
        Some(object.data.to_vec())
    }

    fn materialize_file_tree(
        &self,
        blob_store: &BlobStore,
    ) -> std::result::Result<HashMap<FilePathId, Hash256>, String> {
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.repo_path)
            .arg("ls-tree")
            .arg("-rz")
            .arg(self.git_oid.to_string())
            .output()
            .map_err(|err| format!("git ls-tree failed to start: {err}"))?;
        if !output.status.success() {
            return Err(format!(
                "git ls-tree exited with status {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            ));
        }

        let mut file_tree = HashMap::new();
        for raw in output.stdout.split(|byte| *byte == 0) {
            if raw.is_empty() {
                continue;
            }
            let record =
                std::str::from_utf8(raw).map_err(|err| format!("non-utf8 git path: {err}"))?;
            let Some((meta, path)) = record.split_once('\t') else {
                continue;
            };
            let mut meta_parts = meta.split_whitespace();
            let _mode = meta_parts.next();
            let Some(kind) = meta_parts.next() else {
                continue;
            };
            let Some(oid) = meta_parts.next() else {
                continue;
            };
            if kind != "blob" {
                continue;
            }

            let content = Command::new("git")
                .arg("-C")
                .arg(&self.repo_path)
                .arg("cat-file")
                .arg("blob")
                .arg(oid)
                .output()
                .map_err(|err| format!("git cat-file failed to start for {path}: {err}"))?;
            if !content.status.success() {
                return Err(format!(
                    "git cat-file failed for {path} ({oid}) with status {}: {}",
                    content.status,
                    String::from_utf8_lossy(&content.stderr)
                ));
            }
            let hash = blob_store
                .write(&content.stdout)
                .map_err(|err| format!("failed to write git blob for {path}: {err}"))?;
            file_tree.insert(FilePathId::new(path), hash);
        }

        Ok(file_tree)
    }
}

fn change_id_from_git_oid_for_ref_view(oid: &gix::ObjectId) -> SemanticChangeId {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(b"kin-git-import-v1:");
    hasher.update(oid.as_bytes());
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    SemanticChangeId::from_hash(Hash256::from_bytes(bytes))
}

/// Pre-computed mapping from SemanticChangeId to Git OID.
/// Build once, reuse across multiple `build_graph_at_ref` calls for
/// fast scope switching without re-walking the commit DAG.
pub type ChangeOidCache = HashMap<SemanticChangeId, gix::ObjectId>;

/// Build a complete SemanticChangeId → Git OID mapping by walking all
/// reachable commits from HEAD. O(N) in commit count but only needs
/// to be done once per repo session.
pub fn build_change_oid_cache(
    repo: &gix::Repository,
) -> std::result::Result<ChangeOidCache, String> {
    use sha2::{Digest, Sha256};

    let tip = repo.head_id().map_err(|e| e.to_string())?.detach();
    let walk = repo.rev_walk([tip]).all().map_err(|e| e.to_string())?;

    let mut cache = HashMap::new();
    for info_result in walk {
        let info = info_result.map_err(|e| e.to_string())?;
        let oid = info.id;
        let mut hasher = Sha256::new();
        hasher.update(b"kin-git-import-v1:");
        hasher.update(oid.as_bytes());
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        let change_id = SemanticChangeId::from_hash(Hash256::from_bytes(bytes));
        cache.insert(change_id, oid);
    }

    Ok(cache)
}

/// Find the git OID that corresponds to a SemanticChangeId.
/// When a pre-built cache is provided, this is an O(1) lookup.
/// Otherwise falls back to walking all reachable commits (O(N)).
fn find_git_oid_for_change(
    repo: &gix::Repository,
    head: &SemanticChangeId,
    cache: Option<&ChangeOidCache>,
) -> std::result::Result<gix::ObjectId, String> {
    if let Some(cache) = cache {
        return cache
            .get(head)
            .copied()
            .ok_or_else(|| format!("no git commit found for change {head} (cached)"));
    }

    use sha2::{Digest, Sha256};

    let tip = repo.head_id().map_err(|e| e.to_string())?.detach();

    let walk = repo.rev_walk([tip]).all().map_err(|e| e.to_string())?;

    for info_result in walk {
        let info = info_result.map_err(|e| e.to_string())?;
        let oid = info.id;
        let mut hasher = Sha256::new();
        hasher.update(b"kin-git-import-v1:");
        hasher.update(oid.as_bytes());
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        let candidate = SemanticChangeId::from_hash(Hash256::from_bytes(bytes));
        if candidate == *head {
            return Ok(oid);
        }
    }

    Err(format!("no git commit found for change {head}"))
}

/// Snapshot of which changes and entities are alive at the target ref.
///
/// Built from the change sequence reachable from the ref's HEAD. Provides
/// defensive validation during enrichment: when matching a parsed entity to a
/// persisted ID, we require that the persisted entity's `created_in` is in
/// the reachable change set. Without this, a parsed entity could silently
/// adopt an ID that belongs to an entity created on a side branch not part of
/// the ref's history, or to an entity recreated after the ref.
struct RefLifecycle {
    reachable_changes: HashSet<SemanticChangeId>,
    removed_entities: HashSet<EntityId>,
}

impl RefLifecycle {
    fn from_changes(changes: &[SemanticChange]) -> Self {
        let mut reachable_changes = HashSet::with_capacity(changes.len());
        let mut removed_entities = HashSet::new();
        for change in changes {
            reachable_changes.insert(change.id);
            for delta in &change.entity_deltas {
                if let kin_model::EntityDelta::Removed(id) = delta {
                    removed_entities.insert(*id);
                }
                if let kin_model::EntityDelta::Added(entity) = delta {
                    // An entity re-added later overrides an earlier removal in
                    // the same reachable history.
                    removed_entities.remove(&entity.id);
                }
            }
        }
        Self {
            reachable_changes,
            removed_entities,
        }
    }

    /// Returns true when the entity was alive at the ref: created within the
    /// reachable change set and not removed by any reachable change.
    ///
    /// Entities with `created_in: None` are treated as alive — these come
    /// from in-memory overlays that pre-date a commit, or from test fixtures
    /// where lifecycle anchors haven't been backfilled.
    fn is_alive_at_ref(&self, entity: &kin_model::Entity) -> bool {
        if self.removed_entities.contains(&entity.id) {
            return false;
        }
        match entity.created_in {
            None => true,
            Some(change_id) => self.reachable_changes.contains(&change_id),
        }
    }
}

/// Resolves historical FilePathIds to the canonical path that appears in the
/// reconstructed file tree at the ref.
///
/// Replays artifact deltas in topological order to track move/rename history:
/// when a path is removed and another path is added with the same blob hash
/// inside the same change, the new path is treated as a rename target for the
/// old path. This is more stable than the previous basename-only fallback,
/// which silently misrouted entity spans when two files shared a basename.
struct HistoricalPathResolver {
    /// Maps a path that may appear in legacy entity records (origin or span)
    /// to its current canonical path in the reconstructed file tree.
    canonical_for_legacy: HashMap<String, FilePathId>,
    /// Map from basename to all paths in the reconstructed file tree sharing that basename.
    basename_to_paths: HashMap<String, Vec<FilePathId>>,
}

impl HistoricalPathResolver {
    fn from_changes(changes: &[SemanticChange], file_tree: &HashMap<FilePathId, Hash256>) -> Self {
        let mut canonical_for_legacy: HashMap<String, FilePathId> = HashMap::new();

        // Replay artifact deltas to learn rename chains. A rename is detected
        // when one change contains both a Removed and an Added (or Modified
        // with no old_hash) sharing a blob hash. The Removed path becomes a
        // legacy alias of the new canonical path.
        for change in changes {
            let mut removed_by_hash: HashMap<Hash256, FilePathId> = HashMap::new();
            for delta in &change.artifact_deltas {
                if delta.kind == ArtifactDeltaKind::Removed {
                    if let Some(hash) = delta.old_hash {
                        removed_by_hash.insert(hash, delta.file_id.clone());
                    }
                }
            }
            for delta in &change.artifact_deltas {
                if !matches!(
                    delta.kind,
                    ArtifactDeltaKind::Added | ArtifactDeltaKind::Modified
                ) {
                    continue;
                }
                let Some(new_hash) = delta.new_hash else {
                    continue;
                };
                if let Some(legacy_path) = removed_by_hash.get(&new_hash) {
                    if *legacy_path != delta.file_id {
                        canonical_for_legacy.insert(legacy_path.0.clone(), delta.file_id.clone());
                    }
                }
            }
        }

        // Collapse chains: if A -> B and B -> C, A should also resolve to C.
        // Iterate until stable.
        let mut changed = true;
        while changed {
            changed = false;
            let snapshot: Vec<(String, FilePathId)> = canonical_for_legacy
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            for (legacy, target) in snapshot {
                if let Some(next) = canonical_for_legacy.get(&target.0).cloned() {
                    if next != target {
                        canonical_for_legacy.insert(legacy, next);
                        changed = true;
                    }
                }
            }
        }

        let mut basename_to_paths: HashMap<String, Vec<FilePathId>> = HashMap::new();
        for file_id in file_tree.keys() {
            if let Some(basename) = Path::new(&file_id.0)
                .file_name()
                .and_then(|name| name.to_str())
            {
                basename_to_paths
                    .entry(basename.to_string())
                    .or_default()
                    .push(file_id.clone());
            }
        }

        Self {
            canonical_for_legacy,
            basename_to_paths,
        }
    }

    /// Resolve a legacy `FilePathId` to its canonical path in the ref tree.
    /// Returns `None` when no canonical mapping can be established.
    fn resolve(
        &self,
        file_id: &FilePathId,
        file_tree: &HashMap<FilePathId, Hash256>,
    ) -> Option<FilePathId> {
        if file_tree.contains_key(file_id) {
            return Some(file_id.clone());
        }
        if let Some(canonical) = self.canonical_for_legacy.get(&file_id.0) {
            if file_tree.contains_key(canonical) {
                return Some(canonical.clone());
            }
        }

        let basename = Path::new(&file_id.0).file_name()?.to_str()?;
        let candidates = self.basename_to_paths.get(basename)?;

        // 1. Strict suffix match (longest-path suffix match)
        let mut suffix_matches: Vec<&FilePathId> = candidates
            .iter()
            .filter(|path| {
                if path.0 == file_id.0 {
                    return true;
                }
                // path.0 ends with / + file_id.0
                if path.0.len() > file_id.0.len() && path.0.ends_with(&file_id.0) {
                    let prefix_len = path.0.len() - file_id.0.len();
                    if path.0.as_bytes()[prefix_len - 1] == b'/' {
                        return true;
                    }
                }
                // file_id.0 ends with / + path.0
                if file_id.0.len() > path.0.len() && file_id.0.ends_with(&path.0) {
                    let prefix_len = file_id.0.len() - path.0.len();
                    if file_id.0.as_bytes()[prefix_len - 1] == b'/' {
                        return true;
                    }
                }
                false
            })
            .collect();

        if !suffix_matches.is_empty() {
            suffix_matches.sort_by_key(|p| std::cmp::Reverse(p.0.len()));
            if suffix_matches.len() == 1 || suffix_matches[0].0.len() > suffix_matches[1].0.len() {
                return Some(suffix_matches[0].clone());
            }
        }

        // 2. Component-wise suffix match: try matching candidates that share a common suffix of
        // at least 2 components, picking the one with the longest matching suffix if it is unique.
        let mut best_candidate: Option<(&FilePathId, usize)> = None;
        let mut second_best_len = 0;
        for path in candidates {
            let len = common_component_suffix_len(&file_id.0, &path.0);
            if len >= 2 {
                if let Some((_, best_len)) = best_candidate {
                    if len > best_len {
                        second_best_len = best_len;
                        best_candidate = Some((path, len));
                    } else if len == best_len {
                        second_best_len = len;
                    } else if len > second_best_len {
                        second_best_len = len;
                    }
                } else {
                    best_candidate = Some((path, len));
                }
            }
        }
        if let Some((path, best_len)) = best_candidate {
            if best_len > second_best_len {
                return Some(path.clone());
            }
        }

        // 3. Last-resort basename match (if unique)
        if candidates.len() == 1 {
            return Some(candidates[0].clone());
        }

        None
    }
}

fn common_component_suffix_len(a: &str, b: &str) -> usize {
    a.rsplit('/')
        .zip(b.rsplit('/'))
        .take_while(|(ap, bp)| ap == bp)
        .count()
}

pub fn collect_changes_at_ref<G>(graph: &G, head: &SemanticChangeId) -> Result<Vec<SemanticChange>>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    let mut seen = HashSet::new();
    let mut ordered = Vec::new();
    enum Frame {
        Visit(SemanticChangeId),
        Emit(SemanticChange),
    }

    let mut stack = vec![Frame::Visit(*head)];
    while let Some(frame) = stack.pop() {
        match frame {
            Frame::Visit(id) => {
                if !seen.insert(id) {
                    continue;
                }
                let change = graph
                    .get_change(&id)
                    .map_err(|err| KinError::Graph(err.to_string()))?
                    .ok_or_else(|| KinError::Graph(format!("change {} not found", id)))?;
                stack.push(Frame::Emit(change.clone()));
                for parent in change.parents.iter().rev() {
                    stack.push(Frame::Visit(*parent));
                }
            }
            Frame::Emit(change) => ordered.push(change),
        }
    }
    Ok(ordered)
}

fn build_change_children(
    changes: &[SemanticChange],
) -> HashMap<SemanticChangeId, Vec<SemanticChangeId>> {
    let mut children: HashMap<SemanticChangeId, Vec<SemanticChangeId>> = HashMap::new();
    for change in changes {
        for parent in &change.parents {
            children.entry(*parent).or_default().push(change.id);
        }
    }
    children
}

fn filter_temporal_cochange_relations(snapshot: &mut GraphSnapshot) {
    let change_ids: HashSet<SemanticChangeId> = snapshot.changes.keys().copied().collect();
    let before = snapshot.relations.len();
    snapshot.relations.retain(|_id, relation| {
        if relation.kind != RelationKind::CoChanges {
            return true;
        }
        match relation.created_in {
            Some(ref change_id) => change_ids.contains(change_id),
            None => false,
        }
    });
    let removed = before - snapshot.relations.len();
    if removed > 0 {
        tracing::debug!(
            removed,
            remaining = snapshot.relations.len(),
            "filtered out-of-scope cochange relations from historical snapshot"
        );
    }
}

fn normalize_entity_file_origins_to_historical_tree(
    snapshot: &mut GraphSnapshot,
    file_tree: &HashMap<FilePathId, Hash256>,
    path_resolver: &HistoricalPathResolver,
) {
    for entity in snapshot.entities.values_mut() {
        if let Some(file_origin) = entity.file_origin.as_mut() {
            if let Some(canonical) = path_resolver.resolve(file_origin, file_tree) {
                *file_origin = canonical;
            }
        }
        if let Some(span) = entity.span.as_mut() {
            if let Some(canonical) = path_resolver.resolve(&span.file, file_tree) {
                span.file = canonical;
            }
        }
    }
}

fn rebuild_non_entity_tracked_files(
    snapshot: &mut GraphSnapshot,
    file_tree: &HashMap<FilePathId, Hash256>,
    reader: &BlobReader<'_>,
    build_start: std::time::Instant,
    build_timeout_secs: f64,
) -> Result<()> {
    let entity_paths: HashSet<String> = snapshot
        .entities
        .values()
        .filter_map(|entity| entity.file_origin.as_ref())
        .map(|file_id| file_id.0.clone())
        .collect();

    for (file_id, hash) in file_tree {
        if build_start.elapsed().as_secs_f64() > build_timeout_secs {
            tracing::warn!(
                "rebuild_non_entity_tracked_files: timeout after {:.1}s, returning partial results",
                build_start.elapsed().as_secs_f64()
            );
            break;
        }
        if entity_paths.contains(&file_id.0) {
            continue;
        }

        let content = match reader.read(hash, &file_id.0) {
            Some(content) => content,
            None => {
                tracing::warn!(file = %file_id, hash = %hash, "skipping historical tracked file with missing blob");
                continue;
            }
        };

        match FileClassifier::classify(Path::new(&file_id.0)) {
            FileClassification::EntitySource => {}
            FileClassification::ShallowSyntax { language_hint } => {
                if let Some(shallow) =
                    kin_parser::parse_shallow_file(&content, file_id, &language_hint)
                {
                    snapshot.shallow_files.push(ShallowTrackedFile {
                        file_id: file_id.clone(),
                        language_hint,
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
                    });
                } else {
                    snapshot
                        .opaque_artifacts
                        .push(build_opaque_artifact(file_id, *hash, None, &content));
                }
            }
            FileClassification::StructuredArtifact(kind) => {
                let artifact =
                    extract_artifact(kind, &content, file_id).unwrap_or(StructuredArtifact {
                        file_id: file_id.clone(),
                        kind,
                        content_hash: *hash,
                        text_preview: preview_text(&content),
                    });
                snapshot.structured_artifacts.push(artifact);
            }
            FileClassification::OpaqueArtifact { mime_hint } => {
                snapshot
                    .opaque_artifacts
                    .push(build_opaque_artifact(file_id, *hash, mime_hint, &content));
            }
        }
    }

    Ok(())
}

fn rebuild_entity_source_file_layouts(
    snapshot: &mut GraphSnapshot,
    file_tree: &HashMap<FilePathId, Hash256>,
    reader: &BlobReader<'_>,
    lifecycle: &RefLifecycle,
    build_start: std::time::Instant,
    build_timeout_secs: f64,
) -> Result<()> {
    let pipeline = IndexPipeline::new();
    let mut rebuilt_entities = Vec::new();
    let mut parsed_relations = Vec::new();
    let mut parsed_files = Vec::new();
    let mut parsed_layouts = Vec::new();
    let mut projection_relations = Vec::new();
    let known_files: HashSet<String> = file_tree.keys().map(|file_id| file_id.0.clone()).collect();

    for (file_id, hash) in file_tree {
        if build_start.elapsed().as_secs_f64() > build_timeout_secs {
            tracing::warn!(
                "rebuild_entity_source_file_layouts: timeout after {:.1}s, returning partial results",
                build_start.elapsed().as_secs_f64()
            );
            break;
        }
        if !matches!(
            FileClassifier::classify(Path::new(&file_id.0)),
            FileClassification::EntitySource
        ) {
            continue;
        }

        let content = match reader.read(hash, &file_id.0) {
            Some(content) => content,
            None => {
                tracing::warn!(
                    file = %file_id,
                    hash = %hash,
                    "skipping historical source layout with missing blob"
                );
                continue;
            }
        };

        // Keep raw historical source text searchable for ref-scoped locate,
        // even when semantic entity replay succeeds for the file.
        snapshot
            .opaque_artifacts
            .push(build_historical_source_artifact(file_id, *hash, &content));
        projection_relations.extend(build_projection_derived_relations_for_file(
            &file_id.0,
            &content,
            &known_files,
            |path| snapshot_artifact_id_for_path(snapshot, path),
        ));

        let file_entities = snapshot
            .entities
            .values()
            .filter(|entity| entity.file_origin.as_ref() == Some(file_id))
            .cloned()
            .collect::<Vec<_>>();
        let indexed = if file_entities.is_empty()
            || should_probe_sparse_historical_source(&file_entities, content.len())
        {
            match pipeline.index_file_content_with_tests(
                file_id,
                &content,
                kin_blobs::Hash256::from_bytes(*hash.as_bytes()),
            ) {
                Ok(indexed) => Some(indexed),
                Err(err) => {
                    tracing::warn!(
                        file = %file_id,
                        hash = %hash,
                        error = %err,
                        "skipping historical source fallback parse that could not be indexed"
                    );
                    None
                }
            }
        } else {
            None
        };

        if let Some(indexed) = indexed.as_ref() {
            if indexed.indexed_file.entities.is_empty() {
                if !file_entities.is_empty() {
                    let contextual_entities =
                        enrich_entities_with_historical_source_context(&file_entities, &content);
                    for entity in &contextual_entities {
                        snapshot.entities.insert(entity.id, entity.clone());
                    }
                    snapshot.file_layouts.push(build_entity_file_layout(
                        file_id,
                        &contextual_entities,
                        content.len(),
                        ParseCompleteness::Partial(
                            "historical ref view layout derived from persisted entity spans and file-surface lexical context"
                                .to_string(),
                        ),
                    ));
                    continue;
                }
            }
        }

        if file_entities.is_empty() {
            let Some(indexed) = indexed else {
                continue;
            };

            if indexed.indexed_file.entities.is_empty() {
                continue;
            }

            parsed_relations.extend(indexed.indexed_file.relations.iter().cloned());
            parsed_files.push(FileParseData {
                file_path: indexed.indexed_file.file_id.0.clone(),
                entities: indexed.indexed_file.entities.clone(),
                relations: indexed.indexed_file.extracted_relations.clone(),
                imports: indexed.indexed_file.imports.clone(),
            });
            rebuilt_entities.extend(indexed.indexed_file.entities);
            parsed_layouts.push(indexed.indexed_file.file_layout);
            continue;
        }

        if let Some(indexed) = indexed {
            if let Some(enriched) = enrich_sparse_historical_source_file(
                &file_entities,
                indexed.indexed_file,
                lifecycle,
            ) {
                parsed_files.push(enriched.parse_data);
                rebuilt_entities.extend(enriched.entities);
                parsed_layouts.push(enriched.file_layout);
                continue;
            }
        }

        snapshot.file_layouts.push(build_entity_file_layout(
            file_id,
            &file_entities,
            content.len(),
            ParseCompleteness::Partial(
                "historical ref view layout derived from persisted entity spans".to_string(),
            ),
        ));
    }

    if !rebuilt_entities.is_empty() {
        snapshot.file_layouts.extend(parsed_layouts);
        for entity in rebuilt_entities {
            snapshot.entities.insert(entity.id, entity);
        }

        let universe_entities = snapshot.entities.values().cloned().collect::<Vec<_>>();
        parsed_relations.extend(link_cross_file_against_entities(
            &parsed_files,
            &universe_entities,
        ));
    }

    parsed_relations.extend(projection_relations);
    for relation in parsed_relations {
        snapshot.relations.insert(relation.id, relation);
    }

    Ok(())
}

#[allow(deprecated)]
fn snapshot_artifact_id_for_path(snapshot: &GraphSnapshot, path: &str) -> Option<ArtifactId> {
    let file_id = FilePathId::new(path);
    Some(
        snapshot
            .artifact_index
            .get(&file_id)
            .copied()
            .unwrap_or_else(|| ArtifactId::from_file_id(&file_id)),
    )
}

fn should_probe_sparse_historical_source(
    persisted_entities: &[kin_model::Entity],
    file_len: usize,
) -> bool {
    if persisted_entities.is_empty() {
        return true;
    }

    let bytes_per_entity = file_len / persisted_entities.len().max(1);
    bytes_per_entity >= 512
        || (persisted_entities.len() <= 4 && file_len >= 1024)
        || (persisted_entities.len() <= 16 && file_len >= 4096)
}

fn enrich_sparse_historical_source_file(
    persisted_entities: &[kin_model::Entity],
    indexed_file: kin_index::IndexedFile,
    lifecycle: &RefLifecycle,
) -> Option<HistoricalSourceFileEnrichment> {
    if !should_enrich_with_parsed_semantics(persisted_entities, &indexed_file.entities) {
        return None;
    }

    // Gap 2: refuse to bind parsed entities to persisted IDs that were not
    // alive at the ref. When any persisted candidate fails the lifecycle
    // check, reparse the file fresh — keep newly minted IDs from the parser
    // rather than reusing potentially-recycled persisted IDs. This is the
    // safer semantic: a fresh-ID entity may miss continuity with HEAD, but
    // it never binds entity spans to the wrong historical identity.
    let any_stale = persisted_entities
        .iter()
        .any(|entity| !lifecycle.is_alive_at_ref(entity));
    if any_stale {
        let file_layout = build_entity_file_layout(
            &indexed_file.file_id,
            &indexed_file.entities,
            indexed_file
                .file_layout
                .regions
                .last()
                .map_or(0, |region| match region {
                    SourceRegion::EntityRef { byte_range, .. }
                    | SourceRegion::Trivia { byte_range } => byte_range.end,
                }),
            ParseCompleteness::Partial(
                "historical ref view layout reparsed without binding because persisted entities were not alive at ref"
                    .to_string(),
            ),
        );
        return Some(HistoricalSourceFileEnrichment {
            entities: indexed_file.entities.clone(),
            file_layout,
            parse_data: FileParseData {
                file_path: indexed_file.file_id.0,
                entities: indexed_file.entities,
                relations: indexed_file.extracted_relations,
                imports: indexed_file.imports,
            },
        });
    }

    let stabilized_entities =
        stabilize_parsed_entities(persisted_entities, indexed_file.entities, lifecycle);
    let merged_entities = merge_historical_file_entities(persisted_entities, stabilized_entities);
    let file_layout = build_entity_file_layout(
        &indexed_file.file_id,
        &merged_entities,
        indexed_file
            .file_layout
            .regions
            .last()
            .map_or(0, |region| match region {
                SourceRegion::EntityRef { byte_range, .. }
                | SourceRegion::Trivia { byte_range } => byte_range.end,
            }),
        ParseCompleteness::Partial(
            "historical ref view layout enriched from parsed blob and persisted entity IDs"
                .to_string(),
        ),
    );

    Some(HistoricalSourceFileEnrichment {
        entities: merged_entities.clone(),
        file_layout,
        parse_data: FileParseData {
            file_path: indexed_file.file_id.0,
            entities: merged_entities,
            relations: indexed_file.extracted_relations,
            imports: indexed_file.imports,
        },
    })
}

fn should_enrich_with_parsed_semantics(
    persisted_entities: &[kin_model::Entity],
    parsed_entities: &[kin_model::Entity],
) -> bool {
    if persisted_entities.is_empty() || parsed_entities.len() <= persisted_entities.len() {
        return false;
    }

    let persisted_keys = persisted_entities
        .iter()
        .map(entity_match_key)
        .collect::<HashSet<_>>();
    let parsed_keys = parsed_entities
        .iter()
        .map(entity_match_key)
        .collect::<HashSet<_>>();

    let shared = parsed_keys.intersection(&persisted_keys).count();
    let parsed_only = parsed_keys.difference(&persisted_keys).count();

    shared > 0 && parsed_only >= 2
}

fn stabilize_parsed_entities(
    persisted_entities: &[kin_model::Entity],
    parsed_entities: Vec<kin_model::Entity>,
    lifecycle: &RefLifecycle,
) -> Vec<kin_model::Entity> {
    let mut matched_persisted = HashSet::<EntityId>::new();

    parsed_entities
        .into_iter()
        .map(|mut parsed| {
            // Gap 1: only match against persisted entities that were alive at
            // the ref. An entity created on an unreachable branch, or removed
            // before the ref, must not contribute its ID to a reparsed entity.
            let existing = persisted_entities
                .iter()
                .filter(|candidate| !matched_persisted.contains(&candidate.id))
                .filter(|candidate| lifecycle.is_alive_at_ref(candidate))
                .find(|candidate| entity_match_key(candidate) == entity_match_key(&parsed))
                .or_else(|| {
                    persisted_entities
                        .iter()
                        .filter(|candidate| !matched_persisted.contains(&candidate.id))
                        .filter(|candidate| lifecycle.is_alive_at_ref(candidate))
                        .find(|candidate| {
                            candidate.name == parsed.name
                                && candidate.file_origin == parsed.file_origin
                        })
                });

            if let Some(existing) = existing {
                matched_persisted.insert(existing.id);
                parsed.id = existing.id;
                parsed.created_in = existing.created_in;
                parsed.superseded_by = existing.superseded_by;
                parsed.lineage_parent = existing.lineage_parent;
            }

            parsed
        })
        .collect()
}

fn merge_historical_file_entities(
    persisted_entities: &[kin_model::Entity],
    parsed_entities: Vec<kin_model::Entity>,
) -> Vec<kin_model::Entity> {
    let mut merged = persisted_entities.to_vec();
    let mut positions = merged
        .iter()
        .enumerate()
        .map(|(idx, entity)| (entity.id, idx))
        .collect::<HashMap<_, _>>();

    for entity in parsed_entities {
        if let Some(existing_idx) = positions.get(&entity.id).copied() {
            merged[existing_idx] = entity;
        } else {
            positions.insert(entity.id, merged.len());
            merged.push(entity);
        }
    }

    merged
}

fn entity_match_key(entity: &kin_model::Entity) -> (EntityKind, String) {
    (entity.kind, entity.name.clone())
}

struct HistoricalSourceFileEnrichment {
    entities: Vec<kin_model::Entity>,
    file_layout: FileLayout,
    parse_data: FileParseData,
}

fn build_opaque_artifact(
    file_id: &FilePathId,
    content_hash: Hash256,
    mime_hint: Option<String>,
    content: &[u8],
) -> OpaqueArtifact {
    OpaqueArtifact {
        file_id: file_id.clone(),
        content_hash,
        mime_type: mime_hint.clone(),
        text_preview: preview_text_if_likely_text(content, mime_hint.as_deref()),
    }
}

fn build_historical_source_artifact(
    file_id: &FilePathId,
    content_hash: Hash256,
    content: &[u8],
) -> OpaqueArtifact {
    OpaqueArtifact {
        file_id: file_id.clone(),
        content_hash,
        mime_type: Some("text/x-source".to_string()),
        text_preview: historical_source_text(content),
    }
}

fn enrich_entities_with_historical_source_context(
    entities: &[kin_model::Entity],
    content: &[u8],
) -> Vec<kin_model::Entity> {
    let Some(source_text) = historical_source_text(content) else {
        return entities.to_vec();
    };

    entities
        .iter()
        .cloned()
        .map(|mut entity| {
            entity.metadata.extra.insert(
                EMBEDDING_BODY_PREVIEW_KEY.to_string(),
                serde_json::Value::String(source_text.clone()),
            );
            entity.metadata.extra.insert(
                FILE_SURFACE_CONTEXT_KEY.to_string(),
                serde_json::Value::String(source_text.clone()),
            );
            entity
        })
        .collect()
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

fn historical_source_text(content: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(content).ok()?;
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }

    Some(trimmed.chars().take(256_000).collect())
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

fn build_entity_file_layout(
    file_id: &FilePathId,
    entities: &[kin_model::Entity],
    file_len: usize,
    parse_completeness: ParseCompleteness,
) -> FileLayout {
    let mut entity_spans: Vec<(EntityId, Range<usize>)> = entities
        .iter()
        .filter_map(|entity| {
            entity
                .span
                .as_ref()
                .map(|span| (entity.id, span.start_byte..span.end_byte))
        })
        .collect();
    entity_spans.sort_by_key(|(_, range)| range.start);

    let mut regions = Vec::new();
    let mut cursor = 0;
    for (entity_id, byte_range) in entity_spans {
        if byte_range.start > cursor {
            regions.push(SourceRegion::Trivia {
                byte_range: cursor..byte_range.start,
            });
        }
        regions.push(SourceRegion::EntityRef {
            entity_id,
            byte_range: byte_range.clone(),
        });
        cursor = byte_range.end;
    }
    if cursor < file_len {
        regions.push(SourceRegion::Trivia {
            byte_range: cursor..file_len,
        });
    }

    FileLayout {
        file_id: file_id.clone(),
        parse_completeness,
        imports: ImportSection {
            byte_range: 0..0,
            items: Vec::new(),
        },
        regions,
    }
}

fn summarize_shallow_items(items: impl IntoIterator<Item = String>) -> Vec<String> {
    let mut seen = std::collections::BTreeSet::new();
    let mut result = Vec::new();
    for item in items {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }
        if seen.insert(trimmed.to_string()) {
            result.push(trimmed.to_string());
            if result.len() >= 16 {
                break;
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    use kin_blobs::BlobStore;
    use kin_model::{
        ArtifactDelta, ArtifactDeltaKind, AuthorId, Entity, EntityDelta, EntityKind, EntityRole,
        EntityStore, FingerprintAlgorithm, LanguageId, SemanticChange, SemanticFingerprint,
        SourceSpan, Timestamp, Visibility,
    };

    fn change(
        id: SemanticChangeId,
        parents: Vec<SemanticChangeId>,
        artifact_deltas: Vec<ArtifactDelta>,
    ) -> SemanticChange {
        SemanticChange {
            id,
            parents,
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: format!("change {}", id),
            entity_deltas: vec![],
            relation_deltas: vec![],
            artifact_deltas,
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: None,
        }
    }

    fn git_change_id_for_test(git_oid_hex: &str) -> SemanticChangeId {
        use sha2::{Digest, Sha256};

        let oid = gix::ObjectId::from_hex(git_oid_hex.as_bytes()).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(b"kin-git-import-v1:");
        hasher.update(oid.as_bytes());
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        SemanticChangeId::from_hash(Hash256::from_bytes(bytes))
    }

    fn run_git(repo: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(args)
            .output()
            .unwrap_or_else(|err| panic!("failed to run git {args:?}: {err}"));
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8_lossy(&output.stdout).trim().to_string()
    }

    #[test]
    fn build_graph_at_ref_reconstructs_historical_tracked_files() {
        let graph = InMemoryGraph::new();
        let temp = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::new(temp.path().join("objects")).unwrap();

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x11; 32]));
        graph
            .create_change(&change(genesis_id, vec![], vec![]))
            .unwrap();

        let readme_v1 = blob_store.write(b"Authentication guide for v1").unwrap();
        let cargo_v1 = blob_store.write(b"[package]\nname = \"kin\"\n").unwrap();
        let add_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x12; 32]));
        graph
            .create_change(&change(
                add_id,
                vec![genesis_id],
                vec![
                    ArtifactDelta {
                        file_id: FilePathId::new("README.md"),
                        kind: ArtifactDeltaKind::Added,
                        old_hash: None,
                        new_hash: Some(readme_v1),
                    },
                    ArtifactDelta {
                        file_id: FilePathId::new("Cargo.toml"),
                        kind: ArtifactDeltaKind::Added,
                        old_hash: None,
                        new_hash: Some(cargo_v1),
                    },
                ],
            ))
            .unwrap();

        let readme_v2 = blob_store.write(b"Deployment guide for v2").unwrap();
        let head_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x13; 32]));
        graph
            .create_change(&change(
                head_id,
                vec![add_id],
                vec![ArtifactDelta {
                    file_id: FilePathId::new("README.md"),
                    kind: ArtifactDeltaKind::Modified,
                    old_hash: Some(readme_v1),
                    new_hash: Some(readme_v2),
                }],
            ))
            .unwrap();

        let historical = build_graph_at_ref(&graph, &blob_store, &add_id).unwrap();

        let structured = historical.list_structured_artifacts().unwrap();
        assert_eq!(structured.len(), 1);
        assert_eq!(structured[0].file_id.0, "Cargo.toml");

        let opaque = historical.list_opaque_artifacts().unwrap();
        assert_eq!(opaque.len(), 1);
        assert_eq!(opaque[0].file_id.0, "README.md");
        assert!(opaque[0]
            .text_preview
            .as_deref()
            .unwrap_or_default()
            .contains("Authentication guide"));

        assert!(!historical
            .text_search("Authentication", 10)
            .unwrap()
            .is_empty());
        assert!(historical.text_search("Deployment", 10).unwrap().is_empty());
    }

    #[test]
    fn build_graph_at_ref_with_repo_uses_git_tree_over_stale_artifact_delta() {
        let repo = tempfile::tempdir().unwrap();
        run_git(repo.path(), &["init"]);
        run_git(repo.path(), &["config", "user.email", "kin@example.test"]);
        run_git(repo.path(), &["config", "user.name", "Kin Test"]);

        let source_path = repo.path().join("src/lib.cpp");
        std::fs::create_dir_all(source_path.parent().unwrap()).unwrap();
        std::fs::write(
            &source_path,
            "int main() {\n  return 0;\n}\n// OLD_BASE_ONLY\n",
        )
        .unwrap();
        run_git(repo.path(), &["add", "src/lib.cpp"]);
        run_git(repo.path(), &["commit", "-m", "base"]);
        let base_oid = run_git(repo.path(), &["rev-parse", "HEAD"]);

        std::fs::write(
            &source_path,
            "int main() {\n  return 0;\n}\n// JSON_PRIVATE_UNLESS_TESTED\n",
        )
        .unwrap();
        run_git(repo.path(), &["add", "src/lib.cpp"]);
        run_git(repo.path(), &["commit", "-m", "future"]);

        let graph = InMemoryGraph::new();
        let blob_temp = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::new(blob_temp.path().join("objects")).unwrap();
        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x91; 32]));
        graph
            .create_change(&change(genesis_id, vec![], vec![]))
            .unwrap();

        let stale_future_hash = blob_store
            .write(b"int main() {\n  return 0;\n}\n// JSON_PRIVATE_UNLESS_TESTED\n")
            .unwrap();
        let base_id = git_change_id_for_test(&base_oid);
        graph
            .create_change(&change(
                base_id,
                vec![genesis_id],
                vec![ArtifactDelta {
                    file_id: FilePathId::new("src/lib.cpp"),
                    kind: ArtifactDeltaKind::Added,
                    old_hash: None,
                    new_hash: Some(stale_future_hash),
                }],
            ))
            .unwrap();

        let historical = build_graph_at_git_ref_with_repo(
            &graph,
            &blob_store,
            &base_id,
            repo.path(),
            &base_oid,
            None,
        )
        .unwrap();

        assert!(!historical
            .text_search("OLD_BASE_ONLY", 10)
            .unwrap()
            .is_empty());
        assert!(historical
            .text_search("JSON_PRIVATE_UNLESS_TESTED", 10)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn build_graph_at_ref_indexes_historical_source_text_for_entity_files() {
        let graph = InMemoryGraph::new();
        let temp = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::new(temp.path().join("objects")).unwrap();

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x14; 32]));
        graph
            .create_change(&change(genesis_id, vec![], vec![]))
            .unwrap();

        let source_hash = blob_store
            .write(
                b"int main(void) {\n  // --exit-status should return a distinct parse error code\n  return 0;\n}\n",
            )
            .unwrap();
        let main_entity = test_entity("main", "src/main.c");
        let add_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x15; 32]));
        graph
            .create_change(&SemanticChange {
                id: add_id,
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "add main".to_string(),
                entity_deltas: vec![EntityDelta::Added(main_entity)],
                relation_deltas: vec![],
                artifact_deltas: vec![ArtifactDelta {
                    file_id: FilePathId::new("src/main.c"),
                    kind: ArtifactDeltaKind::Added,
                    old_hash: None,
                    new_hash: Some(source_hash),
                }],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let historical = build_graph_at_ref(&graph, &blob_store, &add_id).unwrap();

        assert!(historical
            .list_opaque_artifacts()
            .unwrap()
            .iter()
            .any(|artifact| artifact.file_id.0 == "src/main.c"
                && artifact
                    .text_preview
                    .as_deref()
                    .unwrap_or_default()
                    .contains("--exit-status")));
        assert!(!historical
            .text_search("--exit-status", 10)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn build_graph_at_ref_preserves_semantic_entity_identity_from_history() {
        let graph = InMemoryGraph::new();
        let temp = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::new(temp.path().join("objects")).unwrap();

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x21; 32]));
        graph
            .create_change(&change(genesis_id, vec![], vec![]))
            .unwrap();

        let current_hash = blob_store
            .write(b"def processor():\n    return 'processor'\n")
            .unwrap();
        let auto_parse_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x22; 32]));
        let processor = test_entity("processor", "src/lib.py");
        graph
            .create_change(&SemanticChange {
                id: auto_parse_id,
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "auto-parse".to_string(),
                entity_deltas: vec![EntityDelta::Added(processor.clone())],
                relation_deltas: vec![],
                artifact_deltas: vec![ArtifactDelta {
                    file_id: FilePathId::new("src/lib.py"),
                    kind: ArtifactDeltaKind::Added,
                    old_hash: None,
                    new_hash: Some(current_hash),
                }],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let historical_hash = blob_store
            .write(b"def handler():\n    return 'handler'\n")
            .unwrap();
        let historical_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x23; 32]));
        graph
            .create_change(&change(
                historical_id,
                vec![auto_parse_id],
                vec![ArtifactDelta {
                    file_id: FilePathId::new("src/lib.py"),
                    kind: ArtifactDeltaKind::Modified,
                    old_hash: Some(current_hash),
                    new_hash: Some(historical_hash),
                }],
            ))
            .unwrap();

        let historical = build_graph_at_ref(&graph, &blob_store, &historical_id).unwrap();
        let entities = historical.list_all_entities().unwrap();
        assert_eq!(entities.len(), 1);
        assert!(
            entities
                .iter()
                .any(|entity| entity.id == processor.id && entity.name == "processor"),
            "historical views should preserve semantic entity identity from the change DAG"
        );
        assert!(
            entities.iter().all(|entity| entity.name != "handler"),
            "source blobs alone should not silently rewrite semantic history"
        );

        let layout = historical
            .get_file_layout(&FilePathId::new("src/lib.py"))
            .unwrap()
            .expect("historical entity-source file should still expose a layout");
        assert!(
            layout.regions.iter().any(|region| matches!(
                region,
                kin_model::SourceRegion::EntityRef { entity_id, .. } if *entity_id == processor.id
            )),
            "historical file layouts should point at the persisted entity IDs"
        );
    }

    #[test]
    fn build_graph_at_ref_falls_back_to_blob_parsing_for_artifact_only_history() {
        let graph = InMemoryGraph::new();
        let temp = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::new(temp.path().join("objects")).unwrap();

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x31; 32]));
        graph
            .create_change(&change(genesis_id, vec![], vec![]))
            .unwrap();

        let historical_hash = blob_store
            .write(b"def handler():\n    return 'handler'\n")
            .unwrap();
        let historical_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x32; 32]));
        graph
            .create_change(&change(
                historical_id,
                vec![genesis_id],
                vec![ArtifactDelta {
                    file_id: FilePathId::new("src/lib.py"),
                    kind: ArtifactDeltaKind::Added,
                    old_hash: None,
                    new_hash: Some(historical_hash),
                }],
            ))
            .unwrap();

        let historical = build_graph_at_ref(&graph, &blob_store, &historical_id).unwrap();
        let entities = historical.list_all_entities().unwrap();
        assert!(
            entities.iter().any(|entity| entity.name == "handler"),
            "artifact-only imported history should still expose source entities via blob parsing"
        );

        let layout = historical
            .get_file_layout(&FilePathId::new("src/lib.py"))
            .unwrap()
            .expect("artifact-only source file should expose a parsed layout");
        assert!(
            layout
                .regions
                .iter()
                .any(|region| matches!(region, kin_model::SourceRegion::EntityRef { .. })),
            "fallback parsed layouts should contain entity regions"
        );
    }

    #[test]
    fn build_graph_at_ref_normalizes_dangling_file_origin_aliases() {
        let graph = InMemoryGraph::new();
        let temp = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::new(temp.path().join("objects")).unwrap();

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x39; 32]));
        graph
            .create_change(&change(genesis_id, vec![], vec![]))
            .unwrap();

        let source_hash = blob_store
            .write(b"def processor():\n    return 'processor'\n")
            .unwrap();
        let head_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x3a; 32]));
        let mut aliased = test_entity("processor", "lib.py");
        aliased.file_origin = Some(FilePathId::new("lib.py"));
        aliased.span = Some(SourceSpan {
            file: FilePathId::new("lib.py"),
            start_byte: 0,
            end_byte: 14,
            start_line: 1,
            start_col: 1,
            end_line: 1,
            end_col: 14,
        });
        graph
            .create_change(&SemanticChange {
                id: head_id,
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "aliased historical file".to_string(),
                entity_deltas: vec![EntityDelta::Added(aliased.clone())],
                relation_deltas: vec![],
                artifact_deltas: vec![ArtifactDelta {
                    file_id: FilePathId::new("src/lib.py"),
                    kind: ArtifactDeltaKind::Added,
                    old_hash: None,
                    new_hash: Some(source_hash),
                }],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let historical = build_graph_at_ref(&graph, &blob_store, &head_id).unwrap();
        let processor = historical
            .list_all_entities()
            .unwrap()
            .into_iter()
            .find(|entity| entity.id == aliased.id)
            .expect("historical entity should still exist");
        assert_eq!(
            processor.file_origin,
            Some(FilePathId::new("src/lib.py")),
            "dangling basename aliases should normalize to the tracked historical file"
        );
        assert_eq!(
            processor.span.as_ref().map(|span| span.file.clone()),
            Some(FilePathId::new("src/lib.py")),
            "span file aliases should normalize alongside file origins"
        );
    }

    #[test]
    fn build_graph_at_ref_normalizes_suffix_path_aliases() {
        let graph = InMemoryGraph::new();
        let temp = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::new(temp.path().join("objects")).unwrap();

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x3b; 32]));
        graph
            .create_change(&change(genesis_id, vec![], vec![]))
            .unwrap();

        let source_hash = blob_store
            .write(b"def processor():\n    return 'processor'\n")
            .unwrap();
        let head_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x3c; 32]));
        let mut aliased = test_entity("processor", "src/lib.py");
        aliased.file_origin = Some(FilePathId::new("src/lib.py"));
        aliased.span = Some(SourceSpan {
            file: FilePathId::new("src/lib.py"),
            start_byte: 0,
            end_byte: 14,
            start_line: 1,
            start_col: 1,
            end_line: 1,
            end_col: 14,
        });
        graph
            .create_change(&SemanticChange {
                id: head_id,
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "suffix-aliased historical file".to_string(),
                entity_deltas: vec![EntityDelta::Added(aliased.clone())],
                relation_deltas: vec![],
                artifact_deltas: vec![ArtifactDelta {
                    file_id: FilePathId::new("project/src/lib.py"),
                    kind: ArtifactDeltaKind::Added,
                    old_hash: None,
                    new_hash: Some(source_hash),
                }],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let historical = build_graph_at_ref(&graph, &blob_store, &head_id).unwrap();
        let processor = historical
            .list_all_entities()
            .unwrap()
            .into_iter()
            .find(|entity| entity.id == aliased.id)
            .expect("historical entity should still exist");
        assert_eq!(
            processor.file_origin,
            Some(FilePathId::new("project/src/lib.py")),
            "suffix-based path aliases should normalize when basename is ambiguous or missing"
        );
    }

    #[test]
    fn build_graph_at_ref_enriches_sparse_historical_source_overlap() {
        let graph = InMemoryGraph::new();
        let temp = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::new(temp.path().join("objects")).unwrap();

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x41; 32]));
        graph
            .create_change(&change(genesis_id, vec![], vec![]))
            .unwrap();

        let historical_source = format!(
            "{}\n\
def processor(value):\n    return value + 1\n\n\
def helper_format(value):\n    return f\"fmt:{{value}}\"\n\n\
def uri_encoder(value):\n    return value.replace(' ', '%20')\n",
            "# preserved historical context\n".repeat(64)
        );
        let historical_hash = blob_store.write(historical_source.as_bytes()).unwrap();
        let sparse_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x42; 32]));
        let processor = test_entity("processor", "src/lib.py");
        graph
            .create_change(&SemanticChange {
                id: sparse_id,
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "sparse imported history".to_string(),
                entity_deltas: vec![EntityDelta::Added(processor.clone())],
                relation_deltas: vec![],
                artifact_deltas: vec![ArtifactDelta {
                    file_id: FilePathId::new("src/lib.py"),
                    kind: ArtifactDeltaKind::Added,
                    old_hash: None,
                    new_hash: Some(historical_hash),
                }],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let historical = build_graph_at_ref(&graph, &blob_store, &sparse_id).unwrap();
        let entities = historical.list_all_entities().unwrap();
        assert!(
            entities
                .iter()
                .any(|entity| entity.id == processor.id && entity.name == "processor"),
            "overlapping persisted entities should keep their semantic IDs"
        );
        assert!(
            entities.iter().any(|entity| entity.name == "helper_format"),
            "sparse historical files should be enriched with missing parsed entities"
        );
        assert!(
            entities.iter().any(|entity| entity.name == "uri_encoder"),
            "historical enrichment should expose additional parsed entities from the blob"
        );

        assert!(
            !historical
                .text_search("helper_format", 10)
                .unwrap()
                .is_empty(),
            "enriched historical entities should be searchable"
        );

        let layout = historical
            .get_file_layout(&FilePathId::new("src/lib.py"))
            .unwrap()
            .expect("sparse historical source file should expose a rebuilt layout");
        let entity_region_count = layout
            .regions
            .iter()
            .filter(|region| matches!(region, kin_model::SourceRegion::EntityRef { .. }))
            .count();
        assert!(
            entity_region_count >= 3,
            "enriched layout should include regions for parsed entities, got {entity_region_count}"
        );
    }

    #[test]
    fn collect_changes_at_ref_handles_deep_linear_history_iteratively() {
        let graph = InMemoryGraph::new();
        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x61; 32]));
        graph
            .create_change(&change(genesis_id, vec![], vec![]))
            .unwrap();

        let mut previous = genesis_id;
        let mut head = genesis_id;
        for idx in 0..3_000u16 {
            let mut bytes = [0u8; 32];
            bytes[..2].copy_from_slice(&(idx + 1).to_be_bytes());
            let id = SemanticChangeId::from_hash(Hash256::from_bytes(bytes));
            graph
                .create_change(&change(id, vec![previous], vec![]))
                .unwrap();
            previous = id;
            head = id;
        }

        let ordered = collect_changes_at_ref(&graph, &head).unwrap();
        assert_eq!(ordered.len(), 3_001);
        assert_eq!(ordered.first().map(|change| change.id), Some(genesis_id));
        assert_eq!(ordered.last().map(|change| change.id), Some(head));
    }

    fn test_entity(name: &str, path: &str) -> Entity {
        Entity {
            id: kin_model::EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Python,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([1; 32]),
                signature_hash: Hash256::from_bytes([2; 32]),
                behavior_hash: Hash256::from_bytes([3; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(path)),
            span: Some(SourceSpan {
                file: FilePathId::new(path),
                start_byte: 0,
                end_byte: 0,
                start_line: 1,
                start_col: 1,
                end_line: 1,
                end_col: 1,
            }),
            signature: format!("def {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: kin_model::EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    #[test]
    fn filter_vector_results_to_scope_retains_only_in_scope_entities() {
        let e1 = EntityId::new();
        let e2 = EntityId::new();
        let e3 = EntityId::new();
        let artifact_key =
            kin_model::RetrievalKey::Artifact(kin_model::ArtifactId::from_path("README.md"));

        let mut scoped = HashSet::new();
        scoped.insert(e1);
        // e2 is NOT in scope

        let results = vec![
            (kin_model::RetrievalKey::Entity(e1), 0.9),
            (kin_model::RetrievalKey::Entity(e2), 0.8),
            (kin_model::RetrievalKey::Entity(e3), 0.7),
            (artifact_key, 0.6),
        ];

        let filtered = filter_vector_results_to_scope(results, &scoped, 10);
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].0, kin_model::RetrievalKey::Entity(e1));
    }

    #[test]
    fn filter_vector_results_to_scope_respects_limit() {
        let mut scoped = HashSet::new();
        let mut results = Vec::new();
        for i in 0..10 {
            let eid = EntityId::new();
            scoped.insert(eid);
            results.push((kin_model::RetrievalKey::Entity(eid), 1.0 - i as f32 * 0.1));
        }

        let filtered = filter_vector_results_to_scope(results, &scoped, 3);
        assert_eq!(filtered.len(), 3);
    }

    /// Gap 1: a persisted entity whose `created_in` falls outside the ref's
    /// reachable change set must not contribute its ID to a reparsed entity.
    #[test]
    fn stabilize_parsed_entities_skips_persisted_outside_ref_history() {
        let reachable_id = SemanticChangeId::from_hash(Hash256::from_bytes([0xa1; 32]));
        let unreachable_id = SemanticChangeId::from_hash(Hash256::from_bytes([0xa2; 32]));
        let lifecycle = RefLifecycle {
            reachable_changes: [reachable_id].into_iter().collect(),
            removed_entities: HashSet::new(),
        };

        let mut alive = test_entity("processor", "src/lib.py");
        alive.created_in = Some(reachable_id);
        let alive_id = alive.id;

        let mut stale = test_entity("processor", "src/lib.py");
        stale.created_in = Some(unreachable_id);

        let mut parsed = test_entity("processor", "src/lib.py");
        let original_parsed_id = parsed.id;
        // Use a stable parsed id so we can assert which persisted ID won.
        parsed.id = EntityId::new();
        let parsed_distinct_id = parsed.id;

        // Persisted list deliberately has the stale match first; lifecycle
        // filter must prefer the reachable match instead of taking the first.
        let stabilized = stabilize_parsed_entities(
            &[stale.clone(), alive.clone()],
            vec![parsed.clone()],
            &lifecycle,
        );
        assert_eq!(stabilized.len(), 1);
        assert_eq!(
            stabilized[0].id, alive_id,
            "should adopt the ref-alive persisted ID, not the stale one"
        );
        assert_ne!(stabilized[0].id, parsed_distinct_id);
        let _ = original_parsed_id;

        // Now omit the alive candidate — only the stale candidate is present.
        // The parsed entity should keep its own new ID instead of binding to
        // the stale persisted ID.
        let stabilized_no_alive =
            stabilize_parsed_entities(&[stale], vec![parsed.clone()], &lifecycle);
        assert_eq!(stabilized_no_alive.len(), 1);
        assert_eq!(
            stabilized_no_alive[0].id, parsed_distinct_id,
            "no alive persisted candidate should mean the parsed ID stays untouched"
        );
    }

    /// Gap 1: removed entities reachable from the ref must also be excluded
    /// even if their `created_in` is reachable — supersession bookkeeping.
    #[test]
    fn ref_lifecycle_excludes_removed_entities_within_reach() {
        let create_id = SemanticChangeId::from_hash(Hash256::from_bytes([0xb1; 32]));
        let remove_id = SemanticChangeId::from_hash(Hash256::from_bytes([0xb2; 32]));
        let mut victim = test_entity("legacy", "src/lib.py");
        victim.created_in = Some(create_id);
        let create_change = SemanticChange {
            id: create_id,
            parents: vec![],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "create".into(),
            entity_deltas: vec![EntityDelta::Added(victim.clone())],
            relation_deltas: vec![],
            artifact_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: None,
        };
        let remove_change = SemanticChange {
            id: remove_id,
            parents: vec![create_id],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "remove".into(),
            entity_deltas: vec![EntityDelta::Removed(victim.id)],
            relation_deltas: vec![],
            artifact_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: None,
        };

        let lifecycle = RefLifecycle::from_changes(&[create_change, remove_change]);
        assert!(!lifecycle.is_alive_at_ref(&victim));
    }

    /// Gap 2: if any persisted entity in a sparse historical source file is
    /// not alive at the ref, enrichment reparses fresh without binding —
    /// preserving parser-issued IDs rather than reusing potentially recycled
    /// persisted IDs.
    #[test]
    fn build_graph_at_ref_reparses_fresh_when_persisted_entity_deleted_at_ref() {
        let graph = InMemoryGraph::new();
        let temp = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::new(temp.path().join("objects")).unwrap();

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0xc0; 32]));
        graph
            .create_change(&change(genesis_id, vec![], vec![]))
            .unwrap();

        // Stage 1: create `victim` and add a sparse source file.
        let stale_source = format!(
            "{}\n\
def victim():\n    return 1\n\n\
def helper_format(value):\n    return value\n\n\
def uri_encoder(value):\n    return value\n",
            "# preserved historical context\n".repeat(64)
        );
        let stale_hash = blob_store.write(stale_source.as_bytes()).unwrap();
        let create_id = SemanticChangeId::from_hash(Hash256::from_bytes([0xc1; 32]));
        let mut victim = test_entity("victim", "src/lib.py");
        victim.created_in = Some(create_id);
        graph
            .create_change(&SemanticChange {
                id: create_id,
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "create victim".to_string(),
                entity_deltas: vec![EntityDelta::Added(victim.clone())],
                relation_deltas: vec![],
                artifact_deltas: vec![ArtifactDelta {
                    file_id: FilePathId::new("src/lib.py"),
                    kind: ArtifactDeltaKind::Added,
                    old_hash: None,
                    new_hash: Some(stale_hash),
                }],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        // Stage 2: remove `victim` AND modify the source. This is the ref
        // we'll reconstruct: the source file no longer contains `victim`,
        // but the persisted historical entity record for `victim` (lineage)
        // would still be reachable if we didn't filter by lifecycle.
        let new_source = format!(
            "{}\n\
def helper_format(value):\n    return value\n\n\
def uri_encoder(value):\n    return value\n",
            "# preserved historical context\n".repeat(64)
        );
        let new_hash = blob_store.write(new_source.as_bytes()).unwrap();
        let ref_id = SemanticChangeId::from_hash(Hash256::from_bytes([0xc2; 32]));
        graph
            .create_change(&SemanticChange {
                id: ref_id,
                parents: vec![create_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "remove victim, update source".to_string(),
                entity_deltas: vec![EntityDelta::Removed(victim.id)],
                relation_deltas: vec![],
                artifact_deltas: vec![ArtifactDelta {
                    file_id: FilePathId::new("src/lib.py"),
                    kind: ArtifactDeltaKind::Modified,
                    old_hash: Some(stale_hash),
                    new_hash: Some(new_hash),
                }],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let historical = build_graph_at_ref(&graph, &blob_store, &ref_id).unwrap();
        let entities = historical.list_all_entities().unwrap();
        assert!(
            entities.iter().all(|entity| entity.id != victim.id),
            "deleted entity must not appear in ref-reconstructed graph"
        );
        // Note: the new source doesn't contain `victim`, so it should not
        // exist by name either.
        assert!(
            entities.iter().all(|entity| entity.name != "victim"),
            "deleted entity name must not be revived by reparse"
        );
    }

    /// Gap 5: when two files in the historical tree share a basename, a
    /// dangling entity origin that points to that basename must NOT be
    /// silently routed to whichever file was first inserted. Suffix-based
    /// disambiguation should keep the entity on the file whose full path
    /// matches the entity record.
    #[test]
    fn build_graph_at_ref_disambiguates_basename_collisions_via_suffix() {
        let graph = InMemoryGraph::new();
        let temp = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::new(temp.path().join("objects")).unwrap();

        let genesis_id = SemanticChangeId::from_hash(Hash256::from_bytes([0xd1; 32]));
        graph
            .create_change(&change(genesis_id, vec![], vec![]))
            .unwrap();

        let mod_a = blob_store.write(b"def alpha():\n    return 'a'\n").unwrap();
        let mod_b = blob_store.write(b"def beta():\n    return 'b'\n").unwrap();

        let head_id = SemanticChangeId::from_hash(Hash256::from_bytes([0xd2; 32]));
        let mut entity_a = test_entity("alpha", "crates/a/src/mod.rs");
        entity_a.file_origin = Some(FilePathId::new("crates/a/src/mod.rs"));
        entity_a.span = Some(SourceSpan {
            file: FilePathId::new("crates/a/src/mod.rs"),
            start_byte: 0,
            end_byte: 14,
            start_line: 1,
            start_col: 1,
            end_line: 1,
            end_col: 14,
        });

        graph
            .create_change(&SemanticChange {
                id: head_id,
                parents: vec![genesis_id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "collision".to_string(),
                entity_deltas: vec![EntityDelta::Added(entity_a.clone())],
                relation_deltas: vec![],
                artifact_deltas: vec![
                    ArtifactDelta {
                        file_id: FilePathId::new("crates/a/src/mod.rs"),
                        kind: ArtifactDeltaKind::Added,
                        old_hash: None,
                        new_hash: Some(mod_a),
                    },
                    ArtifactDelta {
                        file_id: FilePathId::new("crates/b/src/mod.rs"),
                        kind: ArtifactDeltaKind::Added,
                        old_hash: None,
                        new_hash: Some(mod_b),
                    },
                ],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let historical = build_graph_at_ref(&graph, &blob_store, &head_id).unwrap();
        let alpha = historical
            .list_all_entities()
            .unwrap()
            .into_iter()
            .find(|entity| entity.id == entity_a.id)
            .expect("alpha entity should exist in ref view");
        assert_eq!(
            alpha.file_origin,
            Some(FilePathId::new("crates/a/src/mod.rs")),
            "entity already pointed at a/src/mod.rs and must not be rerouted to b/src/mod.rs"
        );
    }

    /// Gap 5: a rename between commits is tracked via blob-hash continuity.
    /// An entity whose record still references the pre-rename path should
    /// normalize to the post-rename canonical path at the ref.
    #[test]
    fn historical_path_resolver_follows_blob_hash_renames() {
        let resolver_blob = Hash256::from_bytes([0xe1; 32]);
        let create_id = SemanticChangeId::from_hash(Hash256::from_bytes([0xe2; 32]));
        let rename_id = SemanticChangeId::from_hash(Hash256::from_bytes([0xe3; 32]));

        let create_change = SemanticChange {
            id: create_id,
            parents: vec![],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "create".into(),
            entity_deltas: vec![],
            relation_deltas: vec![],
            artifact_deltas: vec![ArtifactDelta {
                file_id: FilePathId::new("old/path/file.rs"),
                kind: ArtifactDeltaKind::Added,
                old_hash: None,
                new_hash: Some(resolver_blob),
            }],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: None,
        };
        let rename_change = SemanticChange {
            id: rename_id,
            parents: vec![create_id],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "rename".into(),
            entity_deltas: vec![],
            relation_deltas: vec![],
            artifact_deltas: vec![
                ArtifactDelta {
                    file_id: FilePathId::new("old/path/file.rs"),
                    kind: ArtifactDeltaKind::Removed,
                    old_hash: Some(resolver_blob),
                    new_hash: None,
                },
                ArtifactDelta {
                    file_id: FilePathId::new("new/path/file.rs"),
                    kind: ArtifactDeltaKind::Added,
                    old_hash: None,
                    new_hash: Some(resolver_blob),
                },
            ],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: None,
        };

        let mut file_tree = HashMap::new();
        file_tree.insert(FilePathId::new("new/path/file.rs"), resolver_blob);

        let resolver =
            HistoricalPathResolver::from_changes(&[create_change, rename_change], &file_tree);
        let resolved = resolver
            .resolve(&FilePathId::new("old/path/file.rs"), &file_tree)
            .expect("rename should be tracked");
        assert_eq!(resolved, FilePathId::new("new/path/file.rs"));
    }

    /// Gap 4: when the blob store doesn't have a hash and no git repair is
    /// available, reads return None — no panic, no silent garbage.
    #[test]
    fn blob_reader_returns_none_when_all_tiers_miss() {
        let temp = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::new(temp.path().join("objects")).unwrap();
        let reader = BlobReader::new(&blob_store, None, None);
        // Hash that was never written.
        let missing = kin_blobs::Hash256::from_bytes([0xfe; 32]);
        assert!(reader.read(&missing, "any/path").is_none());
    }

    /// Gap 4 (audit follow-up): when a fallback tier returns content whose
    /// hash does not match the expected hash, accept_repaired_blob refuses
    /// the repair (returns None) and emits a warn-level log so the
    /// silent-pass mode is observable to operators.
    ///
    /// Note: log emission itself is not asserted here — the kin-core test
    /// suite has no log-capture helper. The log promotion to warn is
    /// covered by inspecting the source: accept_repaired_blob uses
    /// `tracing::warn!` on the mismatch path.
    #[test]
    fn blob_reader_warns_on_hash_mismatch_during_repair() {
        let temp = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::new(temp.path().join("objects")).unwrap();
        let reader = BlobReader::new(&blob_store, None, None);

        // Expected hash addresses some imaginary blob; the content we hand
        // in corresponds to a different payload and therefore hashes to a
        // different value. accept_repaired_blob must refuse it.
        let real_content = b"actual blob content from git fallback";
        let actual_hash = kin_blobs::digest(real_content);
        let expected_hash = kin_blobs::Hash256::from_bytes([0xab; 32]);
        assert_ne!(actual_hash, expected_hash);

        let result = reader.accept_repaired_blob(
            &expected_hash,
            "src/lib.rs",
            real_content.to_vec(),
            "git tree",
        );
        assert!(
            result.is_none(),
            "hash-mismatched repaired blob must be rejected"
        );

        // The blob store must NOT have been polluted by the rejected content.
        assert!(
            blob_store.read(&expected_hash).is_err(),
            "rejected blob must not be back-filled under the expected hash"
        );
        assert!(
            blob_store.read(&actual_hash).is_err(),
            "rejected blob must not be back-filled under its own hash either"
        );
    }

    /// Gap 5 (audit follow-up): rename chains spanning more than one hop
    /// must resolve transitively. A → B → C means resolve("path-a")
    /// returns "path-c", and resolving the intermediate "path-b" also
    /// reaches "path-c".
    #[test]
    fn historical_path_resolver_follows_multi_hop_renames() {
        let blob_ab = Hash256::from_bytes([0xf1; 32]);
        let blob_bc = Hash256::from_bytes([0xf2; 32]);

        let create_id = SemanticChangeId::from_hash(Hash256::from_bytes([0xf3; 32]));
        let rename1_id = SemanticChangeId::from_hash(Hash256::from_bytes([0xf4; 32]));
        let rename2_id = SemanticChangeId::from_hash(Hash256::from_bytes([0xf5; 32]));

        let create_change = SemanticChange {
            id: create_id,
            parents: vec![],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "create".into(),
            entity_deltas: vec![],
            relation_deltas: vec![],
            artifact_deltas: vec![ArtifactDelta {
                file_id: FilePathId::new("path-a"),
                kind: ArtifactDeltaKind::Added,
                old_hash: None,
                new_hash: Some(blob_ab),
            }],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: None,
        };
        // First hop: path-a -> path-b, content unchanged so blob_ab carries.
        let rename1 = SemanticChange {
            id: rename1_id,
            parents: vec![create_id],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "a->b".into(),
            entity_deltas: vec![],
            relation_deltas: vec![],
            artifact_deltas: vec![
                ArtifactDelta {
                    file_id: FilePathId::new("path-a"),
                    kind: ArtifactDeltaKind::Removed,
                    old_hash: Some(blob_ab),
                    new_hash: None,
                },
                ArtifactDelta {
                    file_id: FilePathId::new("path-b"),
                    kind: ArtifactDeltaKind::Added,
                    old_hash: None,
                    new_hash: Some(blob_ab),
                },
            ],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: None,
        };
        // Second hop: path-b -> path-c with a new content hash (blob_bc).
        // The resolver still chains b->c via the Removed/Added pair on
        // blob_bc; collapse then promotes a -> c.
        let rename2 = SemanticChange {
            id: rename2_id,
            parents: vec![rename1_id],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "b->c".into(),
            entity_deltas: vec![],
            relation_deltas: vec![],
            artifact_deltas: vec![
                ArtifactDelta {
                    file_id: FilePathId::new("path-b"),
                    kind: ArtifactDeltaKind::Removed,
                    old_hash: Some(blob_bc),
                    new_hash: None,
                },
                ArtifactDelta {
                    file_id: FilePathId::new("path-c"),
                    kind: ArtifactDeltaKind::Added,
                    old_hash: None,
                    new_hash: Some(blob_bc),
                },
            ],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: None,
        };

        let mut file_tree = HashMap::new();
        file_tree.insert(FilePathId::new("path-c"), blob_bc);

        let resolver =
            HistoricalPathResolver::from_changes(&[create_change, rename1, rename2], &file_tree);

        let resolved_a = resolver
            .resolve(&FilePathId::new("path-a"), &file_tree)
            .expect("multi-hop chain a->b->c should resolve");
        assert_eq!(
            resolved_a,
            FilePathId::new("path-c"),
            "transitive rename chain should collapse a -> c"
        );

        let resolved_b = resolver
            .resolve(&FilePathId::new("path-b"), &file_tree)
            .expect("mid-chain reference should still resolve to canonical");
        assert_eq!(
            resolved_b,
            FilePathId::new("path-c"),
            "intermediate path b should also resolve to canonical c"
        );
    }

    #[test]
    fn historical_path_resolver_resolves_nested_monorepo_paths() {
        let resolver_blob = Hash256::from_bytes([0xaa; 32]);
        let mut file_tree = HashMap::new();
        // The tree has the inner path (like in old commit)
        file_tree.insert(FilePathId::new("src/compiler/phases/css.js"), resolver_blob);

        let resolver = HistoricalPathResolver::from_changes(&[], &file_tree);

        // Resolving a query/HEAD path that is nested (monorepo layout)
        let resolved = resolver
            .resolve(
                &FilePathId::new("packages/svelte/src/compiler/phases/css.js"),
                &file_tree,
            )
            .expect("should resolve nested query path to inner tree path");
        assert_eq!(resolved, FilePathId::new("src/compiler/phases/css.js"));

        // Resolving an inner path when tree has a nested path (the other way around)
        let mut file_tree_nested = HashMap::new();
        file_tree_nested.insert(
            FilePathId::new("packages/svelte/src/compiler/phases/css.js"),
            resolver_blob,
        );

        let resolver_nested = HistoricalPathResolver::from_changes(&[], &file_tree_nested);
        let resolved_nested = resolver_nested
            .resolve(
                &FilePathId::new("src/compiler/phases/css.js"),
                &file_tree_nested,
            )
            .expect("should resolve inner query path to nested tree path");
        assert_eq!(
            resolved_nested,
            FilePathId::new("packages/svelte/src/compiler/phases/css.js")
        );
    }

    #[test]
    fn historical_path_resolver_resolves_renamed_packages() {
        let resolver_blob = Hash256::from_bytes([0xaa; 32]);
        let mut file_tree = HashMap::new();
        // The tree has the historical path: packages/material-ui/src/useAutocomplete/index.js
        file_tree.insert(
            FilePathId::new("packages/material-ui/src/useAutocomplete/index.js"),
            resolver_blob,
        );
        file_tree.insert(
            FilePathId::new("packages/material-ui/src/index.js"),
            resolver_blob,
        );

        let resolver = HistoricalPathResolver::from_changes(&[], &file_tree);

        // Resolving a legacy path that had its package renamed: packages/mui-material/src/useAutocomplete/index.js
        let resolved = resolver
            .resolve(
                &FilePathId::new("packages/mui-material/src/useAutocomplete/index.js"),
                &file_tree,
            )
            .expect("should resolve renamed package path via common suffix");
        assert_eq!(
            resolved,
            FilePathId::new("packages/material-ui/src/useAutocomplete/index.js")
        );
    }

    /// Gap 2 (audit follow-up): mixed binding — when only some persisted
    /// entities are alive at the ref, enrich_sparse_historical_source_file
    /// MUST reparse fresh and reuse NO persisted IDs. This guards against
    /// degrading the all-or-nothing semantic into a per-entity decision.
    #[test]
    fn enrich_sparse_reparses_fresh_when_any_persisted_entity_not_alive() {
        let reachable_id = SemanticChangeId::from_hash(Hash256::from_bytes([0xb0; 32]));
        let unreachable_id = SemanticChangeId::from_hash(Hash256::from_bytes([0xb1; 32]));

        let mut alive_one = test_entity("alive_one", "src/lib.py");
        alive_one.created_in = Some(reachable_id);
        let mut alive_two = test_entity("alive_two", "src/lib.py");
        alive_two.created_in = Some(reachable_id);
        let mut stale = test_entity("stale_dropped", "src/lib.py");
        stale.created_in = Some(unreachable_id);

        let persisted = vec![alive_one.clone(), alive_two.clone(), stale.clone()];
        let persisted_ids: HashSet<EntityId> = persisted.iter().map(|entity| entity.id).collect();

        // Parser sees four entities — two whose (kind, name) keys overlap
        // with persisted alive entries, plus two brand-new ones. This
        // satisfies `should_enrich_with_parsed_semantics` (parsed.len >
        // persisted.len, shared > 0, parsed_only >= 2).
        let parsed_alive_one = test_entity("alive_one", "src/lib.py");
        let parsed_alive_two = test_entity("alive_two", "src/lib.py");
        let parsed_new_one = test_entity("brand_new_one", "src/lib.py");
        let parsed_new_two = test_entity("brand_new_two", "src/lib.py");
        let parsed_ids: HashSet<EntityId> = [
            parsed_alive_one.id,
            parsed_alive_two.id,
            parsed_new_one.id,
            parsed_new_two.id,
        ]
        .into_iter()
        .collect();

        // Sanity: parser-issued IDs are distinct from any persisted ID.
        for parsed_id in &parsed_ids {
            assert!(
                !persisted_ids.contains(parsed_id),
                "test fixture invariant: parser IDs must not collide with persisted IDs"
            );
        }

        let indexed_file = kin_index::IndexedFile {
            file_id: FilePathId::new("src/lib.py"),
            language: kin_model::LanguageId::Python,
            entities: vec![
                parsed_alive_one,
                parsed_alive_two,
                parsed_new_one,
                parsed_new_two,
            ],
            relations: vec![],
            unresolved_relations: vec![],
            file_layout: FileLayout {
                file_id: FilePathId::new("src/lib.py"),
                parse_completeness: ParseCompleteness::Full,
                imports: ImportSection {
                    byte_range: 0..0,
                    items: vec![],
                },
                regions: vec![],
            },
            parse_state: kin_model::ParseState::Valid,
            blob_hash: Hash256::from_bytes([0xcc; 32]),
            extracted_relations: vec![],
            imports: vec![],
        };

        let lifecycle = RefLifecycle {
            reachable_changes: [reachable_id].into_iter().collect(),
            removed_entities: HashSet::new(),
        };

        let enrichment = enrich_sparse_historical_source_file(&persisted, indexed_file, &lifecycle)
            .expect("mixed-binding input should still enter the reparse-fresh branch");

        // All-or-nothing: no persisted ID may appear in the returned
        // enrichment. This is the load-bearing guarantee — flipping to a
        // per-entity decision would allow alive_one/alive_two to bind
        // while stale stays unbound, which we explicitly forbid here.
        for entity in &enrichment.entities {
            assert!(
                !persisted_ids.contains(&entity.id),
                "reparsed enrichment must not reuse persisted IDs (entity {} reused {})",
                entity.name,
                entity.id
            );
        }
        assert_eq!(
            enrichment.entities.len(),
            4,
            "reparse-fresh path returns parser entities verbatim"
        );
        // The file layout must reflect the partial-parse origin so callers
        // can observe that this enrichment is not a full historical bind.
        assert!(
            matches!(
                enrichment.file_layout.parse_completeness,
                ParseCompleteness::Partial(_)
            ),
            "reparse-fresh path must emit a Partial layout to signal lifecycle gap"
        );
    }
}
