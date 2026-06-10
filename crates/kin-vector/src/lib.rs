// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Custom HNSW (Hierarchical Navigable Small World) index for approximate
//! nearest-neighbor search over entity embeddings.  Pure-Rust graph that is
//! compiled directly into the binary — no C++ FFI, no platform-specific build
//! scripts.
//!
//! Generic over the key type via the [`VectorId`] trait.  Ships with
//! [`DefaultId`] (UUID-based) and blanket impls for `u64`, `u32`, and
//! `uuid::Uuid`.

use std::collections::BinaryHeap;
use std::hash::Hash;
use std::path::{Path, PathBuf};
use std::{cmp::Reverse, fs, fs::File, fs::OpenOptions};

use fs2::FileExt;
use hashbrown::{HashMap, HashSet};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors returned by the vector index.
#[derive(Debug, thiserror::Error)]
pub enum VectorError {
    #[error("index error: {0}")]
    IndexError(String),
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
    /// A persisted index was built with a different model/graph than the caller
    /// expects. Loading it would return silently-wrong neighbors, so the load is
    /// refused. Distinct from a dimension mismatch: two models can share a
    /// dimension yet be incompatible.
    #[error(
        "vector index model mismatch on {field}: snapshot was built with \"{stored}\", \
         but \"{expected}\" was requested (loading would return silently-wrong neighbors)"
    )]
    ModelMismatch {
        field: &'static str,
        expected: String,
        stored: String,
    },
}

// ---------------------------------------------------------------------------
// VectorId trait + default impls
// ---------------------------------------------------------------------------

/// Trait bound for vector index keys.
pub trait VectorId:
    Copy
    + Eq
    + Hash
    + Send
    + Sync
    + std::fmt::Debug
    + serde::Serialize
    + serde::de::DeserializeOwned
    + 'static
{
}

/// Default ID type (UUID-based, matching the original EntityId pattern).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct DefaultId(pub uuid::Uuid);

impl DefaultId {
    pub fn new() -> Self {
        Self(uuid::Uuid::new_v4())
    }
}

impl Default for DefaultId {
    fn default() -> Self {
        Self::new()
    }
}

impl VectorId for DefaultId {}
impl VectorId for u64 {}
impl VectorId for u32 {}
impl VectorId for uuid::Uuid {}

// ---------------------------------------------------------------------------
// HNSW parameters
// ---------------------------------------------------------------------------

/// Maximum number of bi-directional connections per node at each layer.
const M: usize = 16;

/// Maximum connections at layer 0 (conventionally 2 * M).
const M_MAX_0: usize = 32;

/// Beam width during construction.
const EF_CONSTRUCTION: usize = 200;

/// Default beam width during search.
const EF_SEARCH: usize = 50;

/// Normalization factor for level generation: 1 / ln(M).
fn ml() -> f64 {
    1.0 / (M as f64).ln()
}

// ---------------------------------------------------------------------------
// Distance
// ---------------------------------------------------------------------------

/// Cosine distance: 1.0 - cosine_similarity.  Lower is more similar.
#[inline]
pub fn cosine_distance(a: &[f32], b: &[f32]) -> f32 {
    debug_assert_eq!(a.len(), b.len());
    if a.is_empty() || b.is_empty() || a.len() != b.len() {
        return 1.0;
    }
    let mut dot = 0.0f32;
    let mut norm_a = 0.0f32;
    let mut norm_b = 0.0f32;
    for i in 0..a.len() {
        dot += a[i] * b[i];
        norm_a += a[i] * a[i];
        norm_b += b[i] * b[i];
    }
    let denom = (norm_a * norm_b).sqrt();
    if denom < f32::EPSILON {
        return 1.0;
    }
    1.0 - dot / denom
}

// ---------------------------------------------------------------------------
// Index self-description (model identity + graph provenance)
// ---------------------------------------------------------------------------

/// Provenance stamped into a persisted index so that a load can prove the
/// snapshot is compatible with the caller's current model and graph — not merely
/// the same vector dimensionality.
///
/// Dimensionality alone is NOT sufficient: two different embedding models can
/// share a dimension (e.g. both 768-d). Loading vectors embedded by model A and
/// querying with model B passes a dimension-only check yet returns
/// silently-wrong neighbors. Stamp `model_id` (and optionally `graph_root`) so a
/// same-dimension model swap is caught at load time via
/// [`IndexDescriptor::verify_compatible`].
///
/// Both fields are optional so legacy/unstamped snapshots still deserialize
/// (they decode to `None`).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexDescriptor {
    /// Identity of the embedding model that produced the stored vectors, e.g.
    /// `"bge-small-en-v1.5@1"`. `None` for legacy/unstamped snapshots.
    #[serde(default)]
    pub model_id: Option<String>,
    /// Root hash / id of the graph snapshot this index was built against.
    /// `None` when unstamped.
    #[serde(default)]
    pub graph_root: Option<String>,
}

impl IndexDescriptor {
    /// Verify a loaded snapshot's descriptor (`self`) is compatible with what the
    /// caller `expected`.
    ///
    /// Only fields the caller pins (`Some`) are enforced; a `None` expected field
    /// means "don't care". If the caller pins a field but the snapshot did not
    /// stamp it (`None`), or stamped a different value, the load is rejected — we
    /// cannot prove the vectors were produced by the expected model, and the
    /// whole point is to refuse silently-wrong neighbors.
    pub fn verify_compatible(&self, expected: &IndexDescriptor) -> Result<(), VectorError> {
        check_descriptor_field(
            "model_id",
            self.model_id.as_deref(),
            expected.model_id.as_deref(),
        )?;
        check_descriptor_field(
            "graph_root",
            self.graph_root.as_deref(),
            expected.graph_root.as_deref(),
        )?;
        Ok(())
    }
}

fn check_descriptor_field(
    field: &'static str,
    stored: Option<&str>,
    expected: Option<&str>,
) -> Result<(), VectorError> {
    let Some(exp) = expected else {
        return Ok(()); // caller does not pin this field
    };
    if stored == Some(exp) {
        return Ok(());
    }
    Err(VectorError::ModelMismatch {
        field,
        expected: exp.to_string(),
        stored: stored.unwrap_or("<unstamped>").to_string(),
    })
}

// ---------------------------------------------------------------------------
// Core HNSW graph
// ---------------------------------------------------------------------------

#[derive(Clone, Serialize, Deserialize)]
pub struct HnswNode {
    /// The embedding vector.
    pub vector: Vec<f32>,
    /// connections[level] = list of neighbor internal indices at that level.
    pub connections: Vec<Vec<usize>>,
    /// Maximum level this node participates in.
    pub level: usize,
}

/// Internal mutable state of the HNSW graph.
#[derive(Serialize, Deserialize)]
#[serde(bound(serialize = "Id: VectorId", deserialize = "Id: VectorId"))]
pub struct HnswGraph<Id: VectorId = DefaultId> {
    pub nodes: Vec<HnswNode>,
    /// Internal index of the current entry point, if any.
    pub entry_point: Option<usize>,
    /// The highest level currently in the graph.
    pub max_level: usize,
    pub dimensions: usize,
    /// Bi-directional mapping Id <-> internal index.
    pub id_to_idx: HashMap<Id, usize>,
    pub idx_to_id: Vec<Id>,
    /// Indices that were removed and can be reused.
    pub free_list: Vec<usize>,
    /// Simple u64 state for reproducible-ish level generation.
    pub rng_state: u64,
    /// Self-description (model identity + graph provenance) of the vectors in
    /// this graph. Last field + `#[serde(default)]` so legacy snapshots that
    /// predate stamping still deserialize (descriptor decodes to default/`None`).
    #[serde(default)]
    pub descriptor: IndexDescriptor,
}

impl<Id: VectorId> HnswGraph<Id> {
    fn new(dimensions: usize) -> Self {
        Self {
            nodes: Vec::new(),
            entry_point: None,
            max_level: 0,
            dimensions,
            id_to_idx: HashMap::new(),
            idx_to_id: Vec::new(),
            free_list: Vec::new(),
            rng_state: 0x12345678_9abcdef0,
            descriptor: IndexDescriptor::default(),
        }
    }

    /// Cheap xorshift64 for level generation.
    fn next_rand(&mut self) -> f64 {
        let mut s = self.rng_state;
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        self.rng_state = s;
        // Map to (0, 1)
        (s as f64) / (u64::MAX as f64)
    }

    /// Assign a random level for a new node following the HNSW paper's
    /// geometric distribution: floor(-ln(uniform) * mL).
    fn random_level(&mut self) -> usize {
        let r = self.next_rand().max(1e-15);
        (-r.ln() * ml()).floor() as usize
    }

    fn active_count(&self) -> usize {
        self.id_to_idx.len()
    }

    // -- greedy search helpers -----------------------------------------------

    /// Greedy search at a single layer starting from a single node.
    /// Returns the closest `ef` nodes at that layer to `query`.
    fn search_layer(
        &self,
        query: &[f32],
        entry: usize,
        ef: usize,
        layer: usize,
        predicate: Option<&dyn Fn(&Id) -> bool>,
    ) -> Vec<(f32, usize)> {
        let _span = tracing::info_span!(
            "kin_vector.search_layer",
            dims = query.len(),
            ef = ef,
            layer = layer
        )
        .entered();
        let mut visited = HashSet::new();
        visited.insert(entry);

        // Guard: skip freed nodes whose vectors have been cleared
        if self.nodes[entry].vector.is_empty() {
            return Vec::new();
        }
        if layer >= self.nodes[entry].connections.len() {
            return Vec::new();
        }

        let entry_dist = cosine_distance(query, &self.nodes[entry].vector);

        // (distance, idx) — BinaryHeap is max-heap by default
        let mut candidates: BinaryHeap<Reverse<(OrderedF32, usize)>> = BinaryHeap::new();
        let mut result: BinaryHeap<(OrderedF32, usize)> = BinaryHeap::new();

        candidates.push(Reverse((OrderedF32(entry_dist), entry)));
        if predicate.map_or(true, |p| p(&self.idx_to_id[entry])) {
            result.push((OrderedF32(entry_dist), entry));
        }

        while let Some(Reverse((OrderedF32(c_dist), c_idx))) = candidates.pop() {
            let worst_dist = result
                .peek()
                .map(|(OrderedF32(d), _)| *d)
                .unwrap_or(f32::MAX);
            if c_dist > worst_dist {
                break;
            }

            let node = &self.nodes[c_idx];
            let neighbors = if layer < node.connections.len() {
                &node.connections[layer]
            } else {
                continue;
            };

            for &nb in neighbors {
                if !visited.insert(nb) {
                    continue;
                }
                // Skip freed nodes whose vectors have been cleared
                if self.nodes[nb].vector.is_empty() {
                    continue;
                }
                if layer >= self.nodes[nb].connections.len() {
                    continue;
                }
                let nb_dist = cosine_distance(query, &self.nodes[nb].vector);
                let worst_dist = result
                    .peek()
                    .map(|(OrderedF32(d), _)| *d)
                    .unwrap_or(f32::MAX);

                if nb_dist < worst_dist || result.len() < ef {
                    candidates.push(Reverse((OrderedF32(nb_dist), nb)));
                    if predicate.map_or(true, |p| p(&self.idx_to_id[nb])) {
                        result.push((OrderedF32(nb_dist), nb));
                        if result.len() > ef {
                            result.pop();
                        }
                    }
                }
            }
        }

        result
            .into_sorted_vec()
            .into_iter()
            .map(|(OrderedF32(d), idx)| (d, idx))
            .collect()
    }

    /// Greedy descent through layers > target_layer, returning the single
    /// closest node at each layer as the new entry point.
    fn greedy_closest(
        &self,
        query: &[f32],
        mut current: usize,
        top_level: usize,
        target_level: usize,
    ) -> usize {
        let _span = tracing::info_span!(
            "kin_vector.greedy_closest",
            dims = query.len(),
            top_level = top_level,
            target_level = target_level
        )
        .entered();
        let mut level = top_level;
        while level > target_level {
            let mut changed = true;
            while changed {
                changed = false;
                let node = &self.nodes[current];
                if level < node.connections.len() {
                    for &nb in &node.connections[level] {
                        if self.nodes[nb].vector.is_empty() {
                            continue;
                        }
                        if level >= self.nodes[nb].connections.len() {
                            continue;
                        }
                        let d_nb = cosine_distance(query, &self.nodes[nb].vector);
                        let d_cur = cosine_distance(query, &self.nodes[current].vector);
                        if d_nb < d_cur {
                            current = nb;
                            changed = true;
                        }
                    }
                }
            }
            level -= 1;
        }
        current
    }

    /// Select neighbours using the simple heuristic from the HNSW paper.
    /// Takes the `m` closest candidates.
    fn select_neighbors(candidates: &[(f32, usize)], m: usize) -> Vec<usize> {
        candidates.iter().take(m).map(|&(_, idx)| idx).collect()
    }

    fn sort_scored_neighbors(scored: &mut [(f32, usize)]) {
        scored.sort_by(|a, b| a.0.total_cmp(&b.0).then_with(|| a.1.cmp(&b.1)));
    }

    /// Insert a node into the graph.
    fn insert(&mut self, entity_id: Id, vector: &[f32]) -> Result<(), VectorError> {
        let dims = self.dimensions;
        if vector.len() != dims {
            return Err(VectorError::IndexError(format!(
                "embedding dimension mismatch: expected {}, got {}",
                dims,
                vector.len()
            )));
        }

        let level = self.random_level();
        let node = HnswNode {
            vector: vector.to_vec(),
            connections: vec![Vec::new(); level + 1],
            level,
        };

        // Allocate or reuse an internal index.
        let idx = if let Some(free_idx) = self.free_list.pop() {
            self.nodes[free_idx] = node;
            self.idx_to_id[free_idx] = entity_id;
            free_idx
        } else {
            let idx = self.nodes.len();
            self.nodes.push(node);
            self.idx_to_id.push(entity_id);
            idx
        };
        self.id_to_idx.insert(entity_id, idx);

        // If the graph was empty, this is the entry point.
        let entry = match self.entry_point {
            None => {
                self.entry_point = Some(idx);
                self.max_level = level;
                return Ok(());
            }
            Some(ep) => ep,
        };

        let mut current = entry;

        // Phase 1: greedy descent from max_level down to level+1
        if self.max_level > level {
            current = self.greedy_closest(vector, current, self.max_level, level);
        }

        // Phase 2: insert at each layer from min(level, max_level) down to 0
        let insert_top = level.min(self.max_level);
        for lc in (0..=insert_top).rev() {
            let neighbors_found = self.search_layer(vector, current, EF_CONSTRUCTION, lc, None);
            let m_max = if lc == 0 { M_MAX_0 } else { M };
            let selected: Vec<usize> = Self::select_neighbors(&neighbors_found, m_max)
                .into_iter()
                .filter(|&nb| lc < self.nodes[nb].connections.len())
                .collect();

            // Set this node's connections at this layer
            self.nodes[idx].connections[lc] = selected.clone();

            // Add bidirectional connections
            for &nb in &selected {
                if lc >= self.nodes[nb].connections.len() {
                    continue;
                }
                self.nodes[nb].connections[lc].push(idx);
                let nb_m_max = if lc == 0 { M_MAX_0 } else { M };
                if self.nodes[nb].connections[lc].len() > nb_m_max {
                    // Prune: keep only the closest nb_m_max neighbors.
                    // Clone data to satisfy the borrow checker.
                    let nb_vec = self.nodes[nb].vector.clone();
                    let conns = self.nodes[nb].connections[lc].clone();
                    let mut scored: Vec<(f32, usize)> = conns
                        .iter()
                        .map(|&n| (cosine_distance(&nb_vec, &self.nodes[n].vector), n))
                        .collect();
                    Self::sort_scored_neighbors(&mut scored);
                    self.nodes[nb].connections[lc] =
                        scored.into_iter().take(nb_m_max).map(|(_, n)| n).collect();
                }
            }

            // Use the closest found neighbor as the entry for the next layer
            if let Some(&(_, closest)) = neighbors_found.first() {
                current = closest;
            }
        }

        // Update entry point if this node has a higher level
        if level > self.max_level {
            self.entry_point = Some(idx);
            self.max_level = level;
        }

        Ok(())
    }

    /// Remove a node from the graph.  We disconnect it from all neighbors and
    /// add its slot to the free list.  We do NOT try to repair neighbor
    /// connectivity — this is acceptable for a soft-delete approach common in
    /// HNSW implementations.
    fn remove(&mut self, entity_id: &Id) -> bool {
        let idx = match self.id_to_idx.remove(entity_id) {
            Some(idx) => idx,
            None => return false,
        };

        // Disconnect from all neighbors at all layers.
        let connections = self.nodes[idx].connections.clone();
        for (layer, neighbors) in connections.iter().enumerate() {
            for &nb in neighbors {
                if nb < self.nodes.len() && layer < self.nodes[nb].connections.len() {
                    self.nodes[nb].connections[layer].retain(|&n| n != idx);
                }
            }
        }
        for node in &mut self.nodes {
            for neighbors in &mut node.connections {
                neighbors.retain(|&n| n != idx);
            }
        }

        // Clear the node's data
        self.nodes[idx].connections.clear();
        self.nodes[idx].vector.clear();
        self.nodes[idx].level = 0;
        self.free_list.push(idx);

        // If we removed the entry point, pick a new one.
        //
        // Selection MUST be a pure function of graph content, never of
        // `id_to_idx`'s iteration order: that map is re-seeded per process on
        // every deserialize (hashbrown's randomized hasher), so a tie broken "by
        // whoever was visited first" makes the entry point — the start of every
        // search's greedy descent — vary across daemon boots even from a
        // byte-identical persisted index. That jitters approximate-kNN results at
        // the candidate-set boundary (a re-routed descent can surface a whole
        // different neighbor). Choose the active node with the highest level,
        // breaking ties by the smallest internal index, so the result is identical
        // regardless of visitation order.
        if self.entry_point == Some(idx) {
            self.entry_point = None;
            self.max_level = 0;
            for (&_eid, &other_idx) in &self.id_to_idx {
                let other_level = self.nodes[other_idx].level;
                let replace = match self.entry_point {
                    None => true,
                    Some(cur) => {
                        other_level > self.max_level
                            || (other_level == self.max_level && other_idx < cur)
                    }
                };
                if replace {
                    self.entry_point = Some(other_idx);
                    self.max_level = other_level;
                }
            }
        }

        true
    }

    /// K-NN search.  Returns (Id, distance) pairs sorted by distance ascending.
    fn search(
        &self,
        query: &[f32],
        limit: usize,
        predicate: Option<&dyn Fn(&Id) -> bool>,
    ) -> Vec<(Id, f32)> {
        let _span =
            tracing::info_span!("kin_vector.search", dims = query.len(), limit = limit).entered();
        let entry = match self.entry_point {
            Some(ep) => ep,
            None => return Vec::new(),
        };

        // Phase 1: greedy descent through upper layers
        let current = self.greedy_closest(query, entry, self.max_level, 0);

        // Phase 2: beam search at layer 0 with ef = max(ef_search, limit)
        let ef = EF_SEARCH.max(limit);
        let results = self.search_layer(query, current, ef, 0, predicate);

        results
            .into_iter()
            .take(limit)
            .filter_map(|(dist, idx)| {
                if idx < self.idx_to_id.len() {
                    let id = self.idx_to_id[idx];
                    if self.id_to_idx.get(&id) == Some(&idx) {
                        return Some((id, dist));
                    }
                }
                None
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Ordered f32 wrapper for BinaryHeap
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
pub struct OrderedF32(pub f32);

impl Eq for OrderedF32 {}

impl PartialOrd for OrderedF32 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OrderedF32 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.total_cmp(&other.0)
    }
}

// ---------------------------------------------------------------------------
// Persistence helpers
// ---------------------------------------------------------------------------

const RECOVERY_MARKER_VERSION: u32 = 2;
const HNSW_FORMAT_VERSION: u8 = 1;

#[derive(Serialize, Deserialize)]
pub struct RecoveryMarker {
    pub version: u32,
    pub byte_len: u64,
    pub sha256: [u8; 32],
}

#[derive(Serialize, Deserialize)]
#[serde(bound(serialize = "Id: VectorId", deserialize = "Id: VectorId"))]
pub struct HnswSnapshot<Id: VectorId = DefaultId> {
    pub format_version: u8,
    pub graph: HnswGraph<Id>,
}

fn recovery_tmp_path(path: &Path) -> PathBuf {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some(ext) if !ext.is_empty() => path.with_extension(format!("{ext}.tmp")),
        _ => path.with_extension("tmp"),
    }
}

fn recovery_marker_path(path: &Path) -> PathBuf {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some(ext) if !ext.is_empty() => path.with_extension(format!("{ext}.tmp.meta")),
        _ => path.with_extension("tmp.meta"),
    }
}

fn write_lock_path(path: &Path) -> PathBuf {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some(ext) if !ext.is_empty() => path.with_extension(format!("{ext}.write.lock")),
        _ => path.with_extension("write.lock"),
    }
}

fn acquire_write_lock(path: &Path, label: &str) -> Result<File, VectorError> {
    let lock_path = write_lock_path(path);
    let lock = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .open(&lock_path)
        .map_err(|e| {
            VectorError::IndexError(format!(
                "failed to open {label} write lock {}: {e}",
                lock_path.display()
            ))
        })?;
    lock.lock_exclusive().map_err(|e| {
        VectorError::IndexError(format!(
            "failed to acquire {label} write lock {}: {e}",
            lock_path.display()
        ))
    })?;
    Ok(lock)
}

fn fsync_and_rename(tmp_path: &Path, path: &Path) -> Result<(), VectorError> {
    let file = File::open(tmp_path).map_err(|e| {
        VectorError::IndexError(format!(
            "failed to reopen for fsync {}: {e}",
            tmp_path.display()
        ))
    })?;
    file.sync_all()
        .map_err(|e| VectorError::IndexError(format!("fsync failed: {e}")))?;

    fs::rename(tmp_path, path).map_err(|e| {
        VectorError::IndexError(format!(
            "failed to rename {} -> {}: {e}",
            tmp_path.display(),
            path.display()
        ))
    })?;

    if let Some(parent) = path.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }

    Ok(())
}

fn write_bytes_with_fsync(path: &Path, bytes: &[u8]) -> Result<(), VectorError> {
    fs::write(path, bytes)
        .map_err(|e| VectorError::IndexError(format!("failed to write {}: {e}", path.display())))?;
    let file = File::open(path).map_err(|e| {
        VectorError::IndexError(format!(
            "failed to reopen for fsync {}: {e}",
            path.display()
        ))
    })?;
    file.sync_all()
        .map_err(|e| VectorError::IndexError(format!("fsync failed: {e}")))?;
    Ok(())
}

fn sync_parent_dir(path: &Path) {
    if let Some(parent) = path.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
}

fn clear_recovery_candidate(path: &Path, label: &str) -> Result<(), VectorError> {
    let tmp_path = recovery_tmp_path(path);
    let marker_path = recovery_marker_path(path);
    if tmp_path.exists() {
        fs::remove_file(&tmp_path).map_err(|e| {
            VectorError::IndexError(format!(
                "failed to clear stale temporary {label} {}: {e}",
                tmp_path.display()
            ))
        })?;
    }
    if marker_path.exists() {
        fs::remove_file(&marker_path).map_err(|e| {
            VectorError::IndexError(format!(
                "failed to clear stale recovery marker {}: {e}",
                marker_path.display()
            ))
        })?;
    }
    Ok(())
}

fn write_recovery_marker(path: &Path, bytes: &[u8]) -> Result<(), VectorError> {
    let marker_path = recovery_marker_path(path);
    let marker = RecoveryMarker {
        version: RECOVERY_MARKER_VERSION,
        byte_len: bytes.len() as u64,
        sha256: Sha256::digest(bytes).into(),
    };
    let marker_bytes = serde_json::to_vec(&marker).map_err(|e| {
        VectorError::IndexError(format!(
            "failed to serialize recovery marker {}: {e}",
            marker_path.display()
        ))
    })?;
    write_bytes_with_fsync(&marker_path, &marker_bytes)?;
    sync_parent_dir(path);
    Ok(())
}

fn write_bytes_recovery_candidate(
    path: &Path,
    bytes: &[u8],
    label: &str,
) -> Result<(), VectorError> {
    let tmp_path = recovery_tmp_path(path);
    clear_recovery_candidate(path, label)?;
    write_bytes_with_fsync(&tmp_path, bytes)?;
    write_recovery_marker(path, bytes)
}

fn promote_recovery_candidate(path: &Path) -> Result<(), VectorError> {
    let tmp_path = recovery_tmp_path(path);
    let marker_path = recovery_marker_path(path);
    fsync_and_rename(&tmp_path, path)?;
    if marker_path.exists() {
        fs::remove_file(&marker_path).map_err(|e| {
            VectorError::IndexError(format!(
                "failed to remove recovery marker {}: {e}",
                marker_path.display()
            ))
        })?;
        sync_parent_dir(path);
    }
    Ok(())
}

fn load_recovery_marker(path: &Path) -> Result<RecoveryMarker, VectorError> {
    let marker_path = recovery_marker_path(path);
    let marker_bytes = fs::read(&marker_path).map_err(|e| {
        VectorError::IndexError(format!(
            "failed to read recovery marker {}: {e}",
            marker_path.display()
        ))
    })?;
    serde_json::from_slice(&marker_bytes).map_err(|e| {
        VectorError::IndexError(format!(
            "failed to parse recovery marker {}: {e}",
            marker_path.display()
        ))
    })
}

fn load_proven_recovery_bytes(path: &Path, label: &str) -> Result<Vec<u8>, VectorError> {
    let tmp_path = recovery_tmp_path(path);
    let marker_path = recovery_marker_path(path);
    let marker = load_recovery_marker(path).map_err(|err| {
        VectorError::IndexError(format!(
            "recovery {label} {} is unproven without a valid marker {}: {err}",
            tmp_path.display(),
            marker_path.display()
        ))
    })?;

    if marker.version != RECOVERY_MARKER_VERSION {
        return Err(VectorError::IndexError(format!(
            "recovery marker {} uses unsupported version {}",
            marker_path.display(),
            marker.version
        )));
    }

    let bytes = fs::read(&tmp_path).map_err(|e| {
        VectorError::IndexError(format!(
            "failed to read recovery vector index {}: {e}",
            tmp_path.display()
        ))
    })?;
    if bytes.len() as u64 != marker.byte_len {
        return Err(VectorError::IndexError(format!(
            "recovery vector index {} length {} does not match marker {} length {}",
            tmp_path.display(),
            bytes.len(),
            marker_path.display(),
            marker.byte_len
        )));
    }
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    if digest != marker.sha256 {
        return Err(VectorError::IndexError(format!(
            "recovery vector index {} checksum does not match marker {}",
            tmp_path.display(),
            marker_path.display()
        )));
    }

    Ok(bytes)
}

fn atomic_save_bytes(path: &Path, bytes: &[u8], label: &str) -> Result<(), VectorError> {
    let _lock = acquire_write_lock(path, label)?;
    write_bytes_recovery_candidate(path, bytes, label)?;
    promote_recovery_candidate(path)
}

fn try_load_snapshot<Id: VectorId>(bytes: &[u8]) -> Result<HnswGraph<Id>, VectorError> {
    let snapshot: HnswSnapshot<Id> = rmp_serde::from_slice(bytes).map_err(|e| {
        VectorError::IndexError(format!("failed to deserialize HNSW snapshot: {e}"))
    })?;
    if snapshot.format_version != HNSW_FORMAT_VERSION {
        return Err(VectorError::IndexError(format!(
            "unsupported HNSW format version {}",
            snapshot.format_version
        )));
    }
    Ok(snapshot.graph)
}

fn recover_from_tmp<Id: VectorId>(
    path: &Path,
    primary_error: Option<&VectorError>,
) -> Result<HnswGraph<Id>, VectorError> {
    let tmp_path = recovery_tmp_path(path);
    if !tmp_path.exists() {
        return Err(match primary_error {
            Some(err) => VectorError::IndexError(format!(
                "failed to load vector index {} and no recovery index exists: {err}",
                path.display()
            )),
            None => VectorError::IndexError(format!(
                "vector index {} is missing and recovery index {} is not present",
                path.display(),
                tmp_path.display()
            )),
        });
    }

    let bytes = load_proven_recovery_bytes(path, "vector index").map_err(|tmp_err| {
        let prefix = match primary_error {
            Some(primary_err) => format!(
                "failed to load primary vector index {}: {primary_err}; ",
                path.display()
            ),
            None => format!("primary vector index {} is missing; ", path.display()),
        };
        VectorError::IndexError(format!(
            "{prefix}recovery index {} is invalid: {tmp_err}",
            tmp_path.display()
        ))
    })?;

    let graph = try_load_snapshot(&bytes).map_err(|tmp_err| {
        let prefix = match primary_error {
            Some(primary_err) => format!(
                "failed to load primary vector index {}: {primary_err}; ",
                path.display()
            ),
            None => format!("primary vector index {} is missing; ", path.display()),
        };
        VectorError::IndexError(format!(
            "{prefix}recovery index {} is invalid: {tmp_err}",
            tmp_path.display()
        ))
    })?;

    promote_recovery_candidate(path).map_err(|err| {
        VectorError::IndexError(format!(
            "loaded recovery index {} but failed to promote it to {}: {err}",
            tmp_path.display(),
            path.display()
        ))
    })?;

    Ok(graph)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// HNSW-backed vector similarity index for entity embeddings.
///
/// Pure-Rust implementation of the Hierarchical Navigable Small World algorithm
/// for approximate nearest-neighbor search. Each entity can have an optional
/// embedding vector; this index stores and queries them.
///
/// Generic over the key type `Id` via the [`VectorId`] trait.  Defaults to
/// [`DefaultId`] (UUID-based) for drop-in compatibility with the original
/// KinDB `EntityId`.
pub struct VectorIndex<Id: VectorId = DefaultId> {
    graph: RwLock<HnswGraph<Id>>,
    /// Optional path for persisting the index to disk.
    persistence_path: RwLock<Option<PathBuf>>,
}

impl<Id: VectorId> VectorIndex<Id> {
    /// Create a new vector index for embeddings of the given dimensionality.
    pub fn new(dimensions: usize) -> Result<Self, VectorError> {
        let _span = tracing::info_span!("kin_vector.new", dimensions = dimensions).entered();
        Ok(Self {
            graph: RwLock::new(HnswGraph::new(dimensions)),
            persistence_path: RwLock::new(None),
        })
    }

    /// Create a new index, stamping its self-description (model identity + graph
    /// provenance) so future loads can verify compatibility, not just dimension.
    pub fn new_with_descriptor(
        dimensions: usize,
        descriptor: IndexDescriptor,
    ) -> Result<Self, VectorError> {
        let index = Self::new(dimensions)?;
        index.set_descriptor(descriptor);
        Ok(index)
    }

    /// The persisted self-description (model identity + graph provenance).
    pub fn descriptor(&self) -> IndexDescriptor {
        self.graph.read().descriptor.clone()
    }

    /// Stamp / replace the self-description; persisted on the next `save`.
    pub fn set_descriptor(&self, descriptor: IndexDescriptor) {
        self.graph.write().descriptor = descriptor;
    }

    /// The dimensionality of vectors in this index.
    pub fn dimensions(&self) -> usize {
        self.graph.read().dimensions
    }

    /// Number of vectors currently indexed.
    pub fn len(&self) -> usize {
        self.graph.read().active_count()
    }

    /// Whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether the index already contains an embedding for the given entity.
    pub fn contains(&self, entity_id: &Id) -> bool {
        self.graph.read().id_to_idx.contains_key(entity_id)
    }

    /// All keys currently held in the index.
    ///
    /// Lets callers reconcile the index against an external source of truth —
    /// e.g. dropping vectors whose keys no longer exist in the graph.
    pub fn keys(&self) -> Vec<Id> {
        self.graph.read().id_to_idx.keys().copied().collect()
    }

    /// Get the embedding vector for the given entity, if present.
    pub fn get(&self, entity_id: &Id) -> Option<Vec<f32>> {
        let graph = self.graph.read();
        let idx = graph.id_to_idx.get(entity_id)?;
        let node = graph.nodes.get(*idx)?;
        if node.vector.is_empty() {
            None
        } else {
            Some(node.vector.clone())
        }
    }

    /// Add or update the embedding for an entity.
    ///
    /// The embedding slice must have exactly `dimensions` elements.
    pub fn upsert(&self, entity_id: Id, embedding: &[f32]) -> Result<(), VectorError> {
        let _span = tracing::info_span!("kin_vector.upsert", dims = embedding.len()).entered();
        let mut graph = self.graph.write();

        if embedding.len() != graph.dimensions {
            return Err(VectorError::IndexError(format!(
                "embedding dimension mismatch: expected {}, got {}",
                graph.dimensions,
                embedding.len()
            )));
        }

        // Remove old vector if present
        graph.remove(&entity_id);

        graph.insert(entity_id, embedding)
    }

    /// Remove the embedding for an entity.
    pub fn remove(&self, entity_id: &Id) -> Result<(), VectorError> {
        let _span = tracing::info_span!("kin_vector.remove").entered();
        let mut graph = self.graph.write();
        graph.remove(entity_id);
        Ok(())
    }

    /// Search for the `limit` most similar entities to the given embedding.
    ///
    /// Returns pairs of (Id, distance_score) sorted by similarity.
    pub fn search_similar(
        &self,
        embedding: &[f32],
        limit: usize,
    ) -> Result<Vec<(Id, f32)>, VectorError> {
        let _span = tracing::info_span!(
            "kin_vector.search_similar",
            dims = embedding.len(),
            limit = limit
        )
        .entered();
        let graph = self.graph.read();

        if embedding.len() != graph.dimensions {
            return Err(VectorError::IndexError(format!(
                "query dimension mismatch: expected {}, got {}",
                graph.dimensions,
                embedding.len()
            )));
        }

        if graph.active_count() == 0 {
            return Ok(Vec::new());
        }

        Ok(graph.search(embedding, limit, None))
    }

    /// Search for the `limit` most similar entities to the given embedding, filtering by a predicate.
    ///
    /// Returns pairs of (Id, distance_score) sorted by similarity.
    pub fn search_similar_filtered(
        &self,
        embedding: &[f32],
        limit: usize,
        predicate: impl Fn(&Id) -> bool,
    ) -> Result<Vec<(Id, f32)>, VectorError> {
        let _span = tracing::info_span!(
            "kin_vector.search_similar_filtered",
            dims = embedding.len(),
            limit = limit
        )
        .entered();
        let graph = self.graph.read();

        if embedding.len() != graph.dimensions {
            return Err(VectorError::IndexError(format!(
                "query dimension mismatch: expected {}, got {}",
                graph.dimensions,
                embedding.len()
            )));
        }

        if graph.active_count() == 0 {
            return Ok(Vec::new());
        }

        let pred_dyn: &dyn Fn(&Id) -> bool = &predicate;
        Ok(graph.search(embedding, limit, Some(pred_dyn)))
    }

    /// Set the persistence path for this index.
    pub fn set_persistence_path(&self, path: impl Into<PathBuf>) {
        *self.persistence_path.write() = Some(path.into());
    }

    /// Save the HNSW index to disk.
    ///
    /// Persists the full HNSW graph as a single MessagePack file with atomic
    /// write semantics (write-to-tmp then rename).
    pub fn save(&self, path: &Path) -> Result<(), VectorError> {
        let _span = tracing::info_span!(
            "kin_vector.save",
            path = %path.display()
        )
        .entered();
        let graph = self.graph.read();
        let snapshot = HnswSnapshot {
            format_version: HNSW_FORMAT_VERSION,
            graph: HnswGraph {
                nodes: graph.nodes.clone(),
                entry_point: graph.entry_point,
                max_level: graph.max_level,
                dimensions: graph.dimensions,
                id_to_idx: graph.id_to_idx.clone(),
                idx_to_id: graph.idx_to_id.clone(),
                free_list: graph.free_list.clone(),
                rng_state: graph.rng_state,
                descriptor: graph.descriptor.clone(),
            },
        };
        let bytes = rmp_serde::to_vec(&snapshot)
            .map_err(|e| VectorError::IndexError(format!("failed to serialize HNSW index: {e}")))?;
        atomic_save_bytes(path, &bytes, "vector index")
    }

    /// Load a previously saved HNSW index from disk.
    ///
    /// Returns a new `VectorIndex` with the loaded index data.
    /// The `dimensions` parameter is used to validate the loaded data matches.
    pub fn load(path: &Path, dimensions: usize) -> Result<Self, VectorError> {
        let _span = tracing::info_span!(
            "kin_vector.load",
            path = %path.display(),
            dimensions = dimensions
        )
        .entered();
        let vi = Self::load_from_disk(path)?;
        let loaded_dims = vi.dimensions();
        if loaded_dims != dimensions {
            return Err(VectorError::IndexError(format!(
                "loaded vector index has dimensions {loaded_dims}, expected {dimensions}",
            )));
        }
        Ok(vi)
    }

    /// Load a previously saved index and verify it is compatible with the
    /// caller's `expected` self-description (model identity + graph provenance),
    /// in addition to vector dimensionality.
    ///
    /// Use this instead of [`VectorIndex::load`] whenever the index was built by
    /// a specific embedding model: it returns [`VectorError::ModelMismatch`] when
    /// a same-dimension model swap (or graph-root change) would otherwise load
    /// silently-wrong vectors. Only the fields the caller pins on `expected` are
    /// enforced (see [`IndexDescriptor::verify_compatible`]).
    pub fn load_checked(
        path: &Path,
        dimensions: usize,
        expected: &IndexDescriptor,
    ) -> Result<Self, VectorError> {
        let vi = Self::load(path, dimensions)?;
        vi.descriptor().verify_compatible(expected)?;
        Ok(vi)
    }

    /// Load a previously saved HNSW index from disk without dimension validation.
    ///
    /// The dimensions are read from the persisted data. Use this when the
    /// embedder is not available (e.g., loading an existing index for search
    /// without the `embeddings` feature enabled).
    pub fn load_from_disk(path: &Path) -> Result<Self, VectorError> {
        let _span = tracing::info_span!(
            "kin_vector.load_from_disk",
            path = %path.display()
        )
        .entered();
        let graph = if path.exists() {
            let bytes = fs::read(path).map_err(|e| {
                VectorError::IndexError(format!(
                    "failed to load vector index from {}: {e}",
                    path.display()
                ))
            })?;
            match try_load_snapshot(&bytes) {
                Ok(g) => g,
                Err(err) => recover_from_tmp(path, Some(&err))?,
            }
        } else {
            recover_from_tmp(path, None)?
        };

        Ok(Self {
            graph: RwLock::new(graph),
            persistence_path: RwLock::new(Some(path.to_path_buf())),
        })
    }
}

impl<Id: VectorId> std::fmt::Debug for VectorIndex<Id> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let graph = self.graph.read();
        f.debug_struct("VectorIndex")
            .field("dimensions", &graph.dimensions)
            .field("vectors", &graph.active_count())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seed_for_level_at_least(min_level: usize) -> u64 {
        for seed in 0..10_000u64 {
            let mut probe = HnswGraph::<DefaultId>::new(1);
            probe.rng_state = seed;
            if probe.random_level() >= min_level {
                return seed;
            }
        }
        panic!("no seed found for level >= {min_level}");
    }

    #[test]
    fn create_and_add_vectors() {
        let idx = VectorIndex::new(4).unwrap();
        let e1 = DefaultId::new();
        let e2 = DefaultId::new();

        idx.upsert(e1, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.upsert(e2, &[0.0, 1.0, 0.0, 0.0]).unwrap();

        assert_eq!(idx.len(), 2);
    }

    #[test]
    fn dimension_mismatch_rejected() {
        let idx = VectorIndex::new(4).unwrap();
        let e1 = DefaultId::new();

        let result = idx.upsert(e1, &[1.0, 0.0]);
        assert!(result.is_err());
    }

    #[test]
    fn search_returns_nearest() {
        let idx = VectorIndex::new(4).unwrap();
        let e1 = DefaultId::new();
        let e2 = DefaultId::new();
        let e3 = DefaultId::new();

        idx.upsert(e1, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.upsert(e2, &[0.0, 1.0, 0.0, 0.0]).unwrap();
        idx.upsert(e3, &[0.9, 0.1, 0.0, 0.0]).unwrap();

        let results = idx.search_similar(&[1.0, 0.0, 0.0, 0.0], 2).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, e1);
    }

    #[test]
    fn remove_vector() {
        let idx = VectorIndex::new(4).unwrap();
        let e1 = DefaultId::new();

        idx.upsert(e1, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        assert_eq!(idx.len(), 1);

        idx.remove(&e1).unwrap();
        assert_eq!(idx.len(), 0);
    }

    #[test]
    fn contains_tracks_membership() {
        let idx = VectorIndex::new(4).unwrap();
        let e1 = DefaultId::new();
        let e2 = DefaultId::new();

        assert!(!idx.contains(&e1));
        idx.upsert(e1, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        assert!(idx.contains(&e1));
        assert!(!idx.contains(&e2));
        idx.remove(&e1).unwrap();
        assert!(!idx.contains(&e1));
    }

    #[test]
    fn keys_reflect_current_membership() {
        let idx = VectorIndex::new(2).unwrap();
        let e1 = DefaultId::new();
        let e2 = DefaultId::new();

        assert!(idx.keys().is_empty());
        idx.upsert(e1, &[1.0, 0.0]).unwrap();
        idx.upsert(e2, &[0.0, 1.0]).unwrap();
        let keys = idx.keys();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&e1) && keys.contains(&e2));

        idx.remove(&e1).unwrap();
        let keys = idx.keys();
        assert_eq!(keys, vec![e2]);
    }

    #[test]
    fn remove_clears_inbound_references_even_without_reverse_edge() {
        let stale = DefaultId::new();
        let keeper = DefaultId::new();
        let mut graph = HnswGraph::new(1);
        graph.nodes = vec![
            HnswNode {
                vector: vec![1.0],
                connections: vec![vec![]],
                level: 0,
            },
            HnswNode {
                vector: vec![0.5],
                connections: vec![vec![], vec![0]],
                level: 1,
            },
        ];
        graph.entry_point = Some(1);
        graph.max_level = 1;
        graph.id_to_idx.insert(stale, 0);
        graph.id_to_idx.insert(keeper, 1);
        graph.idx_to_id = vec![stale, keeper];

        assert!(graph.remove(&stale));
        assert!(graph.nodes[1].connections[1].is_empty());
    }

    /// Helper: a four-node graph whose entry point (idx 1, level 3) sits above a
    /// DELIBERATE tie at the next level — idx 0 and idx 2 are both level 2. With a
    /// fresh `HnswGraph` each call, `id_to_idx` carries an independent per-process
    /// hasher seed, so its iteration order over the post-removal candidates varies
    /// run to run. This is exactly the shape that made entry-point reselection
    /// nondeterministic across daemon boots.
    fn graph_with_entrypoint_tie() -> (HnswGraph<DefaultId>, [DefaultId; 4]) {
        let ids = [
            DefaultId::new(),
            DefaultId::new(),
            DefaultId::new(),
            DefaultId::new(),
        ];
        let mut graph = HnswGraph::new(1);
        graph.nodes = vec![
            // idx 0: level 2 (tie candidate, LOWEST index → must win)
            HnswNode {
                vector: vec![0.0],
                connections: vec![vec![], vec![], vec![]],
                level: 2,
            },
            // idx 1: level 3 (the entry point we remove)
            HnswNode {
                vector: vec![1.0],
                connections: vec![vec![], vec![], vec![], vec![]],
                level: 3,
            },
            // idx 2: level 2 (tie candidate, higher index → must lose the tie)
            HnswNode {
                vector: vec![2.0],
                connections: vec![vec![], vec![], vec![]],
                level: 2,
            },
            // idx 3: level 1
            HnswNode {
                vector: vec![3.0],
                connections: vec![vec![], vec![]],
                level: 1,
            },
        ];
        graph.entry_point = Some(1);
        graph.max_level = 3;
        for (i, id) in ids.iter().enumerate() {
            graph.id_to_idx.insert(*id, i);
        }
        graph.idx_to_id = ids.to_vec();
        (graph, ids)
    }

    #[test]
    fn remove_reselects_entry_point_by_level_then_lowest_index() {
        // Removing the entry point must promote the highest-level survivor, and
        // break a level tie by the SMALLEST internal index — a content-defined
        // rule, not "whoever id_to_idx happened to visit first".
        let (mut graph, ids) = graph_with_entrypoint_tie();
        assert!(graph.remove(&ids[1]));
        // idx 0 and idx 2 both have level 2; idx 0 is lower → it wins.
        assert_eq!(graph.entry_point, Some(0));
        assert_eq!(graph.max_level, 2);
    }

    #[test]
    fn remove_entry_point_reselection_is_independent_of_map_seed() {
        // Build many independent graphs with identical content. Each `HnswGraph`
        // gets its own hashbrown seed, so `id_to_idx` iterates these four ids in
        // varying orders across instances. After removing the entry point, EVERY
        // instance must land on the same new entry point — proving reselection no
        // longer leaks per-process map order into the search start node.
        let mut chosen = Vec::new();
        for _ in 0..64 {
            let (mut graph, ids) = graph_with_entrypoint_tie();
            assert!(graph.remove(&ids[1]));
            chosen.push(graph.entry_point);
        }
        assert!(
            chosen.iter().all(|c| *c == Some(0)),
            "entry-point reselection varied across map seeds: {chosen:?}"
        );
    }

    #[test]
    fn reconcile_removal_order_does_not_change_search_results() {
        // Mirrors the boot reconcile (`prune_orphaned_vectors`): two indices built
        // identically, then the SAME orphan set removed in opposite orders. With
        // deterministic entry-point reselection the two must return byte-identical
        // neighbors — the per-boot score jitter this fix targets.
        let pairs: Vec<(u64, Vec<f32>)> = (0..64)
            .map(|i| {
                let f = i as f32;
                let v = vec![
                    (f * 0.131).sin(),
                    (f * 0.071).cos(),
                    (f * 0.029).sin(),
                    (f * 0.017).cos(),
                ];
                (i as u64, v)
            })
            .collect();
        let build = || {
            let idx = VectorIndex::<u64>::new(4).unwrap();
            for (id, v) in &pairs {
                idx.upsert(*id, v).unwrap();
            }
            idx
        };
        let idx_fwd = build();
        let idx_rev = build();

        let orphans: Vec<u64> = (0..64u64).filter(|i| i % 5 == 0).collect();
        for id in orphans.iter() {
            idx_fwd.remove(id).unwrap();
        }
        for id in orphans.iter().rev() {
            idx_rev.remove(id).unwrap();
        }

        for q in [
            vec![0.2f32, -0.3, 0.5, 0.8],
            vec![-0.9, 0.1, 0.4, -0.2],
            vec![0.5, 0.5, -0.5, 0.5],
        ] {
            let a = idx_fwd.search_similar(&q, 12).unwrap();
            let b = idx_rev.search_similar(&q, 12).unwrap();
            assert_eq!(a, b, "removal order changed search results for query {q:?}");
        }
    }

    #[test]
    fn insert_ignores_neighbors_without_active_layer() {
        let low = DefaultId::new();
        let high = DefaultId::new();
        let newcomer = DefaultId::new();
        let mut graph = HnswGraph::new(1);
        graph.nodes = vec![
            HnswNode {
                vector: vec![0.0],
                connections: vec![vec![]],
                level: 0,
            },
            HnswNode {
                vector: vec![1.0],
                connections: vec![vec![], vec![0]],
                level: 1,
            },
        ];
        graph.entry_point = Some(1);
        graph.max_level = 1;
        graph.id_to_idx.insert(low, 0);
        graph.id_to_idx.insert(high, 1);
        graph.idx_to_id = vec![low, high];
        graph.rng_state = seed_for_level_at_least(1);

        graph.insert(newcomer, &[0.5]).unwrap();

        let newcomer_idx = graph.id_to_idx[&newcomer];
        assert!(graph.nodes[newcomer_idx].connections[1]
            .iter()
            .all(|&nb| nb != 0));
    }

    #[test]
    fn sort_scored_neighbors_handles_nan_distances() {
        let mut scored = vec![(f32::NAN, 2usize), (0.0, 1usize), (f32::NAN, 0usize)];
        HnswGraph::<DefaultId>::sort_scored_neighbors(&mut scored);
        assert_eq!(scored[0].1, 1);
        assert_eq!(scored[1].1, 0);
        assert_eq!(scored[2].1, 2);
    }

    #[test]
    fn upsert_replaces_existing() {
        let idx = VectorIndex::new(4).unwrap();
        let e1 = DefaultId::new();

        idx.upsert(e1, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.upsert(e1, &[0.0, 1.0, 0.0, 0.0]).unwrap();

        assert_eq!(idx.len(), 1);

        let results = idx.search_similar(&[0.0, 1.0, 0.0, 0.0], 1).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, e1);
    }

    #[test]
    fn search_empty_index() {
        let idx = VectorIndex::<DefaultId>::new(4).unwrap();
        let results = idx.search_similar(&[1.0, 0.0, 0.0, 0.0], 5).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn save_reload_preserves_search_coherence() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.hnsw");

        let idx = VectorIndex::new(4).unwrap();
        let e1 = DefaultId::new();
        let e2 = DefaultId::new();
        let e3 = DefaultId::new();

        idx.upsert(e1, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.upsert(e2, &[0.0, 1.0, 0.0, 0.0]).unwrap();
        idx.upsert(e3, &[0.9, 0.1, 0.0, 0.0]).unwrap();
        idx.save(&path).unwrap();

        let loaded = VectorIndex::<DefaultId>::load(&path, 4).unwrap();
        let results = loaded.search_similar(&[1.0, 0.0, 0.0, 0.0], 2).unwrap();

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, e1);
        assert_eq!(results[1].0, e3);
    }

    #[test]
    fn load_rejects_corrupted_main_index_after_save() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.hnsw");

        let idx = VectorIndex::new(4).unwrap();
        idx.upsert(DefaultId::new(), &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.save(&path).unwrap();

        fs::write(&path, b"corrupted hnsw index").unwrap();

        let error = VectorIndex::<DefaultId>::load(&path, 4).unwrap_err();
        assert!(
            error.to_string().contains("failed to deserialize")
                || error.to_string().contains("recovery"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn save_atomically_replaces_main_index() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.hnsw");
        let tmp_path = recovery_tmp_path(&path);

        let idx = VectorIndex::new(4).unwrap();
        let e1 = DefaultId::new();
        let e2 = DefaultId::new();

        idx.upsert(e1, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.save(&path).unwrap();

        fs::write(&tmp_path, b"partial main index write").unwrap();

        idx.upsert(e2, &[0.9, 0.1, 0.0, 0.0]).unwrap();
        idx.save(&path).unwrap();

        let loaded = VectorIndex::<DefaultId>::load(&path, 4).unwrap();
        let results = loaded.search_similar(&[1.0, 0.0, 0.0, 0.0], 2).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, e1);
        assert_eq!(results[1].0, e2);
        assert!(!tmp_path.exists());
    }

    #[test]
    fn load_recovers_from_valid_tmp_when_primary_is_missing() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.hnsw");
        let tmp_path = recovery_tmp_path(&path);
        let marker_path = recovery_marker_path(&path);

        let idx = VectorIndex::new(4).unwrap();
        let entity_id = DefaultId::new();
        idx.upsert(entity_id, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.save(&path).unwrap();

        let bytes = fs::read(&path).unwrap();
        write_bytes_recovery_candidate(&path, &bytes, "vector index").unwrap();
        fs::remove_file(&path).unwrap();

        let loaded = VectorIndex::<DefaultId>::load(&path, 4).unwrap();
        let results = loaded.search_similar(&[1.0, 0.0, 0.0, 0.0], 1).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, entity_id);
        assert!(path.exists());
        assert!(!tmp_path.exists());
        assert!(!marker_path.exists());
    }

    #[test]
    fn load_recovers_from_valid_tmp_when_primary_is_corrupted() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.hnsw");
        let tmp_path = recovery_tmp_path(&path);
        let marker_path = recovery_marker_path(&path);

        let idx = VectorIndex::new(4).unwrap();
        let entity_id = DefaultId::new();
        idx.upsert(entity_id, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.save(&path).unwrap();

        let bytes = fs::read(&path).unwrap();
        write_bytes_recovery_candidate(&path, &bytes, "vector index").unwrap();
        fs::write(&path, b"corrupted hnsw index").unwrap();

        let loaded = VectorIndex::<DefaultId>::load(&path, 4).unwrap();
        let results = loaded.search_similar(&[1.0, 0.0, 0.0, 0.0], 1).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, entity_id);
        assert!(!tmp_path.exists());
        assert!(!marker_path.exists());
    }

    #[test]
    fn atomic_save_serializes_concurrent_writers() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = std::sync::Arc::new(dir.path().join("vectors.hnsw"));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
        let mut handles = Vec::new();

        for idx in 0..4u8 {
            let path = path.clone();
            let barrier = barrier.clone();
            handles.push(std::thread::spawn(move || {
                let bytes = vec![idx; 4096];
                barrier.wait();
                atomic_save_bytes(&path, &bytes, "vector index")
            }));
        }

        for handle in handles {
            handle.join().unwrap().unwrap();
        }

        let bytes = fs::read(path.as_ref()).unwrap();
        assert_eq!(bytes.len(), 4096);
        assert!(!recovery_tmp_path(path.as_ref()).exists());
        assert!(!recovery_marker_path(path.as_ref()).exists());
    }

    #[test]
    fn load_rejects_unproven_tmp_when_primary_is_missing() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.hnsw");
        let tmp_path = recovery_tmp_path(&path);

        let idx = VectorIndex::new(4).unwrap();
        idx.upsert(DefaultId::new(), &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.save(&path).unwrap();

        fs::rename(&path, &tmp_path).unwrap();

        let error = VectorIndex::<DefaultId>::load(&path, 4).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("unproven without a valid marker"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn load_rejects_tmp_with_mismatched_marker() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.hnsw");
        let marker_path = recovery_marker_path(&path);

        let idx = VectorIndex::new(4).unwrap();
        idx.upsert(DefaultId::new(), &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.save(&path).unwrap();

        let bytes = fs::read(&path).unwrap();
        write_bytes_recovery_candidate(&path, &bytes, "vector index").unwrap();
        fs::remove_file(&path).unwrap();

        let marker_bytes = fs::read(&marker_path).unwrap();
        let mut marker: RecoveryMarker = serde_json::from_slice(&marker_bytes).unwrap();
        marker.byte_len += 1;
        fs::write(&marker_path, serde_json::to_vec(&marker).unwrap()).unwrap();

        let error = VectorIndex::<DefaultId>::load(&path, 4).unwrap_err();
        assert!(
            error.to_string().contains("does not match marker"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn many_vectors_search_quality() {
        let idx = VectorIndex::new(8).unwrap();
        let mut entities = Vec::new();

        for i in 0..100 {
            let eid = DefaultId::new();
            let mut vec = [0.0f32; 8];
            vec[i % 8] = 1.0;
            vec[(i + 1) % 8] = 0.5;
            idx.upsert(eid, &vec).unwrap();
            entities.push((eid, vec));
        }

        assert_eq!(idx.len(), 100);

        let results = idx.search_similar(&entities[0].1, 5).unwrap();
        assert!(!results.is_empty());
        assert_eq!(results[0].0, entities[0].0);
    }

    #[test]
    fn cosine_distance_sanity() {
        assert!((cosine_distance(&[1.0, 0.0], &[1.0, 0.0]) - 0.0).abs() < 1e-6);
        assert!((cosine_distance(&[1.0, 0.0], &[0.0, 1.0]) - 1.0).abs() < 1e-6);
        assert!((cosine_distance(&[1.0, 0.0], &[-1.0, 0.0]) - 2.0).abs() < 1e-6);
    }

    #[test]
    fn load_from_disk_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.hnsw");

        let idx = VectorIndex::new(4).unwrap();
        let e1 = DefaultId::new();
        let e2 = DefaultId::new();
        idx.upsert(e1, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.upsert(e2, &[0.0, 1.0, 0.0, 0.0]).unwrap();
        idx.save(&path).unwrap();

        // Load without specifying dimensions
        let loaded = VectorIndex::<DefaultId>::load_from_disk(&path).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded.dimensions(), 4);

        // Search works on loaded index
        let results = loaded.search_similar(&[1.0, 0.0, 0.0, 0.0], 2).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, e1);
    }

    #[test]
    fn generic_u64_index() {
        let idx = VectorIndex::<u64>::new(4).unwrap();
        idx.upsert(1u64, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.upsert(2u64, &[0.0, 1.0, 0.0, 0.0]).unwrap();

        assert_eq!(idx.len(), 2);

        let results = idx.search_similar(&[1.0, 0.0, 0.0, 0.0], 1).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, 1u64);
    }

    #[test]
    fn generic_uuid_index() {
        let idx = VectorIndex::<uuid::Uuid>::new(4).unwrap();
        let id1 = uuid::Uuid::new_v4();
        let id2 = uuid::Uuid::new_v4();

        idx.upsert(id1, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.upsert(id2, &[0.0, 1.0, 0.0, 0.0]).unwrap();

        let results = idx.search_similar(&[1.0, 0.0, 0.0, 0.0], 1).unwrap();
        assert_eq!(results[0].0, id1);
    }

    // -- index self-description (model identity + graph provenance) -----------

    fn descriptor(model: &str, root: &str) -> IndexDescriptor {
        IndexDescriptor {
            model_id: Some(model.to_string()),
            graph_root: Some(root.to_string()),
        }
    }

    #[test]
    fn descriptor_round_trips_through_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("idx.hnsw");

        let idx =
            VectorIndex::<DefaultId>::new_with_descriptor(4, descriptor("bge-small@1", "root-abc"))
                .unwrap();
        idx.upsert(DefaultId::new(), &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.save(&path).unwrap();

        let loaded = VectorIndex::<DefaultId>::load_from_disk(&path).unwrap();
        assert_eq!(loaded.descriptor(), descriptor("bge-small@1", "root-abc"));
    }

    #[test]
    fn load_checked_accepts_matching_model_and_root() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("idx.hnsw");

        let idx =
            VectorIndex::<DefaultId>::new_with_descriptor(4, descriptor("bge-small@1", "root-abc"))
                .unwrap();
        idx.upsert(DefaultId::new(), &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.save(&path).unwrap();

        let loaded = VectorIndex::<DefaultId>::load_checked(
            &path,
            4,
            &descriptor("bge-small@1", "root-abc"),
        )
        .unwrap();
        assert_eq!(loaded.len(), 1);
    }

    #[test]
    fn load_checked_rejects_same_dimension_model_swap() {
        // The core bug: identical dimension (4) but a different embedding model.
        // A dimension-only check would pass and return silently-wrong neighbors.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("idx.hnsw");

        let idx =
            VectorIndex::<DefaultId>::new_with_descriptor(4, descriptor("model-A@1", "root-1"))
                .unwrap();
        idx.upsert(DefaultId::new(), &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.save(&path).unwrap();

        // Dimension-only load still succeeds (demonstrates the gap)...
        assert!(VectorIndex::<DefaultId>::load(&path, 4).is_ok());

        // ...but the checked load catches the swap.
        let err =
            VectorIndex::<DefaultId>::load_checked(&path, 4, &descriptor("model-B@1", "root-1"))
                .unwrap_err();
        match err {
            VectorError::ModelMismatch {
                field,
                expected,
                stored,
            } => {
                assert_eq!(field, "model_id");
                assert_eq!(expected, "model-B@1");
                assert_eq!(stored, "model-A@1");
            }
            other => panic!("expected ModelMismatch, got {other:?}"),
        }
    }

    #[test]
    fn load_checked_rejects_graph_root_change() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("idx.hnsw");

        let idx =
            VectorIndex::<DefaultId>::new_with_descriptor(4, descriptor("model-A@1", "root-1"))
                .unwrap();
        idx.upsert(DefaultId::new(), &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.save(&path).unwrap();

        let err =
            VectorIndex::<DefaultId>::load_checked(&path, 4, &descriptor("model-A@1", "root-2"))
                .unwrap_err();
        assert!(matches!(err, VectorError::ModelMismatch { field, .. } if field == "graph_root"));
    }

    #[test]
    fn load_checked_rejects_unstamped_snapshot_when_model_pinned() {
        // A legacy index saved without a descriptor cannot be proven compatible.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("idx.hnsw");

        let idx = VectorIndex::<DefaultId>::new(4).unwrap(); // no descriptor stamped
        idx.upsert(DefaultId::new(), &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.save(&path).unwrap();

        let err =
            VectorIndex::<DefaultId>::load_checked(&path, 4, &descriptor("model-B@1", "root-1"))
                .unwrap_err();
        match err {
            VectorError::ModelMismatch { field, stored, .. } => {
                assert_eq!(field, "model_id");
                assert_eq!(stored, "<unstamped>");
            }
            other => panic!("expected ModelMismatch, got {other:?}"),
        }
    }

    #[test]
    fn verify_compatible_ignores_unpinned_fields() {
        let stored = descriptor("model-A@1", "root-1");
        // Caller pins nothing -> compatible.
        stored
            .verify_compatible(&IndexDescriptor::default())
            .unwrap();
        // Caller pins only the model -> compatible.
        stored
            .verify_compatible(&IndexDescriptor {
                model_id: Some("model-A@1".into()),
                graph_root: None,
            })
            .unwrap();
    }

    #[test]
    fn legacy_snapshot_without_descriptor_field_still_loads() {
        // Backward-compat: a graph serialized in the PRE-descriptor layout (one
        // fewer field) must still deserialize, with the descriptor defaulting to
        // None. This pins the `#[serde(default)]` trailing-field behavior under
        // rmp-serde's array struct encoding.
        #[derive(Serialize)]
        struct OldGraph {
            nodes: Vec<HnswNode>,
            entry_point: Option<usize>,
            max_level: usize,
            dimensions: usize,
            id_to_idx: HashMap<DefaultId, usize>,
            idx_to_id: Vec<DefaultId>,
            free_list: Vec<usize>,
            rng_state: u64,
        }
        #[derive(Serialize)]
        struct OldSnapshot {
            format_version: u8,
            graph: OldGraph,
        }

        let old = OldSnapshot {
            format_version: HNSW_FORMAT_VERSION,
            graph: OldGraph {
                nodes: Vec::new(),
                entry_point: None,
                max_level: 0,
                dimensions: 8,
                id_to_idx: HashMap::new(),
                idx_to_id: Vec::new(),
                free_list: Vec::new(),
                rng_state: 7,
            },
        };
        let bytes = rmp_serde::to_vec(&old).unwrap();

        let graph = try_load_snapshot::<DefaultId>(&bytes).unwrap();
        assert_eq!(graph.dimensions, 8);
        assert_eq!(graph.descriptor, IndexDescriptor::default());
    }
}
