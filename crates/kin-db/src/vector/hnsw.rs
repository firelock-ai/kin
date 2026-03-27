// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Custom HNSW (Hierarchical Navigable Small World) index for approximate
//! nearest-neighbor search over entity embeddings.  Replaces the previous
//! usearch-backed implementation with a pure-Rust graph that is compiled
//! directly into the binary — no C++ FFI, no platform-specific build scripts.

use std::collections::BinaryHeap;
use std::path::{Path, PathBuf};
use std::{cmp::Reverse, fs, fs::File};

use hashbrown::{HashMap, HashSet};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::KinDbError;
use crate::types::EntityId;

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
fn cosine_distance(a: &[f32], b: &[f32]) -> f32 {
    debug_assert_eq!(a.len(), b.len());
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
// Core HNSW graph
// ---------------------------------------------------------------------------

#[derive(Clone, Serialize, Deserialize)]
struct HnswNode {
    /// The embedding vector.
    vector: Vec<f32>,
    /// connections[level] = list of neighbor internal indices at that level.
    connections: Vec<Vec<usize>>,
    /// Maximum level this node participates in.
    level: usize,
}

/// Internal mutable state of the HNSW graph.
#[derive(Serialize, Deserialize)]
struct HnswGraph {
    nodes: Vec<HnswNode>,
    /// Internal index of the current entry point, if any.
    entry_point: Option<usize>,
    /// The highest level currently in the graph.
    max_level: usize,
    dimensions: usize,
    /// Bi-directional mapping EntityId <-> internal index.
    id_to_idx: HashMap<EntityId, usize>,
    idx_to_id: Vec<EntityId>,
    /// Indices that were removed and can be reused.
    free_list: Vec<usize>,
    /// Simple u64 state for reproducible-ish level generation.
    rng_state: u64,
}

impl HnswGraph {
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
    ) -> Vec<(f32, usize)> {
        let mut visited = HashSet::new();
        visited.insert(entry);

        let entry_dist = cosine_distance(query, &self.nodes[entry].vector);

        // (distance, idx) — BinaryHeap is max-heap by default
        let mut candidates: BinaryHeap<Reverse<(OrderedF32, usize)>> = BinaryHeap::new();
        let mut result: BinaryHeap<(OrderedF32, usize)> = BinaryHeap::new();

        candidates.push(Reverse((OrderedF32(entry_dist), entry)));
        result.push((OrderedF32(entry_dist), entry));

        while let Some(Reverse((OrderedF32(c_dist), c_idx))) = candidates.pop() {
            let worst_dist = result.peek().map(|(OrderedF32(d), _)| *d).unwrap_or(f32::MAX);
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
                let nb_dist = cosine_distance(query, &self.nodes[nb].vector);
                let worst_dist = result.peek().map(|(OrderedF32(d), _)| *d).unwrap_or(f32::MAX);

                if nb_dist < worst_dist || result.len() < ef {
                    candidates.push(Reverse((OrderedF32(nb_dist), nb)));
                    result.push((OrderedF32(nb_dist), nb));
                    if result.len() > ef {
                        result.pop();
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
        let mut level = top_level;
        while level > target_level {
            let mut changed = true;
            while changed {
                changed = false;
                let node = &self.nodes[current];
                if level < node.connections.len() {
                    for &nb in &node.connections[level] {
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

    /// Insert a node into the graph.
    fn insert(&mut self, entity_id: EntityId, vector: &[f32]) -> Result<(), KinDbError> {
        let dims = self.dimensions;
        if vector.len() != dims {
            return Err(KinDbError::IndexError(format!(
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
            let neighbors_found = self.search_layer(vector, current, EF_CONSTRUCTION, lc);
            let m_max = if lc == 0 { M_MAX_0 } else { M };
            let selected = Self::select_neighbors(&neighbors_found, m_max);

            // Set this node's connections at this layer
            self.nodes[idx].connections[lc] = selected.clone();

            // Add bidirectional connections
            for &nb in &selected {
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
                    scored.sort_by(|a, b| {
                        a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal)
                    });
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
    fn remove(&mut self, entity_id: &EntityId) -> bool {
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

        // Clear the node's data
        self.nodes[idx].connections.clear();
        self.nodes[idx].vector.clear();
        self.nodes[idx].level = 0;
        self.free_list.push(idx);

        // If we removed the entry point, pick a new one.
        if self.entry_point == Some(idx) {
            self.entry_point = None;
            self.max_level = 0;
            // Find the active node with the highest level.
            for (&_eid, &other_idx) in &self.id_to_idx {
                let other_level = self.nodes[other_idx].level;
                if self.entry_point.is_none() || other_level > self.max_level {
                    self.entry_point = Some(other_idx);
                    self.max_level = other_level;
                }
            }
        }

        true
    }

    /// K-NN search.  Returns (EntityId, distance) pairs sorted by distance ascending.
    fn search(&self, query: &[f32], limit: usize) -> Vec<(EntityId, f32)> {
        let entry = match self.entry_point {
            Some(ep) => ep,
            None => return Vec::new(),
        };

        // Phase 1: greedy descent through upper layers
        let current = self.greedy_closest(query, entry, self.max_level, 0);

        // Phase 2: beam search at layer 0 with ef = max(ef_search, limit)
        let ef = EF_SEARCH.max(limit);
        let results = self.search_layer(query, current, ef, 0);

        results
            .into_iter()
            .take(limit)
            .filter_map(|(dist, idx)| {
                // Skip free-list entries
                if idx < self.idx_to_id.len()
                    && self.id_to_idx.contains_key(&self.idx_to_id[idx])
                {
                    Some((self.idx_to_id[idx], dist))
                } else {
                    None
                }
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Ordered f32 wrapper for BinaryHeap
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
struct OrderedF32(f32);

impl Eq for OrderedF32 {}

impl PartialOrd for OrderedF32 {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OrderedF32 {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0
            .partial_cmp(&other.0)
            .unwrap_or(std::cmp::Ordering::Equal)
    }
}

// ---------------------------------------------------------------------------
// Persistence helpers
// ---------------------------------------------------------------------------

const RECOVERY_MARKER_VERSION: u32 = 2;
const HNSW_FORMAT_VERSION: u8 = 1;

#[derive(Serialize, Deserialize)]
struct RecoveryMarker {
    version: u32,
    byte_len: u64,
    sha256: [u8; 32],
}

#[derive(Serialize, Deserialize)]
struct HnswSnapshot {
    format_version: u8,
    graph: HnswGraph,
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

fn fsync_and_rename(tmp_path: &Path, path: &Path) -> Result<(), KinDbError> {
    let file = File::open(tmp_path).map_err(|e| {
        KinDbError::IndexError(format!(
            "failed to reopen for fsync {}: {e}",
            tmp_path.display()
        ))
    })?;
    file.sync_all()
        .map_err(|e| KinDbError::IndexError(format!("fsync failed: {e}")))?;

    fs::rename(tmp_path, path).map_err(|e| {
        KinDbError::IndexError(format!(
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

fn write_bytes_with_fsync(path: &Path, bytes: &[u8]) -> Result<(), KinDbError> {
    fs::write(path, bytes)
        .map_err(|e| KinDbError::IndexError(format!("failed to write {}: {e}", path.display())))?;
    let file = File::open(path).map_err(|e| {
        KinDbError::IndexError(format!(
            "failed to reopen for fsync {}: {e}",
            path.display()
        ))
    })?;
    file.sync_all()
        .map_err(|e| KinDbError::IndexError(format!("fsync failed: {e}")))?;
    Ok(())
}

fn sync_parent_dir(path: &Path) {
    if let Some(parent) = path.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
}

fn clear_recovery_candidate(path: &Path, label: &str) -> Result<(), KinDbError> {
    let tmp_path = recovery_tmp_path(path);
    let marker_path = recovery_marker_path(path);
    if tmp_path.exists() {
        fs::remove_file(&tmp_path).map_err(|e| {
            KinDbError::IndexError(format!(
                "failed to clear stale temporary {label} {}: {e}",
                tmp_path.display()
            ))
        })?;
    }
    if marker_path.exists() {
        fs::remove_file(&marker_path).map_err(|e| {
            KinDbError::IndexError(format!(
                "failed to clear stale recovery marker {}: {e}",
                marker_path.display()
            ))
        })?;
    }
    Ok(())
}

fn write_recovery_marker(path: &Path, bytes: &[u8]) -> Result<(), KinDbError> {
    let marker_path = recovery_marker_path(path);
    let marker = RecoveryMarker {
        version: RECOVERY_MARKER_VERSION,
        byte_len: bytes.len() as u64,
        sha256: Sha256::digest(bytes).into(),
    };
    let marker_bytes = serde_json::to_vec(&marker).map_err(|e| {
        KinDbError::IndexError(format!(
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
) -> Result<(), KinDbError> {
    let tmp_path = recovery_tmp_path(path);
    clear_recovery_candidate(path, label)?;
    write_bytes_with_fsync(&tmp_path, bytes)?;
    write_recovery_marker(path, bytes)
}

fn promote_recovery_candidate(path: &Path) -> Result<(), KinDbError> {
    let tmp_path = recovery_tmp_path(path);
    let marker_path = recovery_marker_path(path);
    fsync_and_rename(&tmp_path, path)?;
    if marker_path.exists() {
        fs::remove_file(&marker_path).map_err(|e| {
            KinDbError::IndexError(format!(
                "failed to remove recovery marker {}: {e}",
                marker_path.display()
            ))
        })?;
        sync_parent_dir(path);
    }
    Ok(())
}

fn load_recovery_marker(path: &Path) -> Result<RecoveryMarker, KinDbError> {
    let marker_path = recovery_marker_path(path);
    let marker_bytes = fs::read(&marker_path).map_err(|e| {
        KinDbError::IndexError(format!(
            "failed to read recovery marker {}: {e}",
            marker_path.display()
        ))
    })?;
    serde_json::from_slice(&marker_bytes).map_err(|e| {
        KinDbError::IndexError(format!(
            "failed to parse recovery marker {}: {e}",
            marker_path.display()
        ))
    })
}

fn load_proven_recovery_bytes(path: &Path, label: &str) -> Result<Vec<u8>, KinDbError> {
    let tmp_path = recovery_tmp_path(path);
    let marker_path = recovery_marker_path(path);
    let marker = load_recovery_marker(path).map_err(|err| {
        KinDbError::IndexError(format!(
            "recovery {label} {} is unproven without a valid marker {}: {err}",
            tmp_path.display(),
            marker_path.display()
        ))
    })?;

    if marker.version != RECOVERY_MARKER_VERSION {
        return Err(KinDbError::IndexError(format!(
            "recovery marker {} uses unsupported version {}",
            marker_path.display(),
            marker.version
        )));
    }

    let bytes = fs::read(&tmp_path).map_err(|e| {
        KinDbError::IndexError(format!(
            "failed to read recovery vector index {}: {e}",
            tmp_path.display()
        ))
    })?;
    if bytes.len() as u64 != marker.byte_len {
        return Err(KinDbError::IndexError(format!(
            "recovery vector index {} length {} does not match marker {} length {}",
            tmp_path.display(),
            bytes.len(),
            marker_path.display(),
            marker.byte_len
        )));
    }
    let digest: [u8; 32] = Sha256::digest(&bytes).into();
    if digest != marker.sha256 {
        return Err(KinDbError::IndexError(format!(
            "recovery vector index {} checksum does not match marker {}",
            tmp_path.display(),
            marker_path.display()
        )));
    }

    Ok(bytes)
}

fn atomic_save_bytes(path: &Path, bytes: &[u8], label: &str) -> Result<(), KinDbError> {
    write_bytes_recovery_candidate(path, bytes, label)?;
    promote_recovery_candidate(path)
}

fn try_load_snapshot(bytes: &[u8]) -> Result<HnswGraph, KinDbError> {
    let snapshot: HnswSnapshot = rmp_serde::from_slice(bytes).map_err(|e| {
        KinDbError::IndexError(format!("failed to deserialize HNSW snapshot: {e}"))
    })?;
    if snapshot.format_version != HNSW_FORMAT_VERSION {
        return Err(KinDbError::IndexError(format!(
            "unsupported HNSW format version {}",
            snapshot.format_version
        )));
    }
    Ok(snapshot.graph)
}

fn recover_from_tmp(
    path: &Path,
    primary_error: Option<&KinDbError>,
) -> Result<HnswGraph, KinDbError> {
    let tmp_path = recovery_tmp_path(path);
    if !tmp_path.exists() {
        return Err(match primary_error {
            Some(err) => KinDbError::IndexError(format!(
                "failed to load vector index {} and no recovery index exists: {err}",
                path.display()
            )),
            None => KinDbError::IndexError(format!(
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
        KinDbError::IndexError(format!(
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
        KinDbError::IndexError(format!(
            "{prefix}recovery index {} is invalid: {tmp_err}",
            tmp_path.display()
        ))
    })?;

    promote_recovery_candidate(path).map_err(|err| {
        KinDbError::IndexError(format!(
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
pub struct VectorIndex {
    graph: RwLock<HnswGraph>,
    /// Optional path for persisting the index to disk.
    persistence_path: RwLock<Option<PathBuf>>,
}

impl VectorIndex {
    /// Create a new vector index for embeddings of the given dimensionality.
    pub fn new(dimensions: usize) -> Result<Self, KinDbError> {
        Ok(Self {
            graph: RwLock::new(HnswGraph::new(dimensions)),
            persistence_path: RwLock::new(None),
        })
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

    /// Add or update the embedding for an entity.
    ///
    /// The embedding slice must have exactly `dimensions` elements.
    pub fn upsert(&self, entity_id: EntityId, embedding: &[f32]) -> Result<(), KinDbError> {
        let mut graph = self.graph.write();

        if embedding.len() != graph.dimensions {
            return Err(KinDbError::IndexError(format!(
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
    pub fn remove(&self, entity_id: &EntityId) -> Result<(), KinDbError> {
        let mut graph = self.graph.write();
        graph.remove(entity_id);
        Ok(())
    }

    /// Search for the `limit` most similar entities to the given embedding.
    ///
    /// Returns pairs of (EntityId, distance_score) sorted by similarity.
    pub fn search_similar(
        &self,
        embedding: &[f32],
        limit: usize,
    ) -> Result<Vec<(EntityId, f32)>, KinDbError> {
        let graph = self.graph.read();

        if embedding.len() != graph.dimensions {
            return Err(KinDbError::IndexError(format!(
                "query dimension mismatch: expected {}, got {}",
                graph.dimensions,
                embedding.len()
            )));
        }

        if graph.active_count() == 0 {
            return Ok(Vec::new());
        }

        Ok(graph.search(embedding, limit))
    }

    /// Set the persistence path for this index.
    pub fn set_persistence_path(&self, path: impl Into<PathBuf>) {
        *self.persistence_path.write() = Some(path.into());
    }

    /// Save the HNSW index to disk.
    ///
    /// Persists the full HNSW graph as a single MessagePack file with atomic
    /// write semantics (write-to-tmp then rename).
    pub fn save(&self, path: &Path) -> Result<(), KinDbError> {
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
            },
        };
        let bytes = rmp_serde::to_vec(&snapshot).map_err(|e| {
            KinDbError::IndexError(format!("failed to serialize HNSW index: {e}"))
        })?;
        atomic_save_bytes(path, &bytes, "vector index")
    }

    /// Load a previously saved HNSW index from disk.
    ///
    /// Returns a new `VectorIndex` with the loaded index data.
    pub fn load(path: &Path, dimensions: usize) -> Result<Self, KinDbError> {
        let graph = if path.exists() {
            let bytes = fs::read(path).map_err(|e| {
                KinDbError::IndexError(format!(
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

        if graph.dimensions != dimensions {
            return Err(KinDbError::IndexError(format!(
                "loaded vector index has dimensions {}, expected {}",
                graph.dimensions, dimensions
            )));
        }

        Ok(Self {
            graph: RwLock::new(graph),
            persistence_path: RwLock::new(Some(path.to_path_buf())),
        })
    }
}

impl std::fmt::Debug for VectorIndex {
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

    #[test]
    fn create_and_add_vectors() {
        let idx = VectorIndex::new(4).unwrap();
        let e1 = EntityId::new();
        let e2 = EntityId::new();

        idx.upsert(e1, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.upsert(e2, &[0.0, 1.0, 0.0, 0.0]).unwrap();

        assert_eq!(idx.len(), 2);
    }

    #[test]
    fn dimension_mismatch_rejected() {
        let idx = VectorIndex::new(4).unwrap();
        let e1 = EntityId::new();

        let result = idx.upsert(e1, &[1.0, 0.0]);
        assert!(result.is_err());
    }

    #[test]
    fn search_returns_nearest() {
        let idx = VectorIndex::new(4).unwrap();
        let e1 = EntityId::new();
        let e2 = EntityId::new();
        let e3 = EntityId::new();

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
        let e1 = EntityId::new();

        idx.upsert(e1, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        assert_eq!(idx.len(), 1);

        idx.remove(&e1).unwrap();
        assert_eq!(idx.len(), 0);
    }

    #[test]
    fn upsert_replaces_existing() {
        let idx = VectorIndex::new(4).unwrap();
        let e1 = EntityId::new();

        idx.upsert(e1, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.upsert(e1, &[0.0, 1.0, 0.0, 0.0]).unwrap();

        assert_eq!(idx.len(), 1);

        let results = idx.search_similar(&[0.0, 1.0, 0.0, 0.0], 1).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, e1);
    }

    #[test]
    fn search_empty_index() {
        let idx = VectorIndex::new(4).unwrap();
        let results = idx.search_similar(&[1.0, 0.0, 0.0, 0.0], 5).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn save_reload_preserves_search_coherence() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.hnsw");

        let idx = VectorIndex::new(4).unwrap();
        let e1 = EntityId::new();
        let e2 = EntityId::new();
        let e3 = EntityId::new();

        idx.upsert(e1, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.upsert(e2, &[0.0, 1.0, 0.0, 0.0]).unwrap();
        idx.upsert(e3, &[0.9, 0.1, 0.0, 0.0]).unwrap();
        idx.save(&path).unwrap();

        let loaded = VectorIndex::load(&path, 4).unwrap();
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
        idx.upsert(EntityId::new(), &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.save(&path).unwrap();

        fs::write(&path, b"corrupted hnsw index").unwrap();

        let error = VectorIndex::load(&path, 4).unwrap_err();
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
        let e1 = EntityId::new();
        let e2 = EntityId::new();

        idx.upsert(e1, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.save(&path).unwrap();

        fs::write(&tmp_path, b"partial main index write").unwrap();

        idx.upsert(e2, &[0.9, 0.1, 0.0, 0.0]).unwrap();
        idx.save(&path).unwrap();

        let loaded = VectorIndex::load(&path, 4).unwrap();
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
        let entity_id = EntityId::new();
        idx.upsert(entity_id, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.save(&path).unwrap();

        let bytes = fs::read(&path).unwrap();
        write_bytes_recovery_candidate(&path, &bytes, "vector index").unwrap();
        fs::remove_file(&path).unwrap();

        let loaded = VectorIndex::load(&path, 4).unwrap();
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
        let entity_id = EntityId::new();
        idx.upsert(entity_id, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.save(&path).unwrap();

        let bytes = fs::read(&path).unwrap();
        write_bytes_recovery_candidate(&path, &bytes, "vector index").unwrap();
        fs::write(&path, b"corrupted hnsw index").unwrap();

        let loaded = VectorIndex::load(&path, 4).unwrap();
        let results = loaded.search_similar(&[1.0, 0.0, 0.0, 0.0], 1).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, entity_id);
        assert!(!tmp_path.exists());
        assert!(!marker_path.exists());
    }

    #[test]
    fn load_rejects_unproven_tmp_when_primary_is_missing() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.hnsw");
        let tmp_path = recovery_tmp_path(&path);

        let idx = VectorIndex::new(4).unwrap();
        idx.upsert(EntityId::new(), &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.save(&path).unwrap();

        fs::rename(&path, &tmp_path).unwrap();

        let error = VectorIndex::load(&path, 4).unwrap_err();
        assert!(
            error.to_string().contains("unproven without a valid marker"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn load_rejects_tmp_with_mismatched_marker() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.hnsw");
        let marker_path = recovery_marker_path(&path);

        let idx = VectorIndex::new(4).unwrap();
        idx.upsert(EntityId::new(), &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.save(&path).unwrap();

        let bytes = fs::read(&path).unwrap();
        write_bytes_recovery_candidate(&path, &bytes, "vector index").unwrap();
        fs::remove_file(&path).unwrap();

        let marker_bytes = fs::read(&marker_path).unwrap();
        let mut marker: RecoveryMarker = serde_json::from_slice(&marker_bytes).unwrap();
        marker.byte_len += 1;
        fs::write(&marker_path, serde_json::to_vec(&marker).unwrap()).unwrap();

        let error = VectorIndex::load(&path, 4).unwrap_err();
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
            let eid = EntityId::new();
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
}
