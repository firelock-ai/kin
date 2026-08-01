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

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::{cmp::Reverse, fs, fs::File, fs::OpenOptions};

use fs2::FileExt;
use hashbrown::{HashMap, HashSet};
use parking_lot::RwLock;
use rayon::prelude::*;
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

/// Number of nodes inserted serially to warm a cold graph before the parallel
/// batch path engages. Parallel candidate search needs a non-empty graph to
/// search against; a small serial seed provides one. Kept modest so the serial
/// prefix is cheap while still giving the first parallel chunk a connected graph.
const PARALLEL_SEED: usize = 128;

type CanonicalOrderItem<Id> = (u64, Vec<u8>, Id, Vec<f32>, usize);

/// Normalization factor for level generation: 1 / ln(M).
fn ml() -> f64 {
    1.0 / (M as f64).ln()
}

// ---------------------------------------------------------------------------
// Stable, process-independent key hashing
// ---------------------------------------------------------------------------

/// FNV-1a 64-bit hasher with a fixed offset basis.
///
/// Unlike the default `RandomState`, this is seeded identically in every
/// process, so feeding a key's `Hash` encoding through it yields the same u64
/// on every daemon boot. That stability is what lets HNSW level assignment and
/// tie-breaks be derived from the key itself rather than from insert-order
/// history (which varies run to run under the reconcile/embed race).
struct Fnv64(u64);

impl Default for Fnv64 {
    fn default() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }
}

impl Hasher for Fnv64 {
    fn finish(&self) -> u64 {
        self.0
    }

    fn write(&mut self, bytes: &[u8]) {
        let mut h = self.0;
        for &b in bytes {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
        self.0 = h;
    }
}

/// Stable 64-bit hash of a key, derived only from the key's contents.
///
/// The FNV-1a digest is run through a splitmix64 finalizer so even short or
/// sequential keys (e.g. small `u64` ids) avalanche to a ~uniform u64. The
/// result is process-independent and is used both to (a) assign a node's HNSW
/// level and (b) break distance ties — making slot/insert history unobservable
/// in search results.
fn key_hash<Id: Hash>(id: &Id) -> u64 {
    let mut h = Fnv64::default();
    id.hash(&mut h);
    let mut z = h.finish().wrapping_add(0x9e37_79b9_7f4a_7c15);
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

/// Assign a node's HNSW level from a STABLE hash of its key rather than a
/// running RNG counter.
///
/// The key hash is mapped to a uniform `u` in `(0, 1]` and run through the SAME
/// geometric transform the previous RNG path used — `floor(-ln(u) * mL)` with
/// `mL = 1 / ln(M)`. Because a well-distributed hash makes `u` uniform on
/// `(0, 1]` (exactly the distribution the old xorshift output had), the per-level
/// probabilities are unchanged: `P(level >= k) = exp(-k / mL) = M^-k`, i.e.
/// `1/16` at level >= 1, `1/256` at level >= 2, and so on. Only the *source* of
/// `u` changes — from insert-order-dependent to key-stable — so the level skew
/// that HNSW relies on for its log-search performance is preserved.
fn hnsw_level_for_key<Id: Hash>(id: &Id) -> usize {
    let u = ((key_hash(id) as f64) / (u64::MAX as f64)).max(1e-15);
    (-u.ln() * ml()).floor() as usize
}

// ---------------------------------------------------------------------------
// Distance
// ---------------------------------------------------------------------------

/// Cosine distance: 1.0 - cosine_similarity.  Lower is more similar.
///
/// On aarch64 built with the `simd` feature (both the shipped default), the default
/// path is the NEON kernel in [`cosine_distance_neon`], taken whenever the
/// `KIN_VECTOR_SIMD` env gate resolves on — which it does by default now that the
/// kernel's scalar parity and CPU efficiency are measured and approved. The two
/// kernels are NOT bit-identical: SIMD reduces four lanes then folds, a different
/// (but fixed, cross-run-deterministic) summation order than the scalar sequential
/// sum. That ~2-ulp delta only ever transposes effectively-equidistant neighbors;
/// it is characterized and bounded in the `simd` tests.
///
/// The scalar reduction in [`cosine_distance_scalar`] stays reachable for A/B (or a
/// bit-identical-to-frozen-benchmark run) by setting `KIN_VECTOR_SIMD` to `0`,
/// `false`, `no`, or `off`; it is also the only path when the `simd` feature is off
/// or the target is not aarch64.
#[inline]
pub fn cosine_distance(a: &[f32], b: &[f32]) -> f32 {
    debug_assert_eq!(a.len(), b.len());
    if a.is_empty() || b.is_empty() || a.len() != b.len() {
        return 1.0;
    }
    #[cfg(all(feature = "simd", target_arch = "aarch64"))]
    {
        if simd_enabled() {
            // SAFETY: NEON is part of the mandatory aarch64 baseline (Rust always
            // enables the `neon` target feature on aarch64), so these intrinsics
            // are unconditionally available on every target this branch compiles
            // for — no runtime CPU probe is needed.
            return unsafe { cosine_distance_neon(a, b) };
        }
    }
    cosine_distance_scalar(a, b)
}

/// Scalar cosine distance — the canonical, default reduction. Assumes `a` and `b`
/// are non-empty and equal length (the public [`cosine_distance`] guards that).
/// This is intentionally a separate `#[inline]` fn so that whenever the NEON
/// kernel is not taken (the default, or `simd` feature off) the public entry point
/// is byte-for-byte the original scalar code.
#[inline]
fn cosine_distance_scalar(a: &[f32], b: &[f32]) -> f32 {
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

/// Runtime gate for the SIMD distance kernel (`KIN_VECTOR_SIMD`, default ON).
/// On by default now that the NEON kernel's scalar parity and CPU efficiency are
/// measured and approved; the scalar reduction stays reachable for A/B by setting
/// the env to an off value (see [`simd_enabled_from_env`]). Sampled once per
/// process so the hot path never re-reads the environment. Gated to aarch64 to
/// match its only caller (the NEON branch of [`cosine_distance`]); on other targets
/// there is no SIMD kernel to gate.
#[cfg(all(feature = "simd", target_arch = "aarch64"))]
fn simd_enabled() -> bool {
    use std::sync::OnceLock;
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| simd_enabled_from_env(std::env::var("KIN_VECTOR_SIMD").ok().as_deref()))
}

/// Resolve the `KIN_VECTOR_SIMD` gate from its raw env value. Default ON: an unset
/// value — or any value that is not an explicit off token — enables the NEON
/// kernel, while `0`, `false`, `no`, or `off` (case-insensitive, surrounding
/// whitespace ignored) select the scalar reduction. Mirrors kin-search's
/// `KIN_SEARCH_INCREMENTAL_PERSIST` resolution so the two graduated gates share one
/// default-on convention. Kept as a pure fn of the raw value so the resolution is
/// unit-testable without the process-global `OnceLock`.
#[cfg(all(feature = "simd", target_arch = "aarch64"))]
fn simd_enabled_from_env(value: Option<&str>) -> bool {
    let Some(value) = value.map(str::trim) else {
        return true;
    };
    !(value == "0"
        || value.eq_ignore_ascii_case("false")
        || value.eq_ignore_ascii_case("no")
        || value.eq_ignore_ascii_case("off"))
}

/// aarch64 NEON cosine distance. Accumulates `dot`, `norm_a`, `norm_b` in four
/// f32 lanes, then folds each with one `vaddvq_f32` (a single, fixed-order
/// horizontal add) and finishes the `len % 4` tail in sequential scalar order.
///
/// DETERMINISM: the lane layout, the `vaddvq_f32` fold, and the tail order are
/// all fixed and instruction-defined — there is no reassociation and no
/// fast-math, so the result is bit-identical across runs and processes (proven by
/// the `simd` stability test). It is deliberately mul-then-add (no FMA) to track
/// the scalar kernel's rounding structure as closely as the lane order allows.
///
/// SAFETY: NEON is guaranteed on aarch64; callers invoke this only under
/// `cfg(target_arch = "aarch64")`.
#[cfg(all(feature = "simd", target_arch = "aarch64"))]
#[target_feature(enable = "neon")]
unsafe fn cosine_distance_neon(a: &[f32], b: &[f32]) -> f32 {
    use core::arch::aarch64::*;

    let n = a.len();
    let mut dot = vdupq_n_f32(0.0);
    let mut na = vdupq_n_f32(0.0);
    let mut nb = vdupq_n_f32(0.0);

    let mut i = 0usize;
    let simd_end = n - (n % 4);
    while i < simd_end {
        let va = vld1q_f32(a.as_ptr().add(i));
        let vb = vld1q_f32(b.as_ptr().add(i));
        // mul-then-add (no FMA) to mirror the scalar kernel's two-step rounding.
        dot = vaddq_f32(dot, vmulq_f32(va, vb));
        na = vaddq_f32(na, vmulq_f32(va, va));
        nb = vaddq_f32(nb, vmulq_f32(vb, vb));
        i += 4;
    }

    // Fixed-order horizontal fold of the four lanes.
    let mut dot_s = vaddvq_f32(dot);
    let mut na_s = vaddvq_f32(na);
    let mut nb_s = vaddvq_f32(nb);

    // Tail (len % 4) in the same sequential order the scalar path uses.
    while i < n {
        let x = *a.get_unchecked(i);
        let y = *b.get_unchecked(i);
        dot_s += x * y;
        na_s += x * x;
        nb_s += y * y;
        i += 1;
    }

    let denom = (na_s * nb_s).sqrt();
    if denom < f32::EPSILON {
        return 1.0;
    }
    1.0 - dot_s / denom
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

/// Serialize an `id -> internal index` map in canonical ascending-index order so
/// the persisted index is byte-identical across builds. A `HashMap`'s native
/// iteration order is process-randomized; the internal index is a bijection over
/// live entries, so ordering by it is total and deterministic.
fn serialize_id_to_idx_canonical<S, Id>(
    map: &HashMap<Id, usize>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    Id: VectorId,
{
    let mut entries: Vec<(&Id, &usize)> = map.iter().collect();
    entries.sort_unstable_by_key(|&(_, idx)| *idx);
    serializer.collect_map(entries)
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
    ///
    /// Serialized in canonical ascending-index order so the persisted bytes are
    /// byte-identical across builds; a `HashMap`'s native iteration order is
    /// process-randomized and would otherwise leak into the saved index.
    #[serde(serialize_with = "serialize_id_to_idx_canonical")]
    pub id_to_idx: HashMap<Id, usize>,
    pub idx_to_id: Vec<Id>,
    /// Indices that were removed and can be reused.
    pub free_list: Vec<usize>,
    /// Reserved slot. No code path reads this value.
    ///
    /// Layer assignment, tie-breaking, and entry-point selection all derive from
    /// a stable digest of the node key (see `hnsw_level_for_key` and
    /// `key_hash`), so the graph contains no pseudorandom generator and no
    /// generator state. This slot predates that design; it is written at a fixed
    /// constant and is only ever copied forward, never consumed.
    ///
    /// It is retained rather than deleted because `HnswGraph` is persisted with
    /// `rmp_serde::to_vec`, which encodes a struct as a positional array. Since
    /// the field carries no name in the serialized bytes, dropping it would
    /// shift `descriptor` from position 8 to position 7 and every previously
    /// saved index would fail to deserialize.
    pub reserved_legacy_slot: u64,
    /// Self-description (model identity + graph provenance) of the vectors in
    /// this graph. Last field + `#[serde(default)]` so legacy snapshots that
    /// predate stamping still deserialize (descriptor decodes to default/`None`).
    #[serde(default)]
    pub descriptor: IndexDescriptor,
    /// Reverse edge index: backlinks[target][layer] = source indices with an
    /// outgoing edge to target at layer. This is rebuilt on load and intentionally
    /// not serialized; it exists to keep removal bounded by incident degree.
    #[serde(skip)]
    pub backlinks: Vec<Vec<Vec<usize>>>,
    /// Mutations can happen in caller order; before search/save, rebuild once in
    /// canonical key order so final topology is independent of ingestion order.
    #[serde(skip)]
    pub canonical_order_dirty: bool,
}

/// Read-only result of planning a node's insertion against a fixed graph state.
///
/// Splitting "where would this node link" (a pure, parallelizable read over the
/// graph) from "apply those links" (a serial mutation) lets a batch compute many
/// plans concurrently and then commit them one at a time. `per_layer[lc]` holds
/// the selected neighbor indices at layer `lc`, for `lc` in `0..=insert_top`. An
/// empty `per_layer` means the graph had no entry point when planned, so the node
/// becomes the entry point on commit.
struct InsertionPlan {
    per_layer: Vec<Vec<usize>>,
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
            reserved_legacy_slot: 0x12345678_9abcdef0,
            descriptor: IndexDescriptor::default(),
            backlinks: Vec::new(),
            canonical_order_dirty: false,
        }
    }

    fn active_count(&self) -> usize {
        self.id_to_idx.len()
    }

    /// A persistence snapshot of the graph: the serialized fields copied, with the
    /// rebuilt-on-load reverse index dropped and the canonical-order flag cleared.
    /// Taken under the graph lock so the heavy serialize + fsync can run after the
    /// lock is released, without blocking concurrent upserts.
    fn clone_for_persist(&self) -> HnswGraph<Id> {
        HnswGraph {
            nodes: self.nodes.clone(),
            entry_point: self.entry_point,
            max_level: self.max_level,
            dimensions: self.dimensions,
            id_to_idx: self.id_to_idx.clone(),
            idx_to_id: self.idx_to_id.clone(),
            free_list: self.free_list.clone(),
            reserved_legacy_slot: self.reserved_legacy_slot,
            descriptor: self.descriptor.clone(),
            backlinks: Vec::new(),
            canonical_order_dirty: false,
        }
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

        // Heap entries are ordered by (distance, key_hash, idx). The key_hash —
        // a process-independent hash of the node's key — breaks distance ties so
        // that which of two equidistant nodes survives the `ef` cap (and the
        // final ordering) is a pure function of the node keys, never of the
        // insert/slot history that produced their internal indices. `idx` is a
        // final fallback only on an (astronomically unlikely) key_hash collision.
        let entry_kh = key_hash(&self.idx_to_id[entry]);
        let mut candidates: BinaryHeap<Reverse<(OrderedF32, u64, usize)>> = BinaryHeap::new();
        let mut result: BinaryHeap<(OrderedF32, u64, usize)> = BinaryHeap::new();

        candidates.push(Reverse((OrderedF32(entry_dist), entry_kh, entry)));
        if predicate.is_none_or(|p| p(&self.idx_to_id[entry])) {
            result.push((OrderedF32(entry_dist), entry_kh, entry));
        }

        while let Some(Reverse((OrderedF32(c_dist), _, c_idx))) = candidates.pop() {
            let worst_dist = result
                .peek()
                .map(|(OrderedF32(d), _, _)| *d)
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
                    .map(|(OrderedF32(d), _, _)| *d)
                    .unwrap_or(f32::MAX);

                if nb_dist < worst_dist || result.len() < ef {
                    let nb_kh = key_hash(&self.idx_to_id[nb]);
                    candidates.push(Reverse((OrderedF32(nb_dist), nb_kh, nb)));
                    if predicate.is_none_or(|p| p(&self.idx_to_id[nb])) {
                        result.push((OrderedF32(nb_dist), nb_kh, nb));
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
            .map(|(OrderedF32(d), _, idx)| (d, idx))
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

    fn canonical_id_bytes(id: &Id) -> Result<Vec<u8>, VectorError> {
        rmp_serde::to_vec(id).map_err(|e| {
            VectorError::IndexError(format!("failed to serialize vector id for ordering: {e}"))
        })
    }

    fn canonical_id_cmp(a: &(u64, &[u8]), b: &(u64, &[u8])) -> Ordering {
        a.0.cmp(&b.0).then_with(|| a.1.cmp(b.1))
    }

    fn ensure_backlink_slot(&mut self, target: usize, layer: usize) {
        if self.backlinks.len() <= target {
            self.backlinks.resize_with(target + 1, Vec::new);
        }
        if self.backlinks[target].len() <= layer {
            self.backlinks[target].resize_with(layer + 1, Vec::new);
        }
    }

    fn add_backlink(&mut self, target: usize, layer: usize, source: usize) {
        if target >= self.nodes.len() {
            return;
        }
        self.ensure_backlink_slot(target, layer);
        let sources = &mut self.backlinks[target][layer];
        if !sources.contains(&source) {
            sources.push(source);
            sources.sort_unstable();
        }
    }

    fn remove_backlink(&mut self, target: usize, layer: usize, source: usize) {
        if target >= self.backlinks.len() || layer >= self.backlinks[target].len() {
            return;
        }
        self.backlinks[target][layer].retain(|&candidate| candidate != source);
    }

    fn dedupe_neighbors(neighbors: Vec<usize>) -> Vec<usize> {
        let mut deduped = Vec::with_capacity(neighbors.len());
        for neighbor in neighbors {
            if !deduped.contains(&neighbor) {
                deduped.push(neighbor);
            }
        }
        deduped
    }

    fn set_connections(&mut self, source: usize, layer: usize, neighbors: Vec<usize>) {
        if source >= self.nodes.len() || layer >= self.nodes[source].connections.len() {
            return;
        }

        let next = Self::dedupe_neighbors(neighbors);
        let previous = std::mem::replace(&mut self.nodes[source].connections[layer], next.clone());

        for target in &previous {
            if !next.contains(target) {
                self.remove_backlink(*target, layer, source);
            }
        }
        for target in &next {
            if !previous.contains(target) {
                self.add_backlink(*target, layer, source);
            }
        }
    }

    fn add_directed_connection(&mut self, source: usize, target: usize, layer: usize) {
        if source >= self.nodes.len() || layer >= self.nodes[source].connections.len() {
            return;
        }
        if !self.nodes[source].connections[layer].contains(&target) {
            self.nodes[source].connections[layer].push(target);
            self.add_backlink(target, layer, source);
        }
    }

    fn rebuild_backlinks(&mut self) {
        self.backlinks.clear();
        self.backlinks.resize_with(self.nodes.len(), Vec::new);

        for source in 0..self.nodes.len() {
            let connections = self.nodes[source].connections.clone();
            for (layer, neighbors) in connections.into_iter().enumerate() {
                for target in Self::dedupe_neighbors(neighbors) {
                    self.add_backlink(target, layer, source);
                }
            }
        }
    }

    fn ensure_backlinks_ready(&mut self) {
        if self.backlinks.len() != self.nodes.len() {
            self.rebuild_backlinks();
        }
    }

    /// Sort `(distance, idx)` pairs ascending by distance, breaking ties by the
    /// node's stable key hash rather than by internal index. NaN distances sort
    /// last (via `total_cmp`). Key-based tie-breaks keep neighbor pruning
    /// independent of slot-allocation history.
    fn sort_scored_neighbors(&self, scored: &mut [(f32, usize)]) {
        scored.sort_by(|a, b| {
            a.0.total_cmp(&b.0)
                .then_with(|| key_hash(&self.idx_to_id[a.1]).cmp(&key_hash(&self.idx_to_id[b.1])))
        });
    }

    /// Insert a node into the graph.
    fn insert(&mut self, entity_id: Id, vector: &[f32]) -> Result<(), VectorError> {
        let level = hnsw_level_for_key(&entity_id);
        self.insert_with_level(entity_id, vector, level)?;
        self.canonical_order_dirty = true;
        Ok(())
    }

    fn insert_with_level(
        &mut self,
        entity_id: Id,
        vector: &[f32],
        level: usize,
    ) -> Result<(), VectorError> {
        if vector.len() != self.dimensions {
            return Err(VectorError::IndexError(format!(
                "embedding dimension mismatch: expected {}, got {}",
                self.dimensions,
                vector.len()
            )));
        }

        // Plan the node's links against the current graph (read-only), then apply
        // them. Computing the plan before the node is allocated yields identical
        // neighbors to the historical interleaved insert: the new node carries no
        // inbound edges, so it is unreachable during its own candidate search, and
        // each layer's search reads only that layer's connections — never the
        // links the same insert mutates at other layers.
        let plan = self.compute_insertion_plan(vector, level);
        self.commit_insertion(entity_id, vector, level, plan);
        Ok(())
    }

    /// Plan where `vector` (at `level`) would link, as a pure read over the
    /// current graph. Returns the selected neighbor indices per layer. Safe to run
    /// concurrently for many nodes against the same immutable graph.
    fn compute_insertion_plan(&self, vector: &[f32], level: usize) -> InsertionPlan {
        let entry = match self.entry_point {
            None => {
                return InsertionPlan {
                    per_layer: Vec::new(),
                }
            }
            Some(ep) => ep,
        };

        let mut current = entry;

        // Greedy descent from max_level down to level+1.
        if self.max_level > level {
            current = self.greedy_closest(vector, current, self.max_level, level);
        }

        // Beam search and neighbor selection at each layer from
        // min(level, max_level) down to 0.
        let insert_top = level.min(self.max_level);
        let mut per_layer: Vec<Vec<usize>> = vec![Vec::new(); insert_top + 1];
        for lc in (0..=insert_top).rev() {
            let neighbors_found = self.search_layer(vector, current, EF_CONSTRUCTION, lc, None);
            let m_max = if lc == 0 { M_MAX_0 } else { M };
            per_layer[lc] = Self::select_neighbors(&neighbors_found, m_max)
                .into_iter()
                .filter(|&nb| lc < self.nodes[nb].connections.len())
                .collect();

            // Use the closest found neighbor as the entry for the next layer.
            if let Some(&(_, closest)) = neighbors_found.first() {
                current = closest;
            }
        }

        InsertionPlan { per_layer }
    }

    /// Allocate a slot for `entity_id` and wire up the links from a previously
    /// computed [`InsertionPlan`]. This is the only mutating half of an insert and
    /// runs serially.
    fn commit_insertion(
        &mut self,
        entity_id: Id,
        vector: &[f32],
        level: usize,
        plan: InsertionPlan,
    ) {
        let node = HnswNode {
            vector: vector.to_vec(),
            connections: vec![Vec::new(); level + 1],
            level,
        };

        // Allocate or reuse an internal index.
        let idx = if let Some(free_idx) = self.free_list.pop() {
            self.nodes[free_idx] = node;
            self.idx_to_id[free_idx] = entity_id;
            if self.backlinks.len() <= free_idx {
                self.backlinks.resize_with(free_idx + 1, Vec::new);
            }
            self.backlinks[free_idx].clear();
            free_idx
        } else {
            let idx = self.nodes.len();
            self.nodes.push(node);
            self.idx_to_id.push(entity_id);
            self.backlinks.push(Vec::new());
            idx
        };
        self.id_to_idx.insert(entity_id, idx);

        // If the graph was empty, this node is the entry point.
        if self.entry_point.is_none() {
            self.entry_point = Some(idx);
            self.max_level = level;
            return;
        }

        self.apply_insertion_links(idx, level, plan);
    }

    /// Apply the per-layer neighbor links from a plan to node `idx`, adding the
    /// bidirectional edges and pruning over-full neighbors. Mirrors the historical
    /// in-place insert mutation exactly.
    fn apply_insertion_links(&mut self, idx: usize, level: usize, plan: InsertionPlan) {
        for (lc, selected) in plan.per_layer.iter().enumerate().rev() {
            // Set this node's connections at this layer.
            self.set_connections(idx, lc, selected.clone());

            // Add bidirectional connections.
            for &nb in selected {
                if lc >= self.nodes[nb].connections.len() {
                    continue;
                }
                self.add_directed_connection(nb, idx, lc);
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
                    self.sort_scored_neighbors(&mut scored);
                    let pruned = scored.into_iter().take(nb_m_max).map(|(_, n)| n).collect();
                    self.set_connections(nb, lc, pruned);
                }
            }
        }

        // Update entry point if this node has a higher level.
        if level > self.max_level {
            self.entry_point = Some(idx);
            self.max_level = level;
        }
    }

    fn ensure_canonical_order(&mut self) -> Result<(), VectorError> {
        if !self.canonical_order_dirty {
            return Ok(());
        }

        let dimensions = self.dimensions;
        let reserved_legacy_slot = self.reserved_legacy_slot;
        let descriptor = self.descriptor.clone();
        let mut items: Vec<CanonicalOrderItem<Id>> = Vec::with_capacity(self.id_to_idx.len());

        for (&id, &idx) in &self.id_to_idx {
            let node = self.nodes.get(idx).ok_or_else(|| {
                VectorError::IndexError(format!(
                    "vector id {id:?} points at missing HNSW node {idx}"
                ))
            })?;
            if node.vector.is_empty() {
                return Err(VectorError::IndexError(format!(
                    "vector id {id:?} points at removed HNSW node {idx}"
                )));
            }
            items.push((
                key_hash(&id),
                Self::canonical_id_bytes(&id)?,
                id,
                node.vector.clone(),
                node.level,
            ));
        }

        items.sort_by(|a, b| Self::canonical_id_cmp(&(a.0, &a.1), &(b.0, &b.1)));

        let mut rebuilt = HnswGraph::new(dimensions);
        rebuilt.reserved_legacy_slot = reserved_legacy_slot;
        rebuilt.descriptor = descriptor;
        for (_, _, id, vector, level) in items {
            rebuilt.insert_with_level(id, &vector, level)?;
        }
        rebuilt.canonical_order_dirty = false;
        *self = rebuilt;

        Ok(())
    }

    /// Remove a node from the graph.  We disconnect it from all neighbors and
    /// add its slot to the free list.  We do NOT try to repair neighbor
    /// connectivity — this is acceptable for a soft-delete approach common in
    /// HNSW implementations.
    fn remove(&mut self, entity_id: &Id) -> bool {
        let idx = match self.id_to_idx.get(entity_id).copied() {
            Some(idx) => idx,
            None => return false,
        };
        self.ensure_backlinks_ready();
        self.id_to_idx.remove(entity_id);

        // Drop outbound edges from this node by removing its source backlink from
        // each target. The node's own connection lists are cleared below.
        let outgoing = self.nodes[idx].connections.clone();
        for (layer, neighbors) in outgoing.into_iter().enumerate() {
            for nb in neighbors {
                self.remove_backlink(nb, layer, idx);
            }
        }

        // Drop inbound edges using the reverse-edge index. This replaces the old
        // full-graph scan and is bounded by the number of incident sources.
        let incoming = if idx < self.backlinks.len() {
            std::mem::take(&mut self.backlinks[idx])
        } else {
            Vec::new()
        };
        for (layer, sources) in incoming.into_iter().enumerate() {
            for source in sources {
                if source < self.nodes.len() && layer < self.nodes[source].connections.len() {
                    self.nodes[source].connections[layer].retain(|&n| n != idx);
                }
            }
        }

        // Clear the node's data
        self.nodes[idx].connections.clear();
        self.nodes[idx].vector.clear();
        self.nodes[idx].level = 0;
        if idx < self.backlinks.len() {
            self.backlinks[idx].clear();
        }
        self.free_list.push(idx);
        self.canonical_order_dirty = true;

        // If we removed the entry point, pick a new one.
        //
        // Selection MUST be a pure function of graph content, never of
        // `id_to_idx`'s iteration order OR of internal-index allocation history:
        //
        //  * That map is re-seeded per process on every deserialize (hashbrown's
        //    randomized hasher), so a tie broken "by whoever was visited first"
        //    makes the entry point vary across daemon boots even from a
        //    byte-identical persisted index.
        //  * Internal indices are assigned from the free-list, so under the
        //    reconcile/embed re-embed race the SAME surviving node can hold a
        //    different `idx` between runs; an `idx`-based tie-break therefore
        //    leaks slot history into the entry point too.
        //
        // The entry point is the start of every search's greedy descent, so any
        // jitter there re-routes descents and surfaces different neighbors at the
        // candidate-set boundary. Choose the active node with the highest level,
        // breaking ties by the smallest stable KEY HASH, so the result is
        // identical regardless of visitation order AND of slot history.
        if self.entry_point == Some(idx) {
            self.entry_point = None;
            self.max_level = 0;
            let mut best_key_hash: Option<u64> = None;
            for (eid, &other_idx) in &self.id_to_idx {
                let other_level = self.nodes[other_idx].level;
                let other_kh = key_hash(eid);
                let replace = match best_key_hash {
                    None => true,
                    Some(cur_kh) => {
                        other_level > self.max_level
                            || (other_level == self.max_level && other_kh < cur_kh)
                    }
                };
                if replace {
                    self.entry_point = Some(other_idx);
                    self.max_level = other_level;
                    best_key_hash = Some(other_kh);
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
        // Advisory lock file: never truncate (content is irrelevant to flock, and
        // truncating would be a behavior change). Explicit to satisfy clippy's
        // suspicious_open_options without altering the open semantics.
        .truncate(false)
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
    // `File::open` is read-only. Unix accepts `fsync` on that descriptor, but
    // Windows implements `File::sync_all` with `FlushFileBuffers`, whose handle
    // must carry GENERIC_WRITE. Reopen without create/truncate so the already
    // written candidate is flushed exactly as-is on every platform.
    let file = OpenOptions::new().write(true).open(tmp_path).map_err(|e| {
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
    sync_parent_dir(path)
}

fn write_bytes_with_fsync(path: &Path, bytes: &[u8]) -> Result<(), VectorError> {
    fs::write(path, bytes)
        .map_err(|e| VectorError::IndexError(format!("failed to write {}: {e}", path.display())))?;
    // Keep the reopen writable for the same cross-platform reason as
    // `fsync_and_rename`: Windows refuses FlushFileBuffers on a read-only
    // handle with ERROR_ACCESS_DENIED.
    let file = OpenOptions::new().write(true).open(path).map_err(|e| {
        VectorError::IndexError(format!(
            "failed to reopen for fsync {}: {e}",
            path.display()
        ))
    })?;
    file.sync_all()
        .map_err(|e| VectorError::IndexError(format!("fsync failed: {e}")))?;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), VectorError> {
    #[cfg(windows)]
    let dir = {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Foundation::GENERIC_WRITE;
        use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_BACKUP_SEMANTICS;

        // Opening a directory on Windows requires BACKUP_SEMANTICS, while
        // FlushFileBuffers requires a handle carrying GENERIC_WRITE. A normal
        // File::open supplies neither guarantee and can therefore turn this
        // durability barrier into ERROR_ACCESS_DENIED.
        OpenOptions::new()
            .access_mode(GENERIC_WRITE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
    };
    #[cfg(not(windows))]
    let dir = File::open(path);

    let dir = dir.map_err(|e| {
        VectorError::IndexError(format!(
            "failed to open directory for fsync {}: {e}",
            path.display()
        ))
    })?;
    let metadata = dir.metadata().map_err(|e| {
        VectorError::IndexError(format!(
            "failed to verify fsync directory {}: {e}",
            path.display()
        ))
    })?;
    if !metadata.is_dir() {
        return Err(VectorError::IndexError(format!(
            "fsync path is not a directory: {}",
            path.display()
        )));
    }
    dir.sync_all().map_err(|e| {
        VectorError::IndexError(format!("failed to fsync directory {}: {e}", path.display()))
    })
}

fn sync_parent_dir(path: &Path) -> Result<(), VectorError> {
    // A relative leaf such as `vectors.hnsw` has an empty parent path. Treat
    // that as the current directory so the namespace update still gets a
    // durability barrier.
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    sync_directory(parent)
}

fn clear_recovery_candidate(path: &Path, label: &str) -> Result<(), VectorError> {
    let tmp_path = recovery_tmp_path(path);
    let marker_path = recovery_marker_path(path);
    let mut removed = false;
    if tmp_path.exists() {
        fs::remove_file(&tmp_path).map_err(|e| {
            VectorError::IndexError(format!(
                "failed to clear stale temporary {label} {}: {e}",
                tmp_path.display()
            ))
        })?;
        removed = true;
    }
    if marker_path.exists() {
        fs::remove_file(&marker_path).map_err(|e| {
            VectorError::IndexError(format!(
                "failed to clear stale recovery marker {}: {e}",
                marker_path.display()
            ))
        })?;
        removed = true;
    }
    if removed {
        sync_parent_dir(path)?;
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
    sync_parent_dir(path)
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
        sync_parent_dir(path)?;
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
    let mut graph = snapshot.graph;
    graph.rebuild_backlinks();
    Ok(graph)
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
    fn with_canonical_graph<R>(
        &self,
        f: impl FnOnce(&HnswGraph<Id>) -> Result<R, VectorError>,
    ) -> Result<R, VectorError> {
        let graph = self.graph.upgradable_read();
        if graph.canonical_order_dirty {
            let mut graph = parking_lot::RwLockUpgradableReadGuard::upgrade(graph);
            graph.ensure_canonical_order()?;
            f(&graph)
        } else {
            f(&graph)
        }
    }

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

    /// Fraction of allocated slots that hold deleted (not yet reclaimed) nodes.
    ///
    /// Returns `0.0` when the index is empty or there are no pending deletes.
    /// After `compact()` this is always `0.0`.
    pub fn deleted_fraction(&self) -> f32 {
        let graph = self.graph.read();
        let total = graph.nodes.len();
        if total == 0 {
            return 0.0;
        }
        graph.free_list.len() as f32 / total as f32
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

    /// Add or update a batch of embeddings under a single write lock, using all
    /// available cores for the expensive candidate search.
    ///
    /// Insertion is split into a read-only planning phase and a serial commit. The
    /// per-node candidate search (the cost that dominates HNSW build) is run for a
    /// whole chunk in parallel against a frozen graph snapshot via the ambient
    /// rayon pool; the cheap graph mutation is then applied serially in canonical
    /// key order. Chunks grow with the graph so it stays populated as it fills.
    ///
    /// Determinism: the resulting intermediate graph is a pure function of the key
    /// set (commit order is canonical, planning is order-independent), and — like
    /// the single-key path — it is canonicalized to the byte-identical authoritative
    /// topology by [`VectorIndex::ensure_canonical_order`] / `save` before any
    /// query result is taken. Parallel batch build and serial single upserts
    /// therefore produce identical query results after canonicalization.
    pub fn upsert_batch(&self, items: Vec<(Id, Vec<f32>)>) -> Result<(), VectorError> {
        let _span = tracing::info_span!("kin_vector.upsert_batch", count = items.len()).entered();
        let mut graph = self.graph.write();
        let dims = graph.dimensions;

        for (_, embedding) in &items {
            if embedding.len() != dims {
                return Err(VectorError::IndexError(format!(
                    "embedding dimension mismatch: expected {}, got {}",
                    dims,
                    embedding.len()
                )));
            }
        }
        if items.is_empty() {
            return Ok(());
        }

        // Resolve duplicate keys within the batch (last value wins), matching a
        // sequence of single upserts of the same key.
        let mut resolved: HashMap<Id, Vec<f32>> = HashMap::with_capacity(items.len());
        for (id, embedding) in items {
            resolved.insert(id, embedding);
        }

        // Drop any existing node for these keys so each is a fresh insert.
        let existing: Vec<Id> = resolved.keys().copied().collect();
        for id in &existing {
            graph.remove(id);
        }

        // Order the inserts by canonical key order — the same order
        // canonicalization uses — so the intermediate graph is a deterministic
        // function of the key set rather than of caller order or planning
        // parallelism.
        let mut keyed: Vec<CanonicalOrderItem<Id>> = Vec::with_capacity(resolved.len());
        for (id, embedding) in resolved {
            let level = hnsw_level_for_key(&id);
            let bytes = HnswGraph::<Id>::canonical_id_bytes(&id)?;
            keyed.push((key_hash(&id), bytes, id, embedding, level));
        }
        keyed.sort_by(|a, b| HnswGraph::<Id>::canonical_id_cmp(&(a.0, &a.1), &(b.0, &b.1)));

        // Warm a cold graph serially so parallel planning always has a non-empty
        // graph to search against (and stays connected).
        let mut cursor = 0usize;
        if graph.entry_point.is_none() {
            let seed = keyed.len().min(PARALLEL_SEED);
            for (_, _, id, embedding, level) in &keyed[..seed] {
                graph.insert_with_level(*id, embedding, *level)?;
            }
            cursor = seed;
        }

        // Doubling chunks: plan a chunk in parallel against the frozen graph, then
        // commit serially. Chunk size tracks the live graph size so the graph stays
        // populated as it grows and intra-chunk link loss stays bounded.
        while cursor < keyed.len() {
            let chunk_len = graph
                .active_count()
                .max(PARALLEL_SEED)
                .min(keyed.len() - cursor);
            let end = cursor + chunk_len;
            let chunk = &keyed[cursor..end];

            let plans: Vec<InsertionPlan> = {
                let frozen: &HnswGraph<Id> = &graph;
                chunk
                    .par_iter()
                    .map(|(_, _, _, embedding, level)| {
                        frozen.compute_insertion_plan(embedding, *level)
                    })
                    .collect()
            };

            for ((_, _, id, embedding, level), plan) in chunk.iter().zip(plans) {
                graph.commit_insertion(*id, embedding, *level, plan);
            }
            cursor = end;
        }

        graph.canonical_order_dirty = true;
        Ok(())
    }

    /// Rebuilds the graph from scratch in canonical insertion order to ensure deterministic serialization.
    pub fn ensure_canonical_order(&self) -> Result<(), VectorError> {
        let mut graph = self.graph.write();
        graph.ensure_canonical_order()
    }

    /// Compact the index by rebuilding the HNSW graph from live nodes only.
    ///
    /// Soft-deletes remove nodes and their incident edges but leave the
    /// surrounding graph structure unchanged.  After a high-delete-rate
    /// reconcile the surviving nodes can end up with fewer cross-cluster
    /// connections than they would have in a freshly built graph, which
    /// degrades ANN recall.  `compact()` forces a full rebuild, restoring
    /// connectivity among the live nodes at the cost of an O(n log n) pass.
    ///
    /// After the call `deleted_fraction()` returns `0.0`.
    pub fn compact(&self) -> Result<(), VectorError> {
        let mut graph = self.graph.write();
        graph.canonical_order_dirty = true;
        graph.ensure_canonical_order()
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
        let pred_dyn: &dyn Fn(&Id) -> bool = &predicate;
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
        // Canonicalize (if needed) and copy a consistent snapshot under the graph
        // lock, then release the lock BEFORE the heavy serialize + fsync so the
        // GPU-fed upsert path is not blocked by index IO. Concurrent upserts after
        // this point simply land in the next save.
        let snapshot = self.with_canonical_graph(|graph| {
            Ok(HnswSnapshot {
                format_version: HNSW_FORMAT_VERSION,
                graph: graph.clone_for_persist(),
            })
        })?;
        let bytes = rmp_serde::to_vec(&snapshot)
            .map_err(|e| VectorError::IndexError(format!("failed to serialize HNSW index: {e}")))?;
        atomic_save_bytes(path, &bytes, "vector index")
    }

    /// Load a previously saved HNSW index from disk (dimension check only).
    ///
    /// # Deprecation
    ///
    /// Prefer [`VectorIndex::load_checked`] whenever the index was built by a
    /// specific embedding model. `load` checks only that the stored dimension
    /// matches `dimensions`; it does **not** verify model identity or graph
    /// provenance. Two embedding models can share the same dimension while
    /// producing incompatible vector spaces, so a model swap can load
    /// silently-wrong neighbors without any error. `load_checked` adds the
    /// provenance check and returns [`VectorError::ModelMismatch`] in that case.
    ///
    /// Use `load` only when no `IndexDescriptor` is available (e.g. loading an
    /// index for inspection without the original model context).
    #[deprecated(
        note = "Use `load_checked` instead; `load` only verifies dimensions and will \
                silently return wrong neighbors after a same-dimension model swap."
    )]
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
    /// Returns [`VectorError::ModelMismatch`] when a same-dimension model swap
    /// (or graph-root change) would otherwise load silently-wrong vectors. Only
    /// the fields the caller pins on `expected` are enforced (see
    /// [`IndexDescriptor::verify_compatible`]).
    pub fn load_checked(
        path: &Path,
        dimensions: usize,
        expected: &IndexDescriptor,
    ) -> Result<Self, VectorError> {
        let _span = tracing::info_span!(
            "kin_vector.load_checked",
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

    /// Find a `DefaultId` whose key-hash-derived HNSW level is at least
    /// `min_level`. Levels are now a pure function of the key, so tests that need
    /// a node above layer 0 pick a qualifying key instead of seeding an RNG.
    fn default_id_with_level_at_least(min_level: usize) -> DefaultId {
        for n in 0..1_000_000u128 {
            let id = DefaultId(uuid::Uuid::from_u128(n));
            if hnsw_level_for_key(&id) >= min_level {
                return id;
            }
        }
        panic!("no key found for level >= {min_level}");
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
    ///
    /// The keys are FIXED (not random) so the key-hash tie-break has a single
    /// deterministic winner across instances; only the per-process map seed
    /// varies between calls. The winner is whichever of idx 0 / idx 2 has the
    /// smaller `key_hash`.
    fn graph_with_entrypoint_tie() -> (HnswGraph<DefaultId>, [DefaultId; 4]) {
        let ids = [
            DefaultId(uuid::Uuid::from_u128(0xA1)),
            DefaultId(uuid::Uuid::from_u128(0xB2)),
            DefaultId(uuid::Uuid::from_u128(0xC3)),
            DefaultId(uuid::Uuid::from_u128(0xD4)),
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
    fn remove_reselects_entry_point_by_level_then_smallest_key_hash() {
        // Removing the entry point must promote the highest-level survivor, and
        // break a level tie by the SMALLEST stable key hash — a content-defined
        // rule, not "whoever id_to_idx happened to visit first" and not the
        // internal index (which carries slot/insert history under the re-embed
        // race).
        let (mut graph, ids) = graph_with_entrypoint_tie();
        assert!(graph.remove(&ids[1]));
        // idx 0 and idx 2 both have level 2; the smaller key hash wins.
        let expected = if key_hash(&ids[0]) <= key_hash(&ids[2]) {
            Some(0)
        } else {
            Some(2)
        };
        assert_eq!(graph.entry_point, expected);
        assert_eq!(graph.max_level, 2);
    }

    #[test]
    fn remove_entry_point_reselection_is_independent_of_map_seed() {
        // Build many independent graphs with identical content. Each `HnswGraph`
        // gets its own hashbrown seed, so `id_to_idx` iterates these four ids in
        // varying orders across instances. After removing the entry point, EVERY
        // instance must land on the same new entry point — proving reselection no
        // longer leaks per-process map order into the search start node.
        let expected = {
            let (_, ids) = graph_with_entrypoint_tie();
            if key_hash(&ids[0]) <= key_hash(&ids[2]) {
                Some(0)
            } else {
                Some(2)
            }
        };
        let mut chosen = Vec::new();
        for _ in 0..64 {
            let (mut graph, ids) = graph_with_entrypoint_tie();
            assert!(graph.remove(&ids[1]));
            chosen.push(graph.entry_point);
        }
        assert!(
            chosen.iter().all(|c| *c == expected),
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

    /// The core regression test for the HNSW-determinism fix.
    ///
    /// Two indices reach the SAME final content, but index B gets there via a
    /// DIFFERENT remove/insert *interleaving*: every few keys it re-embeds
    /// (remove + re-`upsert`, identical key and vector) a VARYING number of extra
    /// times, immediately after that key's first insert — exactly the mid-run
    /// upsert churn the reconcile/embed race produces (a re-embed's count and
    /// interleaving vary run to run).
    ///
    /// Each churn is performed before the next key is inserted, so a re-embedded
    /// key's FINAL insert still happens against the same set of predecessors as
    /// in the clean sequence; the graph stays small enough (< M_MAX_0 nodes) that
    /// no neighbor pruning ever fires, so remove+re-insert against the same node
    /// set is a true graph identity. The ONLY things the churn perturbs are (a)
    /// how many inserts precede later keys and (b) the free-list / internal-index
    /// history — precisely the two sources this fix neutralizes by deriving levels
    /// and tie-breaks from stable key hashes.
    ///
    /// Before the fix, the extra inserts advanced the shared level RNG, shifting
    /// every later node's level and diverging the topology; after the fix, kNN
    /// results AND the entry point are byte-identical between the two sequences.
    #[test]
    fn interleaved_reembed_history_does_not_change_results() {
        let pairs: Vec<(u64, Vec<f32>)> = (0..28)
            .map(|i| {
                let f = i as f32;
                (
                    i as u64,
                    vec![
                        (f * 0.137).sin(),
                        (f * 0.091).cos(),
                        (f * 0.041).sin(),
                        (f * 0.023).cos(),
                    ],
                )
            })
            .collect();

        // Sequence A: each key inserted exactly once, in order.
        let idx_a = VectorIndex::<u64>::new(4).unwrap();
        for (id, v) in &pairs {
            idx_a.upsert(*id, v).unwrap();
        }

        // Sequence B: same order, but every 5th key is re-embedded a varying
        // number of extra times right after its first insert.
        let idx_b = VectorIndex::<u64>::new(4).unwrap();
        for (n, (id, v)) in pairs.iter().enumerate() {
            idx_b.upsert(*id, v).unwrap();
            if n % 5 == 0 {
                for _ in 0..(1 + n % 3) {
                    idx_b.remove(id).unwrap();
                    idx_b.upsert(*id, v).unwrap();
                }
            }
        }

        assert_eq!(idx_a.len(), idx_b.len());

        // Identical kNN results for every probe.
        for q in [
            vec![0.2f32, -0.3, 0.5, 0.8],
            vec![-0.9, 0.1, 0.4, -0.2],
            vec![0.5, 0.5, -0.5, 0.5],
            vec![0.1, 0.9, 0.2, -0.7],
        ] {
            let a = idx_a.search_similar(&q, 15).unwrap();
            let b = idx_b.search_similar(&q, 15).unwrap();
            assert_eq!(a, b, "re-embed interleaving changed results for {q:?}");
        }

        // Identical entry point (the start of every greedy descent). Compare by
        // KEY, since the internal index legitimately differs between histories.
        let entry_key = |idx: &VectorIndex<u64>| -> Option<u64> {
            let g = idx.graph.read();
            g.entry_point.map(|ep| g.idx_to_id[ep])
        };
        assert_eq!(
            entry_key(&idx_a),
            entry_key(&idx_b),
            "re-embed interleaving changed the entry point"
        );
    }

    /// HNSW topology is incrementally constructed, so raw caller insertion order
    /// can change candidate sets. Public search/save now canonicalizes dirty
    /// graphs exactly once in stable key order before the graph is used, making
    /// the operational topology a function of final content rather than of
    /// ingestion order.
    ///
    /// Why this exists: `interleaved_reembed_history_does_not_change_results`
    /// (above) only re-embeds keys IN PLACE in the SAME order, so it never
    /// exercises a *different* insert order. But each node's neighbor selection
    /// reads the graph built SO FAR, so two indices built from the SAME vector set
    /// in different orders can wire up different connections — even with the
    /// key-hash levels/tie-breaks (efe77db) that make every per-step decision
    /// order-independent. The key-hash fixes removed the *tie-order* leak; the
    /// canonical rebuild below removes the remaining *candidate set* drift. This
    /// inserts the same 600 vectors sorted vs reversed and asserts identical kNN
    /// + entry point after the same canonicalization boundary search/save uses.
    #[test]
    fn hnsw_search_is_invariant_to_insert_order() {
        // Deterministic pseudo-vector for key `i` (no RNG → reproducible across
        // processes and runs; this characterization must not itself be flaky).
        fn vec_for(i: u64, dim: usize) -> Vec<f32> {
            (0..dim)
                .map(|d| {
                    let x =
                        (i.wrapping_mul(2654435761).wrapping_add(d as u64 * 40503) % 1000) as f32;
                    ((x / 1000.0) * std::f32::consts::TAU).sin()
                        + ((i as f32) * 0.013 * (d as f32 + 1.0)).cos()
                })
                .collect()
        }
        fn build(order: &[u64], dim: usize) -> VectorIndex<u64> {
            let idx = VectorIndex::<u64>::new(dim).unwrap();
            for &k in order {
                idx.upsert(k, &vec_for(k, dim)).unwrap();
            }
            idx
        }

        let n: u64 = 600;
        let dim = 48;
        let sorted: Vec<u64> = (0..n).collect();
        let reversed: Vec<u64> = (0..n).rev().collect();

        let a = build(&sorted, dim);
        let b = build(&reversed, dim);
        a.ensure_canonical_order().unwrap();
        b.ensure_canonical_order().unwrap();
        assert_eq!(a.len(), b.len(), "same vector SET must give same size");

        let limit = 20;
        let ids = |idx: &VectorIndex<u64>, query: &[f32]| -> Vec<u64> {
            idx.search_similar(query, limit)
                .unwrap()
                .into_iter()
                .map(|(id, _)| id)
                .collect()
        };
        let warm_query = vec_for(10_000, dim);
        assert_eq!(
            ids(&a, &warm_query),
            ids(&b, &warm_query),
            "insert order changed kNN at the first canonicalizing search"
        );

        // Same entry point (the start of every greedy descent). Compare by KEY —
        // the internal index legitimately differs between insert histories.
        let entry_key = |idx: &VectorIndex<u64>| -> Option<u64> {
            let g = idx.graph.read();
            g.entry_point.map(|ep| g.idx_to_id[ep])
        };
        assert_eq!(
            entry_key(&a),
            entry_key(&b),
            "insert order changed the HNSW entry point"
        );

        // Identical kNN for every probe — the property the frozen-golden protocol
        // depends on and that a durable topology fix must restore.
        for q in 0..8u64 {
            let query = vec_for(10_000 + q, dim);
            assert_eq!(
                ids(&a, &query),
                ids(&b, &query),
                "insert order changed kNN for probe {q} (sorted vs reversed)"
            );
        }
    }

    /// Canonicalization is now deferred (lazy): public search no longer rebuilds
    /// the graph on every call; callers run [`VectorIndex::ensure_canonical_order`]
    /// (or `save`, which canonicalizes via `with_canonical_graph`) at the boundary
    /// where order-independence is required. This pins the two guarantees that make
    /// that safe: (1) the lazy explicit canonicalization and the eager save-path
    /// canonicalization produce bit-identical query results, even from different
    /// insert orders; and (2) the canonical node ordering is a deterministic
    /// function of the key set alone — identical regardless of insert order — and
    /// re-canonicalizing a clean graph is a no-op.
    #[test]
    fn canonicalization_lazy_matches_eager_and_is_deterministic() {
        fn vec_for(i: u64, dim: usize) -> Vec<f32> {
            (0..dim)
                .map(|d| {
                    let x =
                        (i.wrapping_mul(2654435761).wrapping_add(d as u64 * 40503) % 1000) as f32;
                    ((x / 1000.0) * std::f32::consts::TAU).sin()
                        + ((i as f32) * 0.013 * (d as f32 + 1.0)).cos()
                })
                .collect()
        }
        fn build(order: &[u64], dim: usize) -> VectorIndex<u64> {
            let idx = VectorIndex::<u64>::new(dim).unwrap();
            for &k in order {
                idx.upsert(k, &vec_for(k, dim)).unwrap();
            }
            idx
        }

        let n: u64 = 300;
        let dim = 32;
        let limit = 20;
        let sorted: Vec<u64> = (0..n).collect();
        let reversed: Vec<u64> = (0..n).rev().collect();
        let queries: Vec<Vec<f32>> = (0..8).map(|q| vec_for(50_000 + q, dim)).collect();

        // kNN as (id, distance bits) so the comparison is exact, not approximate.
        let knn = |idx: &VectorIndex<u64>, q: &[f32]| -> Vec<(u64, u32)> {
            idx.search_similar(q, limit)
                .unwrap()
                .into_iter()
                .map(|(id, d)| (id, d.to_bits()))
                .collect()
        };

        // Eager: `save` canonicalizes the in-memory graph in place via
        // `with_canonical_graph` (the pre-existing canonicalization entry point).
        let eager = build(&reversed, dim);
        let dir = tempfile::tempdir().unwrap();
        eager.save(&dir.path().join("eager.hnsw")).unwrap();

        // Lazy: defer to the explicit API, from a DIFFERENT insert order.
        let lazy = build(&sorted, dim);
        lazy.ensure_canonical_order().unwrap();

        for (qi, q) in queries.iter().enumerate() {
            assert_eq!(
                knn(&eager, q),
                knn(&lazy, q),
                "lazy explicit canonicalization diverged from eager save-path canonicalization on query {qi}"
            );
        }

        // The canonical node ordering itself is a deterministic function of the key
        // set — identical idx_to_id sequence regardless of insert order.
        let canonical_keys =
            |idx: &VectorIndex<u64>| -> Vec<u64> { idx.graph.read().idx_to_id.clone() };
        assert_eq!(
            canonical_keys(&eager),
            canonical_keys(&lazy),
            "canonical node order is not insert-order independent"
        );

        // Idempotent: re-canonicalizing a clean graph changes nothing.
        let before = canonical_keys(&lazy);
        lazy.ensure_canonical_order().unwrap();
        assert_eq!(
            before,
            canonical_keys(&lazy),
            "re-canonicalizing a clean graph mutated it"
        );
        for (qi, q) in queries.iter().enumerate() {
            assert_eq!(
                knn(&eager, q),
                knn(&lazy, q),
                "second canonicalization perturbed query {qi}"
            );
        }
    }

    fn batch_test_vec(i: u64, dim: usize) -> Vec<f32> {
        (0..dim)
            .map(|d| {
                let x = (i.wrapping_mul(2654435761).wrapping_add(d as u64 * 40503) % 1000) as f32;
                ((x / 1000.0) * std::f32::consts::TAU).sin()
                    + ((i as f32) * 0.013 * (d as f32 + 1.0)).cos()
            })
            .collect()
    }

    type BatchFingerprint = (Vec<u64>, Option<u64>, Vec<(usize, Vec<Vec<usize>>)>);

    fn batch_fingerprint(idx: &VectorIndex<u64>) -> BatchFingerprint {
        let g = idx.graph.read();
        let entry = g.entry_point.map(|ep| g.idx_to_id[ep]);
        let nodes = g
            .nodes
            .iter()
            .map(|node| (node.level, node.connections.clone()))
            .collect();
        (g.idx_to_id.clone(), entry, nodes)
    }

    fn batch_knn(idx: &VectorIndex<u64>, q: &[f32], limit: usize) -> Vec<(u64, u32)> {
        idx.search_similar(q, limit)
            .unwrap()
            .into_iter()
            .map(|(id, d)| (id, d.to_bits()))
            .collect()
    }

    /// The parallel batch build is a throughput path, not a result path: once the
    /// graph is canonicalized at the search/save boundary, a parallel
    /// `upsert_batch` and the equivalent sequence of serial single upserts must
    /// produce the byte-identical authoritative topology AND identical kNN. This is
    /// the determinism guarantee the citable proof depends on — parallel-built
    /// index == serial-built index after canonicalization. `n` spans several
    /// doubling chunks so the real parallel planning path is exercised.
    #[test]
    fn upsert_batch_canonicalizes_identically_to_sequential() {
        let n: u64 = 1500;
        let dim = 32;
        let limit = 20;
        let items: Vec<(u64, Vec<f32>)> = (0..n).map(|k| (k, batch_test_vec(k, dim))).collect();
        let queries: Vec<Vec<f32>> = (0..8).map(|q| batch_test_vec(90_000 + q, dim)).collect();

        let batched = VectorIndex::<u64>::new(dim).unwrap();
        batched.upsert_batch(items.clone()).unwrap();

        let sequential = VectorIndex::<u64>::new(dim).unwrap();
        for (k, v) in &items {
            sequential.upsert(*k, v).unwrap();
        }

        assert_eq!(batched.len(), sequential.len());

        // Pre-canonicalization the parallel intermediate is intentionally a
        // different (approximate) topology, but it must still be a valid, populated
        // search index.
        for q in &queries {
            assert_eq!(
                batch_knn(&batched, q, limit).len(),
                limit,
                "parallel batch intermediate is not searchable"
            );
        }

        // After the canonicalization boundary that save/search use, parallel batch
        // and serial single upserts collapse to the identical authoritative graph.
        batched.ensure_canonical_order().unwrap();
        sequential.ensure_canonical_order().unwrap();
        assert_eq!(
            batch_fingerprint(&batched),
            batch_fingerprint(&sequential),
            "parallel batch and serial upserts diverged after canonicalization"
        );
        for (qi, q) in queries.iter().enumerate() {
            assert_eq!(
                batch_knn(&batched, q, limit),
                batch_knn(&sequential, q, limit),
                "parallel batch vs serial kNN diverged (post-canonicalization) on query {qi}"
            );
        }
    }

    /// The parallel batch's intermediate graph is a pure function of the key set:
    /// it is byte-identical regardless of caller input order (the commit order is
    /// canonical and planning is order-independent) and stable across repeated
    /// runs despite the parallelism. This is what makes the parallelism safe — no
    /// thread-interleaving or caller-order signal leaks into the topology.
    #[test]
    fn parallel_batch_build_is_order_and_run_independent() {
        let n: u64 = 1200;
        let dim = 24;
        let limit = 15;
        let forward: Vec<(u64, Vec<f32>)> = (0..n).map(|k| (k, batch_test_vec(k, dim))).collect();
        let mut shuffled = forward.clone();
        // Deterministic shuffle (no RNG): swap symmetric pairs.
        let len = shuffled.len();
        for i in 0..len / 2 {
            shuffled.swap(i, len - 1 - i);
        }

        let a = VectorIndex::<u64>::new(dim).unwrap();
        a.upsert_batch(forward.clone()).unwrap();
        let b = VectorIndex::<u64>::new(dim).unwrap();
        b.upsert_batch(shuffled).unwrap();
        let c = VectorIndex::<u64>::new(dim).unwrap();
        c.upsert_batch(forward).unwrap();

        // Caller order independent AND run-to-run stable, even before canonicalization.
        assert_eq!(
            batch_fingerprint(&a),
            batch_fingerprint(&b),
            "parallel batch intermediate depended on caller input order"
        );
        assert_eq!(
            batch_fingerprint(&a),
            batch_fingerprint(&c),
            "parallel batch intermediate varied across identical runs"
        );

        for q in 0..8u64 {
            let query = batch_test_vec(120_000 + q, dim);
            assert_eq!(batch_knn(&a, &query, limit), batch_knn(&b, &query, limit));
            assert_eq!(batch_knn(&a, &query, limit), batch_knn(&c, &query, limit));
        }
    }

    /// Dimension mismatches inside a batch are rejected, mirroring single upsert.
    #[test]
    fn upsert_batch_rejects_dimension_mismatch() {
        let idx = VectorIndex::<u64>::new(4).unwrap();
        let result = idx.upsert_batch(vec![
            (1u64, vec![1.0, 0.0, 0.0, 0.0]),
            (2u64, vec![1.0, 0.0]),
        ]);
        assert!(result.is_err());
    }

    /// The key-hash level source must reproduce the HNSW geometric level
    /// distribution the old RNG produced: `P(level >= k) = M^-k`. A wrong skew is
    /// an HNSW performance cliff, so this pins it empirically over a large key
    /// sample.
    #[test]
    fn level_distribution_matches_geometric() {
        let n = 200_000u64;
        let mut ge1 = 0u64;
        let mut ge2 = 0u64;
        let mut ge3 = 0u64;
        for k in 0..n {
            let level = hnsw_level_for_key(&k);
            if level >= 1 {
                ge1 += 1;
            }
            if level >= 2 {
                ge2 += 1;
            }
            if level >= 3 {
                ge3 += 1;
            }
        }
        let f1 = ge1 as f64 / n as f64;
        let f2 = ge2 as f64 / n as f64;
        let f3 = ge3 as f64 / n as f64;
        // M = 16 → expected 1/16, 1/256, 1/4096.
        assert!(
            (f1 - 1.0 / 16.0).abs() < 0.006,
            "P(level>=1)={f1}, expected ~{}",
            1.0 / 16.0
        );
        assert!(
            (f2 - 1.0 / 256.0).abs() < 0.0025,
            "P(level>=2)={f2}, expected ~{}",
            1.0 / 256.0
        );
        assert!(
            (f3 - 1.0 / 4096.0).abs() < 0.0015,
            "P(level>=3)={f3}, expected ~{}",
            1.0 / 4096.0
        );
    }

    /// A node's HNSW level is whatever was persisted — `load` never recomputes it
    /// from the current key-hash formula. This proves indices built under the old
    /// RNG level scheme keep working without any migration step, and that the
    /// off-formula level survives a save/reload round-trip untouched.
    #[test]
    fn persisted_node_levels_survive_load_without_migration() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.hnsw");

        let k_hi = 7u64;
        let k_lo = 8u64;
        // A stored level the current key-hash formula would NOT assign to k_hi.
        let forced_hi_level = hnsw_level_for_key(&k_hi) + 3;
        assert_ne!(forced_hi_level, hnsw_level_for_key(&k_hi));

        let mut graph = HnswGraph::<u64>::new(2);
        graph.nodes = vec![
            HnswNode {
                vector: vec![0.0, 1.0],
                connections: vec![Vec::new(); forced_hi_level + 1],
                level: forced_hi_level,
            },
            HnswNode {
                vector: vec![1.0, 0.0],
                connections: vec![Vec::new()],
                level: 0,
            },
        ];
        graph.entry_point = Some(0);
        graph.max_level = forced_hi_level;
        graph.id_to_idx.insert(k_hi, 0);
        graph.id_to_idx.insert(k_lo, 1);
        graph.idx_to_id = vec![k_hi, k_lo];

        let vi = VectorIndex::<u64> {
            graph: RwLock::new(graph),
            persistence_path: RwLock::new(None),
        };
        vi.save(&path).unwrap();

        let loaded = VectorIndex::<u64>::load_from_disk(&path).unwrap();
        assert_eq!(loaded.graph.read().nodes[0].level, forced_hi_level);
        assert_ne!(forced_hi_level, hnsw_level_for_key(&k_hi));
        assert_eq!(loaded.len(), 2);
    }

    /// After a normal save/reload, fresh key-based-level inserts coexist with the
    /// loaded nodes and both remain searchable — the "mixed old/new indices load
    /// and work" guarantee, end to end.
    #[test]
    fn reload_then_insert_keeps_old_and_new_searchable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rt.hnsw");

        let mk = |i: u64| -> Vec<f32> {
            let f = i as f32;
            vec![
                (f * 0.13).sin(),
                (f * 0.07).cos(),
                (f * 0.29).sin(),
                (f * 0.17).cos(),
            ]
        };

        let idx = VectorIndex::<u64>::new(4).unwrap();
        for i in 0..40u64 {
            idx.upsert(i, &mk(i)).unwrap();
        }
        idx.save(&path).unwrap();

        let loaded = VectorIndex::<u64>::load_from_disk(&path).unwrap();
        for i in 40..50u64 {
            loaded.upsert(i, &mk(i)).unwrap();
        }
        assert_eq!(loaded.len(), 50);

        for probe in [5u64, 45u64] {
            let v = loaded.get(&probe).unwrap();
            let r = loaded.search_similar(&v, 1).unwrap();
            assert_eq!(r[0].0, probe, "probe {probe} not its own nearest neighbor");
        }
    }

    #[test]
    fn insert_ignores_neighbors_without_active_layer() {
        let low = DefaultId::new();
        let high = DefaultId::new();
        // Levels are key-derived now: pick a newcomer key that lands at level >= 1
        // so it has a layer-1 to (try to) connect at.
        let newcomer = default_id_with_level_at_least(1);
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

        graph.insert(newcomer, &[0.5]).unwrap();

        let newcomer_idx = graph.id_to_idx[&newcomer];
        assert!(graph.nodes[newcomer_idx].connections[1]
            .iter()
            .all(|&nb| nb != 0));
    }

    #[test]
    fn sort_scored_neighbors_handles_nan_distances() {
        // Finite distances sort before NaN (via total_cmp); ties among equal
        // (here NaN) distances break by the node's stable key hash, NOT by
        // internal index — so pruning order is independent of slot history.
        let mut graph = HnswGraph::<u64>::new(1);
        graph.idx_to_id = vec![10u64, 11u64, 12u64];

        let mut scored = vec![(f32::NAN, 2usize), (0.0, 1usize), (f32::NAN, 0usize)];
        graph.sort_scored_neighbors(&mut scored);

        // The single finite distance comes first.
        assert_eq!(scored[0], (0.0, 1));
        // The two NaN entries (idx 0 and 2) are ordered by key hash.
        let expected_second = if key_hash(&graph.idx_to_id[0]) <= key_hash(&graph.idx_to_id[2]) {
            0
        } else {
            2
        };
        assert_eq!(scored[1].1, expected_second);
        assert_eq!(
            scored[2].1,
            if expected_second == 0 { 2 } else { 0 },
            "both NaN entries must be present, ordered deterministically"
        );

        // Sorting a differently-ordered input yields the identical index order
        // (determinism). Compare by index, since NaN != NaN makes a direct
        // tuple-vec equality always false.
        let mut again = vec![(f32::NAN, 0usize), (0.0, 1usize), (f32::NAN, 2usize)];
        graph.sort_scored_neighbors(&mut again);
        let order_again: Vec<usize> = again.iter().map(|&(_, i)| i).collect();
        let order_scored: Vec<usize> = scored.iter().map(|&(_, i)| i).collect();
        assert_eq!(order_again, order_scored);
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

        let loaded = VectorIndex::<DefaultId>::load_from_disk(&path).unwrap();
        let results = loaded.search_similar(&[1.0, 0.0, 0.0, 0.0], 2).unwrap();

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, e1);
        assert_eq!(results[1].0, e3);
    }

    #[cfg(windows)]
    #[test]
    fn persistence_flushes_writable_windows_handles_before_promotion() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.hnsw");
        let tmp_path = recovery_tmp_path(&path);

        write_bytes_with_fsync(&tmp_path, b"durable vector candidate")
            .expect("FlushFileBuffers must receive a writable temporary-file handle");
        fsync_and_rename(&tmp_path, &path)
            .expect("the writable candidate must flush before atomic promotion");

        assert_eq!(fs::read(path).unwrap(), b"durable vector candidate");
    }

    #[cfg(windows)]
    #[test]
    fn persistence_flushes_windows_parent_directory_with_writable_handle() {
        let dir = tempfile::TempDir::new().unwrap();

        // This is the exact legacy barrier: File::open creates a read-only
        // handle and does not request directory semantics. It cannot provide a
        // Windows namespace durability guarantee.
        let legacy_barrier = File::open(dir.path()).and_then(|dir| dir.sync_all());
        assert!(
            legacy_barrier.is_err(),
            "the regression proof expects the legacy read-only directory barrier to fail"
        );

        sync_directory(dir.path()).expect(
            "the Windows directory barrier must use GENERIC_WRITE and FILE_FLAG_BACKUP_SEMANTICS",
        );

        let path = dir.path().join("vectors.hnsw");
        let tmp_path = recovery_tmp_path(&path);
        write_bytes_with_fsync(&tmp_path, b"durable namespace candidate").unwrap();
        fsync_and_rename(&tmp_path, &path)
            .expect("atomic promotion must propagate a successful parent-directory barrier");
    }

    #[test]
    fn persistence_directory_barrier_rejects_regular_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("not-a-directory");
        fs::write(&path, b"ordinary file").unwrap();

        let error = sync_directory(&path).unwrap_err();
        assert!(
            error.to_string().contains("not a directory"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn load_rejects_corrupted_main_index_after_save() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.hnsw");

        let idx = VectorIndex::new(4).unwrap();
        idx.upsert(DefaultId::new(), &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.save(&path).unwrap();

        fs::write(&path, b"corrupted hnsw index").unwrap();

        let error = VectorIndex::<DefaultId>::load_from_disk(&path).unwrap_err();
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

        let loaded = VectorIndex::<DefaultId>::load_from_disk(&path).unwrap();
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

        let loaded = VectorIndex::<DefaultId>::load_from_disk(&path).unwrap();
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

        let loaded = VectorIndex::<DefaultId>::load_from_disk(&path).unwrap();
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

        let error = VectorIndex::<DefaultId>::load_from_disk(&path).unwrap_err();
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

        let error = VectorIndex::<DefaultId>::load_from_disk(&path).unwrap_err();
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

        // The vectors repeat every 8 entities (i and i+8 share a vector), so
        // querying entities[0].1 has many exact (distance-0) matches. Search
        // quality means the nearest result is one of those exact matches — which
        // duplicate surfaces is now decided by a stable key hash, not by internal
        // index, so assert on the vector (distance ~0) rather than a specific id.
        let results = idx.search_similar(&entities[0].1, 5).unwrap();
        assert!(!results.is_empty());
        assert!(
            results[0].1 < 1e-6,
            "nearest result was not an exact-vector match: dist={}",
            results[0].1
        );
        let top_vec = idx.get(&results[0].0).unwrap();
        assert_eq!(top_vec, entities[0].1.to_vec());
    }

    #[test]
    fn cosine_distance_sanity() {
        assert!((cosine_distance(&[1.0, 0.0], &[1.0, 0.0]) - 0.0).abs() < 1e-6);
        assert!((cosine_distance(&[1.0, 0.0], &[0.0, 1.0]) - 1.0).abs() < 1e-6);
        assert!((cosine_distance(&[1.0, 0.0], &[-1.0, 0.0]) - 2.0).abs() < 1e-6);
    }

    /// The `KIN_VECTOR_SIMD` gate resolves default-ON now that the NEON kernel has
    /// graduated: an unset value — or any value that is not an explicit off token —
    /// takes the SIMD path, while `0`, `false`, `no`, or `off` keep the scalar
    /// reduction reachable for A/B. Mirrors kin-search's incremental-persist gate.
    /// Pinning the full truth table here guards against a silent re-flip of the
    /// default and documents the exact off-switch tokens. Pure resolution, so it
    /// never touches the once-per-process gate the running kernel samples.
    #[cfg(all(feature = "simd", target_arch = "aarch64"))]
    #[test]
    fn simd_gate_defaults_on_and_scalar_stays_reachable() {
        // Default ON: unset and any non-off token enable the NEON kernel.
        assert!(simd_enabled_from_env(None));
        assert!(simd_enabled_from_env(Some("")));
        assert!(simd_enabled_from_env(Some("1")));
        assert!(simd_enabled_from_env(Some("true")));
        assert!(simd_enabled_from_env(Some("TRUE")));
        assert!(simd_enabled_from_env(Some("yes")));
        assert!(simd_enabled_from_env(Some("on")));
        assert!(simd_enabled_from_env(Some("unexpected")));

        // Scalar reduction stays reachable via the explicit off tokens (A/B switch).
        assert!(!simd_enabled_from_env(Some("0")));
        assert!(!simd_enabled_from_env(Some("false")));
        assert!(!simd_enabled_from_env(Some("FALSE")));
        assert!(!simd_enabled_from_env(Some("no")));
        assert!(!simd_enabled_from_env(Some("off")));
        assert!(!simd_enabled_from_env(Some("  off  ")));
    }

    /// Determinism + delta characterization for the aarch64 NEON distance kernel.
    ///
    /// Asserts: (1) the NEON path is bit-stable across calls (its cross-run
    /// determinism — fixed lane layout + `vaddvq_f32` fold, no reassociation), and
    /// (2) it tracks the scalar kernel within a tight, documented bound (the two
    /// are NOT bit-identical — SIMD folds four lanes in a different summation order
    /// than the scalar sequential sum). Covers non-multiple-of-4 tails and the
    /// adversarial cases the kernel must not mishandle: identical vectors,
    /// opposite vectors, near-zero norms (degenerate denom → 1.0 short-circuit),
    /// denormals, and all-zeros.
    #[cfg(all(feature = "simd", target_arch = "aarch64"))]
    #[test]
    fn simd_neon_matches_scalar_and_is_deterministic() {
        // Deterministic pseudo-random vector — no RNG so the characterization is
        // itself reproducible across runs/machines.
        fn vec_for(seed: u64, dim: usize) -> Vec<f32> {
            (0..dim)
                .map(|d| {
                    let h = seed
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add((d as u64).wrapping_mul(1442695040888963407))
                        .wrapping_add(0x9E3779B97F4A7C15);
                    ((h >> 40) as f32 / (1u64 << 24) as f32 - 0.5) * 2.0
                })
                .collect()
        }
        // cosine_distance ∈ [0, 2] (always finite, non-negative), so the raw f32
        // bit pattern is monotonic with value → a plain bit-difference IS the ulp
        // distance. (No NaN/sign-zero edge cases reach here.)
        fn ulp_diff(a: f32, b: f32) -> i64 {
            (a.to_bits() as i64 - b.to_bits() as i64).abs()
        }

        let mut cases: Vec<(Vec<f32>, Vec<f32>)> = Vec::new();
        for &dim in &[1usize, 2, 3, 4, 7, 8, 31, 48, 127, 768] {
            cases.push((
                vec_for(dim as u64 * 2, dim),
                vec_for(dim as u64 * 2 + 1, dim),
            ));
            let v = vec_for(99 + dim as u64, dim);
            cases.push((v.clone(), v.clone())); // identical → ~0
            let v = vec_for(7 + dim as u64, dim);
            let neg: Vec<f32> = v.iter().map(|x| -x).collect();
            cases.push((v, neg)); // opposite → ~2
            cases.push((vec![1e-30f32; dim], vec![1e-30f32; dim])); // near-zero norm
            cases.push((vec![f32::from_bits(1); dim], vec![f32::from_bits(3); dim])); // denormals
            cases.push((vec![0.0f32; dim], vec![0.0f32; dim])); // all zeros
        }

        let mut max_abs = 0.0f32;
        let mut max_ulp = 0i64;
        for (a, b) in &cases {
            let s = cosine_distance_scalar(a, b);
            let n1 = unsafe { cosine_distance_neon(a, b) };
            let n2 = unsafe { cosine_distance_neon(a, b) };
            assert_eq!(
                n1.to_bits(),
                n2.to_bits(),
                "NEON kernel is not deterministic (dim {})",
                a.len()
            );
            assert!(s.is_finite() && n1.is_finite(), "non-finite distance");
            assert!(
                (0.0..=2.0).contains(&n1),
                "NEON distance out of range: {n1}"
            );
            max_abs = max_abs.max((s - n1).abs());
            max_ulp = max_ulp.max(ulp_diff(s, n1));
        }
        eprintln!(
            "[simd-delta] NEON vs scalar over {} cases: max_abs={max_abs:.3e} max_ulp={max_ulp}",
            cases.len()
        );
        // Documented ceiling. OBSERVED on Apple Silicon over these 60 cases:
        // max_abs ≈ 2.4e-7, max_ulp = 2 — i.e. the NEON result differs from the
        // scalar result by at most two ulps, purely from folding four lanes
        // instead of summing sequentially. The 1e-4 bound is generous vs that yet
        // tight enough that a deliberate FMA/reassociation change (which would
        // grow the delta by orders of magnitude) trips the test. Re-record the
        // printed value if the kernel's reduction structure is changed on purpose.
        assert!(
            max_abs < 1e-4,
            "NEON delta vs scalar exceeds documented bound: max_abs={max_abs:.3e} (max_ulp={max_ulp})"
        );
    }

    /// Characterizes how the SIMD default ranks neighbors relative to the scalar
    /// reduction. The two kernels differ by a bounded sub-ulp epsilon (see the test
    /// above), so the NEON order is NOT guaranteed bit-identical to scalar: it can
    /// transpose candidates whose true distances fall within that epsilon. This
    /// pins the two properties that keep that safe and deterministic:
    ///   (1) the NEON ranking is reproducible across repeated computation — a pure
    ///       function of the vectors, exactly like the scalar ranking; and
    ///   (2) any disagreement with the scalar order is a near-tie transposition
    ///       only: wherever the NEON order inverts the scalar distance order, the
    ///       inversion magnitude is below a tight epsilon, so the SIMD default never
    ///       coarsely reorders the result set — only swaps effectively-equidistant
    ///       neighbors.
    /// A regression that grows the kernel delta (e.g. an accidental FMA or
    /// reassociation) would push an inversion past the epsilon and trip this.
    #[cfg(all(feature = "simd", target_arch = "aarch64"))]
    #[test]
    fn simd_ranking_only_transposes_near_ties_vs_scalar() {
        fn vec_for(seed: u64, dim: usize) -> Vec<f32> {
            (0..dim)
                .map(|d| {
                    let h = seed
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add((d as u64).wrapping_mul(1442695040888963407))
                        .wrapping_add(0x9E3779B97F4A7C15);
                    ((h >> 40) as f32 / (1u64 << 24) as f32 - 0.5) * 2.0
                })
                .collect()
        }

        let dim = 768;
        let candidates: Vec<(u64, Vec<f32>)> = (0..256u64).map(|k| (k, vec_for(k, dim))).collect();

        // Rank by a distance fn using the SAME (distance, key_hash) order the index
        // applies, returning ranked (id, distance) pairs.
        let rank = |q: &[f32], dist: &dyn Fn(&[f32], &[f32]) -> f32| -> Vec<(u64, f32)> {
            let mut scored: Vec<(f32, u64)> =
                candidates.iter().map(|(k, v)| (dist(q, v), *k)).collect();
            scored.sort_by(|a, b| {
                a.0.total_cmp(&b.0)
                    .then_with(|| key_hash(&a.1).cmp(&key_hash(&b.1)))
            });
            scored.into_iter().map(|(d, k)| (k, d)).collect()
        };

        let mut max_inversion = 0.0f32;
        for qi in 0..16u64 {
            let q = vec_for(900_000 + qi, dim);

            // (1) NEON ranking is reproducible across calls.
            let neon = rank(&q, &|a, b| unsafe { cosine_distance_neon(a, b) });
            let neon_again = rank(&q, &|a, b| unsafe { cosine_distance_neon(a, b) });
            let neon_ids: Vec<u64> = neon.iter().map(|(k, _)| *k).collect();
            let neon_ids_again: Vec<u64> = neon_again.iter().map(|(k, _)| *k).collect();
            assert_eq!(
                neon_ids, neon_ids_again,
                "NEON ranking is not reproducible for query {qi}"
            );

            // (2) Any inversion of the scalar distance order under the NEON order is
            // a near-tie only.
            let scalar = rank(&q, &|a, b| cosine_distance_scalar(a, b));
            let scalar_dist: std::collections::HashMap<u64, f32> = scalar.iter().copied().collect();
            for pair in neon.windows(2) {
                let d_here = scalar_dist[&pair[0].0];
                let d_next = scalar_dist[&pair[1].0];
                if d_here > d_next {
                    let inversion = d_here - d_next;
                    max_inversion = max_inversion.max(inversion);
                    assert!(
                        inversion < 1e-5,
                        "query {qi}: NEON order inverts scalar distances by {inversion:.3e} \
                         (exceeds near-tie epsilon) — kernel delta has grown"
                    );
                }
            }
        }
        eprintln!(
            "[simd-rank] max scalar-distance inversion under NEON order: {max_inversion:.3e}"
        );
    }

    /// CPU-efficiency measurement for KIN_VECTOR_SIMD: wall-clock ns/op for the
    /// scalar vs NEON cosine-distance kernel over a fixed, deterministic workload,
    /// and the speedup ratio. This is the perf half of the graduation evidence —
    /// the correctness half is `simd_neon_matches_scalar_and_is_deterministic`,
    /// `simd_ranking_only_transposes_near_ties_vs_scalar`, and the query-path
    /// parity binary.
    ///
    /// #[ignore]'d on purpose: it is BUILT with the suite but never run as part of
    /// it, because a fair timing number requires a quiet machine (no concurrent
    /// GPU / other perf lanes) — a number taken under contention is meaningless.
    /// Schedule it deliberately in a quiet window with:
    ///
    ///   cargo test -p kin-vector --release --features simd \
    ///     simd_vs_scalar_cpu_efficiency_measurement -- --ignored --nocapture
    ///
    /// It reports numbers and never asserts a speedup threshold: the default-flip
    /// decision is made on the measured value, not gated inside the test.
    #[cfg(all(feature = "simd", target_arch = "aarch64"))]
    #[test]
    #[ignore = "CPU-efficiency measurement; run only in a quiet window (no GPU/other perf lanes) — timing is contaminated otherwise"]
    fn simd_vs_scalar_cpu_efficiency_measurement() {
        use std::hint::black_box;
        use std::time::Instant;

        fn env_usize(key: &str, default: usize) -> usize {
            std::env::var(key)
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(default)
        }
        // Deterministic pseudo-random vector, matching the parity tests' generator
        // so the timed workload is reproducible across machines and runs.
        fn vec_for(seed: u64, dim: usize) -> Vec<f32> {
            (0..dim)
                .map(|d| {
                    let h = seed
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add((d as u64).wrapping_mul(1442695040888963407))
                        .wrapping_add(0x9E3779B97F4A7C15);
                    ((h >> 40) as f32 / (1u64 << 24) as f32 - 0.5) * 2.0
                })
                .collect()
        }

        let dim = env_usize("KIN_VECTOR_BENCH_DIM", 768);
        let n_vectors = env_usize("KIN_VECTOR_BENCH_VECTORS", 1024);
        let iters = env_usize("KIN_VECTOR_BENCH_ITERS", 200).max(1);

        let corpus: Vec<Vec<f32>> = (0..n_vectors as u64).map(|k| vec_for(k, dim)).collect();
        let query = vec_for(0x00C0_FFEE, dim);

        // Warm both paths so caches and CPU state are settled before timing.
        let mut warm = 0.0f32;
        for v in &corpus {
            warm += cosine_distance_scalar(&query, v);
            warm += unsafe { cosine_distance_neon(&query, v) };
        }
        black_box(warm);

        let time = |f: &dyn Fn(&[f32], &[f32]) -> f32| -> f64 {
            let start = Instant::now();
            let mut acc = 0.0f32;
            for _ in 0..iters {
                for v in &corpus {
                    acc += f(black_box(&query), black_box(v.as_slice()));
                }
            }
            black_box(acc);
            start.elapsed().as_secs_f64()
        };

        let ops = (iters * n_vectors) as f64;
        let scalar_s = time(&|a, b| cosine_distance_scalar(a, b));
        let neon_s = time(&|a, b| unsafe { cosine_distance_neon(a, b) });
        let scalar_ns = scalar_s / ops * 1e9;
        let neon_ns = neon_s / ops * 1e9;
        let speedup = scalar_ns / neon_ns;

        println!(
            "[simd-cpu] KIN_VECTOR_SIMD cosine_distance dim={dim} vectors={n_vectors} iters={iters} \
             ops={ops:.0} | scalar={scalar_ns:.2} ns/op neon={neon_ns:.2} ns/op speedup={speedup:.2}x"
        );
        // Measurement, not a gate: guard only against a degenerate/zero reading.
        assert!(
            scalar_ns > 0.0 && neon_ns > 0.0,
            "degenerate timing (scalar={scalar_ns} neon={neon_ns})"
        );
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
    #[allow(deprecated)]
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

    /// `reserved_legacy_slot` is written to disk but must have no influence on
    /// anything. Two snapshots differing ONLY in that slot must produce different
    /// bytes (so the slot is genuinely part of the persisted format, and this
    /// test is not vacuous) and yet identical topology and identical search
    /// results after load (so the slot is genuinely never read).
    ///
    /// This is what makes the no-pseudorandom-generator property checkable
    /// rather than merely asserted: layer assignment, tie-breaking, and
    /// entry-point selection derive from stable key digests, so a persisted u64
    /// named or shaped like generator state can be proven inert.
    #[test]
    fn reserved_legacy_slot_is_persisted_but_never_read() {
        let dim = 24;
        let n: u64 = 400;
        let idx = VectorIndex::<u64>::new(dim).unwrap();
        idx.upsert_batch((0..n).map(|k| (k, batch_test_vec(k, dim))).collect())
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("idx.hnsw");
        idx.save(&path).unwrap();
        let base = std::fs::read(&path).unwrap();

        let reserialize = |slot: u64| -> Vec<u8> {
            let mut graph = try_load_snapshot::<u64>(&base).unwrap();
            graph.reserved_legacy_slot = slot;
            rmp_serde::to_vec(&HnswSnapshot {
                format_version: HNSW_FORMAT_VERSION,
                graph,
            })
            .unwrap()
        };

        let lo = reserialize(0);
        let hi = reserialize(u64::MAX);

        // Persisted: the slot reaches the serialized bytes. Without this the rest
        // of the test would prove nothing.
        assert_ne!(
            lo, hi,
            "the reserved slot must actually be persisted for this test to mean anything"
        );

        let g_lo = try_load_snapshot::<u64>(&lo).unwrap();
        let g_hi = try_load_snapshot::<u64>(&hi).unwrap();
        assert_eq!(g_lo.reserved_legacy_slot, 0);
        assert_eq!(g_hi.reserved_legacy_slot, u64::MAX);

        // Never read: identical topology despite the maximally different slot.
        assert_eq!(g_lo.entry_point, g_hi.entry_point, "entry point");
        assert_eq!(g_lo.max_level, g_hi.max_level, "max level");
        assert_eq!(g_lo.idx_to_id, g_hi.idx_to_id, "index to id mapping");
        assert_eq!(g_lo.free_list, g_hi.free_list, "free list");
        assert_eq!(g_lo.nodes.len(), g_hi.nodes.len(), "node count");
        for (i, (a, b)) in g_lo.nodes.iter().zip(g_hi.nodes.iter()).enumerate() {
            assert_eq!(a.level, b.level, "node {i} level");
            assert_eq!(a.connections, b.connections, "node {i} connections");
        }

        // Never read: identical search behavior.
        for q in 0..32u64 {
            let query = batch_test_vec(q.wrapping_mul(7).wrapping_add(3), dim);
            assert_eq!(
                g_lo.search(&query, 10, None),
                g_hi.search(&query, 10, None),
                "search diverged for query {q} on the reserved slot value alone"
            );
        }
    }

    /// Establishes, rather than assumes, that deleting `reserved_legacy_slot`
    /// outright would be an on-disk format break.
    ///
    /// `save` serializes with `rmp_serde::to_vec`, which encodes a struct as a
    /// positional array with no field names in the bytes. Removing the slot
    /// would therefore shift `descriptor` from position 8 into position 7, where
    /// a loader still expects a u64. This test builds a real index with today's
    /// `save`, then reads those exact bytes with the field layout a
    /// slot-less build would have, and pins that it fails.
    #[test]
    fn dropping_the_reserved_legacy_slot_would_break_the_persisted_format() {
        let dim = 8;
        let idx = VectorIndex::<u64>::new(dim).unwrap();
        idx.upsert_batch((0..16u64).map(|k| (k, batch_test_vec(k, dim))).collect())
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("idx.hnsw");
        idx.save(&path).unwrap();
        let persisted = std::fs::read(&path).unwrap();

        // Control: today's loader reads a today-written index.
        try_load_snapshot::<u64>(&persisted)
            .expect("the current loader must read a currently-written index");

        // The layout a build with the slot deleted would have: identical field
        // order, minus the slot.
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct SlotlessGraph {
            nodes: Vec<HnswNode>,
            entry_point: Option<usize>,
            max_level: usize,
            dimensions: usize,
            id_to_idx: HashMap<u64, usize>,
            idx_to_id: Vec<u64>,
            free_list: Vec<usize>,
            #[serde(default)]
            descriptor: IndexDescriptor,
        }
        #[derive(Deserialize)]
        #[allow(dead_code)]
        struct SlotlessSnapshot {
            format_version: u8,
            graph: SlotlessGraph,
        }

        assert!(
            rmp_serde::from_slice::<SlotlessSnapshot>(&persisted).is_err(),
            "an index persisted with the reserved slot must NOT be readable by a \
             layout that dropped it; if this ever passes, the positional-layout \
             rationale documented on the field is wrong and the field could be \
             deleted outright"
        );
    }

    /// Citable-bar guarantee (strict byte-determinism of the persisted index):
    /// the SERIALIZED bytes of `save` must be identical across repeated parallel
    /// batch builds of the same input/config, and independent of caller input
    /// order. The existing fingerprint tests pin the in-memory topology; this pins
    /// the persisted bytes the parity proof actually compares, catching any
    /// non-canonical serialization (e.g. a `HashMap`'s iteration order) the
    /// topology fingerprint cannot see. `n` spans several doubling chunks so the
    /// real parallel planning path runs.
    #[test]
    fn saved_index_bytes_are_identical_across_repeated_parallel_builds() {
        let n: u64 = 800;
        let dim = 24;
        let forward: Vec<(u64, Vec<f32>)> = (0..n).map(|k| (k, batch_test_vec(k, dim))).collect();

        let build_and_save_bytes = |items: Vec<(u64, Vec<f32>)>| -> Vec<u8> {
            let idx = VectorIndex::<u64>::new(dim).unwrap();
            idx.upsert_batch(items).unwrap();
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("idx.hnsw");
            idx.save(&path).unwrap();
            std::fs::read(&path).unwrap()
        };

        let reference = build_and_save_bytes(forward.clone());

        // Repeated identical-input parallel builds must serialize byte-identically.
        for rep in 0..12 {
            assert_eq!(
                build_and_save_bytes(forward.clone()),
                reference,
                "saved index bytes diverged on identical-input parallel build rep {rep}"
            );
        }

        // Caller input order must not change the saved bytes either.
        let mut shuffled = forward.clone();
        let len = shuffled.len();
        for i in 0..len / 2 {
            shuffled.swap(i, len - 1 - i);
        }
        assert_eq!(
            build_and_save_bytes(shuffled),
            reference,
            "saved index bytes depended on caller input order"
        );
    }

    /// Recall metric: for each query, compute the true k-NN by brute force over
    /// `candidates`, then measure what fraction the ANN result captures.
    fn recall_at_k(
        idx: &VectorIndex<u64>,
        queries: &[(u64, Vec<f32>)],
        candidates: &[(u64, Vec<f32>)],
        k: usize,
    ) -> f32 {
        let mut total = 0usize;
        let mut hits = 0usize;
        for (qid, qvec) in queries {
            let ann: std::collections::HashSet<u64> = idx
                .search_similar(qvec, k)
                .unwrap()
                .into_iter()
                .map(|(id, _)| id)
                .collect();
            let mut dists: Vec<(u64, f32)> = candidates
                .iter()
                .filter(|(id, _)| *id != *qid)
                .map(|(id, v)| {
                    let d: f32 = v.iter().zip(qvec).map(|(a, b)| (a - b) * (a - b)).sum();
                    (*id, d)
                })
                .collect();
            dists.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
            dists.truncate(k);
            hits += dists.iter().filter(|(id, _)| ann.contains(id)).count();
            total += dists.len();
        }
        if total == 0 {
            1.0
        } else {
            hits as f32 / total as f32
        }
    }

    /// compact() rebuilds the HNSW graph from live nodes only, restoring
    /// cross-cluster connectivity that soft-deletes fragment.
    ///
    /// After a 50% bulk delete:
    ///   - deleted_fraction() reflects the pending deletes
    ///   - compact() must not degrade recall vs the post-delete baseline
    ///   - after compact(), deleted_fraction() is 0.0
    #[test]
    fn compact_restores_recall_after_bulk_deletes() {
        let n: u64 = 300;
        let dim = 16;
        let k = 10;
        let vectors: Vec<(u64, Vec<f32>)> = (0..n).map(|i| (i, batch_test_vec(i, dim))).collect();

        let idx = VectorIndex::<u64>::new(dim).unwrap();
        idx.upsert_batch(vectors.clone()).unwrap();

        // The odd-indexed vectors are our query / survivor set.
        let survivors: Vec<(u64, Vec<f32>)> = vectors
            .iter()
            .filter(|(id, _)| id % 2 == 1)
            .cloned()
            .collect();

        // Sanity: baseline recall with the full index is reasonable.
        let baseline = recall_at_k(&idx, &survivors, &vectors, k);
        assert!(
            baseline > 0.7,
            "baseline recall {baseline:.3} unexpectedly low before any deletion"
        );

        // Delete all even-indexed vectors (≈50 % of the index).
        for (id, _) in vectors.iter().filter(|(id, _)| id % 2 == 0) {
            idx.remove(id).unwrap();
        }

        let frac = idx.deleted_fraction();
        assert!(
            frac > 0.4 && frac < 0.6,
            "expected ~50 % deleted slots, got {frac:.3}"
        );

        // Recall over surviving vectors against the surviving candidate set.
        let recall_pre = recall_at_k(&idx, &survivors, &survivors, k);

        // compact() rebuilds from live nodes, clearing the free-list.
        idx.compact().unwrap();
        assert_eq!(
            idx.deleted_fraction(),
            0.0,
            "after compact, free_list must be empty"
        );
        assert_eq!(
            idx.len(),
            survivors.len(),
            "live count unchanged by compact"
        );

        let recall_post = recall_at_k(&idx, &survivors, &survivors, k);
        assert!(
            recall_post >= recall_pre,
            "compact must not degrade recall: pre={recall_pre:.3} post={recall_post:.3}"
        );
        assert!(
            recall_post > 0.6,
            "post-compact recall {recall_post:.3} should be reasonable"
        );
    }
}
