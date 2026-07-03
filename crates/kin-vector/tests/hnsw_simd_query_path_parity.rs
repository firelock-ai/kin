// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC
//
// Graduation evidence for KIN_VECTOR_SIMD: the real HNSW query path
// (`VectorIndex::search_similar`) returns the correct nearest-neighbor SET under
// the NEON distance kernel. A separate binary so the once-per-process
// `KIN_VECTOR_SIMD` gate (OnceLock in the lib) is set before the first distance
// call — the same isolation `hnsw_determinism_simd.rs` uses.
//
// Kernel-level scalar/NEON parity (the ~2-ulp delta) and its near-tie ranking
// bound are already pinned by the in-crate `simd_*` unit tests. Those tests show
// the only place the delta can legitimately reorder neighbors is a near-tie. So
// this corpus is built as well-separated orthogonal clusters: every query's true
// neighbors sit at ~0 cosine distance and every non-neighbor at ~1, with no
// near-tie boundary. That makes "the SIMD query path returns the scalar-correct
// neighbors" a hard set-equality assertion end-to-end, not a recall threshold.

#![cfg(all(feature = "simd", target_arch = "aarch64"))]

use std::collections::BTreeSet;

use kin_vector::VectorIndex;

/// Pure cluster center: the basis direction for cluster `c`.
fn center(dim: usize, c: usize) -> Vec<f32> {
    let mut v = vec![0.0f32; dim];
    v[c % dim] = 1.0;
    v
}

/// Member `m` of cluster `c`: the center plus a tiny deterministic jitter on a
/// rotating auxiliary dimension. Cosine distance is scale-invariant and the
/// dominant component stays on dimension `c`, so every member is ~0 cosine
/// distance from its own center and ~1 from every other cluster's center.
fn member(dim: usize, c: usize, m: usize) -> Vec<f32> {
    let mut v = center(dim, c);
    let aux = (c * 7 + m * 3 + 1) % dim;
    if aux != c % dim {
        v[aux] = 0.01 * (m as f32 + 1.0);
    }
    v
}

#[test]
fn simd_query_path_returns_correct_neighbor_set() {
    // Force the NEON kernel for this whole process, before any distance call.
    std::env::set_var("KIN_VECTOR_SIMD", "1");

    let dim = 64usize;
    let clusters = 12usize;
    let per_cluster = 8usize;

    let idx = VectorIndex::<u64>::new(dim).unwrap();
    for c in 0..clusters {
        for m in 0..per_cluster {
            let id = (c * 100 + m) as u64;
            idx.upsert(id, &member(dim, c, m)).unwrap();
        }
    }
    assert_eq!(idx.len(), clusters * per_cluster);

    for c in 0..clusters {
        let query = center(dim, c);

        let hits = idx.search_similar(&query, per_cluster).unwrap();
        let got: BTreeSet<u64> = hits.iter().map(|(id, _)| *id).collect();
        let want: BTreeSet<u64> = (0..per_cluster).map(|m| (c * 100 + m) as u64).collect();
        assert_eq!(
            got, want,
            "SIMD query path returned the wrong neighbor set for cluster {c}: got {got:?}, want {want:?}"
        );

        // The real query path is deterministic under the NEON kernel: an
        // identical repeat query returns the identical ordered result.
        let hits_again = idx.search_similar(&query, per_cluster).unwrap();
        assert_eq!(
            hits, hits_again,
            "SIMD query path is not deterministic for cluster {c}"
        );
    }

    println!(
        "[simd-query-path] KIN_VECTOR_SIMD: PASS — {clusters} clusters x {per_cluster} pts, \
         exact neighbor-set match under the NEON kernel on all {clusters} search_similar queries"
    );
}
