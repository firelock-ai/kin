// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC
//
// Requirement (3) of the SIMD distance lane: run the HNSW determinism conviction
// UNDER the SIMD distance path. Compiled only with `--features simd` on aarch64.
//
// This is a separate test binary so the `KIN_VECTOR_SIMD` env gate (sampled once
// per process via OnceLock in the lib) is set cleanly before the first distance
// call — no interleaving with the default-path unit tests. It mirrors the
// in-crate conviction `interleaved_reembed_history_does_not_change_results`, but
// over the public API and with the NEON kernel active, proving the SIMD distance
// keeps kNN bit-stable across rebuilds and in-place re-embeds.

#![cfg(all(feature = "simd", target_arch = "aarch64"))]

use kin_vector::VectorIndex;

fn vec_for(i: u64, dim: usize) -> Vec<f32> {
    (0..dim)
        .map(|d| {
            let x = (i.wrapping_mul(2654435761).wrapping_add(d as u64 * 40503) % 1000) as f32;
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

fn knn_ids(idx: &VectorIndex<u64>, q: &[f32], limit: usize) -> Vec<u64> {
    idx.search_similar(q, limit)
        .unwrap()
        .into_iter()
        .map(|(id, _)| id)
        .collect()
}

#[test]
fn hnsw_determinism_holds_under_simd_distance() {
    // Force the NEON distance kernel for this process BEFORE any distance call.
    std::env::set_var("KIN_VECTOR_SIMD", "1");

    let n: u64 = 400;
    let dim = 48;
    let order: Vec<u64> = (0..n).collect();
    let queries: Vec<Vec<f32>> = (0..8).map(|q| vec_for(10_000 + q, dim)).collect();
    let limit = 20;

    // (a) Same insert order, two independent builds → identical kNN. This is the
    // baseline reproducibility the frozen protocol relies on; it must hold with
    // the SIMD distance exactly as it does with scalar.
    let a = build(&order, dim);
    let b = build(&order, dim);
    assert_eq!(a.len(), b.len());
    for (qi, q) in queries.iter().enumerate() {
        assert_eq!(
            knn_ids(&a, q, limit),
            knn_ids(&b, q, limit),
            "SIMD distance: same-order rebuild diverged on query {qi}"
        );
    }

    // (b) Re-embed the same keys IN PLACE (same order) a varying number of times,
    // mirroring the in-crate conviction test — must not change results under SIMD.
    let c = VectorIndex::<u64>::new(dim).unwrap();
    for (step, &k) in order.iter().enumerate() {
        c.upsert(k, &vec_for(k, dim)).unwrap();
        if step % 5 == 0 {
            for _ in 0..(1 + step % 3) {
                c.remove(&k).unwrap();
                c.upsert(k, &vec_for(k, dim)).unwrap();
            }
        }
    }
    assert_eq!(a.len(), c.len());
    for (qi, q) in queries.iter().enumerate() {
        assert_eq!(
            knn_ids(&a, q, limit),
            knn_ids(&c, q, limit),
            "SIMD distance: in-place re-embed changed results on query {qi}"
        );
    }

    // (c) Search itself is bit-stable across repeated calls under the SIMD kernel.
    for q in &queries {
        let first = knn_ids(&a, q, limit);
        for _ in 0..4 {
            assert_eq!(first, knn_ids(&a, q, limit), "SIMD search not repeatable");
        }
    }
}
