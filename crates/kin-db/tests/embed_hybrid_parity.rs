// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Runtime proof that the throughput-profile hybrid split is value- and
//! order-preserving.
//!
//! Under `KIN_RESOURCE_PROFILE=throughput` the embedder splits each batch across
//! a GPU arm and a concurrent CPU twin (`balanced_partition` →
//! `dispatch_concurrent`'s `rayon::join`). The split must be transparent: every
//! entity's embedding must be identical (within fp tolerance) to the embedding it
//! gets from the plain, single-arm path, and results must come back in input
//! order regardless of which arm produced each one.
//!
//! On a CPU build (the default test surface) both arms run the same SIMD forward,
//! so the two paths must match essentially bit-for-bit — any divergence means the
//! split corrupted data or scrambled the result order. (Cross-backend GPU-vs-CPU
//! fp parity is measured separately on real Metal hardware; this test pins the
//! dispatch/scatter machinery that the GPU path also relies on.)

use kin_db::CodeEmbedder;

/// A batch of distinct short entities. The Balanced split routes a `ratio /
/// (ratio + 1)` majority to the GPU arm and the remainder to the CPU twin, so
/// even with no long entities both arms run concurrently and the scatter has to
/// re-interleave their results into input order. Kept short so the forwards stay
/// cheap in an unoptimized test build.
fn sample_batch() -> Vec<String> {
    (0..24)
        .map(|i| format!("fn entity_{i}(a: i32, b: i32) -> i32 {{ a * {i} + b - {i} }}"))
        .collect()
}

fn cosine(a: &[f32], b: &[f32]) -> f32 {
    let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    let na: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let nb: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if na == 0.0 || nb == 0.0 {
        0.0
    } else {
        dot / (na * nb)
    }
}

#[test]
#[ignore = "loads the model and runs real forwards on both arms; run explicitly with --ignored"]
fn throughput_hybrid_split_matches_single_arm_and_preserves_order() {
    // Disable the on-disk cache so each embed performs a REAL forward; a cache hit
    // would return identical vectors without ever exercising the hybrid dispatch.
    std::env::set_var("KIN_EMBED_CACHE", "0");
    // Auto backend so the throughput hybrid is allowed to engage (a forced
    // backend disables it by design).
    std::env::remove_var("KIN_EMBED_BACKEND");
    std::env::remove_var("KIN_EMBED_HYBRID");

    let embedder = match CodeEmbedder::new() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("SKIP: could not build embedder (model weights unavailable?): {e}");
            return;
        }
    };
    let texts = sample_batch();

    // A small per-dispatch token budget plus an even split give the CPU subset
    // several sub-batches — that is what makes the CPU arm exercise the
    // concurrent-across-cores path instead of one serial dispatch. Both the
    // reference and the hybrid run use the same budget, so per-entity vectors are
    // directly comparable.
    std::env::set_var("KIN_EMBED_MAX_BATCH_TOKENS", "96");
    std::env::set_var("KIN_EMBED_HYBRID_GPU_TPUT_RATIO", "1");

    // Reference: plain single-arm path (hybrid Off).
    std::env::remove_var("KIN_RESOURCE_PROFILE");
    let reference = embedder
        .embed_batch(&texts)
        .expect("single-arm embed must succeed");
    assert_eq!(reference.len(), texts.len(), "one vector per input");

    // Hybrid: throughput profile splits the batch across the GPU arm and the
    // concurrent CPU twin, and spreads the CPU subset's sub-batches across cores.
    // Reset the dispatch counters first so the snapshot reflects only this embed.
    kin_db::embed::hybrid_metrics::reset();
    std::env::set_var("KIN_RESOURCE_PROFILE", "throughput");
    let hybrid = embedder
        .embed_batch(&texts)
        .expect("throughput-hybrid embed must succeed");
    std::env::remove_var("KIN_RESOURCE_PROFILE");
    std::env::remove_var("KIN_EMBED_MAX_BATCH_TOKENS");
    std::env::remove_var("KIN_EMBED_HYBRID_GPU_TPUT_RATIO");

    // PROVE the CPU twin ran a share of the batch on the idle cores AND that it
    // ran its sub-batches in parallel (not one-at-a-time on a single core).
    let stats = kin_db::embed::hybrid_metrics::snapshot();
    assert!(
        stats.cpu_twin_entities > 0,
        "CPU twin did zero work — the hybrid split did not engage the idle cores ({stats:?})"
    );
    assert!(
        stats.gpu_entities > 0,
        "GPU arm did zero work — the split is degenerate ({stats:?})"
    );
    assert!(
        stats.cpu_parallel_batches > 0,
        "CPU subset was not embedded in parallel across cores ({stats:?})"
    );
    println!(
        "hybrid dispatch: gpu_entities={} cpu_twin_entities={} hybrid_batches={} cpu_parallel_batches={} single_side={} twin_unavailable={}",
        stats.gpu_entities,
        stats.cpu_twin_entities,
        stats.hybrid_batches,
        stats.cpu_parallel_batches,
        stats.single_side_batches,
        stats.twin_unavailable_batches
    );

    assert_eq!(
        hybrid.len(),
        reference.len(),
        "hybrid must return one vector per input, in input order"
    );

    let dim = embedder.dimensions();
    let mut worst_cos = 1.0f32;
    for (i, (h, r)) in hybrid.iter().zip(reference.iter()).enumerate() {
        assert_eq!(h.len(), dim, "hybrid vector {i} has wrong dimension");
        assert!(
            h.iter().all(|x| x.is_finite()),
            "hybrid vector {i} must be finite"
        );
        let cos = cosine(h, r);
        worst_cos = worst_cos.min(cos);
        // Same weights, same CPU SIMD forward on a CPU build — vectors must match
        // the single-arm reference for the SAME input position (order-stable).
        // The CPU-twin arm matches the primary model to the same tolerance the
        // OOM-degrade test proves (cosine > 0.999).
        assert!(
            cos > 0.999,
            "hybrid vector {i} diverged from the single-arm reference (cosine={cos:.8}); \
             the split corrupted data or scrambled result order"
        );
    }
    println!(
        "throughput-hybrid vs single-arm: {} entities, worst cosine={worst_cos:.8}",
        hybrid.len()
    );
}
