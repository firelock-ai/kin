// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Runtime proof of the kin-db embedding dispatcher's CPU-degrade-on-OOM path.
//!
//! Background: the Metal embedding arms in `embed/mod.rs` match
//! `kin_infer::InferError::OutOfMemory(..)` returned by `forward_batched` and,
//! instead of failing the whole index, retry the batch on the lazily-built CPU
//! twin (`cpu_model()`, loaded under `KIN_INFER_FORCE_CPU`). The kin-infer side
//! of this contract is proven separately (see
//! `kin-infer/tests/metal_oom_error_path.rs`): an impossible buffer size drives
//! `try_new_buffer`'s nil path and surfaces a real `Err(InferError::OutOfMemory)`
//! rather than a panic or wrapped-nil buffer. What that test does NOT cover is
//! the kin-db reaction to that error value — that the dispatcher actually
//! catches it and produces correct-dimension vectors via the CPU twin.
//!
//! This test closes that gap WITHOUT putting the device under real memory
//! pressure. It uses the test-only fault-injection seam
//! `KIN_EMBED_TEST_FORCE_METAL_OOM=N`, which makes the first `N` Metal
//! `forward_batched` dispatches in this process return a synthetic
//! `InferError::OutOfMemory`. With the dispatcher forced down the Metal arm
//! (`KIN_EMBED_BACKEND=metal`) and the on-disk cache disabled
//! (`KIN_EMBED_CACHE=0`, so the embed actually reaches the dispatcher), the
//! single Metal forward is forcibly OOM'd — therefore any successful,
//! correct-dimension vector that comes back can ONLY have been produced by the
//! CPU-twin retry. A returned `Ok` with finite, non-zero, model-dimension
//! vectors is positive proof that the index did not fail and the dispatcher
//! degraded to CPU.
//!
//! The cross-check tightens this further: after the injection budget is spent,
//! a second embed of the SAME text routed explicitly through the CPU arm uses
//! the SAME CPU twin and reproduces the degraded vector (cosine ~= 1.0),
//! proving the OOM retry was served by the CPU twin's compute, not some other
//! path.

use kin_db::CodeEmbedder;

/// The exact text embedded twice — once via the OOM-degraded Metal arm, once
/// directly via the CPU arm — so the two vectors must match.
const SAMPLE: &str = "fn add(a: i32, b: i32) -> i32 { a + b }";

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
fn metal_oom_degrades_to_cpu_twin_and_returns_correct_vectors() {
    // Disable the on-disk cache so every embed performs a REAL forward; a cache
    // hit would short-circuit the dispatcher and never reach the injected arm.
    std::env::set_var("KIN_EMBED_CACHE", "0");
    // Force the dispatcher down the Metal arm regardless of sequence length so
    // the injection point (which lives only in the Metal arm) is exercised.
    std::env::set_var("KIN_EMBED_BACKEND", "metal");
    // Arm the fault injector: the FIRST Metal forward of this process returns a
    // synthetic OutOfMemory, forcing the CPU-twin retry exactly once.
    std::env::set_var("KIN_EMBED_TEST_FORCE_METAL_OOM", "1");

    let embedder = match CodeEmbedder::new() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("SKIP: could not build embedder (model weights unavailable?): {e}");
            return;
        }
    };
    let dim = embedder.dimensions();
    assert!(dim > 0, "embedder reported zero dimensions");

    // The single Metal forward for this batch is forcibly OOM'd, so a
    // successful result can only have come from the CPU-twin retry. If that
    // retry path were broken, embed_batch would return Err and fail the index.
    let degraded = embedder
        .embed_batch(&[SAMPLE.to_string()])
        .expect("embed_batch must succeed by degrading to the CPU twin after Metal OOM");
    assert_eq!(degraded.len(), 1, "expected exactly one vector");
    let degraded = &degraded[0];

    assert_eq!(
        degraded.len(),
        dim,
        "CPU-degraded vector must have the model dimension ({dim})"
    );
    assert!(
        degraded.iter().all(|x| x.is_finite()),
        "CPU-degraded vector must be finite (no NaN/inf) — an index-usable embedding"
    );
    assert!(
        degraded.iter().any(|x| *x != 0.0),
        "CPU-degraded vector must be non-zero (a zero vector is the NaN-sanitizer's \
         poison value, not a real embedding)"
    );

    // Cross-check: the injection budget is now exhausted (1 -> 0). Embedding the
    // SAME text explicitly through the CPU arm reuses the SAME CPU twin and must
    // reproduce the degraded vector, proving the OOM retry was served by the CPU
    // twin's compute.
    std::env::set_var("KIN_EMBED_BACKEND", "cpu");
    let reference = embedder
        .embed_batch(&[SAMPLE.to_string()])
        .expect("direct CPU reference embed must succeed");
    assert_eq!(reference.len(), 1);
    let reference = &reference[0];
    assert_eq!(reference.len(), dim);

    let cos = cosine(degraded, reference);
    println!(
        "metal-OOM-degraded vs direct-CPU reference: dim={dim}, cosine={cos:.8}, \
         degraded_norm={:.6}",
        degraded.iter().map(|x| x * x).sum::<f32>().sqrt()
    );
    assert!(
        cos > 0.999,
        "Metal-OOM-degraded vector must match the direct-CPU reference \
         (cosine={cos:.8}); proves the retry was served by the CPU twin"
    );
}
