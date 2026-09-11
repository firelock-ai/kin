// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC
//
// Metal BufferPool populate/recycle window — repro / detector.
//
// Symptom (observed ~1/3 runs): the STANDALONE norm path occasionally reads an
// unpopulated/stale pooled INPUT buffer. It decodes as the `metal=0` signature —
// layer_norm of a zero input row = (0 − 0)·inv_std·gamma + beta = beta, so a row
// collapses to `beta` when its input was actually nonzero.
//
// Source audit (see the PR): the BufferPool acquire/recycle ordering is
// synchronous-correct by inspection — `commit_wait` gates each standalone op
// (`commit_bounded(empty); wait_until_completed`) and the per-op input buffer is
// owned by the caller across that wait, so it only recycles after GPU completion.
// The residual is therefore a Metal-driver / `StorageModeShared` rapid-reuse
// timing window, not a Rust-visible logic race. The root-cause fix is a Metal
// storage/synchronization change (e.g. `StorageModePrivate` + a staging blit, or
// an explicit fence on reuse) and must be validated on the GPU.
//
// This test is the on-GPU repro that proves the window and verifies any future
// fix. It is `#[ignore]`d: it needs a Metal device and currently reproduces a
// known-open bug, so it is a deliberate repro tool, not a CI gate.
//
//   cargo test -p kin-infer --release --features metal \
//     --test bufferpool_stale_read_repro -- --ignored --nocapture

#![cfg(feature = "metal")]

use kin_infer::gpu::{create_compute, GpuBackend};

/// Hammer the standalone `layer_norm` path with rapid submissions across the
/// widths the embedder uses (plus a non-multiple-of-32) and assert no row is ever
/// read stale: a correctly-normalized row of NON-constant input never equals
/// `beta`, so a row that equals `beta` (or is non-finite) means the input buffer
/// was not populated before the kernel ran.
#[test]
#[ignore = "on-GPU repro of the Metal BufferPool populate/recycle window"]
fn standalone_norm_rapid_submission_no_stale_read() {
    let gpu = create_compute();
    if gpu.backend() != GpuBackend::Metal {
        eprintln!("SKIP: backend is {:?}, not Metal", gpu.backend());
        return;
    }

    let shapes = [
        (384usize, 40usize),
        (768, 40),
        (100, 40),
        (768, 3),
        (384, 1),
    ];
    let iters = 400usize;
    let mut stale = 0usize;
    let mut checked = 0usize;

    for it in 0..iters {
        for &(cols, rows) in &shapes {
            let n = rows * cols;
            // Distinct nonzero, per-row NON-constant data so a stale (zero) read
            // cannot accidentally match a real result.
            let data: Vec<f32> = (0..n)
                .map(|i| (((i + it) % 17) as f32 - 8.0) * 0.13 + 0.5)
                .collect();
            let gamma: Vec<f32> = (0..cols).map(|j| 1.0 + (j % 5) as f32 * 0.01).collect();
            let beta: Vec<f32> = (0..cols).map(|j| (j % 3) as f32 * 0.02).collect();

            let mut out = data.clone();
            gpu.layer_norm(&mut out, &gamma, &beta, rows, cols, 1e-5)
                .expect("layer_norm");

            for r in 0..rows {
                let row = &out[r * cols..(r + 1) * cols];
                let non_finite = row.iter().any(|x| !x.is_finite());
                // Input row was non-constant, so a correct normalized row differs
                // from beta; equality means the input was read as all-zero.
                let collapsed_to_beta = row
                    .iter()
                    .zip(beta.iter())
                    .all(|(x, b)| (x - b).abs() < 1e-6);
                checked += 1;
                if non_finite || collapsed_to_beta {
                    stale += 1;
                    eprintln!(
                        "[bufferpool] stale/unpopulated read: iter={it} cols={cols} rows={rows} row={r}"
                    );
                }
            }
        }
    }

    eprintln!("[bufferpool] checked {checked} rows, {stale} stale");
    assert_eq!(
        stale, 0,
        "BufferPool stale read reproduced: {stale}/{checked} norm rows read a stale/unpopulated pooled input"
    );
}
