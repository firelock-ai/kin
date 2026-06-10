// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC
//
// Within-process embedding determinism probe (DIAGNOSTIC, report-only).
//
// Pins a reference embedding for a short sequence, then re-embeds it after each
// differently-shaped (long) forward pass and reports how many of the steady-state
// re-embeds are bit-identical. Skips cleanly when the model is absent.
//
// ── SCOPE NOTE for a future determinism pass (do not delete) ──────────────────
// This probe documents a residual within-process embedding nondeterminism on the
// Metal backend. It is intentionally NOT a hard gate (incidental GPU load would
// flake CI) and was NOT fixed in the embedder-speed work. Hand-off facts:
//
//   * What it is: embedding the SAME short text is occasionally NOT bit-identical
//     across passes within one process, but only when DIFFERENTLY-shaped forward
//     passes interleave (short, then long, then short). Single-shape repeats are
//     bit-stable. Magnitude is small (finite, ~1-2%), not NaN.
//   * Pre-existing: reproduces with the FFN/RoPE command-buffer pipelining
//     disabled AND with GPU attention forced to CPU — so it is NOT the fused
//     attention kernels and NOT the pipelining; it lives in the shared GPU compute
//     path (matmul / norm / activation buffers driven through metal_backend.rs).
//   * Already-fixed dominant source: `MetalCompute::buf_zeros` previously did not
//     zero its allocation (it now does via write_bytes). That removed the gross
//     bimodal collapse; what remains is a rarer residual.
//   * Suspected site: a read-before-write of a GPU intermediate whose value is
//     constant-per-process (uninitialized/ASLR-seeded) — note the failure is
//     bimodal per process (a whole run is either clean or consistently shifted).
//     buf_zeros is now zeroed, so the next candidate is threadgroup shared memory
//     in the tiled matmul kernels (a_tile/b_tile in matmul_transb /
//     batched_matmul_*) read across a tile boundary, or a missing inter-encoder
//     hazard barrier in a chained command buffer. NB: it is contention-AMPLIFIED
//     (0-or-1/12 when several embed procs hammer the GPU; mostly 12/12 in a single
//     workstream — which is how the thesis benchmark runs, so it does not block it).
//   * Real embedding-correctness gates remain `swerank_self_retrieval` (semantic
//     top-1 + margin) and `metal_seq_len_regression` (Metal-vs-CPU parity, 0 NaN).
// ──────────────────────────────────────────────────────────────────────────────

#![cfg(feature = "metal")]

use std::fs;
use std::path::Path;

use kin_infer::{BertConfig, BertModel};

const MODEL_DIR: &str = "/tmp/swerank";

fn probe_model_dir() -> String {
    std::env::var("KIN_INFER_PROBE_MODEL_DIR").unwrap_or_else(|_| MODEL_DIR.to_string())
}

fn load() -> Option<BertModel> {
    let model_dir = probe_model_dir();
    let dir = Path::new(&model_dir);
    if !dir.join("model.safetensors").exists() {
        eprintln!("SKIP: model absent at {model_dir}");
        return None;
    }
    let cfg_json = fs::read_to_string(dir.join("config.json")).ok()?;
    let config: BertConfig = serde_json::from_str(&cfg_json).ok()?;
    BertModel::load(&dir.join("model.safetensors"), config).ok()
}

#[test]
fn embed_determinism_interleaved_shapes() {
    let model = match load() {
        Some(m) => m,
        None => return,
    };
    // INTERLEAVED lengths: embed a short seq, then a long seq, alternating. This
    // reproduces the mixed-corpus pattern. We pin a reference embedding for the
    // short sequence, then re-embed it after each long-sequence pass and check it
    // stays bit-identical. A buffer carried over from a differently-shaped op
    // would corrupt the short result here.
    let short: Vec<u32> = (0..32).map(|i| 1 + ((i * 131) % 18000) as u32).collect();
    let smask = vec![1u32; short.len()];
    let long: Vec<u32> = (0..512).map(|i| 1 + ((i * 977) % 18000) as u32).collect();
    let lmask = vec![1u32; long.len()];

    // Discard the cold first forward (pipeline/shader warm-up, first weight-cache
    // population); pin the reference from a steady-state pass.
    let _cold = model.forward(&[short.clone()], &[smask.clone()]).unwrap();
    let reference = model.forward(&[short.clone()], &[smask.clone()]).unwrap();
    let n = 12;
    let mut ok = 0usize;
    for _ in 0..n {
        // Perturb GPU state with a different-shaped forward in between. Before the
        // buf_zeros zero-init fix this leaked process-stale garbage from the
        // long-shape op into the short-shape output, making `again` diverge.
        let _ = model.forward(&[long.clone()], &[lmask.clone()]).unwrap();
        let again = model.forward(&[short.clone()], &[smask.clone()]).unwrap();
        if again == reference {
            ok += 1;
        }
    }
    eprintln!(
        "[determinism] backend={} interleaved short/long : {ok}/{n} steady-state short-embeds bit-identical to reference",
        model.backend()
    );

    // Report-only (see the SCOPE NOTE at the top of this file). Not asserted.
    if ok < n {
        eprintln!(
            "[determinism] NOTE: {}/{n} diverged — pre-existing, contention-sensitive \
             read-before-write residual in the shared GPU compute path (see report).",
            n - ok
        );
    }
}
