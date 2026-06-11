// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC
//
// CONVICTION HARNESS — batch-size / batch-composition invariance of a single
// entity's embedding (the LAST variance in the freeze stack).
//
// The concat-cache fix (commit 58a38f0, guard `batched_cold_matches_single_forward`)
// made the batched embedder invariant to PADDING layout. This probe tests the next
// hypothesis: the output of a FIXED text depends on the batch SIZE / COMPOSITION it
// rides in, because the GEMM kernel is selected by a batch-derived dimension:
//
//   * projection / FFN GEMMs gate on `use_mma(m=total_rows, ...)` where
//     total_rows = batch_size * max_len  (metal_backend.rs forward_layer_batched)
//   * attention QK^T / AV gate on `use_mma(m=max_len, ...)`
//   * use_mma requires m >= 32 — below it the SCALAR tile runs, at/above it the
//     simdgroup MMA runs. The two kernels reduce over K in a different order, so a
//     text that crosses the threshold (e.g. a lone short query vs the same text in
//     a batch-of-8, or beside a long filler) gets a LAST-BIT-DIFFERENT vector.
//
// This is a MEASUREMENT (it never asserts divergence — the bug currently exists).
// It embeds ONE short target under a battery of batch configs, extracts the
// target's vector, and bit-compares each to the lone-`forward` baseline. The
// predicted kernel REGIME is printed beside each config so the failure pattern is
// self-explanatory:
//
//   Regime A (proj scalar, attn scalar):  baseline, n1, n2          -> identical
//   Regime B (proj MMA,    attn scalar):  n3, n8, filler20          -> differ from A
//   Regime C (proj MMA,    attn MMA):     filler40, filler60        -> differ from A & B
//
// Run (model + release REQUIRED for a meaningful last-bit comparison):
//   cargo test -p kin-infer --features metal --release \
//       --test embed_batch_size_invariance_probe -- --nocapture
//
// Causation cross-check (forces ONE kernel everywhere -> all regimes collapse to
// identical, proving the kernel split is the cause):
//   KIN_INFER_MMA=0 cargo test -p kin-infer --features metal --release \
//       --test embed_batch_size_invariance_probe -- --nocapture

#![cfg(feature = "metal")]

use kin_infer::{BertConfig, BertModel};
use std::fs;
use std::path::Path;

/// Deterministic synthetic token sequence of length `len` (salt varies content).
fn synth(len: usize, salt: u32) -> (Vec<u32>, Vec<u32>) {
    let ids: Vec<u32> = (0..len)
        .map(|i| {
            1 + ((i as u32)
                .wrapping_mul(2654435761)
                .wrapping_add(salt.wrapping_mul(40503))
                % 20000)
        })
        .collect();
    (ids, vec![1u32; len])
}

/// Per-element comparison of two embeddings: (#differing bits, max |a-b|, cosine).
fn compare(a: &[f32], b: &[f32]) -> (usize, f32, f64) {
    assert_eq!(a.len(), b.len(), "embedding dim mismatch");
    let mut ndiff = 0usize;
    let mut max_abs = 0.0f32;
    let (mut dot, mut na, mut nb) = (0.0f64, 0.0f64, 0.0f64);
    for (&x, &y) in a.iter().zip(b.iter()) {
        if x.to_bits() != y.to_bits() {
            ndiff += 1;
        }
        max_abs = max_abs.max((x - y).abs());
        dot += x as f64 * y as f64;
        na += (x as f64).powi(2);
        nb += (y as f64).powi(2);
    }
    let cos = dot / (na.sqrt() * nb.sqrt()).max(1e-12);
    (ndiff, max_abs, cos)
}

fn run_for_model(model_dir: &str) {
    let dir = Path::new(model_dir);
    if !dir.join("model.safetensors").exists() {
        eprintln!("SKIP: no model at {model_dir}");
        return;
    }
    if cfg!(debug_assertions) {
        eprintln!("!!! REFUSING last-bit parity from a debug build — use --release !!!");
        return;
    }
    let cfg_json = fs::read_to_string(dir.join("config.json")).expect("read config.json");
    let config: BertConfig = match serde_json::from_str(&cfg_json) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("SKIP: {model_dir} config.json not a loadable BertConfig ({e})");
            return;
        }
    };
    let model = BertModel::load(&dir.join("model.safetensors"), config).expect("load model");

    let bucket = std::env::var("KIN_INFER_BUCKET").unwrap_or_else(|_| "(default ON)".into());
    let mma = std::env::var("KIN_INFER_MMA").unwrap_or_else(|_| "(default ON)".into());
    eprintln!(
        "\n=== batch-size invariance probe :: {model_dir} ===\n\
         backend={}  KIN_INFER_BUCKET={bucket}  KIN_INFER_MMA={mma}",
        model.backend()
    );

    // SHORT target (12 tokens) so it sits BELOW the m>=32 MMA floor when alone and
    // crosses it as the batch grows. Always at input index 0.
    const TLEN: usize = 12;
    let (t, tm) = synth(TLEN, 7);
    let baseline = model
        .forward(&[t.clone()], &[tm.clone()])
        .unwrap()
        .pop()
        .unwrap();

    // Each config: (label, predicted regime, batch token_ids, batch masks).
    // The target is always index 0; fillers ride alongside to drive max_len/total_rows.
    let f = |len: usize, salt: u32| synth(len, salt);
    type Batch = (&'static str, &'static str, Vec<Vec<u32>>, Vec<Vec<u32>>);
    let mk = |label, regime, items: Vec<(Vec<u32>, Vec<u32>)>| -> Batch {
        let ids = items.iter().map(|(i, _)| i.clone()).collect();
        let masks = items.iter().map(|(_, m)| m.clone()).collect();
        (label, regime, ids, masks)
    };

    let configs: Vec<Batch> = vec![
        mk(
            "fb_n1     ",
            "A proj=scalar attn=scalar",
            vec![(t.clone(), tm.clone())],
        ),
        mk(
            "fb_n2     ",
            "A proj=scalar attn=scalar",
            vec![(t.clone(), tm.clone()); 2],
        ),
        mk(
            "fb_n3     ",
            "B proj=MMA    attn=scalar",
            vec![(t.clone(), tm.clone()); 3],
        ),
        mk(
            "fb_n8     ",
            "B proj=MMA    attn=scalar",
            vec![(t.clone(), tm.clone()); 8],
        ),
        mk(
            "fb_filler20",
            "B proj=MMA    attn=scalar",
            vec![(t.clone(), tm.clone()), f(20, 101)],
        ),
        mk(
            "fb_filler40",
            "C proj=MMA    attn=MMA   ",
            vec![(t.clone(), tm.clone()), f(40, 102)],
        ),
        mk(
            "fb_filler60",
            "C proj=MMA    attn=MMA   ",
            vec![(t.clone(), tm.clone()), f(60, 103)],
        ),
    ];

    eprintln!(
        "  target_len={TLEN}  (m>=32 -> simdgroup MMA, else scalar tile)\n\
         {:<12} {:<26} {:>10} {:>8} {:>11}  {:>8} {:>11}",
        "config", "predicted_regime", "total_rows", "max_len", "vs_baseline", "ndiff", "max_abs"
    );
    let mut vectors: Vec<(String, Vec<f32>)> = vec![("baseline".into(), baseline.clone())];
    for (label, regime, ids, masks) in &configs {
        let batch_size = ids.len();
        let max_len = ids.iter().map(|v| v.len()).max().unwrap();
        let total_rows = batch_size * max_len;
        let out = model.forward_batched(ids, masks).unwrap();
        let target_vec = out[0].clone(); // target is always index 0
        let (ndiff, max_abs, _cos) = compare(&baseline, &target_vec);
        let verdict = if ndiff == 0 { "IDENTICAL" } else { "DIFFER" };
        eprintln!(
            "{label:<12} {regime:<26} {total_rows:>10} {max_len:>8} {verdict:>11}  {ndiff:>8} {max_abs:>11.3e}"
        );
        vectors.push((label.trim().to_string(), target_vec));
    }

    // Within-regime check: configs predicted to share a kernel regime should be
    // bit-identical to EACH OTHER even where they differ from the baseline.
    eprintln!("\n  within-regime bit-identity (same kernel path => must match):");
    let pairs = [
        ("A: fb_n1  == fb_n2  ", "fb_n1", "fb_n2"),
        ("B: fb_n3  == fb_n8  ", "fb_n3", "fb_n8"),
        ("B: fb_n3  == fb_filler20", "fb_n3", "fb_filler20"),
        (
            "C: fb_filler40 == fb_filler60",
            "fb_filler40",
            "fb_filler60",
        ),
    ];
    let find = |name: &str| {
        vectors
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.clone())
    };
    for (desc, a, b) in pairs {
        if let (Some(va), Some(vb)) = (find(a), find(b)) {
            let (ndiff, max_abs, _) = compare(&va, &vb);
            let verdict = if ndiff == 0 { "IDENTICAL" } else { "DIFFER" };
            eprintln!("    {desc:<32} {verdict:>10}  ndiff={ndiff} max_abs={max_abs:.3e}");
        }
    }
    eprintln!("=== end probe :: {model_dir} ===\n");
}

#[test]
fn batch_size_invariance_probe() {
    for dir in ["/tmp/nomic", "/tmp/swerank", "/tmp/swerank-loadable"] {
        run_for_model(dir);
    }
}

/// Stable fingerprint of every vector in a mixed-length corpus embedded via the
/// production `forward_batched` path. Printed so two SEPARATE PROCESS runs can be
/// diffed — this is the direct test of the reported symptom ("two eval runs on
/// bit-identical state give different query/re-embed vectors"). A matching
/// fingerprint across processes means the batched embedder is cross-process
/// bit-deterministic and the eval variance lives elsewhere.
///   run twice:  for i in 1 2; do <bin> corpus_fingerprint --nocapture; done
#[test]
fn corpus_fingerprint() {
    let model_dir =
        std::env::var("KIN_INFER_PROBE_MODEL_DIR").unwrap_or_else(|_| "/tmp/nomic".into());
    let dir = Path::new(&model_dir);
    if !dir.join("model.safetensors").exists() {
        eprintln!("SKIP: no model at {model_dir}");
        return;
    }
    if cfg!(debug_assertions) {
        eprintln!("!!! REFUSING last-bit fingerprint from a debug build — use --release !!!");
        return;
    }
    let cfg_json = fs::read_to_string(dir.join("config.json")).expect("read config.json");
    let config: BertConfig = serde_json::from_str(&cfg_json).expect("parse config.json");
    let model = BertModel::load(&dir.join("model.safetensors"), config).expect("load model");

    // Mixed-length corpus mimicking a real index: many short, some long, ragged.
    let lens = [7usize, 12, 19, 28, 33, 47, 64, 65, 96, 150, 256, 400];
    let mut ids = Vec::new();
    let mut masks = Vec::new();
    for (s, &l) in lens.iter().enumerate() {
        for j in 0..4 {
            let (i, m) = synth(l, (s * 17 + j) as u32);
            ids.push(i);
            masks.push(m);
        }
    }
    let out = model.forward_batched(&ids, &masks).unwrap();

    // FNV-1a over every embedding's raw bits → one 64-bit corpus fingerprint.
    let mut fnv: u64 = 0xcbf29ce484222325;
    let mut total_bits: u64 = 0;
    for v in &out {
        for &x in v {
            let b = x.to_bits();
            total_bits = total_bits.wrapping_add(b as u64);
            for byte in b.to_le_bytes() {
                fnv ^= byte as u64;
                fnv = fnv.wrapping_mul(0x100000001b3);
            }
        }
    }
    eprintln!(
        "[corpus-fingerprint] model={model_dir} backend={} bucket={} n_vec={} dim={} \
         fnv1a=0x{fnv:016x} bitsum=0x{total_bits:016x}",
        model.backend(),
        std::env::var("KIN_INFER_BUCKET").unwrap_or_else(|_| "default".into()),
        out.len(),
        out.first().map(|v| v.len()).unwrap_or(0),
    );
}
