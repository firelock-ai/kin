// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC
//
// Root-cause probe for the bucketing parity failure (bin-grouped embeddings
// diverged from a single mixed batch at cosine 0.10 across ALL lengths, including
// uniform bins). Hypothesis: `forward_batched`'s result for a FIXED input depends
// on what was called before it — i.e. cross-call state corruption (a reused/stale
// GPU buffer not reset per call). Bucketing makes many varying-shape encode_batched
// calls, so if a prior call corrupts a later one, bucketed output is garbage.
//
// DECISIVE TEST: embed a fixed uniform batch G; then embed it AGAIN after a
// different-shaped batch is interposed. If the two results for the IDENTICAL input
// differ, forward_batched is call-history-dependent (the bug). Uniform-length G
// removes any padding confound — a divergence here is pure inter-call state.
//
//   cargo test -p kin-infer --features metal --release \
//       --test embed_batch_state_probe -- --nocapture

#![cfg(feature = "metal")]

use std::fs;
use std::path::Path;

use kin_infer::{BertConfig, BertModel};

const MODEL_DIR: &str = "/tmp/swerank";

fn synth(len: usize, salt: u32) -> (Vec<u32>, Vec<u32>) {
    let ids: Vec<u32> = (0..len)
        .map(|i| 1 + ((i as u32).wrapping_mul(2654435761).wrapping_add(salt.wrapping_mul(40503)) % 20000))
        .collect();
    (ids, vec![1u32; len])
}

fn cos(a: &[f32], b: &[f32]) -> f64 {
    let mut d = 0.0f64;
    for i in 0..a.len() {
        d += a[i] as f64 * b[i] as f64;
    }
    d // both are L2-normalized => dot == cosine
}

#[test]
fn forward_batched_is_call_history_independent() {
    let dir = Path::new(MODEL_DIR);
    if !dir.join("model.safetensors").exists() {
        eprintln!("SKIP: model not found at {MODEL_DIR}");
        return;
    }
    if cfg!(debug_assertions) {
        eprintln!("!!! REFUSING perf/parity numbers from a debug build — rerun with --release !!!");
        return;
    }
    let cfg_json = fs::read_to_string(dir.join("config.json")).expect("config");
    let config: BertConfig = serde_json::from_str(&cfg_json).expect("parse");
    let model = BertModel::load(&dir.join("model.safetensors"), config).expect("load");
    eprintln!("backend={}", model.backend());

    // Fixed UNIFORM-length group G (24 entities, all len 96 — no padding).
    let g: Vec<(Vec<u32>, Vec<u32>)> = (0..24).map(|j| synth(96, 1000 + j)).collect();
    let g_ids: Vec<Vec<u32>> = g.iter().map(|e| e.0.clone()).collect();
    let g_masks: Vec<Vec<u32>> = g.iter().map(|e| e.1.clone()).collect();

    // A different-shaped batch to interpose (80 mixed-length entities).
    let big: Vec<(Vec<u32>, Vec<u32>)> = (0..80)
        .map(|j| synth([16, 32, 64, 128, 256, 512][(j % 6) as usize], 7000 + j))
        .collect();
    let big_ids: Vec<Vec<u32>> = big.iter().map(|e| e.0.clone()).collect();
    let big_masks: Vec<Vec<u32>> = big.iter().map(|e| e.1.clone()).collect();

    // Warm both shapes (exclude cold pipeline/cache effects).
    let _ = model.forward_batched(&g_ids, &g_masks).unwrap();
    let _ = model.forward_batched(&big_ids, &big_masks).unwrap();

    // ref: embed G. interpose a different shape. test: embed the SAME G again.
    let ref_g = model.forward_batched(&g_ids, &g_masks).unwrap();
    let _ = model.forward_batched(&big_ids, &big_masks).unwrap();
    let test_g = model.forward_batched(&g_ids, &g_masks).unwrap();

    let mut min_cos = 1.0f64;
    for i in 0..ref_g.len() {
        min_cos = min_cos.min(cos(&ref_g[i], &test_g[i]));
    }
    eprintln!(
        "[cross-call] same fixed batch G embedded before vs after an interposed \
         different-shape batch: min_cosine={min_cos:.12}"
    );
    eprintln!(
        "  (cosine 1.0 => forward_batched is call-history-INDEPENDENT (no state bug); \
         <1.0 => result depends on prior calls => the bucketing-killer)"
    );

    // Secondary: batched vs single (batch=1 `forward`) ground truth for G.
    let mut min_cos_single = 1.0f64;
    for (i, e) in g.iter().enumerate() {
        let single = model.forward(&[e.0.clone()], &[e.1.clone()]).unwrap();
        min_cos_single = min_cos_single.min(cos(&ref_g[i], &single[0]));
    }
    eprintln!(
        "[batched-vs-single] forward_batched(G)[i] vs forward([entity_i]): min_cosine={min_cos_single:.12}"
    );

    // Repeat-call determinism (same input, back-to-back, no interposition).
    let again = model.forward_batched(&g_ids, &g_masks).unwrap();
    let mut min_cos_repeat = 1.0f64;
    for i in 0..ref_g.len() {
        min_cos_repeat = min_cos_repeat.min(cos(&test_g[i], &again[i]));
    }
    eprintln!("[repeat] back-to-back same batch: min_cosine={min_cos_repeat:.12}");
}
