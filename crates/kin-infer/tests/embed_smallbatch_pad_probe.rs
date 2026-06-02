// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC
//
// Minimal repro + regression test for the small-batch padding corruption.
//
// Localized finding: a SHORT entity (e.g. 32 tokens) that is PADDED inside a
// SMALL-max_len batch (padded to 64, sharing the batch with 64-token entities) is
// corrupted (cosine ~0.175 vs its true embedding), while the SAME 32-token entity
// padded to 512 in a large batch is correct. The ground truth is `forward` (batch=1),
// which never pads. This test triangulates the trigger and is the fix's regression gate.
//
//   cargo test -p kin-infer --features metal --release \
//       --test embed_smallbatch_pad_probe -- --nocapture

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
    d
}

/// min cosine, over the entities of `short_len`, between their embedding inside a
/// mixed batch [short_len×n .. other_len×n] (padded to max(short_len,other_len)) and
/// their single-`forward` ground truth.
fn short_min_cos(model: &BertModel, short_len: usize, other_len: usize, n: usize) -> f64 {
    let mut batch: Vec<(Vec<u32>, Vec<u32>)> = Vec::new();
    for j in 0..n {
        batch.push(synth(short_len, 100 + j as u32));
    }
    for j in 0..n {
        batch.push(synth(other_len, 200 + j as u32));
    }
    let ids: Vec<Vec<u32>> = batch.iter().map(|e| e.0.clone()).collect();
    let masks: Vec<Vec<u32>> = batch.iter().map(|e| e.1.clone()).collect();
    let _ = model.forward_batched(&ids, &masks).unwrap(); // warm
    let emb = model.forward_batched(&ids, &masks).unwrap();
    let mut min_c = 1.0f64;
    for j in 0..n {
        let single = model.forward(&[batch[j].0.clone()], &[batch[j].1.clone()]).unwrap();
        min_c = min_c.min(cos(&emb[j], &single[0]));
    }
    min_c
}

#[test]
fn small_batch_padding_does_not_corrupt_short_entities() {
    let dir = Path::new(MODEL_DIR);
    if !dir.join("model.safetensors").exists() {
        eprintln!("SKIP: model not found at {MODEL_DIR}");
        return;
    }
    if cfg!(debug_assertions) {
        eprintln!("!!! REFUSING parity numbers from a debug build — rerun with --release !!!");
        return;
    }
    let cfg_json = fs::read_to_string(dir.join("config.json")).expect("config");
    let config: BertConfig = serde_json::from_str(&cfg_json).expect("parse");
    let model = BertModel::load(&dir.join("model.safetensors"), config).expect("load");
    eprintln!("backend={}", model.backend());

    // Trigger case: 32-token entities padded to 64 (sharing batch with 64-token).
    let c_32_in_64 = short_min_cos(&model, 32, 64, 8);
    // Controls (expected fine): 32 padded to 512; 32 alone (no pad); 100 padded to 128.
    let c_32_in_512 = short_min_cos(&model, 32, 512, 8);
    let c_32_in_32 = short_min_cos(&model, 32, 32, 8); // other_len==short_len => no pad
    let c_100_in_128 = short_min_cos(&model, 100, 128, 8);

    eprintln!("[repro] 32-tok padded to  64 (w/ 64-tok): min_cosine vs single = {c_32_in_64:.6}  <-- TRIGGER");
    eprintln!("[ctrl ] 32-tok padded to 512 (w/512-tok): min_cosine vs single = {c_32_in_512:.6}");
    eprintln!("[ctrl ] 32-tok no padding  (32 w/ 32-tok): min_cosine vs single = {c_32_in_32:.6}");
    eprintln!("[ctrl ] 100-tok padded to128 (w/128-tok): min_cosine vs single = {c_100_in_128:.6}");

    // Regression gate: the fix must bring the trigger case up to parity (cosine ~1.0,
    // matching the embedder's ~1e-6 float-noise floor). Pre-fix this is ~0.17.
    assert!(
        c_32_in_64 > 0.999,
        "short entity padded in a small mixed batch is corrupted (cosine {c_32_in_64}) — \
         forward_batched small-batch padding bug not fixed"
    );
}
