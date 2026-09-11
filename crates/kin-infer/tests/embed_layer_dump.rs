// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC
//
// Deterministic per-layer divergence trace for the batched-corruption bug.
// Runs the SAME len-32 entity (corpus_a index 0 = synth(32, salt 0)) two ways in
// ONE process, with KIN_INFER_DUMP_LAYER=1 set so the model eprintln's a per-layer
// fingerprint for both:
//   (1) forward([entity0])                      -> path=single   (ground truth)
//   (2) forward_batched([bin64 group=idx 0..40]) -> path=batched, DUMP_ENTITY=0
// Diff the per-layer `DUMP ...` lines to find the FIRST layer where single vs
// batched diverge → localizes the exact op. (Dump output comes from the model
// instrumentation; this test only triggers the two calls.)
//
//   KIN_INFER_DUMP_LAYER=1 KIN_INFER_DUMP_ENTITY=0 \
//     cargo test -p kin-infer --features metal --release \
//     --test embed_layer_dump -- --nocapture

#![cfg(feature = "metal")]

use std::fs;
use std::path::Path;

use kin_infer::{BertConfig, BertModel};

const MODEL_DIR: &str = "/tmp/swerank";

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

#[test]
fn layer_divergence_trace() {
    let dir = Path::new(MODEL_DIR);
    if !dir.join("model.safetensors").exists() {
        eprintln!("SKIP: model not found at {MODEL_DIR}");
        return;
    }
    let cfg_json = match fs::read_to_string(dir.join("config.json")) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("SKIP: cannot read config.json ({e})");
            return;
        }
    };
    let config: BertConfig = match serde_json::from_str(&cfg_json) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("SKIP: config.json not a loadable BertConfig ({e})");
            return;
        }
    };
    let model = BertModel::load(&dir.join("model.safetensors"), config).expect("load");
    eprintln!("backend={}", model.backend());

    // Reconstruct the bin-64 group exactly as embed_bucket_truth_probe does:
    // lens [32,64,128,256,512] x20, salt = bucket*131 + j. bin64 = idx 0..40
    // = 20 len-32 (salt 0..19) + 20 len-64 (salt 131..150). Entity 0 = synth(32,0).
    let mut bin64: Vec<(Vec<u32>, Vec<u32>)> = Vec::new();
    for j in 0..20u32 {
        bin64.push(synth(32, j));
    }
    for j in 0..20u32 {
        bin64.push(synth(64, 131 + j));
    }
    let ent0 = bin64[0].clone();

    eprintln!("===== SINGLE forward(entity0 len32 salt0) =====");
    let single = model
        .forward(std::slice::from_ref(&ent0.0), std::slice::from_ref(&ent0.1))
        .expect("single");
    eprintln!(
        "single_emb_first3=[{:.6},{:.6},{:.6}]",
        single[0][0], single[0][1], single[0][2]
    );

    eprintln!("===== BATCHED forward_batched(bin64 group, 40 ent, dump entity 0) =====");
    let ids: Vec<Vec<u32>> = bin64.iter().map(|e| e.0.clone()).collect();
    let masks: Vec<Vec<u32>> = bin64.iter().map(|e| e.1.clone()).collect();
    let batched = model.forward_batched(&ids, &masks).expect("batched");
    eprintln!(
        "batched_emb[0]_first3=[{:.6},{:.6},{:.6}]",
        batched[0][0], batched[0][1], batched[0][2]
    );

    // final cosine for context
    let mut dot = 0.0f64;
    for i in 0..single[0].len() {
        dot += single[0][i] as f64 * batched[0][i] as f64;
    }
    eprintln!("FINAL cosine(single, batched[0]) = {dot:.6}");
}
