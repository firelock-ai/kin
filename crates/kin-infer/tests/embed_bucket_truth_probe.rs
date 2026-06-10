// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC
//
// DEFINITIVE parity test for length-bucketing, against the canonical ground truth
// (single `forward`, batch=1, which never pads). Builds the exact corpus the
// bucketing probe used (5 lengths × 20, salt = bucket*131+j) and compares BOTH:
//   - mixed   = forward_batched(all 100)            [the unbucketed baseline]
//   - binned  = forward_batched per length-bin, scattered  [the bucketing impl]
// against single[i] = forward([entity_i]) per entity, per length. This resolves
// whether the earlier 0.175 was real corruption (and in WHICH path) or a probe
// artifact. Minimal prior calls (one warm) to rule out cross-call accumulation.
//
//   cargo test -p kin-infer --features metal --release \
//       --test embed_bucket_truth_probe -- --nocapture

#![cfg(feature = "metal")]

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use kin_infer::{BertConfig, BertModel};

const MODEL_DIR: &str = "/tmp/swerank";

fn probe_model_dir() -> String {
    std::env::var("KIN_INFER_PROBE_MODEL_DIR").unwrap_or_else(|_| MODEL_DIR.to_string())
}

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
fn bin_of(l: usize) -> usize {
    for &b in &[64usize, 128, 256, 512, 1024] {
        if l <= b {
            return b;
        }
    }
    2048
}

#[test]
fn bucketing_vs_ground_truth() {
    let model_dir = probe_model_dir();
    let dir = Path::new(&model_dir);
    if !dir.join("model.safetensors").exists() {
        eprintln!("SKIP: model not found at {model_dir}");
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

    // Exact corpus of the bucketing probe: [32,64,128,256,512] × 20, salt=bucket*131+j.
    let lens = [32usize, 64, 128, 256, 512];
    let mut corpus: Vec<(Vec<u32>, Vec<u32>)> = Vec::new();
    for (b, &len) in lens.iter().enumerate() {
        for j in 0..20 {
            corpus.push(synth(len, (b * 131 + j) as u32));
        }
    }
    let all_ids: Vec<Vec<u32>> = corpus.iter().map(|e| e.0.clone()).collect();
    let all_masks: Vec<Vec<u32>> = corpus.iter().map(|e| e.1.clone()).collect();

    // Ground truth: single forward per entity (batch=1, never pads).
    let single: Vec<Vec<f32>> = corpus
        .iter()
        .map(|e| model.forward(&[e.0.clone()], &[e.1.clone()]).unwrap().pop().unwrap())
        .collect();

    let _ = model.forward_batched(&all_ids, &all_masks).unwrap(); // warm
    let mixed = model.forward_batched(&all_ids, &all_masks).unwrap();

    // binned: group by bin, forward_batched per group, scatter to original index.
    let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
    for (i, e) in corpus.iter().enumerate() {
        groups.entry(bin_of(e.0.len())).or_default().push(i);
    }
    let mut binned = vec![Vec::<f32>::new(); corpus.len()];
    for idxs in groups.values() {
        let gids: Vec<Vec<u32>> = idxs.iter().map(|&i| corpus[i].0.clone()).collect();
        let gms: Vec<Vec<u32>> = idxs.iter().map(|&i| corpus[i].1.clone()).collect();
        let gout = model.forward_batched(&gids, &gms).unwrap();
        for (k, &i) in idxs.iter().enumerate() {
            binned[i] = gout[k].clone();
        }
    }

    // Per length: min cosine of each path vs single-forward ground truth.
    let mut mixed_min: BTreeMap<usize, f64> = BTreeMap::new();
    let mut binned_min: BTreeMap<usize, f64> = BTreeMap::new();
    let mut mb_min: BTreeMap<usize, f64> = BTreeMap::new();
    for i in 0..corpus.len() {
        let l = corpus[i].0.len();
        let mm = mixed_min.entry(l).or_insert(1.0);
        *mm = mm.min(cos(&single[i], &mixed[i]));
        let bm = binned_min.entry(l).or_insert(1.0);
        *bm = bm.min(cos(&single[i], &binned[i]));
        let xm = mb_min.entry(l).or_insert(1.0);
        *xm = xm.min(cos(&mixed[i], &binned[i]));
    }
    eprintln!("[truth] min_cosine vs single-forward, BY LENGTH:");
    eprintln!("  mixed-100  vs single : {mixed_min:?}");
    eprintln!("  binned     vs single : {binned_min:?}");
    eprintln!("  mixed      vs binned : {mb_min:?}");
    let worst_mixed = mixed_min.values().cloned().fold(1.0f64, f64::min);
    let worst_binned = binned_min.values().cloned().fold(1.0f64, f64::min);
    eprintln!("[truth] worst: mixed-vs-single={worst_mixed:.6}  binned-vs-single={worst_binned:.6}");

    // Characterize HOW corrupt binned entities are wrong (end-only read → no
    // inter-op host work, so it does NOT suppress the race). For each corrupt
    // binned[i], find which single[j] it best matches: j!=i ⇒ buffer/index
    // CROSS-ENTITY SWAP; matches nothing ⇒ true garbage.
    eprintln!("[truth] corrupt-entity characterization (binned[i] vs ALL single[j]):");
    let mut n_corrupt = 0;
    for i in 0..corpus.len() {
        let self_cos = cos(&single[i], &binned[i]);
        if self_cos < 0.99 {
            n_corrupt += 1;
            let mut best_j = i;
            let mut best = self_cos;
            for j in 0..single.len() {
                let c = cos(&binned[i], &single[j]);
                if c > best {
                    best = c;
                    best_j = j;
                }
            }
            let swap = if best_j != i { " <-- SWAP" } else { "" };
            eprintln!(
                "  binned[{i}] (len {}) self_cos={self_cos:.4} -> best=single[{best_j}] (len {}) cos={best:.4}{swap}",
                corpus[i].0.len(),
                corpus[best_j].0.len()
            );
        }
    }
    if n_corrupt == 0 {
        eprintln!("  (clean run — no corrupt entities this time)");
    }
}
