// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC
//
// Run-to-run byte-identity guard for the no-lever Metal embed.
//
// Embeds a fixed, real-corpus-shape batch through the default (no-lever) forward
// path and asserts the pooled embeddings are byte-identical when the same input
// is embedded twice in one process. It also prints a stable digest of the kvec
// so two separate PROCESS runs can be compared for the cross-process determinism
// class (Rust HashMap reseeds per process; only an order-stable path yields the
// same bits across runs):
//
//   KIN_RESOURCE_PROFILE=proof KIN_INFER_PROBE_MODEL_DIR=/tmp/swerank \
//     cargo test -p kin-infer --release --features metal \
//       --test embed_byte_determinism -- --nocapture
//   # run twice; EMBED_KVEC_DIGEST must match across the two processes.
//
// Skips cleanly when no nomic_bert model is present, so it never breaks the suite.

#![cfg(feature = "metal")]

use kin_infer::{BertConfig, BertModel};
use std::fs;
use std::path::Path;

const MODEL_DIRS: &[&str] = &["/tmp/swerank", "/tmp/nomic"];

fn load_model() -> Option<BertModel> {
    let mut dirs: Vec<String> = Vec::new();
    if let Ok(d) = std::env::var("KIN_INFER_PROBE_MODEL_DIR") {
        dirs.push(d);
    }
    dirs.extend(MODEL_DIRS.iter().map(|s| s.to_string()));
    for d in dirs {
        let dir = Path::new(&d);
        let weights = dir.join("model.safetensors");
        let cfg_path = dir.join("config.json");
        if !weights.exists() || !cfg_path.exists() {
            continue;
        }
        let Ok(cfg_json) = fs::read_to_string(&cfg_path) else {
            continue;
        };
        let Ok(config) = serde_json::from_str::<BertConfig>(&cfg_json) else {
            continue;
        };
        if let Ok(model) = BertModel::load(&weights, config) {
            return Some(model);
        }
    }
    None
}

/// Deterministic token-id sequence inside a conservative vocab band, avoiding 0.
fn synth(len: usize, salt: u32) -> Vec<u32> {
    (0..len)
        .map(|i| {
            1 + ((i as u32)
                .wrapping_mul(2654435761)
                .wrapping_add(salt.wrapping_mul(40503))
                % 20000)
        })
        .collect()
}

/// FNV-1a over every embedding's f32 bit pattern — order-sensitive, so any byte
/// difference (or row reordering) changes the digest. Stable across processes.
fn digest(embeddings: &[Vec<f32>]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for emb in embeddings {
        for &x in emb {
            for b in x.to_bits().to_le_bytes() {
                h ^= b as u64;
                h = h.wrapping_mul(0x100000001b3);
            }
        }
    }
    h
}

/// Representative code-entity length distribution: short-heavy with a few long,
/// including a non-tile-aligned ragged count (37) and the lengths the indexer
/// actually feeds the embedder.
fn corpus() -> (Vec<Vec<u32>>, Vec<Vec<u32>>) {
    let lens: [usize; 11] = [16, 24, 32, 37, 48, 64, 100, 128, 256, 384, 512];
    let ids: Vec<Vec<u32>> = lens
        .iter()
        .enumerate()
        .map(|(i, &l)| synth(l, i as u32 + 1))
        .collect();
    let masks: Vec<Vec<u32>> = lens.iter().map(|&l| vec![1u32; l]).collect();
    (ids, masks)
}

#[test]
fn no_lever_embed_is_byte_identical() {
    if cfg!(debug_assertions) {
        eprintln!("SKIP: run --release (debug Metal builds hit stale-binary bugs)");
        return;
    }
    let Some(model) = load_model() else {
        eprintln!("SKIP: no nomic_bert model in {MODEL_DIRS:?}");
        return;
    };
    let (ids, masks) = corpus();

    // Warm the pipeline/shader/weight-cache so the timed embeds are steady state.
    let _ = model.forward_batched(&ids, &masks).expect("warm");

    let a = model.forward_batched(&ids, &masks).expect("embed a");
    let b = model.forward_batched(&ids, &masks).expect("embed b");

    assert!(
        a.iter().flatten().all(|x| x.is_finite()),
        "embedding produced non-finite values"
    );
    // Same input, same backend/config, one process: must be bit-for-bit identical.
    assert!(
        a == b,
        "no-lever embed is NOT byte-identical run-to-run (within process)"
    );

    eprintln!(
        "EMBED_KVEC_DIGEST={:016x} entities={} dim={} backend={:?}",
        digest(&a),
        a.len(),
        a.first().map(|e| e.len()).unwrap_or(0),
        model.backend()
    );
}
