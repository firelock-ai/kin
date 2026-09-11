// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC
//
// Stage split for the batched embed forward (`KIN_INFER_STAGE_TIMINGS`).
//
// Validates the encode(device forward + readback) vs pool(host) split and shows
// the forward-level cost of padding directly: two batches carrying near-equal
// REAL token content but different padded widths. The wide (loosely packed)
// batch does far more device work for the same output — the mechanism a wide
// `KIN_EMBED_MAX_BATCH_TOKENS` budget triggers by packing broad length spans.
//
//   KIN_INFER_STAGE_TIMINGS=1 KIN_INFER_POOLED_OUTPUT=0 KIN_INFER_BUCKET=0 \
//   KIN_INFER_PROBE_MODEL_DIR=<hf-snapshot-with-config.json> \
//   cargo test -p kin-infer --release --features metal \
//       --test embed_stage_split -- --nocapture
//
// Skips cleanly when the model or an accelerator is unavailable.

#![cfg(feature = "metal")]

use std::fs;
use std::path::Path;
use std::time::Instant;

use kin_infer::{BertConfig, BertModel};

const MODEL_DIR: &str = "/tmp/swerank";

fn probe_model_dir() -> String {
    std::env::var("KIN_INFER_PROBE_MODEL_DIR").unwrap_or_else(|_| MODEL_DIR.to_string())
}

/// Deterministic in-band token ids of length `len`, all-ones mask (no padding
/// inside the sequence — the worst case for the attention kernels).
fn seq(len: usize, salt: u32) -> (Vec<u32>, Vec<u32>) {
    let ids: Vec<u32> = (0..len)
        .map(|i| 1 + ((i as u32).wrapping_mul(2654435761).wrapping_add(salt)) % 20000)
        .collect();
    (ids, vec![1u32; len])
}

fn encode_pool_ms() -> (f64, f64, u64) {
    let s = kin_infer::stage_timings_snapshot();
    (
        s.encode_nanos as f64 / 1.0e6,
        s.pool_nanos as f64 / 1.0e6,
        s.calls,
    )
}

#[test]
fn embed_stage_split_padding_cost() {
    if cfg!(debug_assertions) {
        eprintln!(
            "\n!!! REFUSING: timing is meaningless in a debug build — rerun with --release !!!"
        );
        return;
    }
    let model_dir = probe_model_dir();
    let dir = Path::new(&model_dir);
    if !dir.join("model.safetensors").exists() || !dir.join("config.json").exists() {
        eprintln!("SKIP: model.safetensors/config.json absent at {model_dir}");
        return;
    }
    let cfg_json = fs::read_to_string(dir.join("config.json")).expect("read config.json");
    let config: BertConfig = match serde_json::from_str(&cfg_json) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("SKIP: config.json not a loadable BertConfig ({e})");
            return;
        }
    };
    let model = BertModel::load(&dir.join("model.safetensors"), config).expect("load model");
    eprintln!("backend={}", model.backend());

    // Warm up (shader/pipeline compile, weight-cache population) — excluded.
    let (wid, wmask) = seq(64, 7);
    let warm = model
        .forward_batched(std::slice::from_ref(&wid), std::slice::from_ref(&wmask))
        .expect("warm");
    assert_eq!(warm.len(), 1);

    // TIGHT: 64 entities all length 64 → 4096 real tokens, padded width 64.
    let tight: Vec<(Vec<u32>, Vec<u32>)> = (0..64).map(|j| seq(64, 100 + j)).collect();
    let tight_ids: Vec<Vec<u32>> = tight.iter().map(|(i, _)| i.clone()).collect();
    let tight_mask: Vec<Vec<u32>> = tight.iter().map(|(_, m)| m.clone()).collect();

    // WIDE: 63 entities of length 8 + one of length 512 → 1016 real tokens, but a
    // single dispatch pads every row to 512 (32768 padded tokens). FEWER real
    // tokens, yet a far larger padded attention area.
    let mut wide: Vec<(Vec<u32>, Vec<u32>)> = (0..63).map(|j| seq(8, 200 + j)).collect();
    wide.push(seq(512, 999));
    let wide_ids: Vec<Vec<u32>> = wide.iter().map(|(i, _)| i.clone()).collect();
    let wide_mask: Vec<Vec<u32>> = wide.iter().map(|(_, m)| m.clone()).collect();

    let reps = 20;

    kin_infer::reset_stage_timings();
    let t = Instant::now();
    for _ in 0..reps {
        model
            .forward_batched(&tight_ids, &tight_mask)
            .expect("tight forward");
    }
    let tight_wall = t.elapsed().as_secs_f64();
    let (tight_enc, tight_pool, tight_calls) = encode_pool_ms();

    kin_infer::reset_stage_timings();
    let t = Instant::now();
    for _ in 0..reps {
        model
            .forward_batched(&wide_ids, &wide_mask)
            .expect("wide forward");
    }
    let wide_wall = t.elapsed().as_secs_f64();
    let (wide_enc, wide_pool, wide_calls) = encode_pool_ms();

    eprintln!("==================== EMBED STAGE SPLIT ====================");
    eprintln!(
        "TIGHT 64x64  real_tok=4096  padded_tok=4096  reps={reps} wall={tight_wall:.3}s \
         encode={tight_enc:.1}ms pool={tight_pool:.1}ms calls={tight_calls}"
    );
    eprintln!(
        "WIDE  63x8+512 real_tok=1016 padded_tok=32768 reps={reps} wall={wide_wall:.3}s \
         encode={wide_enc:.1}ms pool={wide_pool:.1}ms calls={wide_calls}"
    );
    if tight_enc > 0.0 {
        eprintln!(
            "wide/tight encode ratio={:.2}x  (WIDE has 4.0x fewer real tokens but 8.0x padded tokens)",
            wide_enc / tight_enc
        );
    }
    eprintln!("==========================================================");

    // The instrumentation must have populated both stages.
    assert!(tight_calls >= reps as u64 && wide_calls >= reps as u64);
    assert!(
        tight_enc > 0.0 && wide_enc > 0.0,
        "encode stage must be timed"
    );
}
