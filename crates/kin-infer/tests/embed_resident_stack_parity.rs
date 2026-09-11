// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC
//
// Bit-identity gate for the whole-stack GPU-resident forward pass. Keeping the
// residual activations on-device across every transformer layer (one host
// synchronization instead of one per layer) must NOT change any embedding value:
// same kernels, same accumulation order, only residency/timing differ.
//
// This loads the real SweRankEmbed-Small model and encodes a batch twice:
//   - reference: per-layer accelerator path (KIN_INFER_NO_RESIDENT_STACK=1)
//   - candidate: whole-stack resident path (default)
// then asserts the hidden states AND the pooled embeddings are byte-for-byte
// identical. A second resident run guards against residency-induced
// nondeterminism. The model lives outside the repo; the test skips when absent.
//
//   cargo test --features metal --release --test embed_resident_stack_parity -- --nocapture
#![cfg(feature = "metal")]

use kin_infer::{BertConfig, BertModel};
use std::fs;
use std::path::Path;

// Candidate model dirs, in order. The first whose config.json deserializes into a
// BertConfig and has a model.safetensors is used. Both are nomic_bert (RoPE +
// SwiGLU + pre-LN), the M1 embedder family the resident stack must not perturb.
const MODEL_DIRS: &[&str] = &["/tmp/nomic", "/tmp/swerank"];

fn load_probe_model() -> Option<(String, BertModel)> {
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
            eprintln!("SKIP-DIR: {d}/config.json does not deserialize into BertConfig");
            continue;
        };
        match BertModel::load(&weights, config) {
            Ok(model) => return Some((d, model)),
            Err(e) => eprintln!("SKIP-DIR: {d} failed to load ({e})"),
        }
    }
    None
}

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

fn first_bit_mismatch(a: &[f32], b: &[f32]) -> Option<(usize, f32, f32, usize)> {
    let mut count = 0usize;
    let mut first = None;
    for (idx, (x, y)) in a.iter().zip(b.iter()).enumerate() {
        if x.to_bits() != y.to_bits() {
            count += 1;
            if first.is_none() {
                first = Some((idx, *x, *y));
            }
        }
    }
    first.map(|(idx, x, y)| (idx, x, y, count))
}

#[test]
fn resident_stack_is_bit_identical() {
    if cfg!(debug_assertions) {
        eprintln!("!!! REFUSING parity from a debug build — use --release !!!");
        return;
    }
    let Some((model_dir, model)) = load_probe_model() else {
        eprintln!("SKIP: no loadable nomic_bert model found in {MODEL_DIRS:?}");
        return;
    };
    eprintln!("model={model_dir} backend={}", model.backend());

    // A batch of several varied-length sequences exercises the batched stack
    // (batch_size == 1 routes to the single-input `forward`, a different path).
    let lens = [64usize, 48, 57, 33, 64, 40];
    let mut ids = Vec::new();
    let mut masks = Vec::new();
    for (k, &len) in lens.iter().enumerate() {
        let (i, m) = synth(len, 100 + k as u32);
        ids.push(i);
        masks.push(m);
    }

    // Reference: per-layer accelerator path (resident stack disabled).
    std::env::set_var("KIN_INFER_NO_RESIDENT_STACK", "1");
    let (ref_hidden, _, ref_max) = model.encode_batched(&ids, &masks).expect("ref encode");
    let ref_embed = model.forward_batched(&ids, &masks).expect("ref pooled");

    // Candidate: whole-stack GPU-resident path (default).
    std::env::remove_var("KIN_INFER_NO_RESIDENT_STACK");
    let (res_hidden, _, res_max) = model.encode_batched(&ids, &masks).expect("resident encode");
    let res_embed = model
        .forward_batched(&ids, &masks)
        .expect("resident pooled");

    // Self-determinism of the resident path: a second run must match the first.
    let (res_hidden2, _, _) = model
        .encode_batched(&ids, &masks)
        .expect("resident encode 2");

    assert_eq!(ref_max, res_max, "max_len differs between paths");

    let r = ref_hidden.as_slice().expect("contiguous");
    let c = res_hidden.as_slice().expect("contiguous");
    let c2 = res_hidden2.as_slice().expect("contiguous");
    assert_eq!(r.len(), c.len(), "hidden length differs between paths");

    if let Some((idx, a, b, count)) = first_bit_mismatch(c, c2) {
        panic!(
            "resident path is nondeterministic: {count}/{} hidden elements differ across two runs; \
             first at {idx}: {a:.9} vs {b:.9} (bits {:#010x} vs {:#010x})",
            c.len(),
            a.to_bits(),
            b.to_bits()
        );
    }

    if let Some((idx, a, b, count)) = first_bit_mismatch(r, c) {
        panic!(
            "resident stack diverged from per-layer path: {count}/{} hidden elements differ; \
             first at {idx}: {a:.9} vs {b:.9} (bits {:#010x} vs {:#010x})",
            r.len(),
            a.to_bits(),
            b.to_bits()
        );
    }

    // Pooled + L2-normalized embeddings (the public output) must match too.
    assert_eq!(ref_embed.len(), res_embed.len(), "embedding count differs");
    for (e, (re, ce)) in ref_embed.iter().zip(res_embed.iter()).enumerate() {
        assert_eq!(re.len(), ce.len(), "embedding {e} dim differs");
        if let Some((idx, a, b, count)) = first_bit_mismatch(re, ce) {
            panic!(
                "resident pooled embedding {e} diverged: {count}/{} dims differ; \
                 first at {idx}: {a:.9} vs {b:.9}",
                re.len()
            );
        }
    }

    eprintln!(
        "[resident-parity] {} hidden elements + {} embeddings bit-identical (resident == per-layer, and resident self-deterministic)",
        r.len(),
        res_embed.len()
    );
}

// Opt-in throughput comparison (resident vs per-layer round-trip):
//   cargo test --features metal --release --test embed_resident_stack_parity \
//     -- --ignored --nocapture
#[test]
#[ignore]
fn resident_stack_throughput() {
    use std::time::Instant;

    if cfg!(debug_assertions) {
        eprintln!("!!! REFUSING perf numbers from a debug build — use --release !!!");
        return;
    }
    let Some((model_dir, model)) = load_probe_model() else {
        eprintln!("SKIP: no loadable nomic_bert model found in {MODEL_DIRS:?}");
        return;
    };
    eprintln!("model={model_dir} backend={}", model.backend());

    let batch = 32usize;
    let len = 128usize;
    let mut ids = Vec::new();
    let mut masks = Vec::new();
    for k in 0..batch {
        let (i, m) = synth(len, 7 + k as u32);
        ids.push(i);
        masks.push(m);
    }

    let run = |disabled: bool| -> f64 {
        if disabled {
            std::env::set_var("KIN_INFER_NO_RESIDENT_STACK", "1");
        } else {
            std::env::remove_var("KIN_INFER_NO_RESIDENT_STACK");
        }
        // Warm up (caches weights/buffers), then time a fixed number of batches.
        let _ = model.forward_batched(&ids, &masks).expect("warmup");
        let iters = 20usize;
        let t0 = Instant::now();
        for _ in 0..iters {
            let _ = model.forward_batched(&ids, &masks).expect("encode");
        }
        let secs = t0.elapsed().as_secs_f64();
        (iters * batch) as f64 / secs
    };

    let per_layer = run(true);
    let resident = run(false);
    std::env::remove_var("KIN_INFER_NO_RESIDENT_STACK");
    let delta = (resident / per_layer - 1.0) * 100.0;
    eprintln!(
        "[resident-throughput] batch={batch} len={len}: per_layer={per_layer:.1} ent/s, resident={resident:.1} ent/s, delta={delta:+.1}%"
    );
}
