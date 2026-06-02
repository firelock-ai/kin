// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC
//
// Direct forward-pass timing + host-stall profiler for the Metal embedder.
//
// This is a daemon-free, HTTP-free micro-benchmark: it loads the real
// SweRankEmbed-Small model from /tmp/swerank and runs `forward` over a fixed
// set of synthetic token sequences at representative code-entity lengths,
// reporting:
//   - end-to-end ent/s (entities embedded per wall-clock second)
//   - the host-stall split: wall-clock spent blocked in commit+wait vs. the
//     rest of the forward pass (CPU glue + buffer copies + scheduling)
//   - GPU command-buffer submissions per forward pass
//
// The split CONFIRMS whether the embedder is stall-bound (host idle, waiting on
// serialized GPU round-trips) or kernel-bound (GPU genuinely busy). Run with:
//
//   KIN_INFER_METAL_PROFILE=1 cargo test -p kin-infer --features metal \
//       --test embed_speed_profile -- --nocapture
//
// It skips cleanly when the model is absent so it never breaks `cargo test`.

#![cfg(feature = "metal")]

use std::fs;
use std::path::Path;
use std::time::Instant;

use kin_infer::metal_backend;
use kin_infer::{BertConfig, BertModel};

const MODEL_DIR: &str = "/tmp/swerank";

/// Build a deterministic, valid token-id sequence of length `len`. Token ids
/// are kept inside a conservative vocab band so the embedding lookup never
/// indexes out of bounds, with an attention mask that is all-ones (no padding)
/// so every position participates — the worst case for the attention kernels.
fn synth_sequence(len: usize, salt: u32) -> (Vec<u32>, Vec<u32>) {
    let ids: Vec<u32> = (0..len)
        .map(|i| {
            let h = (i as u32)
                .wrapping_mul(2654435761)
                .wrapping_add(salt.wrapping_mul(40503));
            // Keep well within a typical BERT/nomic vocab (>30k); avoid 0 (often [PAD]).
            1 + (h % 20000)
        })
        .collect();
    let mask = vec![1u32; len];
    (ids, mask)
}

/// Embed one sequence through the real model forward pass.
fn embed_one(model: &BertModel, ids: &[u32], mask: &[u32]) -> Vec<f32> {
    model
        .forward(&[ids.to_vec()], &[mask.to_vec()])
        .expect("forward")
        .into_iter()
        .next()
        .expect("one embedding")
}

#[test]
fn metal_embed_forward_profile() {
    let dir = Path::new(MODEL_DIR);
    if !dir.join("model.safetensors").exists() {
        eprintln!(
            "SKIP: model not found at {MODEL_DIR} (model.safetensors absent); \
             skipping embed-speed profile."
        );
        return;
    }

    let cfg_json = fs::read_to_string(dir.join("config.json")).expect("read config.json");
    let config: BertConfig = serde_json::from_str(&cfg_json).expect("parse config.json");
    let hidden = config.hidden_size;
    let layers = config.num_hidden_layers;
    let model = BertModel::load(&dir.join("model.safetensors"), config).expect("load model");

    eprintln!(
        "\n=== Metal embed forward-pass profile ===\n\
         backend={}  hidden={hidden}  layers={layers}",
        model.backend()
    );

    // Representative spread of real code-entity token lengths. Most code
    // entities are short-to-medium; a few are long. These bracket the regime
    // the indexer actually feeds the embedder.
    let seq_lens: &[usize] = &[32, 64, 128, 256, 512];
    let per_len = 8usize; // entities per length bucket
    let mut corpus: Vec<(Vec<u32>, Vec<u32>)> = Vec::new();
    for (bucket, &len) in seq_lens.iter().enumerate() {
        for j in 0..per_len {
            corpus.push(synth_sequence(len, (bucket * 1000 + j) as u32));
        }
    }
    let total = corpus.len();

    // Warm-up: first forward pass triggers weight-buffer caching on the GPU and
    // shader pipeline warm-up; excluding it keeps the steady-state number honest.
    let (wids, wmask) = &corpus[0];
    let warm = embed_one(&model, wids, wmask);
    assert_eq!(warm.len(), hidden, "warm-up embedding dim");
    assert!(warm.iter().all(|x| x.is_finite()), "warm-up produced non-finite");

    // Within-process determinism guard. The very first GPU forward after load is
    // a cold pass (pipeline/shader warm-up, first weight-cache population) and may
    // differ from the steady state, so we compare two *post-warm* passes: the
    // fused/pipelined command buffers must never read an intermediate the GPU
    // hasn't finished writing, so two steady-state embeds of the same text must be
    // bit-identical. (Cross-process float-sum ordering is a separate, known
    // effect handled elsewhere.)
    let steady1 = embed_one(&model, wids, wmask);
    let steady2 = embed_one(&model, wids, wmask);
    assert_eq!(
        steady1, steady2,
        "non-deterministic embedding within one process — a pipelined command \
         buffer is likely reading an intermediate before the GPU finished it"
    );

    // Timed region: reset the host-stall accumulators, embed the whole corpus,
    // measure wall-clock and stall.
    metal_backend::reset_profile();
    let start = Instant::now();
    let mut checksum = 0.0f64;
    for (ids, mask) in &corpus {
        let v = embed_one(&model, ids, mask);
        checksum += v[0] as f64; // keep the optimizer honest
    }
    let wall = start.elapsed();
    let stall_ns = metal_backend::profile_stall_nanos();
    let submissions = metal_backend::profile_submissions();

    let wall_s = wall.as_secs_f64();
    let stall_s = stall_ns as f64 / 1e9;
    let rest_s = (wall_s - stall_s).max(0.0);
    let ent_per_s = total as f64 / wall_s;
    let stall_pct = if wall_s > 0.0 { stall_s / wall_s * 100.0 } else { 0.0 };
    let subs_per_fwd = submissions as f64 / total as f64;

    eprintln!(
        "\nentities={total}  wall={wall_s:.3}s  ent/s={ent_per_s:.2}  (checksum={checksum:.3})"
    );
    eprintln!(
        "host-stall (commit+wait)  = {stall_s:.3}s  ({stall_pct:.1}% of wall)"
    );
    eprintln!(
        "rest (CPU glue + copies)  = {rest_s:.3}s  ({:.1}% of wall)",
        100.0 - stall_pct
    );
    eprintln!(
        "GPU submissions = {submissions}  ->  {subs_per_fwd:.1} commit+wait per forward pass"
    );

    if submissions == 0 {
        eprintln!(
            "\nNOTE: 0 submissions recorded — set KIN_INFER_METAL_PROFILE=1 to enable the \
             stall profiler (the timing/ent-s numbers above are still valid)."
        );
    } else if stall_pct >= 50.0 {
        eprintln!(
            "\nVERDICT: STALL-BOUND ({stall_pct:.0}% of wall in commit+wait, \
             {subs_per_fwd:.0} round-trips/forward) -> command-buffer pipelining is the lever."
        );
    } else {
        eprintln!(
            "\nVERDICT: not stall-dominated ({stall_pct:.0}% in commit+wait) -> \
             kernel/copy-bound; pipelining helps less, evaluate kernel-level work."
        );
    }

    // --- GPU saturation probe: batch=1 vs batched throughput ---
    // If batching N inputs into one forward pass beats N separate batch=1 passes
    // on a per-entity basis, the GPU was UNDERFILLED at batch=1 (a 16x16 tile on a
    // single short sequence does not occupy the M5 Max GPU). The batched path
    // packs batch_size x num_heads independent attention heads and batch_size x
    // seq_len rows through the projection/FFN matmuls, raising occupancy.
    eprintln!("\n=== GPU saturation probe (batch=1 vs batched) ===");
    eprintln!("rayon threads = {}", rayon::current_num_threads());
    let probe_len = 128usize;
    let probe_n = 16usize;
    let batch: Vec<(Vec<u32>, Vec<u32>)> =
        (0..probe_n).map(|j| synth_sequence(probe_len, 7000 + j as u32)).collect();
    let ids_b: Vec<Vec<u32>> = batch.iter().map(|(i, _)| i.clone()).collect();
    let masks_b: Vec<Vec<u32>> = batch.iter().map(|(_, m)| m.clone()).collect();

    // warm both paths
    let _ = model.forward_batched(&ids_b, &masks_b).unwrap();
    let _ = embed_one(&model, &ids_b[0], &masks_b[0]);

    let t_single = Instant::now();
    for (ids, mask) in &batch {
        let _ = embed_one(&model, ids, mask);
    }
    let single_s = t_single.elapsed().as_secs_f64();

    let t_batched = Instant::now();
    let _ = model.forward_batched(&ids_b, &masks_b).unwrap();
    let batched_s = t_batched.elapsed().as_secs_f64();

    let single_eps = probe_n as f64 / single_s;
    let batched_eps = probe_n as f64 / batched_s;
    let speedup = batched_eps / single_eps.max(1e-9);
    eprintln!(
        "len={probe_len} x{probe_n}: batch=1 {single_eps:.1} ent/s  |  batched {batched_eps:.1} ent/s  |  {speedup:.2}x"
    );
    if speedup >= 1.3 {
        eprintln!(
            "VERDICT: GPU UNDERFILLED at batch=1 ({speedup:.1}x from batching) -> batching raises occupancy; \
             the embedder should batch entities through one forward pass."
        );
    } else {
        eprintln!(
            "VERDICT: batching gives only {speedup:.2}x -> batch=1 already near-occupies the GPU at this shape."
        );
    }
    eprintln!();
}
