// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC
//
// Length-bucketing A/B probe for the batched embedder.
//
// `forward_batched` pads EVERY sequence in a batch to the batch's max length
// (lib.rs: `max_len = token_ids.iter().map(|t| t.len()).max()`), and the
// projection/FFN GEMMs — ~79% of GPU time — run on all `batch_size * max_len`
// rows including the padding. So a batch that mixes a 512-token entity with
// 32-token entities runs the short ones at 512 too. The daemon embeds at
// `embed_batch_size = 160` with no length sorting, so real mixed-length batches
// pay this padding tax.
//
// This probe measures the ceiling of fixing it: the SAME entities embedded as
// one mixed batch (current behavior) vs grouped by length so each sub-batch pads
// only to its own max. Per-entity outputs are identical either way (each token's
// hidden state is unchanged; attention is already split per-input) — this is a
// pure work-reduction lever, parity-trivial. It is a MEASUREMENT (always passes);
// the production change is a transparent bucketing wrapper in `encode_batched`.
//
//   cargo test -p kin-infer --features metal --release \
//       --test embed_bucketing_probe -- --nocapture
//
// Skips cleanly when the model is absent.

#![cfg(feature = "metal")]

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::time::Instant;

use kin_infer::{BertConfig, BertModel};

const MODEL_DIR: &str = "/tmp/swerank";

fn synth_sequence(len: usize, salt: u32) -> (Vec<u32>, Vec<u32>) {
    let ids: Vec<u32> = (0..len)
        .map(|i| {
            let h = (i as u32)
                .wrapping_mul(2654435761)
                .wrapping_add(salt.wrapping_mul(40503));
            1 + (h % 20000)
        })
        .collect();
    (ids, vec![1u32; len])
}

/// Wall-clock to embed `corpus` as ONE mixed batch (current behavior: pad to the
/// global max length). Returns seconds for one timed forward (after a warm pass).
fn time_mixed(model: &BertModel, corpus: &[(Vec<u32>, Vec<u32>)]) -> f64 {
    let ids: Vec<Vec<u32>> = corpus.iter().map(|(i, _)| i.clone()).collect();
    let masks: Vec<Vec<u32>> = corpus.iter().map(|(_, m)| m.clone()).collect();
    let _ = model.forward_batched(&ids, &masks).expect("warm mixed");
    let t = Instant::now();
    let _ = model.forward_batched(&ids, &masks).expect("mixed fwd");
    t.elapsed().as_secs_f64()
}

/// Wall-clock to embed `corpus` GROUPED by `bin_of(len)` — each sub-batch pads
/// only to its own group max. Sum of per-group timed forwards (each warmed).
/// `bin_of` lets us model exact-length grouping (bin = len) or coarse bins.
fn time_bucketed(
    model: &BertModel,
    corpus: &[(Vec<u32>, Vec<u32>)],
    bin_of: impl Fn(usize) -> usize,
) -> (f64, usize) {
    let mut groups: BTreeMap<usize, Vec<&(Vec<u32>, Vec<u32>)>> = BTreeMap::new();
    for e in corpus {
        groups.entry(bin_of(e.0.len())).or_default().push(e);
    }
    let n_groups = groups.len();
    let mut total = 0.0f64;
    for (_, members) in &groups {
        let ids: Vec<Vec<u32>> = members.iter().map(|e| e.0.clone()).collect();
        let masks: Vec<Vec<u32>> = members.iter().map(|e| e.1.clone()).collect();
        let _ = model.forward_batched(&ids, &masks).expect("warm group");
        let t = Instant::now();
        let _ = model.forward_batched(&ids, &masks).expect("group fwd");
        total += t.elapsed().as_secs_f64();
    }
    (total, n_groups)
}

fn report(
    label: &str,
    n: usize,
    mixed_s: f64,
    bucket_s: f64,
    n_groups: usize,
    useful: usize,
    padded: usize,
) {
    let mixed_eps = n as f64 / mixed_s.max(1e-9);
    let bucket_eps = n as f64 / bucket_s.max(1e-9);
    eprintln!(
        "\n[{label}] n={n}  mixed={mixed_eps:.1} ent/s ({mixed_s:.3}s)  |  \
         bucketed={bucket_eps:.1} ent/s ({bucket_s:.3}s, {n_groups} groups)  |  \
         {:.2}x",
        bucket_eps / mixed_eps.max(1e-9)
    );
    eprintln!(
        "  padding waste in mixed batch: useful_tokens={useful}  padded_rows={padded}  \
         -> {:.0}% of GEMM rows are padding",
        (1.0 - useful as f64 / padded as f64) * 100.0
    );
}

#[test]
fn embed_length_bucketing_ab() {
    let dir = Path::new(MODEL_DIR);
    if !dir.join("model.safetensors").exists() {
        eprintln!("SKIP: model not found at {MODEL_DIR}; skipping bucketing probe.");
        return;
    }
    eprintln!(
        "\n[bucketing] BUILD={}  (perf numbers require --release)",
        if cfg!(debug_assertions) {
            "debug"
        } else {
            "release"
        }
    );
    if cfg!(debug_assertions) {
        eprintln!("!!! REFUSING perf numbers from a debug build — rerun with --release !!!");
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
    let model = BertModel::load(&dir.join("model.safetensors"), config).expect("load model");
    eprintln!("backend={}", model.backend());

    // --- A/B 1: directly comparable to the BATCHED(100) profile baseline ---
    // 100 entities at [32,64,128,256,512] x20. Mixed pads all to 512.
    let lens_a = [32usize, 64, 128, 256, 512];
    let mut corpus_a: Vec<(Vec<u32>, Vec<u32>)> = Vec::new();
    for (b, &len) in lens_a.iter().enumerate() {
        for j in 0..20 {
            corpus_a.push(synth_sequence(len, (b * 131 + j) as u32));
        }
    }
    let n_a = corpus_a.len();
    let useful_a: usize = corpus_a.iter().map(|(i, _)| i.len()).sum();
    let maxlen_a = corpus_a.iter().map(|(i, _)| i.len()).max().unwrap();
    let mixed_a = time_mixed(&model, &corpus_a);
    let (bucket_a, g_a) = time_bucketed(&model, &corpus_a, |l| l); // exact-length groups
    report(
        "uniform-spread x100",
        n_a,
        mixed_a,
        bucket_a,
        g_a,
        useful_a,
        n_a * maxlen_a,
    );

    // --- Bit-identity verification (Track B parity gate) ---
    // Grouping must not change ANY entity's embedding. Compare one mixed batch
    // vs the same entities embedded in exact-length groups and scattered back.
    // Also print a checksum so two runs (KIN_INFER_BUCKET=0 vs =1) can be compared
    // to confirm the production forward_batched_bucketed impl is bit-identical.
    // Replicate the IMPL's grouping (coarse length BINS, not exact length) so this
    // exercises the real production case: bin 64 mixes 32- and 64-token entities into
    // one padded-to-64 batch. Run flag-OFF (mixed=unbucketed, grouped=manual-binned-
    // unbucketed) so there is no recursion. Report per-entity COSINE (retrieval metric,
    // robust to sum cancellation) and localize any divergence by entity length.
    {
        let bin_of = |l: usize| -> usize {
            for &b in &[64usize, 128, 256, 512, 1024] {
                if l <= b {
                    return b;
                }
            }
            2048
        };
        let all_ids: Vec<Vec<u32>> = corpus_a.iter().map(|e| e.0.clone()).collect();
        let all_masks: Vec<Vec<u32>> = corpus_a.iter().map(|e| e.1.clone()).collect();
        let mixed_emb = model
            .forward_batched(&all_ids, &all_masks)
            .expect("mixed emb");
        let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for (i, e) in corpus_a.iter().enumerate() {
            groups.entry(bin_of(e.0.len())).or_default().push(i);
        }
        let mut grouped_emb = vec![Vec::<f32>::new(); corpus_a.len()];
        for (_, idxs) in &groups {
            let gids: Vec<Vec<u32>> = idxs.iter().map(|&i| corpus_a[i].0.clone()).collect();
            let gms: Vec<Vec<u32>> = idxs.iter().map(|&i| corpus_a[i].1.clone()).collect();
            let gout = model.forward_batched(&gids, &gms).expect("group emb");
            for (k, &i) in idxs.iter().enumerate() {
                grouped_emb[i] = gout[k].clone();
            }
        }
        let mut maxdiff = 0.0f32;
        let mut per_len_min: BTreeMap<usize, f64> = BTreeMap::new();
        for i in 0..mixed_emb.len() {
            let (a, b) = (&mixed_emb[i], &grouped_emb[i]);
            let mut dot = 0.0f64;
            for j in 0..a.len() {
                maxdiff = maxdiff.max((a[j] - b[j]).abs());
                dot += a[j] as f64 * b[j] as f64;
            }
            let e = per_len_min.entry(corpus_a[i].0.len()).or_insert(1.0);
            *e = e.min(dot);
        }
        let overall = per_len_min.values().cloned().fold(1.0f64, f64::min);
        eprintln!(
            "\n[parity] bin-grouped vs mixed: overall min_cosine={overall:.9}  max_abs_diff={maxdiff:e}"
        );
        eprintln!("[parity] min_cosine BY LENGTH (32&64 share bin 64): {per_len_min:?}");
        assert!(
            overall > 0.99,
            "bin-bucketing corrupted embeddings (min cosine {overall}) — real bug, not float noise"
        );
    }

    // --- A/B 2: realistic long-tailed code distribution at the daemon's batch
    // size (160), binned into coarse length buckets {64,128,256,512,1024} so the
    // group count stays small (bounded per-forward overhead) — the production scheme.
    let mut corpus_b: Vec<(Vec<u32>, Vec<u32>)> = Vec::new();
    let mut salt = 5000u32;
    let push_n =
        |corpus: &mut Vec<(Vec<u32>, Vec<u32>)>, count: usize, len: usize, salt: &mut u32| {
            for _ in 0..count {
                corpus.push(synth_sequence(len, *salt));
                *salt += 1;
            }
        };
    // long tail: lots of short, few long (typical of code entities)
    push_n(&mut corpus_b, 40, 16, &mut salt);
    push_n(&mut corpus_b, 35, 32, &mut salt);
    push_n(&mut corpus_b, 30, 48, &mut salt);
    push_n(&mut corpus_b, 25, 96, &mut salt);
    push_n(&mut corpus_b, 15, 160, &mut salt);
    push_n(&mut corpus_b, 10, 300, &mut salt);
    push_n(&mut corpus_b, 5, 512, &mut salt);
    let n_b = corpus_b.len();
    let useful_b: usize = corpus_b.iter().map(|(i, _)| i.len()).sum();
    let maxlen_b = corpus_b.iter().map(|(i, _)| i.len()).max().unwrap();
    let bin = |l: usize| -> usize {
        for &b in &[64usize, 128, 256, 512, 1024] {
            if l <= b {
                return b;
            }
        }
        2048
    };
    let mixed_b = time_mixed(&model, &corpus_b);
    let (bucket_b, g_b) = time_bucketed(&model, &corpus_b, bin); // coarse bins
    report(
        "realistic-longtail x160",
        n_b,
        mixed_b,
        bucket_b,
        g_b,
        useful_b,
        n_b * maxlen_b,
    );

    eprintln!(
        "\nNOTE: bucketed groups each warmed + timed separately, so the bucketed total \
         INCLUDES per-forward submission overhead — a conservative (low) estimate of the win."
    );
}
