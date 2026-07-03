// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC
//
// Real-path embed throughput profiler for the batch-token budget.
//
// Drives the production `CodeEmbedder::embed_batch` path over a deterministic,
// code-shaped length distribution and reports, via `KIN_EMBED_BATCH_TRACE`, the
// effective batch budget the dispatcher actually used, the padded-vs-real work
// each GPU dispatch carried, and the forward wall. Run one process per budget to
// isolate the batch-token budget as a single variable:
//
//   # proof budget
//   KIN_EMBED_CACHE=0 KIN_INIT_WARM_CACHE=0 KIN_EMBED_BATCH_TRACE=1 \
//   KIN_EMBED_MAX_BATCH_TOKENS=16384 \
//   cargo test -p kin-db --features metal --test embed_budget_profile -- --ignored --nocapture
//
//   # throughput budget (this box: 65536 * scale4 = 262144)
//   KIN_EMBED_CACHE=0 KIN_INIT_WARM_CACHE=0 KIN_EMBED_BATCH_TRACE=1 \
//   KIN_EMBED_MAX_BATCH_TOKENS=262144 \
//   cargo test -p kin-db --features metal --test embed_budget_profile -- --ignored --nocapture
//
// The corpus size is `KIN_EMBED_PROFILE_N` (default 2000). It skips cleanly when
// no local accelerator is available so it never breaks a CPU `cargo test`.

#![cfg(feature = "metal")]

use std::time::Instant;

use kin_db::embed::batch_trace;
use kin_db::CodeEmbedder;

/// SplitMix64 — deterministic so both budget arms embed byte-identical corpora.
fn next(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// A code-entity-shaped target token length: a long-tailed mixture from short
/// signatures to occasional whole-file bodies at the 2048-token cap.
fn target_len(state: &mut u64) -> usize {
    let bucket = next(state) % 1000;
    if bucket < 550 {
        8 + (next(state) % 33) as usize // 55%: 8..40   (signatures, small methods)
    } else if bucket < 850 {
        40 + (next(state) % 111) as usize // 30%: 40..150 (functions)
    } else if bucket < 970 {
        150 + (next(state) % 351) as usize // 12%: 150..500 (large functions)
    } else {
        500 + (next(state) % 1549) as usize // 3%: 500..2048 (files / very long)
    }
}

/// Build a whitespace-tokenizing-friendly text of roughly `tokens` words drawn
/// from a small code vocabulary, so the tokenizer yields a length near `tokens`.
fn make_text(tokens: usize, state: &mut u64) -> String {
    const VOCAB: &[&str] = &[
        "fn", "let", "self", "return", "match", "impl", "struct", "for", "while", "if", "else",
        "token", "batch", "result", "vec", "index", "node", "graph", "query", "embed", "cache",
        "score", "value", "field", "async", "await", "mut", "ref", "trait", "enum", "where",
        "const", "static", "pub", "use", "mod", "type", "dyn", "move", "loop", "iter", "map",
    ];
    let mut text = String::with_capacity(tokens * 6);
    for i in 0..tokens.max(1) {
        if i > 0 {
            text.push(' ');
        }
        text.push_str(VOCAB[(next(state) as usize) % VOCAB.len()]);
    }
    text
}

#[test]
#[ignore = "GPU embed micro-benchmark; run explicitly under the kin-lane GPU lock"]
fn embed_budget_profile() {
    let n: usize = std::env::var("KIN_EMBED_PROFILE_N")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2000);

    let embedder = match CodeEmbedder::new() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("SKIP: could not build embedder: {e}");
            return;
        }
    };
    if !embedder.uses_local_accelerator() {
        eprintln!(
            "SKIP: needs a local accelerator; got {:?}",
            embedder.local_backend()
        );
        return;
    }
    eprintln!("backend={:?} n={n}", embedder.local_backend());

    // Warm up: model load, shader compile, first-dispatch costs — excluded from
    // the measured region and its trace totals.
    let mut warm_state = 0xC0FF_EE00_1243_0001u64;
    let warm: Vec<String> = (0..96)
        .map(|_| make_text(target_len(&mut warm_state), &mut warm_state))
        .collect();
    embedder.embed_batch(&warm).expect("warmup embed failed");
    batch_trace::reset();

    // Deterministic corpus (identical bytes across budget arms).
    let mut state = 0x1234_5678_9ABC_DEF0u64;
    let texts: Vec<String> = (0..n)
        .map(|_| make_text(target_len(&mut state), &mut state))
        .collect();

    let start = Instant::now();
    let vectors = embedder.embed_batch(&texts).expect("corpus embed failed");
    let wall = start.elapsed();
    assert_eq!(vectors.len(), n, "embedded vector count mismatch");

    let s = batch_trace::snapshot();
    let wall_s = wall.as_secs_f64();
    let ent_per_s = n as f64 / wall_s;
    let fwd_s = s.forward_secs();
    let non_forward_s = (wall_s - fwd_s).max(0.0);

    eprintln!("==================== EMBED BUDGET PROFILE ====================");
    eprintln!("n={n} wall={wall_s:.2}s ent_per_s={ent_per_s:.2}");
    eprintln!(
        "effective_budget: max_batch_tokens={} max_attention_area={}",
        s.max_tokens, s.max_attention_area
    );
    eprintln!(
        "batches={} mean_count={:.1} max_count={} max_longest={}",
        s.batches,
        s.mean_count(),
        s.max_count,
        s.max_longest
    );
    eprintln!(
        "tokens: real={} padded={} waste={:.2}x",
        s.real_tokens,
        s.padded_tokens,
        s.token_waste()
    );
    eprintln!(
        "attention_area: real={} padded={} waste={:.2}x",
        s.real_area,
        s.padded_area,
        s.area_waste()
    );
    eprintln!(
        "forward_wall={fwd_s:.2}s ({:.1}% of total) | non_forward={non_forward_s:.2}s (tokenize+pool+glue)",
        100.0 * fwd_s / wall_s.max(1e-9)
    );
    eprintln!("=============================================================");
}
