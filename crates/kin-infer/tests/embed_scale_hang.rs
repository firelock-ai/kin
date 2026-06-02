// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC
//
// Scale reproduction for the Metal fused-pipeline hang.
//
// The command-buffer pipelining (`fused_ffn_swiglu`, `rope_pair`) passes a
// small embed (~2 batches / ~232 entities) but stalls after many forward
// passes at large-repo scale (astropy: ~21k entities / ~109 batches). The hang
// is scale-dependent: it manifests only after hundreds of GPU command buffers
// have been vended, when the undrained autorelease pool retaining every
// completed command buffer/encoder backs the queue up against its in-flight
// cap.
//
// This test drives the real SweRankEmbed-Small forward pass `KIN_SCALE_FORWARDS`
// times (default 800) under a watchdog. If the embedder stalls, the watchdog
// fires and the test fails loudly with the forward index it died on, instead of
// hanging the whole suite. It is the fast in-process proxy for the astropy cold
// embed — seconds-to-minutes instead of a multi-GB daemon run.
//
// Run:
//   cargo test -p kin-infer --features metal --test embed_scale_hang -- --nocapture
//
// Skips cleanly when the model is absent.

#![cfg(feature = "metal")]

use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use kin_infer::{BertConfig, BertModel};

const MODEL_DIR: &str = "/tmp/swerank";

/// Deterministic token sequence of length `len`. Ids stay inside a conservative
/// vocab band so the embedding lookup never indexes out of bounds.
fn synth_sequence(len: usize, salt: u32) -> (Vec<u32>, Vec<u32>) {
    let ids: Vec<u32> = (0..len)
        .map(|i| {
            let h = (i as u32)
                .wrapping_mul(2654435761)
                .wrapping_add(salt.wrapping_mul(40503));
            1 + (h % 20000)
        })
        .collect();
    let mask = vec![1u32; len];
    (ids, mask)
}

// IGNORED by default. This is a HEAVY GPU scale test (150 batches of ~16k-token
// forward_batched) that pins the GPU for minutes and — if its parent process is
// killed (e.g. an agent's `cargo test` is interrupted) — orphans and keeps the
// GPU busy until it finishes. Running it via the bare `cargo test` suite is what
// previously left a stray test binary holding the GPU. Run it EXPLICITLY, always
// behind a timeout:
//   timeout 300 cargo test -p kin-infer --features metal --test embed_scale_hang -- --ignored --nocapture
#[test]
#[ignore = "heavy GPU scale repro; run explicitly with a timeout (see header)"]
fn metal_fused_pipeline_survives_many_forwards() {
    let dir = Path::new(MODEL_DIR);
    if !dir.join("model.safetensors").exists() {
        eprintln!("SKIP: model not found at {MODEL_DIR}; skipping scale-hang repro.");
        return;
    }

    let cfg_json = fs::read_to_string(dir.join("config.json")).expect("read config.json");
    let config: BertConfig = serde_json::from_str(&cfg_json).expect("parse config.json");
    let hidden = config.hidden_size;
    let model = BertModel::load(&dir.join("model.safetensors"), config).expect("load model");

    // Drive the REAL embed path: `forward_batched` with ~16,384-token batches
    // (kin-db's METAL_MAX_BATCH_TOKENS), not batch=1. The hang is tied to the
    // large batched forward — its fused-FFN intermediates are rows*inter floats
    // with rows up to ~16k, so each layer churns hundreds of MB of GPU buffers.
    // astropy is ~109 such batches; default to 150 for margin.
    let batches: usize = std::env::var("KIN_SCALE_BATCHES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(150);
    // Tokens per batch — match the Metal default so buffer footprint matches prod.
    let batch_tokens: usize = std::env::var("KIN_SCALE_BATCH_TOKENS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(16_384);
    // Per-entity sequence length; entities-per-batch = batch_tokens / seq_len.
    let seq_len: usize = std::env::var("KIN_SCALE_SEQ_LEN")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(512);
    let per_batch = (batch_tokens / seq_len).max(2);

    eprintln!(
        "\n=== Metal fused-pipeline scale repro (batched) ===\n\
         backend={}  hidden={hidden}  batches={batches}  \
         batch_tokens={batch_tokens}  seq_len={seq_len}  entities/batch={per_batch}  \
         pipeline={}",
        model.backend(),
        std::env::var("KIN_EMBED_PIPELINE").unwrap_or_else(|_| "<unset>".into())
    );

    // Watchdog: a background thread that aborts the process if no forward pass
    // completes within the stall window. A hung `new_command_buffer()` blocks
    // the worker thread indefinitely, so the watchdog is what turns a deadlock
    // into a loud, actionable failure instead of a frozen suite.
    let progress = Arc::new(AtomicUsize::new(0));
    let done = Arc::new(AtomicUsize::new(0));
    let watch_progress = Arc::clone(&progress);
    let watch_done = Arc::clone(&done);
    let stall_window = Duration::from_secs(
        std::env::var("KIN_SCALE_STALL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(60),
    );
    // Hard total-runtime ceiling. The stall watchdog only fires on ZERO progress;
    // a slow-but-progressing run (or an orphaned process whose parent was killed)
    // would otherwise pin the GPU for the whole 150-batch workload. This makes the
    // process SELF-TERMINATE and release the GPU after the cap, so a stray run
    // can never hold the device indefinitely. Override with KIN_SCALE_MAX_SECS.
    let max_total = Duration::from_secs(
        std::env::var("KIN_SCALE_MAX_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(300),
    );
    let watchdog = std::thread::spawn(move || {
        let wd_start = Instant::now();
        let mut last = 0usize;
        let mut last_change = Instant::now();
        loop {
            std::thread::sleep(Duration::from_millis(250));
            if watch_done.load(Ordering::Relaxed) == 1 {
                return;
            }
            if wd_start.elapsed() > max_total {
                eprintln!(
                    "\n!!! SCALE TEST EXCEEDED MAX RUNTIME {:?} — aborting to release the GPU \
                     (orphaned or pathologically slow run). Set KIN_SCALE_MAX_SECS to extend.",
                    max_total
                );
                std::process::abort();
            }
            let cur = watch_progress.load(Ordering::Relaxed);
            if cur != last {
                last = cur;
                last_change = Instant::now();
            } else if last_change.elapsed() > stall_window {
                eprintln!(
                    "\n!!! SCALE-HANG REPRODUCED: no forward completed for {:?}; \
                     stalled at forward #{cur}. The fused command-buffer pipeline \
                     deadlocked the Metal queue.",
                    stall_window
                );
                // Abort hard — the worker is blocked inside Metal and cannot be
                // joined. A non-zero exit makes the hang a deterministic test
                // failure rather than a frozen process.
                std::process::abort();
            }
        }
    });

    // The REAL embed runs inside `tokio::task::spawn_blocking` — a worker thread
    // with NO autorelease pool (only the main thread gets one). Autoreleased
    // Metal command buffers/encoders created there never drain, so they pile up
    // for the thread's whole life. Default to driving the workload on a freshly
    // spawned std::thread to mirror that pool-less context; set
    // KIN_SCALE_SPAWN_THREAD=0 to run inline on the test main thread (which the
    // harness gives a draining pool, hiding the leak).
    let spawn_thread = std::env::var("KIN_SCALE_SPAWN_THREAD")
        .map(|v| v != "0")
        .unwrap_or(true);
    eprintln!(
        "worker = {}",
        if spawn_thread {
            "spawned std::thread (pool-less, mirrors tokio spawn_blocking)"
        } else {
            "test main thread (has an ambient autorelease pool)"
        }
    );

    let start = Instant::now();
    let workload = {
        let progress = Arc::clone(&progress);
        move || -> (f64, usize) {
            let mut checksum = 0.0f64;
            let mut total_entities = 0usize;
            for n in 0..batches {
                // Fresh batch each iteration so buffers are reallocated
                // (cold-cache-like churn), not reused from a warm cache.
                let mut ids_b: Vec<Vec<u32>> = Vec::with_capacity(per_batch);
                let mut masks_b: Vec<Vec<u32>> = Vec::with_capacity(per_batch);
                for j in 0..per_batch {
                    let (ids, mask) = synth_sequence(seq_len, (n * per_batch + j) as u32);
                    ids_b.push(ids);
                    masks_b.push(mask);
                }
                let out = model
                    .forward_batched(&ids_b, &masks_b)
                    .expect("forward_batched");
                assert_eq!(out.len(), per_batch, "batch result count at batch #{n}");
                assert_eq!(out[0].len(), hidden, "embedding dim at batch #{n}");
                assert!(
                    out.iter().all(|v| v.iter().all(|x| x.is_finite())),
                    "non-finite embedding at batch #{n}"
                );
                checksum += out[0][0] as f64;
                total_entities += per_batch;
                progress.store(n + 1, Ordering::Relaxed);
                if (n + 1) % 10 == 0 {
                    eprintln!(
                        "  batch {}/{}  ({} entities, {:.1} ent/s)",
                        n + 1,
                        batches,
                        total_entities,
                        total_entities as f64 / start.elapsed().as_secs_f64()
                    );
                }
            }
            (checksum, total_entities)
        }
    };

    let (checksum, total_entities) = if spawn_thread {
        std::thread::spawn(workload).join().expect("workload thread")
    } else {
        workload()
    };
    done.store(1, Ordering::Relaxed);
    let _ = watchdog.join();

    let wall = start.elapsed().as_secs_f64();
    eprintln!(
        "\nOK: {batches} batches ({total_entities} entities) in {wall:.1}s  \
         ({:.1} ent/s, checksum={checksum:.3}) — no hang.\n",
        total_entities as f64 / wall
    );
}
