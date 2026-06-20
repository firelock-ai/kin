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
use std::time::{Duration, Instant};

use kin_infer::watchdog::{EmbedConfig, EmbedWatchdog};
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

    // The production embed watchdog (kin_infer::watchdog), wrapping this loop
    // exactly as the daemon embed driver should. It aborts the process — releasing
    // the GPU — on parent death (orphan), a hard wall cap, or a sustained
    // below-floor throughput keyed on the PERSISTED-batch delta. The persisted
    // delta is the honest liveness signal the old per-forward stall watchdog
    // missed: a busy-spin that trickles forwards keeps a per-forward timer alive,
    // but if nothing is persisted the floor still trips. We bump `wd` per batch.
    //
    // Env knobs map onto the library config: the legacy KIN_SCALE_MAX_SECS still
    // sets the wall cap (default 300s here for the bounded test), and the floor is
    // derived from the workload's expected rate so a real stall is caught without
    // flagging a slow-but-progressing run.
    let max_total = Duration::from_secs(
        std::env::var("KIN_SCALE_MAX_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(300),
    );
    let stall_window = Duration::from_secs(
        std::env::var("KIN_SCALE_STALL_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(60),
    );
    let wd_cfg = EmbedConfig {
        enabled: true,
        poll: Duration::from_millis(250),
        // Off by default: a live cargo/test parent keeps ppid != 1, but a wifi
        // blip that orphans the binary flips it to 1 and self-exits. Opt out with
        // KIN_EMBED_ORPHAN_CHECK=0 if a harness intentionally reparents the test.
        orphan_check: !std::env::var("KIN_EMBED_ORPHAN_CHECK")
            .map(|v| v == "0")
            .unwrap_or(false),
        wall_cap: Some(max_total),
        // Persisted-batch floor: require at least one batch every `stall_window`.
        // 1 batch / window seconds is the rate floor; a busy-spin persisting
        // nothing trips it, a healthy run never does.
        throughput_floor: Some(1.0 / stall_window.as_secs_f64().max(1.0)),
        floor_window: stall_window,
        floor_grace: Duration::from_secs(15),
    };
    let wd = EmbedWatchdog::spawn::<fn(_)>(wd_cfg, None);

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
        let progress = wd.progress_handle();
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
                // Persisted-batch progress — the liveness signal the watchdog's
                // throughput floor watches (a busy-spin that persists nothing
                // trips it; a healthy run keeps it satisfied).
                progress.bump(1);
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
        std::thread::spawn(workload)
            .join()
            .expect("workload thread")
    } else {
        workload()
    };
    // Clean end-of-loop: dropping the watchdog signals its poller to exit and
    // joins it. No abort on a normal completion.
    drop(wd);

    let wall = start.elapsed().as_secs_f64();
    eprintln!(
        "\nOK: {batches} batches ({total_entities} entities) in {wall:.1}s  \
         ({:.1} ent/s, checksum={checksum:.3}) — no hang.\n",
        total_entities as f64 / wall
    );
}
