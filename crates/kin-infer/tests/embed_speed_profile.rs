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

/// Model directory, overridable with `KIN_INFER_PROBE_MODEL_DIR` so a fixture
/// carrying a fully-specified `config.json` can be substituted for a checkpoint
/// whose upstream config omits the explicit dimension fields the loader needs.
fn probe_model_dir() -> String {
    std::env::var("KIN_INFER_PROBE_MODEL_DIR").unwrap_or_else(|_| MODEL_DIR.to_string())
}

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

/// Resolve the kin-infer git HEAD short-sha at runtime so every emitted number is
/// pinned to an auditable commit. `cargo test` runs with the package root as CWD,
/// so `git rev-parse` resolves against the kin-infer working tree. Falls back to
/// "unknown" if git is unavailable (tarball/CI checkout) — the BUILD/opt-level
/// stamp is still emitted, which is the load-bearing part.
fn head_short_sha() -> String {
    std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// One-line build-provenance stamp printed at the top of EVERY profile run so any
/// quoted ent/s number is pinned to an auditable (build, opt-level, commit) triple.
/// BUILD is the load-bearing field: numbers from a debug build are meaningless, so
/// the run refuses to emit any throughput unless this reads `release`.
///
/// `OPT_LEVEL` is only injected by Cargo for build scripts, not for the test crate
/// itself, so `option_env!` is almost always `None` here — fall back to the cargo
/// profile default (Cargo.toml defines no `[profile.*]` overrides, so dev=0,
/// release=3). The fallback is documented so a future profile override that drifts
/// from these defaults is an obvious place to look.
fn build_stamp() -> String {
    let build = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    let opt = option_env!("OPT_LEVEL").unwrap_or(if cfg!(debug_assertions) { "0" } else { "3" });
    format!(
        "BUILD={build}  opt-level={opt}  kin-infer-HEAD={}",
        head_short_sha()
    )
}

#[test]
fn metal_embed_forward_profile() {
    let model_dir = probe_model_dir();
    let dir = Path::new(&model_dir);
    if !dir.join("model.safetensors").exists() {
        eprintln!(
            "SKIP: model not found at {model_dir} (model.safetensors absent); \
             skipping embed-speed profile."
        );
        return;
    }

    // Build-provenance stamp on EVERY run so any number that escapes this test is
    // pinned to an auditable (build, opt-level, commit) triple. Printed BEFORE the
    // debug refusal so even a refused debug run leaves the stamp on the record.
    eprintln!("\n[embed-speed] {}", build_stamp());

    // HARD refusal in debug builds. Perf numbers from an unoptimized build are
    // meaningless — a debug-build ent/s figure (the infamous "1.9 ent/s") once
    // leaked into discussion as if it were real. Emit a LOUD refusal and return
    // BEFORE any timing runs so no throughput number can EVER be emitted from a
    // debug build.
    if cfg!(debug_assertions) {
        eprintln!(
            "\n!!! REFUSING: perf numbers are meaningless in a debug build — \
             rerun with --release !!!\n    \
             cargo test -p kin-infer --release --features metal \
             --test embed_speed_profile -- --nocapture\n"
        );
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
    assert!(
        warm.iter().all(|x| x.is_finite()),
        "warm-up produced non-finite"
    );

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
    let host_blocked_ns = metal_backend::profile_host_blocked_nanos();
    let submissions = metal_backend::profile_submissions();
    let round_trips = metal_backend::profile_round_trips();
    let forward_calls = metal_backend::profile_forward_calls().max(1);

    let wall_s = wall.as_secs_f64();
    let host_blocked_s = host_blocked_ns as f64 / 1e9;
    let rest_s = (wall_s - host_blocked_s).max(0.0);
    let ent_per_s = total as f64 / wall_s;
    let host_blocked_pct = if wall_s > 0.0 {
        host_blocked_s / wall_s * 100.0
    } else {
        0.0
    };
    let subs_per_fwd = submissions as f64 / forward_calls as f64;
    let trips_per_fwd = round_trips as f64 / forward_calls as f64;
    let blocked_ns_per_fwd = host_blocked_ns as f64 / forward_calls as f64;

    eprintln!(
        "\nentities={total}  wall={wall_s:.3}s  ent/s={ent_per_s:.2}  (checksum={checksum:.3})"
    );
    eprintln!(
        "host-blocked = {host_blocked_s:.3}s  ({host_blocked_pct:.1}% of wall, {blocked_ns_per_fwd:.0} ns/forward)"
    );
    eprintln!(
        "rest (CPU glue + copies)  = {rest_s:.3}s  ({:.1}% of wall)",
        100.0 - host_blocked_pct
    );
    eprintln!(
        "forward_calls={forward_calls}  GPU submissions={submissions} ({subs_per_fwd:.1}/forward)  round_trips={round_trips} ({trips_per_fwd:.1}/forward)"
    );

    if submissions == 0 {
        eprintln!(
            "\nNOTE: 0 submissions recorded — set KIN_INFER_METAL_PROFILE=1 to enable the \
             stall profiler (the timing/ent-s numbers above are still valid)."
        );
    } else if host_blocked_pct >= 50.0 {
        eprintln!(
            "\nVERDICT: STALL-BOUND ({host_blocked_pct:.0}% of wall host-blocked, \
             {trips_per_fwd:.0} blocking waits/forward) -> round-trip collapse is the lever."
        );
    } else {
        eprintln!(
            "\nVERDICT: not stall-dominated ({host_blocked_pct:.0}% host-blocked) -> \
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
    let batch: Vec<(Vec<u32>, Vec<u32>)> = (0..probe_n)
        .map(|j| synth_sequence(probe_len, 7000 + j as u32))
        .collect();
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

    // --- Daemon-regime per-phase breakdown (forward_batched at batch ~100) ---
    // The daemon embeds in large batches (~192), where per-forward submission
    // overhead is amortized — so the bottleneck may differ from batch=1. Profile
    // ONE batched forward and attribute wall-clock to kernel class so we target
    // the MEASURED bottleneck (matmul / attention / norm-softmax / activation /
    // host-copy+readback), not an assumed one.
    eprintln!("\n=== Daemon-regime per-phase breakdown (forward_batched) ===");
    let mut bt: Vec<Vec<u32>> = Vec::new();
    let mut bm: Vec<Vec<u32>> = Vec::new();
    for (bucket, &len) in seq_lens.iter().enumerate() {
        for j in 0..20 {
            let (ids, mask) = synth_sequence(len, (bucket * 97 + j) as u32);
            bt.push(ids);
            bm.push(mask);
        }
    }
    let _ = model.forward_batched(&bt, &bm).expect("warm batched"); // warm
    metal_backend::reset_profile();
    let t_b = Instant::now();
    let _ = model.forward_batched(&bt, &bm).expect("batched fwd");
    let bw = t_b.elapsed().as_secs_f64();
    let (mm, attn, norm, act, copy): (u64, u64, u64, u64, u64) =
        metal_backend::profile_phase_nanos();
    let tot = (mm + attn + norm + act + copy).max(1) as f64;
    let subs_b = metal_backend::profile_submissions();
    let trips_b = metal_backend::profile_round_trips();
    let fwd_b = metal_backend::profile_forward_calls().max(1);
    let host_blocked_b = metal_backend::profile_host_blocked_nanos();
    eprintln!(
        "BATCHED({}) {:.1} ent/s  |  forward_calls={fwd_b}  subs={subs_b} ({:.1}/forward over {} layers)  round_trips={trips_b} ({:.1}/forward)  host_blocked_ns/forward={:.0}",
        bt.len(),
        bt.len() as f64 / bw.max(1e-9),
        subs_b as f64 / fwd_b as f64,
        layers,
        trips_b as f64 / fwd_b as f64,
        host_blocked_b as f64 / fwd_b as f64,
    );
    eprintln!(
        "host-wall phase split: matmul {:.0}% / attention {:.0}% / norm-softmax {:.0}% / activation {:.0}% / copy-readback {:.0}%",
        mm as f64 / tot * 100.0,
        attn as f64 / tot * 100.0,
        norm as f64 / tot * 100.0,
        act as f64 / tot * 100.0,
        copy as f64 / tot * 100.0,
    );

    // --- GPU-timestamp phase distribution (build-invariant) ---
    // The host-wall split above attributes async wall-clock on the HOST and so
    // carries debug-vs-release skew. This distribution is measured from each
    // command buffer's GPUStartTime/GPUEndTime (profile_gpu_phase_nanos), so its
    // SHAPE is invariant across build profiles — it is what lets the team choose
    // fp16-operands vs MMA-tiling by MEASUREMENT instead of host-skewed wall-clock.
    // Framing: absolute throughput = release async wall-clock; distribution =
    // GPU-timestamp, build-invariant.
    let gpu_phases = metal_backend::profile_gpu_phase_nanos();
    let gpu_tot: u64 = gpu_phases.iter().map(|(_, ns)| *ns).sum();
    if gpu_tot == 0 {
        eprintln!(
            "GPU-timestamp dist: 0 ns recorded -> set KIN_INFER_METAL_PROFILE=1 to enable \
             GPU-timestamp phase profiling (host-wall split above is still valid)."
        );
    } else {
        let denom = gpu_tot as f64;
        let dist = gpu_phases
            .iter()
            .map(|(name, ns)| format!("{name} {:.0}%", *ns as f64 / denom * 100.0))
            .collect::<Vec<_>>()
            .join(" / ");
        eprintln!("GPU-timestamp dist (build-invariant): {dist}");
        eprintln!(
            "  (copy~0: host memcpy on unified memory commits no command buffer, so it is \
             not GPU-timed; absolute throughput = release async wall-clock, distribution = \
             GPU-timestamp, build-invariant)"
        );
    }

    // --- Long-sequence batched throughput (matmul-bound regime) ---
    // Large code entities (seq ~1024-2048) are where the projection/FFN GEMMs and
    // O(seq^2) attention dominate, so this is the regime the GEMM/MMA kernel levers
    // most affect. Embed a batch of long sequences, report ent/s and the
    // GPU-timestamp phase split, and assert every output is finite — the long path
    // is exactly where the historical non-finite norm/attention bugs lived.
    eprintln!("\n=== Long-sequence batched throughput (seq=1024) ===");
    let long_len = 1024usize;
    let long_n = 8usize;
    let mut lt: Vec<Vec<u32>> = Vec::new();
    let mut lm: Vec<Vec<u32>> = Vec::new();
    for j in 0..long_n {
        let (ids, mask) = synth_sequence(long_len, 9000 + j as u32);
        lt.push(ids);
        lm.push(mask);
    }
    let warm_long = model.forward_batched(&lt, &lm).expect("warm long batched");
    assert!(
        warm_long.iter().all(|v| v.iter().all(|x| x.is_finite())),
        "long-sequence batched forward produced non-finite output"
    );
    metal_backend::reset_profile();
    let t_l = Instant::now();
    let long_out = model.forward_batched(&lt, &lm).expect("long batched fwd");
    let lw = t_l.elapsed().as_secs_f64();
    assert!(
        long_out.iter().all(|v| v.iter().all(|x| x.is_finite())),
        "long-sequence batched forward produced non-finite output"
    );
    let long_gpu = metal_backend::profile_gpu_phase_nanos();
    let long_gpu_tot: u64 = long_gpu.iter().map(|(_, ns)| *ns).sum();
    eprintln!(
        "LONG-BATCHED(seq={long_len} x{long_n}) {:.2} ent/s",
        long_n as f64 / lw.max(1e-9),
    );
    if long_gpu_tot > 0 {
        let denom = long_gpu_tot as f64;
        let dist = long_gpu
            .iter()
            .map(|(name, ns)| format!("{name} {:.0}%", *ns as f64 / denom * 100.0))
            .collect::<Vec<_>>()
            .join(" / ");
        eprintln!("  GPU-timestamp dist: {dist}");
    }
    eprintln!();
}
