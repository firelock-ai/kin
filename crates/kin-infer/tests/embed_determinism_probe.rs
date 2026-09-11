// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC
//
// Cross-process byte-determinism instrument for the no-lever Metal embed.
//
// This is the promoted form of the earlier within-process report-only probe. The
// residual it chases is BIMODAL PER PROCESS: a whole run is either clean or
// consistently shifted, and it is amplified by GPU contention and by interleaving
// differently-shaped forward passes. That failure mode is invisible to a
// within-process equality check (a shifted process embeds the same input the same
// shifted way twice, so `a == b` still holds — see embed_byte_determinism.rs); it
// only shows up when two SEPARATE processes embed the same input and their kvec
// bytes disagree. So the gate here is cross-process digest stability, exercised
// under optional contention, over the real-corpus shape distribution, on whichever
// resource profile is selected (throughput engages the resident chained-layer
// path that proof disables).
//
// Modes (env):
//   (default)                         single process: embed the corpus, print the
//                                     digest, run the interleaved-shape localizer
//                                     REPORT-ONLY. Never fails CI; skips with no model.
//   KIN_INFER_DETERMINISM_CHILD=1     child worker: embed once, print the digest
//                                     line, return. Used by the parent to harvest a
//                                     second-process digest. Never spawns.
//   KIN_INFER_DETERMINISM_GATE=1      parent spawns N worker processes that embed
//                                     CONCURRENTLY, then ASSERTS every worker digest
//                                     is identical. This is the citable cross-process
//                                     byte-determinism gate. Run it under
//                                     `bin/kin-lane acquire gpu` once the upstream
//                                     graph-content order is pinned, on BOTH
//                                     KIN_RESOURCE_PROFILE=proof and =throughput.
//   KIN_INFER_DETERMINISM_CONTENTION=N  worker count for the gate (default 4).
//
//   KIN_RESOURCE_PROFILE=proof|throughput  select the path under test (run both).
//   KIN_INFER_PROBE_MODEL_DIR=<dir>        nomic_bert/SweRank model dir override.
//
// Why this is report-only by default: incidental GPU load makes the contention
// gate flake, and CI has no model so it skips anyway. The gate is opt-in so the
// citable run is a deliberate, lock-held measurement, not a CI coin-flip.

#![cfg(feature = "metal")]

use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};

use kin_infer::{BertConfig, BertModel};

const MODEL_DIRS: &[&str] = &["/tmp/swerank", "/tmp/nomic"];
const GATE_TEST_NAME: &str = "no_lever_embed_cross_process_byte_identical";

fn load() -> Option<BertModel> {
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

/// Deterministic token-id sequence in a conservative vocab band, avoiding 0. Same
/// generator as embed_byte_determinism.rs so both tests probe the same inputs.
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

/// FNV-1a over every embedding's f32 bit pattern — order-sensitive, stable across
/// processes, so any byte difference or row reordering changes the digest.
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
/// including a non-tile-aligned ragged count (37) — the lengths the indexer
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

/// Embed the full mixed-shape corpus once (steady state) and digest the kvec.
fn embed_corpus_digest(model: &BertModel) -> u64 {
    let (ids, masks) = corpus();
    // Discard the cold first pass (shader/weight-cache warm-up).
    let _ = model.forward_batched(&ids, &masks).expect("warm");
    let out = model.forward_batched(&ids, &masks).expect("embed");
    assert!(
        out.iter().flatten().all(|x| x.is_finite()),
        "embedding produced non-finite values"
    );
    digest(&out)
}

fn child_mode() -> bool {
    std::env::var("KIN_INFER_DETERMINISM_CHILD").is_ok()
}

fn gate_enabled() -> bool {
    std::env::var("KIN_INFER_DETERMINISM_GATE").is_ok()
}

fn worker_count() -> usize {
    std::env::var("KIN_INFER_DETERMINISM_CONTENTION")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(4)
        .max(2)
}

fn release_guard() -> bool {
    if cfg!(debug_assertions) {
        eprintln!("SKIP: run --release (debug Metal builds hit stale-binary bugs)");
        return false;
    }
    true
}

/// Spawn one worker process that re-execs this test binary in CHILD mode and
/// returns its handle with piped stdout. Spawning all workers before harvesting
/// any output is what produces the concurrent GPU contention the residual needs.
fn spawn_worker() -> std::io::Result<std::process::Child> {
    let exe = std::env::current_exe().expect("current_exe");
    let mut cmd = Command::new(exe);
    cmd.args(["--exact", GATE_TEST_NAME, "--nocapture", "--test-threads=1"])
        .env("KIN_INFER_DETERMINISM_CHILD", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // Inherit the profile + model dir so every worker measures the same path.
    for key in ["KIN_RESOURCE_PROFILE", "KIN_INFER_PROBE_MODEL_DIR"] {
        if let Ok(v) = std::env::var(key) {
            cmd.env(key, v);
        }
    }
    cmd.spawn()
}

fn parse_digest(stdout: &str) -> Option<&str> {
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("EMBED_KVEC_DIGEST=") {
            return Some(rest.split_whitespace().next().unwrap_or(rest));
        }
    }
    None
}

/// The cross-process byte-determinism gate.
///
/// CHILD mode: embed the corpus, print the digest to stdout, return.
/// Parent, gate off (default): embed locally, print the digest + the run protocol,
///   report-only.
/// Parent, gate on: spawn N concurrent workers, harvest their digests, and assert
///   they all agree (and agree with the local embed). A disagreement is the
///   bimodal-per-process residual reproducing.
#[test]
fn no_lever_embed_cross_process_byte_identical() {
    if !release_guard() {
        return;
    }
    let Some(model) = load() else {
        // CHILD with no model must still emit a parseable line so the parent can
        // tell "model absent" apart from "worker crashed".
        if child_mode() {
            println!("EMBED_KVEC_DIGEST=SKIP");
        } else {
            eprintln!("SKIP: no nomic_bert model in {MODEL_DIRS:?}");
        }
        return;
    };

    let local = embed_corpus_digest(&model);
    let profile = std::env::var("KIN_RESOURCE_PROFILE").unwrap_or_else(|_| "(default)".into());

    if child_mode() {
        // Workers report to stdout and exit; the parent owns the assertion.
        println!("EMBED_KVEC_DIGEST={local:016x}");
        return;
    }

    eprintln!(
        "[determinism] profile={profile} backend={:?} local EMBED_KVEC_DIGEST={local:016x}",
        model.backend()
    );

    if !gate_enabled() {
        eprintln!(
            "[determinism] report-only. To gate cross-process determinism, hold the GPU \
             (bin/kin-lane acquire gpu) and run with KIN_INFER_DETERMINISM_GATE=1 on BOTH \
             KIN_RESOURCE_PROFILE=proof and =throughput."
        );
        return;
    }

    // Gate: spawn all workers first (concurrent contention), then harvest.
    let n = worker_count();
    eprintln!("[determinism] GATE: spawning {n} concurrent workers (profile={profile})");
    let mut children = Vec::with_capacity(n);
    for _ in 0..n {
        children.push(spawn_worker().expect("spawn worker"));
    }
    let mut digests: Vec<String> = Vec::with_capacity(n);
    for (i, child) in children.into_iter().enumerate() {
        let out = child.wait_with_output().expect("worker output");
        let stdout = String::from_utf8_lossy(&out.stdout);
        match parse_digest(&stdout) {
            Some(d) => {
                eprintln!("[determinism]   worker[{i}] EMBED_KVEC_DIGEST={d}");
                digests.push(d.to_string());
            }
            None => panic!(
                "worker[{i}] produced no digest (exit={:?}); stdout:\n{stdout}",
                out.status.code()
            ),
        }
    }

    if digests.iter().any(|d| d == "SKIP") {
        eprintln!("[determinism] a worker reported SKIP (model absent in worker); not gating");
        return;
    }

    let local_hex = format!("{local:016x}");
    let first = &digests[0];
    let all_agree = digests.iter().all(|d| d == first) && *first == local_hex;
    assert!(
        all_agree,
        "no-lever embed is NOT cross-process byte-identical under contention \
         (profile={profile}): local={local_hex} workers={digests:?} — bimodal-per-process \
         residual reproduced"
    );
    eprintln!("[determinism] GATE PASS: {n} workers + local all agree on {first}");
}

/// Within-process interleaved-shape localizer (promoted from the original probe to
/// the real-corpus distribution). Pins each shape's embedding, perturbs GPU state
/// with a differently-shaped pass, re-embeds, and counts bit-identical re-embeds.
/// Report-only unless KIN_INFER_DETERMINISM_GATE=1 — a same-process check cannot
/// catch the bimodal residual, but it does catch a non-bimodal interleave hazard.
#[test]
fn embed_determinism_interleaved_shapes() {
    if !release_guard() {
        return;
    }
    if child_mode() {
        return; // workers only run the cross-process test
    }
    let Some(model) = load() else {
        eprintln!("SKIP: no nomic_bert model in {MODEL_DIRS:?}");
        return;
    };

    let (ids, masks) = corpus();
    let perturb_idx = ids.len() - 1; // the 512-length pass
    let n = 8usize;
    let mut total = 0usize;
    let mut ok = 0usize;
    let mut diverged_shapes: Vec<usize> = Vec::new();

    for (i, (id, mask)) in ids.iter().zip(masks.iter()).enumerate() {
        if i == perturb_idx {
            continue;
        }
        let one = std::slice::from_ref(id);
        let one_mask = std::slice::from_ref(mask);
        let _cold = model.forward_batched(one, one_mask).expect("cold");
        let reference = model.forward_batched(one, one_mask).expect("reference");
        let mut shape_ok = true;
        for _ in 0..n {
            let _ = model
                .forward_batched(
                    std::slice::from_ref(&ids[perturb_idx]),
                    std::slice::from_ref(&masks[perturb_idx]),
                )
                .expect("perturb");
            let again = model.forward_batched(one, one_mask).expect("again");
            total += 1;
            if again == reference {
                ok += 1;
            } else {
                shape_ok = false;
            }
        }
        if !shape_ok {
            diverged_shapes.push(id.len());
        }
    }

    eprintln!(
        "[determinism] interleaved real-corpus shapes: {ok}/{total} steady-state re-embeds \
         bit-identical (backend={:?})",
        model.backend()
    );
    if !diverged_shapes.is_empty() {
        eprintln!("[determinism] diverged at shapes(lens)={diverged_shapes:?}");
    }

    if gate_enabled() {
        assert_eq!(
            ok, total,
            "interleaved-shape re-embeds diverged at lens {diverged_shapes:?} ({ok}/{total} stable)"
        );
    }
}
