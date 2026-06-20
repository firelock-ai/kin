// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC
//
// Long-sequence Metal correctness gate. Historically seq_len > ~500 produced a
// NaN in the Metal batched embedding path, so kin-db routes long entities to the
// CPU. This test pins the Metal path as finite AND numerically equivalent to the
// CPU twin across the full trained range (up to 2048), including the heavy-pad
// and mixed-length batch shapes a real code corpus produces — so the CPU
// fallback ceiling can be raised with confidence rather than guesswork.
//
//   cargo test --features metal --release --test embed_long_seq_metal_parity -- --nocapture
#![cfg(feature = "metal")]

use kin_infer::{BertConfig, BertModel};
use std::fs;
use std::path::Path;

const MODEL_DIRS: &[&str] = &["/tmp/nomic", "/tmp/swerank"];

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

fn cosine(a: &[f32], b: &[f32]) -> f32 {
    let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    let na: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let nb: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    dot / (na * nb).max(1e-12)
}

#[test]
fn metal_long_seq_matches_cpu() {
    if cfg!(debug_assertions) {
        eprintln!("SKIP: run --release (debug Metal builds hit stale-binary bugs)");
        return;
    }
    // CPU twin first (env is read at model construction), then the GPU model.
    std::env::set_var("KIN_INFER_FORCE_CPU", "1");
    let Some(cpu) = load_model() else {
        eprintln!("SKIP: no nomic_bert model in {MODEL_DIRS:?}");
        return;
    };
    std::env::remove_var("KIN_INFER_FORCE_CPU");
    let Some(metal) = load_model() else {
        eprintln!("SKIP: no nomic_bert model in {MODEL_DIRS:?}");
        return;
    };
    assert_eq!(
        format!("{:?}", metal.backend()),
        "Metal",
        "expected the GPU model on the Metal backend"
    );

    // (lengths) covering the historically-NaN range incl. the exact 1201 the
    // measurement flagged, heavy padding, mixed lengths, and the 2048 ceiling.
    let batches: &[&[usize]] = &[
        &[1201, 1201],
        &[2048, 200],
        &[1536, 1201, 800, 320],
        &[2048, 2048],
    ];
    for lens in batches {
        let ids: Vec<Vec<u32>> = lens
            .iter()
            .enumerate()
            .map(|(i, &l)| synth(l, i as u32 + 1))
            .collect();
        let masks: Vec<Vec<u32>> = lens.iter().map(|&l| vec![1u32; l]).collect();

        let m = metal.forward_batched(&ids, &masks).expect("metal forward");
        let c = cpu.forward_batched(&ids, &masks).expect("cpu forward");

        let nonfinite = m.iter().flatten().filter(|x| !x.is_finite()).count();
        assert_eq!(
            nonfinite, 0,
            "lens={lens:?}: {nonfinite} non-finite on Metal"
        );

        for (i, (mi, ci)) in m.iter().zip(c.iter()).enumerate() {
            let cos = cosine(mi, ci);
            assert!(
                cos > 0.9999,
                "lens={lens:?} entity {i}: Metal vs CPU cosine {cos} (finite-but-wrong)"
            );
        }
    }
}
