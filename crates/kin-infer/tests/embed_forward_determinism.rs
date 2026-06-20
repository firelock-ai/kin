// MINIMAL repro for the embedder-wide corruption. The batch-size sweep showed
// forward (batch=1) itself diverges in "cursed" processes, so the bug is NOT
// batched-specific. This calls forward(x) on the SAME input many times in one
// process and reports the worst cosine vs the first result. A clean process =>
// all 1.0; a cursed process => some call returns a ~0.2-cosine wrong embedding.
// Far cheaper to iterate / frame-capture than batch=100.
//   cargo test --features metal --release --test embed_forward_determinism -- --nocapture
#![cfg(feature = "metal")]

use kin_infer::{BertConfig, BertModel};
use std::fs;
use std::path::Path;

const MODEL_DIR: &str = "/tmp/swerank";

fn probe_model_dir() -> String {
    std::env::var("KIN_INFER_PROBE_MODEL_DIR").unwrap_or_else(|_| MODEL_DIR.to_string())
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
fn cos(a: &[f32], b: &[f32]) -> f64 {
    let mut d = 0.0f64;
    for i in 0..a.len() {
        d += a[i] as f64 * b[i] as f64;
    }
    d
}

#[test]
fn forward_determinism() {
    let model_dir = probe_model_dir();
    let dir = Path::new(&model_dir);
    if !dir.join("model.safetensors").exists() {
        eprintln!("SKIP: no model at {model_dir}");
        return;
    }
    if cfg!(debug_assertions) {
        eprintln!("!!! REFUSING parity from a debug build — use --release !!!");
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
    let model = BertModel::load(&dir.join("model.safetensors"), config).expect("load");
    eprintln!("backend={}", model.backend());

    let (ids, m) = synth(64, 131);
    let ref0 = model
        .forward(&[ids.clone()], &[m.clone()])
        .unwrap()
        .pop()
        .unwrap();
    let mut worst = 1.0f64;
    let mut worst_k = 0usize;
    const REPEATS: usize = 40;
    for k in 1..=REPEATS {
        let e = model
            .forward(&[ids.clone()], &[m.clone()])
            .unwrap()
            .pop()
            .unwrap();
        let c = cos(&ref0, &e);
        if c < worst {
            worst = c;
            worst_k = k;
        }
    }
    let verdict = if worst < 0.99 {
        "NONDETERMINISTIC"
    } else {
        "deterministic"
    };
    eprintln!("[fwd-det] {REPEATS} repeats of forward(same input): worst_cos_vs_first={worst:.6} (call {worst_k}) {verdict}");
}
