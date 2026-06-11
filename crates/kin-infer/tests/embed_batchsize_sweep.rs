// Batch-size bisection for the forward_batched corruption. Reproduces the exact
// len-64 entities that corrupted in the truth probe (bucket=1 salt=131+j) and
// sweeps batch size N, reporting worst cosine vs single-forward ground truth.
// Goal: find the N at which forward_batched starts diverging from forward.
//   cargo test --features metal --release --test embed_batchsize_sweep -- --nocapture
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
fn batchsize_sweep() {
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
    let cfg_json = fs::read_to_string(dir.join("config.json")).expect("config");
    let config: BertConfig = serde_json::from_str(&cfg_json).expect("parse");
    let model = BertModel::load(&dir.join("model.safetensors"), config).expect("load");
    eprintln!("backend={}", model.backend());

    // len 64 = truth-probe bucket index 1, salt = 1*131 + j (exact corrupting entities).
    const LEN: usize = 64;
    let ns = [1usize, 2, 3, 4, 6, 8, 12, 16, 20, 24, 32, 48, 64, 100];
    let maxn = *ns.iter().max().unwrap();

    // Single-forward ground truth for the maxn distinct entities (reused across N).
    let single: Vec<Vec<f32>> = (0..maxn)
        .map(|j| {
            let (ids, m) = synth(LEN, (131 + j) as u32);
            model.forward(&[ids], &[m]).unwrap().pop().unwrap()
        })
        .collect();

    for &n in &ns {
        let ids: Vec<Vec<u32>> = (0..n).map(|j| synth(LEN, (131 + j) as u32).0).collect();
        let masks: Vec<Vec<u32>> = (0..n).map(|j| synth(LEN, (131 + j) as u32).1).collect();
        let batched = model.forward_batched(&ids, &masks).unwrap();
        let mut worst = 1.0f64;
        let mut worst_i = 0usize;
        for i in 0..n {
            let c = cos(&single[i], &batched[i]);
            if c < worst {
                worst = c;
                worst_i = i;
            }
        }
        let tag = if worst < 0.99 { "CORRUPT" } else { "clean  " };
        eprintln!("[sweep] N={n:<4} worst_cos={worst:.6} (entity {worst_i}) {tag}");
    }
}
