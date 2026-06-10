//! Cross-process determinism acceptance harness for the Metal embedding path.
//!
//! The daemon-restart scenario: the same text embedded in two separate processes
//! must yield BIT-IDENTICAL vectors. This harness spawns a fresh child process for
//! each of several embedding arrangements (single `forward`, and a cold
//! `forward_batched` where the target rides a longer filler so it pads wide), then
//! asserts every arrangement's fingerprint of the SAME target text is byte-equal
//! across processes and across the single/batched split.
//!
//! Usage:
//!   det_probe [model_dir]            # parent: spawn children, compare (default /tmp/nomic)
//!   det_probe <model_dir> <mode>     # child: print one fingerprint (solo|batched)
//!
//! Exit code 0 = all arrangements bit-identical; nonzero = drift detected.

use std::path::Path;
use std::process::Command;

use kin_infer::{BertConfig, BertModel};

/// FNV-1a 64-bit over the LE bytes of every f32 bit pattern: equal hashes ⟺
/// bit-identical vectors (modulo astronomically unlikely collision).
fn fnv1a_bits(v: &[f32]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &x in v {
        for b in x.to_bits().to_le_bytes() {
            h ^= b as u64;
            h = h.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
    h
}

fn child(model_dir: &str, mode: &str) {
    let dir = Path::new(model_dir);
    let cfg_json = std::fs::read_to_string(dir.join("config.json")).expect("read config.json");
    let config: BertConfig = serde_json::from_str(&cfg_json).expect("parse config.json");
    let vocab = config.vocab_size.max(2);
    let model = BertModel::load(&dir.join("model.safetensors"), config).expect("load model");

    let target: Vec<u32> = (0..50).map(|j| ((37 + j * 7) % vocab) as u32).collect();
    let tmask = vec![1u32; target.len()];

    let emb = match mode {
        "solo" => model.forward(&[target], &[tmask]).expect("forward").remove(0),
        "batched" => {
            // Cold batched: this fresh process has no prior single forward, so the
            // batched path must build its own (correct) fused FFN weight layout. The
            // long filler forces the target (index 0) to pad wide.
            let filler: Vec<u32> = (0..96).map(|j| ((11 + j * 13) % vocab) as u32).collect();
            model
                .forward_batched(&[target, filler], &[tmask, vec![1u32; 96]])
                .expect("forward_batched")
                .remove(0)
        }
        other => panic!("unknown child mode: {other}"),
    };
    println!("{:016x} {:?}", fnv1a_bits(&emb), model.backend());
}

fn run_child(exe: &str, model_dir: &str, mode: &str) -> String {
    let out = Command::new(exe)
        .args([model_dir, mode])
        .output()
        .expect("spawn child");
    if !out.status.success() {
        panic!(
            "child {mode} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn main() {
    let mut args = std::env::args().skip(1);
    let model_dir = args.next().unwrap_or_else(|| "/tmp/nomic".to_string());

    // Child mode: <model_dir> <mode>.
    if let Some(mode) = args.next() {
        child(&model_dir, &mode);
        return;
    }

    if !Path::new(&model_dir).join("model.safetensors").exists() {
        eprintln!("SKIP: model absent at {model_dir}; pass a model dir as arg.");
        return;
    }

    let exe = std::env::current_exe().expect("current_exe").to_string_lossy().into_owned();
    // Two separate processes per arrangement, plus the single/batched split.
    let solo_a = run_child(&exe, &model_dir, "solo");
    let solo_b = run_child(&exe, &model_dir, "solo");
    let batched_a = run_child(&exe, &model_dir, "batched");
    let batched_b = run_child(&exe, &model_dir, "batched");

    println!("solo    proc#1: {solo_a}");
    println!("solo    proc#2: {solo_b}");
    println!("batched proc#1: {batched_a}");
    println!("batched proc#2: {batched_b}");

    let all = [&solo_a, &solo_b, &batched_a, &batched_b];
    let hash0 = solo_a.split_whitespace().next().unwrap();
    let ok = all.iter().all(|s| s.split_whitespace().next().unwrap() == hash0);
    if ok {
        println!("\nPASS: same text is BIT-IDENTICAL across processes and across the single/batched split.");
    } else {
        println!("\nFAIL: embedding fingerprints differ — cross-process determinism is broken.");
        std::process::exit(1);
    }
}
