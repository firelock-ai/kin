// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC
//
// Self-retrieval probe for the nomic_bert / Salesforce SweRankEmbed-Small wiring.
//
// This is the mandatory correctness gate for the nomic_bert support: it loads the
// real model, embeds several distinct code snippets as documents and a natural
// language query for one of them, then asserts the correct snippet is the top-1
// nearest neighbour by cosine with a clear margin. It is the only guard against a
// silent RoPE / SwiGLU / Wqkv-split / CLS-pooling corruption producing
// finite-but-wrong vectors that still pass every shape check.
//
// The model lives outside the repo (273 MB); the test skips cleanly when it is
// absent so it never breaks an ordinary `cargo test`.

use std::fs;
use std::path::Path;

use kin_infer::{BertConfig, BertModel};
use tokenizers::Tokenizer;

const MODEL_DIR: &str = "/tmp/swerank";
// SweRank is asymmetric: queries get an instruction prefix, documents are raw.
const QUERY_PREFIX: &str = "Represent this query for searching relevant code: ";

fn cosine(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}

fn l2(v: &[f32]) -> f32 {
    v.iter().map(|x| x * x).sum::<f32>().sqrt()
}

/// Embed one text. Documents are passed raw; queries are passed with the prefix
/// already applied by the caller.
fn embed(model: &BertModel, tokenizer: &Tokenizer, text: &str) -> Vec<f32> {
    let enc = tokenizer.encode(text, true).expect("tokenize");
    let ids: Vec<u32> = enc.get_ids().to_vec();
    let mask: Vec<u32> = enc.get_attention_mask().to_vec();
    let out = model
        .forward(&[ids], &[mask])
        .expect("forward");
    out.into_iter().next().expect("one embedding")
}

#[test]
fn swerank_self_retrieval_probe() {
    let dir = Path::new(MODEL_DIR);
    if !dir.join("model.safetensors").exists() {
        eprintln!(
            "SKIP: SweRank model not found at {MODEL_DIR} (model.safetensors absent); \
             skipping self-retrieval probe."
        );
        return;
    }

    // 1. Load config + model + tokenizer from the real artifacts.
    let cfg_json = fs::read_to_string(dir.join("config.json")).expect("read config.json");
    let config: BertConfig = serde_json::from_str(&cfg_json).expect("parse config.json");
    assert_eq!(config.hidden_size, 768, "nomic_bert hidden_size");
    assert_eq!(config.num_hidden_layers, 12, "nomic_bert n_layer");
    assert_eq!(config.num_attention_heads, 12, "nomic_bert n_head");
    assert_eq!(config.intermediate_size, 3072, "nomic_bert n_inner");
    assert_eq!(
        config.rope_theta as i64, 1000,
        "rotary_emb_base alias must yield theta=1000"
    );
    // feed_forward_type is folded from activation_function inside load_from_tensors, so
    // pre-load the raw field is what carries "swiglu"; the fold + gated-FFN path is then
    // proven by the top-1 retrieval assertion below.
    assert_eq!(
        config.activation_function.as_deref(), Some("swiglu"),
        "config.json activation_function must parse as swiglu"
    );

    let model = BertModel::load(&dir.join("model.safetensors"), config).expect("load model");
    let tokenizer = Tokenizer::from_file(dir.join("tokenizer.json")).expect("load tokenizer");

    // Diagnostic: a second model forced to mean pooling, to compare against CLS.
    let cfg2: BertConfig = {
        let mut c: BertConfig = serde_json::from_str(&cfg_json).expect("parse config.json");
        c.pooling_mode = Some("mean".to_string());
        c
    };
    let model_mean =
        BertModel::load(&dir.join("model.safetensors"), cfg2).expect("load model (mean)");

    // 2. Five distinct code snippets as documents.
    let docs = [
        // 0: binary search
        "fn binary_search(arr: &[i32], target: i32) -> Option<usize> {\n    let (mut lo, mut hi) = (0, arr.len());\n    while lo < hi {\n        let mid = (lo + hi) / 2;\n        if arr[mid] == target { return Some(mid); }\n        else if arr[mid] < target { lo = mid + 1; }\n        else { hi = mid; }\n    }\n    None\n}",
        // 1: http GET
        "async fn fetch_url(client: &Client, url: &str) -> Result<String, Error> {\n    let resp = client.get(url).send().await?;\n    let body = resp.text().await?;\n    Ok(body)\n}",
        // 2: recursive fibonacci
        "fn fibonacci(n: u64) -> u64 {\n    if n < 2 { n } else { fibonacci(n - 1) + fibonacci(n - 2) }\n}",
        // 3: json parse into a map
        "fn parse_config(raw: &str) -> HashMap<String, String> {\n    let value: serde_json::Value = serde_json::from_str(raw).unwrap();\n    value.as_object().unwrap().iter()\n        .map(|(k, v)| (k.clone(), v.to_string()))\n        .collect()\n}",
        // 4: in-place quicksort
        "fn quicksort(arr: &mut [i32]) {\n    if arr.len() <= 1 { return; }\n    let pivot = arr[arr.len() / 2];\n    let (mut i, mut j) = (0, arr.len() - 1);\n    // partition around pivot, then recurse on each half\n}",
    ];
    // Query that should match doc 0 (binary search) and nothing else closely.
    let query_text = "function that searches a sorted array for a value by repeatedly halving the search range";
    let correct = 0usize;

    // 3. Embed.
    let doc_vecs: Vec<Vec<f32>> = docs.iter().map(|d| embed(&model, &tokenizer, d)).collect();
    let query_vec = embed(
        &model,
        &tokenizer,
        &format!("{QUERY_PREFIX}{query_text}"),
    );

    // --- Diagnostics (printed before any assertion fires) ---
    // Determinism / self-similarity: embedding the same text twice must be ~identical.
    let doc0_again = embed(&model, &tokenizer, docs[0]);
    eprintln!(
        "[diag] self-cosine doc[0] (cls, embedded twice) = {:.6}",
        cosine(&doc_vecs[0], &doc0_again)
    );
    eprintln!(
        "[diag] doc[0] first 6 dims = {:?}",
        &doc_vecs[0][..6.min(doc_vecs[0].len())]
    );

    // Mean-pooling comparison.
    let doc_vecs_mean: Vec<Vec<f32>> =
        docs.iter().map(|d| embed(&model_mean, &tokenizer, d)).collect();
    let query_vec_mean = embed(
        &model_mean,
        &tokenizer,
        &format!("{QUERY_PREFIX}{query_text}"),
    );
    let mut sims_mean: Vec<(usize, f32)> = doc_vecs_mean
        .iter()
        .enumerate()
        .map(|(i, d)| (i, cosine(&query_vec_mean, d)))
        .collect();
    sims_mean.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
    eprintln!("[diag] MEAN-pool ranking (for comparison):");
    for (rank, (i, sim)) in sims_mean.iter().enumerate() {
        eprintln!("  [diag] mean rank {rank}: doc[{i}] cosine={sim:.4}");
    }

    // 4a. Finiteness + L2≈1 for every vector.
    for (i, v) in doc_vecs.iter().enumerate() {
        assert_eq!(v.len(), 768, "doc {i} dim");
        assert!(v.iter().all(|x| x.is_finite()), "doc {i} has non-finite values");
        let n = l2(v);
        assert!((n - 1.0).abs() < 1e-3, "doc {i} not L2-normalized (||v||={n})");
    }
    assert_eq!(query_vec.len(), 768, "query dim");
    assert!(query_vec.iter().all(|x| x.is_finite()), "query has non-finite values");
    let qn = l2(&query_vec);
    assert!((qn - 1.0).abs() < 1e-3, "query not L2-normalized (||v||={qn})");

    // 4b. Rank documents by cosine to the query.
    let mut sims: Vec<(usize, f32)> = doc_vecs
        .iter()
        .enumerate()
        .map(|(i, d)| (i, cosine(&query_vec, d)))
        .collect();
    sims.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

    eprintln!("\n=== SweRank self-retrieval probe ===");
    eprintln!("query: {query_text}");
    for (rank, (i, sim)) in sims.iter().enumerate() {
        eprintln!("  rank {rank}: doc[{i}] cosine={sim:.4}");
    }

    let top = sims[0].0;
    let top_sim = sims[0].1;
    let runner_up_sim = sims[1].1;
    let margin = top_sim - runner_up_sim;
    eprintln!(
        "top-1 doc[{top}] (expected doc[{correct}]); margin over runner-up = {margin:.4}\n"
    );

    assert_eq!(
        top, correct,
        "top-1 nearest neighbour should be the binary-search snippet (doc {correct}), got doc {top}"
    );
    assert!(
        margin > 0.1,
        "cosine margin of correct doc over best other doc must exceed 0.1 (was {margin:.4})"
    );
}
