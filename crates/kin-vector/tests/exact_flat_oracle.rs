// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! An exact brute-force search arm, and the recall it measures for the shipped
//! HNSW index.
//!
//! The index answers with a graph traversal at `EF_SEARCH = 50`. Nothing in the
//! crate previously compared that answer to the true nearest neighbors, so the
//! approximation error of the shipped configuration was unmeasured. This is the
//! ground truth to measure it against.
//!
//! Two properties make the oracle worth trusting:
//!
//! * It reaches the stored vectors through the same public path the product
//!   does — load the container from disk, then read vectors back out — so it
//!   scores the floats that actually survived serialization, not a copy held in
//!   memory since before the save.
//! * It computes cosine distance itself, in `f64`, with a plain sequential
//!   reduction. It does not call the crate's distance kernel. An oracle built
//!   on the implementation it is checking can only ever agree with it, and the
//!   kernel here has a SIMD path whose reduction order differs from the scalar
//!   one.
//!
//! The metric is cosine, which is what the index ranks by. Scoring an index
//! against a Euclidean oracle measures the disagreement between two metrics on
//! top of the approximation error and cannot separate them.

use kin_vector::VectorIndex;

const DIM: usize = 64;
const CORPUS: u64 = 2_000;
const QUERIES: u64 = 100;
const K: usize = 10;

/// Deterministic vector generation. A fixed sequence keeps the measured recall
/// reproducible across runs and machines, which a seeded RNG dependency would
/// also give but at the cost of a dependency the crate does not otherwise need.
fn synthetic_vector(seed: u64) -> Vec<f32> {
    let mut state = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
    let mut out = Vec::with_capacity(DIM);
    for _ in 0..DIM {
        // splitmix64
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        // Map to [-1, 1).
        out.push(((z >> 11) as f64 / (1u64 << 53) as f64) as f32 * 2.0 - 1.0);
    }
    // Stored vectors are L2-normalized everywhere they are produced for real, so
    // the fixture matches that shape rather than testing a distribution the
    // index never sees.
    let norm = (out.iter().map(|v| (*v as f64) * (*v as f64)).sum::<f64>()).sqrt();
    if norm > 0.0 {
        for v in out.iter_mut() {
            *v = ((*v as f64) / norm) as f32;
        }
    }
    out
}

/// Cosine distance, computed independently of the crate's kernel.
fn exact_cosine_distance(a: &[f32], b: &[f32]) -> f64 {
    let mut dot = 0.0f64;
    let mut norm_a = 0.0f64;
    let mut norm_b = 0.0f64;
    for (x, y) in a.iter().zip(b.iter()) {
        dot += (*x as f64) * (*y as f64);
        norm_a += (*x as f64) * (*x as f64);
        norm_b += (*y as f64) * (*y as f64);
    }
    let denom = (norm_a * norm_b).sqrt();
    if denom == 0.0 {
        return 1.0;
    }
    1.0 - dot / denom
}

/// Exact top-k by brute force over every stored vector.
fn exact_top_k(corpus: &[(u64, Vec<f32>)], query: &[f32], k: usize) -> Vec<(u64, f64)> {
    let mut scored: Vec<(u64, f64)> = corpus
        .iter()
        .map(|(id, v)| (*id, exact_cosine_distance(query, v)))
        .collect();
    // Total order including the id, so an exact tie resolves the same way on
    // every run rather than by sort stability over an arbitrary input order.
    scored.sort_by(|a, b| a.1.total_cmp(&b.1).then_with(|| a.0.cmp(&b.0)));
    scored.truncate(k);
    scored
}

/// Load the corpus back through the public read path, so the oracle scores the
/// vectors as they exist after a container round trip.
fn stored_corpus(index: &VectorIndex<u64>) -> Vec<(u64, Vec<f32>)> {
    let mut keys = index.keys();
    keys.sort_unstable();
    keys.into_iter()
        .map(|k| (k, index.get(&k).expect("a live key must have a vector")))
        .collect()
}

#[test]
fn hnsw_top_k_holds_against_an_exact_flat_search() {
    let index = VectorIndex::<u64>::new(DIM).unwrap();
    index
        .upsert_batch((0..CORPUS).map(|k| (k, synthetic_vector(k))).collect())
        .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("oracle.kvec");
    index.save(&path).unwrap();
    let loaded = VectorIndex::<u64>::load_from_disk(&path).unwrap();

    let stats = loaded
        .load_stats()
        .expect("a loaded index reports its load");
    assert_eq!(
        stats.msgpack_float_decodes, 0,
        "the oracle must be reading the raw payload, not a tagged one"
    );

    let corpus = stored_corpus(&loaded);
    assert_eq!(corpus.len(), CORPUS as usize);

    let mut recall_hits = 0usize;
    let mut recall_total = 0usize;
    // A returned neighbor that is not in the exact top-k but sits at the same
    // distance as the k-th exact result is not an error: the ranking is a total
    // order over distances, and equidistant candidates are interchangeable.
    let mut distance_hits = 0usize;
    let mut worst_query_recall = 1.0f64;

    for q in 0..QUERIES {
        // Queries drawn from outside the corpus id range, so the query vector is
        // never itself a stored vector and the trivially-correct self-match
        // cannot inflate recall.
        let query = synthetic_vector(CORPUS + 1_000 + q);

        let exact = exact_top_k(&corpus, &query, K);
        let kth_distance = exact.last().map(|(_, d)| *d).unwrap_or(f64::MAX);
        let exact_ids: std::collections::HashSet<u64> = exact.iter().map(|(id, _)| *id).collect();

        let ann = loaded.search_similar(&query, K).unwrap();
        assert_eq!(ann.len(), K, "the index must return a full page");

        let mut hits = 0usize;
        for (id, _) in &ann {
            if exact_ids.contains(id) {
                hits += 1;
            }
            let distance = exact_cosine_distance(
                &query,
                &corpus
                    .iter()
                    .find(|(cid, _)| cid == id)
                    .expect("a returned id must be in the corpus")
                    .1,
            );
            if distance <= kth_distance + 1e-9 {
                distance_hits += 1;
            }
        }
        recall_hits += hits;
        recall_total += K;
        worst_query_recall = worst_query_recall.min(hits as f64 / K as f64);
    }

    let recall = recall_hits as f64 / recall_total as f64;
    let distance_recall = distance_hits as f64 / recall_total as f64;
    println!(
        "exact-flat oracle: corpus={CORPUS} dim={DIM} k={K} queries={QUERIES}\n  \
         recall@{K}={recall:.4}  distance-equivalent={distance_recall:.4}  \
         worst-query recall={worst_query_recall:.4}"
    );

    // The floor is set below the measured value, not at it, so ordinary
    // tie-breaking movement does not turn this into a flaky test. It is here to
    // catch a real regression in the traversal, not to pin the current number.
    assert!(
        recall >= 0.95,
        "mean recall@{K} {recall:.4} fell below the floor; \
         distance-equivalent {distance_recall:.4}, worst query {worst_query_recall:.4}"
    );
    assert!(
        worst_query_recall >= 0.5,
        "a single query recalled only {worst_query_recall:.4}, \
         which is a traversal failure rather than approximation error"
    );
}

/// The oracle has to be able to disagree with the index. If it cannot, the
/// recall test above proves nothing. Perturbing one stored vector must move it
/// in the exact ranking, which is what makes a mismatch detectable at all.
#[test]
fn the_oracle_can_disagree() {
    let corpus: Vec<(u64, Vec<f32>)> = (0..64u64).map(|k| (k, synthetic_vector(k))).collect();
    let query = synthetic_vector(9_999);

    let baseline = exact_top_k(&corpus, &query, 5);

    // Plant an exact copy of the query. It must displace whatever was ranked
    // first, at distance zero.
    let mut planted = corpus.clone();
    planted.push((10_000, query.clone()));
    let with_plant = exact_top_k(&planted, &query, 5);

    assert_eq!(with_plant[0].0, 10_000, "an exact match must rank first");
    assert!(
        with_plant[0].1 < 1e-6,
        "an exact match must sit at distance zero, got {}",
        with_plant[0].1
    );
    assert_ne!(
        baseline[0].0, with_plant[0].0,
        "the oracle's ranking must respond to the corpus it is given"
    );
}
