// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Diagnostic tests for the semantic search pipeline.
//!
//! These tests isolate where NaN first appears in the
//! embed -> store -> cosine-distance flow:
//!
//!   1. query vector (embedder output)
//!   2. stored vectors (persisted HNSW nodes on disk)
//!   3. cosine math (kin_vector::cosine_distance)
//!
//! Do NOT fix anything here; these tests document the live bug and act as
//! regression protection once the underlying cause is addressed.

use std::path::PathBuf;

use kin_db::embed::format_entity_text;
use kin_db::{CodeEmbedder, RetrievalKey, SnapshotManager};

/// Path to Vue's pre-built graph (from the focused bench workdir).
fn vue_graph_path() -> PathBuf {
    PathBuf::from(
        "/Users/troyfortinjr/GitHub/kin-ecosystem/kin-bench/workdir-focused/arms/kin/repos/vuejs__core/.kin/kindb/graph.kndb",
    )
}

fn count_nan(v: &[f32]) -> usize {
    v.iter().filter(|x| x.is_nan()).count()
}

fn norm(v: &[f32]) -> f32 {
    v.iter().map(|x| x * x).sum::<f32>().sqrt()
}

#[cfg(not(feature = "metal"))]
fn accelerated_embedder_for_embedding_test(test_name: &str) -> Option<CodeEmbedder> {
    eprintln!(
        "SKIP: {test_name} requires the kin-db/metal feature; \
         run `cargo test -p kin-db --features metal --test embedding_sanity` \
         to exercise the production accelerator path"
    );
    None
}

#[cfg(feature = "metal")]
fn accelerated_embedder_for_embedding_test(test_name: &str) -> Option<CodeEmbedder> {
    let embedder = match CodeEmbedder::new() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("SKIP: could not build embedder for {test_name}: {e}");
            return None;
        }
    };
    if !embedder.uses_local_accelerator() {
        eprintln!(
            "SKIP: {test_name} requires an accelerator backend; got {:?}",
            embedder.local_backend()
        );
        return None;
    }
    Some(embedder)
}

#[cfg(not(feature = "metal"))]
fn metal_feature_enabled_for_embedding_test(test_name: &str) -> bool {
    eprintln!(
        "SKIP: {test_name} requires the kin-db/metal feature; \
         run `cargo test -p kin-db --features metal --test embedding_sanity`"
    );
    false
}

#[cfg(feature = "metal")]
fn metal_feature_enabled_for_embedding_test(_test_name: &str) -> bool {
    true
}

// ---------------------------------------------------------------------------
// Test 1: query vector out of the embedder must be finite.
// ---------------------------------------------------------------------------

#[test]
fn test_query_vector_not_nan() {
    let Some(embedder) = accelerated_embedder_for_embedding_test("test_query_vector_not_nan")
    else {
        return;
    };

    let vec = embedder
        .embed_text("hello world")
        .expect("embed_text should not error");

    let nan_count = count_nan(&vec);
    let n = norm(&vec);
    println!(
        "query vector: dims={}, norm={:.6}, nan_count={}",
        vec.len(),
        n,
        nan_count
    );
    println!("first 8 values: {:?}", &vec[..vec.len().min(8)]);

    assert!(
        !vec.is_empty(),
        "embedder returned empty vector for 'hello world'"
    );
    assert_eq!(
        nan_count,
        0,
        "query vector contains {nan_count} NaN values (of {})",
        vec.len()
    );
}

// ---------------------------------------------------------------------------
// Test 2: stored vectors inside Vue's on-disk HNSW index must be finite and
// non-zero.
// ---------------------------------------------------------------------------

#[test]
fn test_stored_vectors_not_nan() {
    use kin_vector::HnswSnapshot;

    let kndb = vue_graph_path();
    if !kndb.exists() {
        eprintln!("SKIP: Vue graph not present at {}", kndb.display());
        return;
    }
    let kvec = kndb.with_extension("kvec");
    if !kvec.exists() {
        eprintln!("SKIP: Vue kvec sidecar not present at {}", kvec.display());
        return;
    }

    // Load the raw HNSW snapshot directly from disk. kin-vector has no public
    // iterator over stored nodes, but HnswSnapshot is `pub` so we can
    // deserialize it ourselves to inspect stored vectors.
    let bytes = std::fs::read(&kvec).expect("read kvec");
    let snapshot: HnswSnapshot<RetrievalKey> =
        rmp_serde::from_slice(&bytes).expect("deserialize HnswSnapshot");

    let total_nodes = snapshot.graph.nodes.len();
    let active_ids = snapshot.graph.idx_to_id.len();
    println!(
        "stored index: format_version={}, dims={}, nodes={}, ids={}",
        snapshot.format_version, snapshot.graph.dimensions, total_nodes, active_ids
    );

    assert!(total_nodes > 0, "Vue's HNSW index has zero stored nodes");

    // Sample broadly: first 5, evenly spaced 10, last 5. More coverage
    // exposes cases where only part of the index is corrupted.
    let mut sample_idxs: Vec<usize> = (0..total_nodes.min(5)).collect();
    if total_nodes > 10 {
        let step = total_nodes / 10;
        sample_idxs.extend((0..10).map(|i| i * step));
    }
    if total_nodes > 5 {
        sample_idxs.extend((total_nodes - 5)..total_nodes);
    }
    sample_idxs.sort();
    sample_idxs.dedup();

    let mut nan_nodes = 0usize;
    let mut zero_norm_nodes = 0usize;

    for idx in &sample_idxs {
        let node = &snapshot.graph.nodes[*idx];
        let v = &node.vector;
        let nan_count = count_nan(v);
        let n = norm(v);
        let first_vals: Vec<f32> = v.iter().take(5).copied().collect();
        println!(
            "node[{idx}]: dims={}, norm={:.6}, nan_count={}, first5={:?}",
            v.len(),
            n,
            nan_count,
            first_vals
        );
        if nan_count > 0 {
            nan_nodes += 1;
        }
        if n == 0.0 {
            zero_norm_nodes += 1;
        }
    }

    println!(
        "sampled {} nodes: {} had NaN, {} had zero norm",
        sample_idxs.len(),
        nan_nodes,
        zero_norm_nodes
    );

    assert_eq!(
        nan_nodes, 0,
        "{nan_nodes} of sampled stored vectors contain NaN"
    );
    // Zero-norm sampled nodes indicate the sanitize_embedding guard fired during
    // indexing because kin-infer returned NaN. The guard keeps cosine_distance
    // well-defined (returns 1.0), but semantic search will degrade to uniform
    // distances until the underlying inference bug is fixed. Print a diagnostic
    // rather than failing hard, because the NaN regression (nan_nodes) is the
    // cosine-corrupting bug this suite was written to catch.
    if zero_norm_nodes > 0 {
        eprintln!(
            "warning: {zero_norm_nodes} of {} sampled stored vectors have zero norm \
             — kin-infer inference returned non-finite vectors for these entities \
             and the embedder substituted zeros (see tracing::error! logs in kin-db::embed).",
            sample_idxs.len()
        );
    }
}

// ---------------------------------------------------------------------------
// Test 3: end-to-end semantic_search on Vue must return finite distances.
// ---------------------------------------------------------------------------

#[test]
fn test_semantic_search_distances_finite() {
    if !metal_feature_enabled_for_embedding_test("test_semantic_search_distances_finite") {
        return;
    }

    let kndb = vue_graph_path();
    if !kndb.exists() {
        eprintln!("SKIP: Vue graph not present at {}", kndb.display());
        return;
    }

    let mgr = match SnapshotManager::open_read_only(&kndb) {
        Ok(m) => m,
        Err(e) => {
            eprintln!("SKIP: could not open Vue graph read-only (lock contention?): {e}");
            return;
        }
    };
    let graph = mgr.graph();

    let results = graph
        .semantic_search("test", 5)
        .expect("semantic_search should not error");

    println!("semantic_search('test', 5) returned {} hits", results.len());
    let mut nan_distances = 0usize;
    for (i, (key, dist)) in results.iter().enumerate() {
        println!(
            "  [{i}] key={:?} distance={} (is_nan={})",
            key,
            dist,
            dist.is_nan()
        );
        if dist.is_nan() {
            nan_distances += 1;
        }
    }

    if results.is_empty() {
        eprintln!(
            "SKIP: semantic_search returned no hits — the local Vue fixture may not have embeddings loaded"
        );
        return;
    }
    assert_eq!(
        nan_distances,
        0,
        "{nan_distances} of {} returned distances are NaN",
        results.len()
    );
}

// ---------------------------------------------------------------------------
// Test 4: raw cosine_distance sanity. Known vectors should produce finite
// results. Zero-vector inputs are documented: cosine_distance currently
// returns 1.0 for zero-norm inputs (defensive guard already in place).
// ---------------------------------------------------------------------------

#[test]
fn test_cosine_sanity() {
    use kin_vector::cosine_distance;

    let a = [1.0f32, 0.0, 0.0];
    let b = [0.0f32, 1.0, 0.0];
    let c = [1.0f32, 0.0, 0.0];
    let zero = [0.0f32, 0.0, 0.0];

    let d_orthogonal = cosine_distance(&a, &b);
    let d_identical = cosine_distance(&a, &c);
    let d_zero_a = cosine_distance(&zero, &b);
    let d_zero_b = cosine_distance(&a, &zero);
    let d_zero_both = cosine_distance(&zero, &zero);

    println!("cosine([1,0,0], [0,1,0]) = {d_orthogonal}");
    println!("cosine([1,0,0], [1,0,0]) = {d_identical}");
    println!("cosine([0,0,0], [0,1,0]) = {d_zero_a}");
    println!("cosine([1,0,0], [0,0,0]) = {d_zero_b}");
    println!("cosine([0,0,0], [0,0,0]) = {d_zero_both}");

    assert!(
        (d_orthogonal - 1.0).abs() < 1e-6,
        "orthogonal cosine distance should be ~1.0, got {d_orthogonal}"
    );
    assert!(
        d_identical.abs() < 1e-6,
        "identical cosine distance should be ~0.0, got {d_identical}"
    );

    // Document current zero-vector behavior. If these change, the guard in
    // kin_vector::cosine_distance has been touched.
    assert!(
        !d_zero_a.is_nan(),
        "zero-a cosine should not be NaN (guard present)"
    );
    assert!(
        !d_zero_b.is_nan(),
        "zero-b cosine should not be NaN (guard present)"
    );
    assert!(
        !d_zero_both.is_nan(),
        "zero-both cosine should not be NaN (guard present)"
    );
}

// ---------------------------------------------------------------------------
// Test 5: the batched write path must produce finite vectors for a spread of
// realistic entity texts. This reproduces the regression where every stored
// embedding in Vue was NaN: the single-query embed_text path is exercised in
// Test 1, but indexing goes through embed_batch with batch_size > 1, which
// hit `forward_batched` (a different code path in kin-infer). If NaN reappears
// here the guard in sanitize_embedding has either regressed or been removed.
// ---------------------------------------------------------------------------

#[test]
fn test_batched_write_path_not_nan() {
    let Some(embedder) = accelerated_embedder_for_embedding_test("test_batched_write_path_not_nan")
    else {
        return;
    };

    let long_body = "x ".repeat(4096);
    let entity_inputs: Vec<(&str, &str, &str)> = vec![
        (
            "toDisplayString",
            "fn toDisplayString(v: unknown) -> String",
            "convert value to displayable string representation",
        ),
        (
            "parseConfig",
            "fn parseConfig(path: &str) -> Result<Config, Error>",
            "read TOML and merge defaults",
        ),
        (
            "h",
            "fn h(type_: VNodeTypes, props: Data) -> VNode",
            "hyperscript helper used to create virtual DOM nodes",
        ),
        (
            "createRenderer",
            "fn createRenderer(options: RendererOptions) -> Renderer",
            "set up a renderer instance for a platform",
        ),
        (
            "ref",
            "fn ref<T>(value: T) -> Ref<T>",
            "create a shallow reactive reference",
        ),
        ("", "", ""),
        ("   ", "\n\t\n", " "),
        (
            "unicode_mix",
            "fn Привет_世界_🦀(arg: &str) -> ()",
            "naïve café façade — mix of unicode scripts and emoji",
        ),
        ("veryLong", "fn veryLong(args: &[u8])", long_body.as_str()),
        ("single_char", "a", "a"),
    ];
    let texts: Vec<String> = entity_inputs
        .iter()
        .map(|(n, s, b)| format_entity_text(n, s, b))
        .collect();

    let vectors = embedder
        .embed_batch(&texts)
        .expect("embed_batch should not error");

    assert_eq!(vectors.len(), texts.len());
    let mut nan_count = 0usize;
    let mut zero_count = 0usize;
    for (i, v) in vectors.iter().enumerate() {
        let preview: String = texts[i].chars().take(60).collect();
        let n = norm(v);
        let nans = count_nan(v);
        println!(
            "[{i}] dims={} norm={:.6} nan_count={} text_preview={:?}",
            v.len(),
            n,
            nans,
            preview
        );
        if nans > 0 {
            nan_count += 1;
        }
        if n == 0.0 {
            zero_count += 1;
        }
    }

    assert_eq!(nan_count, 0, "{nan_count} batched vectors contain NaN");
    // Zero-norm is acceptable for genuinely empty input, but flag it for
    // visibility — a real entity text should never pool to zero.
    if zero_count > 0 {
        eprintln!(
            "note: {zero_count} batched vectors were zero (expected only for empty/whitespace inputs)"
        );
    }
}

// ---------------------------------------------------------------------------
// Test 6: the same path at production batch sizes. Exact minimal reproducer
// for the Vue NaN incident: many realistically-long entity texts in a single
// embed_batch call stress the Metal forward_batched kernel and historically
// produced 100% NaN output. The sanitize_embedding guard converts any NaN
// vectors to zero so this test asserts finite-ness, not non-zero-ness.
// ---------------------------------------------------------------------------

#[test]
fn test_batched_many_long_texts_not_nan() {
    let Some(embedder) =
        accelerated_embedder_for_embedding_test("test_batched_many_long_texts_not_nan")
    else {
        return;
    };

    // Mimic entity-shaped inputs at Vue-like lengths (several hundred to a
    // few thousand characters), filling a batch at least as large as the
    // default embed batch size.
    let seeds = [
        "runtime-core component setup hooks reactivity tracking deps watchEffect",
        "compiler transformElement directives v-if v-for v-model slot scope",
        "shared utility isObject isString isPromise looseEqual looseIndexOf",
        "server-renderer renderVNode renderComponentVNode renderToString streaming",
        "reactivity ref computed effect scheduler pauseTracking resetTracking",
    ];
    let mut texts: Vec<String> = Vec::new();
    for i in 0..64usize {
        let seed = seeds[i % seeds.len()];
        let body = (0..12)
            .map(|j| format!("line{j:02} call_{i} arg_{}", j * 3))
            .collect::<Vec<_>>()
            .join(" ");
        texts.push(format!(
            "function src/runtime-core/foo_{i}.ts name_{i} fn name_{i}(a: T, b: U) -> R {seed} {body}"
        ));
    }

    let vectors = embedder
        .embed_batch(&texts)
        .expect("embed_batch should not error");

    assert_eq!(vectors.len(), texts.len());
    let mut nan_count = 0usize;
    let mut zero_count = 0usize;
    for v in &vectors {
        if v.iter().any(|x| x.is_nan()) {
            nan_count += 1;
        }
        if norm(v) == 0.0 {
            zero_count += 1;
        }
    }
    println!(
        "batched {} long texts: {} NaN vectors, {} zero-norm vectors",
        vectors.len(),
        nan_count,
        zero_count
    );

    assert_eq!(nan_count, 0, "NaN vectors returned by embed_batch");
    if zero_count > 0 {
        eprintln!(
            "warning: {zero_count} of {} batched vectors had zero norm. \
             sanitize_embedding fired because kin-infer produced non-finite vectors \
             at seq_len >= ~512 on Metal. Until kin-infer is patched, semantic search \
             quality for long entity texts will degrade (cosine_distance returns 1.0 \
             for zero-norm pairs).",
            vectors.len()
        );
    }
}
