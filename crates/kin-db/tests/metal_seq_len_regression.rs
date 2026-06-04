// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Metal BERT attention seq_len regression sweep.
//!
//! Embeds a single synthetic text at a range of token lengths to map where
//! `kin_infer::BertModel` produces non-finite output on Metal. This is the
//! failure-boundary probe for the bug tracked in
//! `planning/metal-bert-nan-bug.md`: Metal attention kernels return NaN at
//! seq_len in the ~500+ regime while CPU is correct.
//!
//! The test is parameterized on `KIN_EMBED_BACKEND` so the same harness
//! verifies both the failure on Metal and the pass on CPU once the fallback
//! dispatcher is in place:
//!
//!   cargo test -p kin-db --test metal_seq_len_regression -- --nocapture
//!     # default (auto): short lens on Metal, long lens routed to CPU — all pass
//!
//!   KIN_EMBED_BACKEND=metal cargo test -p kin-db --test metal_seq_len_regression
//!     # forces Metal; documents the failure boundary (expected fail at 512+)
//!
//!   KIN_EMBED_BACKEND=cpu cargo test -p kin-db --test metal_seq_len_regression
//!     # forces CPU; proves the fallback path is correct at every seq_len

use kin_db::CodeEmbedder;

/// Token lengths to sweep. The 512 boundary is where BGE-small-en-v1.5's
/// max_position_embeddings sits, and also where the Metal attention kernels
/// historically begin producing NaN. 1024 exceeds the model's max and will
/// be truncated by the tokenizer to 512; it is kept for symmetry so that
/// regressing the truncation behaviour would also be caught.
const SEQ_LENS: &[usize] = &[64, 128, 256, 384, 512, 1024];

/// Real Vue-style entity texts sampled from indexing output. Mix of rich
/// code-like bodies to give the attention kernels realistic token
/// distributions.
const VUE_SHAPED_ENTITY_TEXTS: &[&str] = &[
    "function src/runtime-core/renderer.ts createRenderer fn createRenderer(options: RendererOptions) -> Renderer Creates a renderer instance for a given target platform. The renderer exposes render(vnode, container) and hydrate(vnode, container) as its two main mount entry points. Internally it composes the patch pipeline from options: createElement, createText, createComment, setText, setElementText, patchProp, insert, remove, parentNode, nextSibling, querySelector, setScopeId, insertStaticContent, forcePatchProp. Each of those is invoked during mount/update/unmount of virtual DOM nodes and determines how the abstract tree is projected onto a concrete host. The mount path walks the vnode recursively, calling mountComponent or mountElement depending on shapeFlag, and setup() runs before the first render inside the component setup phase.",
    "function src/runtime-core/component.ts setupComponent fn setupComponent(instance: ComponentInternalInstance, isSSR?: boolean) -> Promise<void> | void Runs the component setup pipeline: initProps, initSlots, setupStatefulComponent. setupStatefulComponent creates a proxy over the component instance that exposes props, attrs, slots, emit, expose, and the publicPropertiesMap. It calls the component setup() function inside a paused reactive effect so that dependencies collected there become reactive bindings on the render scope. The return value is normalized: a function becomes the render function, a render block becomes the state object, and everything else is treated as the setup state. finishComponentSetup then resolves the template/render function and applies compile-on-the-fly if the runtime compiler is available.",
    "function src/reactivity/effect.ts effect fn effect<T = any>(fn: () => T, options?: ReactiveEffectOptions) -> ReactiveEffectRunner<T> Creates a reactive effect that re-runs whenever any tracked dependency changes. Under the hood it allocates a ReactiveEffect with the supplied fn and scheduler; unless lazy is set to true, the effect is eagerly invoked once to populate its dependency set. The returned runner is a callable that re-executes the effect and carries a .effect reference for stop() and for passing into scope APIs. watch, watchEffect, computed, and render effects all build on this primitive.",
    "function src/compiler-core/transform.ts transform fn transform(root: RootNode, options: TransformOptions) -> void Traverses the parsed template AST and applies the configured nodeTransforms and directiveTransforms in a single pass. Each transform receives the current node and a TransformContext that exposes helpers, components, directives, imports, cache, hoists, and the current scope. Hoisting, v-once, v-if, v-for, v-model, slot outlet handling, and the component/element codegen preprocessing all flow through this loop. After walking the tree, root-level codegen metadata is finalized and the transformed AST is handed off to the code generator.",
    "function src/shared/normalizeProps.ts normalizeProps fn normalizeProps(value: Record<string, any> | Array<string | Record<string, any>> | null) -> Record<string, any> | null Normalizes the runtime props declaration into the canonical object form used by the component internals. Accepts either an array of prop names, an object of prop specs, or null. Runtime validation, default resolution, and prop type coercion expect the normalized shape, so this runs at component registration time, not per render.",
];

/// Build a padded text whose approximate token count matches `target_tokens`.
/// BGE-small uses WordPiece; "word " tokenizes to roughly one token. Adding a
/// leading preamble stabilizes the prefix so every length looks like a real
/// entity, not pure filler.
fn synth_text(target_tokens: usize) -> String {
    let preamble =
        "function src/runtime-core/component.ts setupComponent fn setupComponent(instance: ComponentInternalInstance) -> SetupResult ";
    let mut out = String::with_capacity(target_tokens * 8);
    out.push_str(preamble);
    // One "word" roughly one token. Slightly over-provision so truncation
    // brings us to the target rather than coming up short.
    let filler_words = target_tokens + 32;
    for i in 0..filler_words {
        out.push_str("word");
        out.push_str(&(i % 1000).to_string());
        out.push(' ');
    }
    out
}

fn count_non_finite(v: &[f32]) -> usize {
    v.iter().filter(|x| !x.is_finite()).count()
}

fn norm(v: &[f32]) -> f32 {
    v.iter().map(|x| x * x).sum::<f32>().sqrt()
}

/// Sweep seq_lens through the single-input path. The existing retry-fallback
/// in `embed_batch` routes any non-finite `forward_batched` chunk through the
/// single-input `forward` path, so this test mostly exercises that safety net.
/// Covers correctness of whatever path the embedder picks end-to-end.
#[test]
#[ignore]
fn metal_seq_len_sweep_single() {
    std::env::set_var("KIN_EMBED_CACHE", "0");

    let embedder = match CodeEmbedder::new() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("SKIP: could not build embedder: {e}");
            return;
        }
    };

    let backend_label = std::env::var("KIN_EMBED_BACKEND").unwrap_or_else(|_| "auto".into());
    println!("metal_seq_len_sweep_single: KIN_EMBED_BACKEND={backend_label}");

    let mut failures: Vec<(usize, usize, f32)> = Vec::new();

    for &target in SEQ_LENS {
        let text = synth_text(target);
        let vec = embedder
            .embed_text(&text)
            .expect("embed_text should not error");

        let nf = count_non_finite(&vec);
        let n = norm(&vec);
        println!(
            "seq_len~{target}: dims={}, norm={:.6}, non_finite_count={}",
            vec.len(),
            n,
            nf
        );

        if nf > 0 || !n.is_finite() || n == 0.0 {
            failures.push((target, nf, n));
        }
    }

    if !failures.is_empty() {
        for (len, nf, n) in &failures {
            eprintln!(
                "FAIL seq_len~{len}: non_finite={nf}, norm={n:.6} \
                 — likely Metal BERT attention NaN at long sequences; see \
                 planning/metal-bert-nan-bug.md"
            );
        }
        panic!(
            "metal_seq_len_sweep_single failed at {} length(s): {:?}",
            failures.len(),
            failures.iter().map(|(l, _, _)| l).collect::<Vec<_>>()
        );
    }
}

/// Sweep seq_lens through the TRUE batched path. This is the failure mode
/// that caused 2980/2980 Vue entities to store zero-vectors: indexing
/// routes to `embed_batch` with many long texts, which packs them into a
/// multi-element call to `BertModel::forward_batched`, whose Metal attention
/// kernels return NaN at seq_len ≈ 512+.
///
/// Without the CPU fallback, the existing retry-fallback in `embed_batch`
/// fires, sanitize_embedding substitutes zeros, and the stored vector is
/// zero-norm. This test treats zero-norm as a hard failure — a real BGE
/// embedding is L2-normalized, so a zero vector is always sentinel output.
/// With the CPU fallback (auto routing at max_seq > 256 or forced cpu),
/// every length should produce a norm-1 vector.
#[test]
#[ignore]
fn metal_seq_len_sweep_batched() {
    std::env::set_var("KIN_EMBED_CACHE", "0");

    let embedder = match CodeEmbedder::new() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("SKIP: could not build embedder: {e}");
            return;
        }
    };

    let backend_label = std::env::var("KIN_EMBED_BACKEND").unwrap_or_else(|_| "auto".into());
    println!("metal_seq_len_sweep_batched: KIN_EMBED_BACKEND={backend_label}");

    // For each seq_len, submit a batch of 4 distinct texts at that length.
    // A batch > 1 is required to reach `forward_batched`'s multi-input path;
    // distinct texts prevent any dedup shortcut from collapsing the batch.
    const BATCH_PER_LEN: usize = 4;
    let mut failures: Vec<(usize, usize, usize)> = Vec::new();

    for &target in SEQ_LENS {
        let texts: Vec<String> = (0..BATCH_PER_LEN)
            .map(|i| format!("{} variant_{} ", synth_text(target), i))
            .collect();
        let vecs = embedder
            .embed_batch(&texts)
            .expect("embed_batch should not error");
        assert_eq!(vecs.len(), BATCH_PER_LEN);

        let nf: usize = vecs.iter().map(|v| count_non_finite(v)).sum();
        let zero_count: usize = vecs.iter().filter(|v| norm(v) == 0.0).count();
        let norms: Vec<f32> = vecs.iter().map(|v| norm(v)).collect();
        println!(
            "seq_len~{target}, batch={}: non_finite={}, zero_norm={}, norms={:?}",
            BATCH_PER_LEN, nf, zero_count, norms
        );

        if nf > 0 || zero_count > 0 {
            failures.push((target, nf, zero_count));
        }
    }

    if !failures.is_empty() {
        for (len, nf, zero) in &failures {
            eprintln!(
                "FAIL seq_len~{len} (batched): non_finite={nf}, zero_norm={zero} \
                 — Metal BERT attention NaN at long sequences through forward_batched. \
                 CPU fallback in kin-db/src/embed/mod.rs should route this through \
                 GpuBackend::Cpu once KIN_EMBED_BACKEND dispatcher lands. \
                 See planning/metal-bert-nan-bug.md."
            );
        }
        panic!(
            "metal_seq_len_sweep_batched failed at {} length(s): {:?}",
            failures.len(),
            failures.iter().map(|(l, _, _)| l).collect::<Vec<_>>()
        );
    }
}

/// Batched write path with Vue-shaped entity texts at production batch sizes.
/// Reproduces the exact indexing workload that produced the original Vue
/// zero-vector incident: many distinct realistic entity texts at long
/// sequence lengths packed into a single forward_batched call.
///
/// This is the closest direct analog to the indexing path that populated the
/// HNSW index with 2980 zero-vectors. If Metal attention regresses here and
/// this test still passes, the retry-fallback in embed_batch is masking it
/// at the cost of extra inference time — which the dispatch heuristic is
/// meant to avoid.
#[test]
#[ignore]
fn vue_shaped_batched_not_nan_or_zero() {
    std::env::set_var("KIN_EMBED_CACHE", "0");

    let embedder = match CodeEmbedder::new() {
        Ok(e) => e,
        Err(e) => {
            eprintln!("SKIP: could not build embedder: {e}");
            return;
        }
    };

    let backend_label = std::env::var("KIN_EMBED_BACKEND").unwrap_or_else(|_| "auto".into());
    println!("vue_shaped_batched: KIN_EMBED_BACKEND={backend_label}");

    // Replicate each seed so the batch is wide enough to force forward_batched.
    let mut texts: Vec<String> = Vec::with_capacity(VUE_SHAPED_ENTITY_TEXTS.len() * 12);
    for (i, seed) in VUE_SHAPED_ENTITY_TEXTS.iter().enumerate() {
        for j in 0..12 {
            texts.push(format!("{seed} entity_copy={i}_{j}"));
        }
    }

    let vecs = embedder
        .embed_batch(&texts)
        .expect("embed_batch should not error");
    assert_eq!(vecs.len(), texts.len());

    let nf: usize = vecs.iter().map(|v| count_non_finite(v)).sum();
    let zero_count: usize = vecs.iter().filter(|v| norm(v) == 0.0).count();
    let norms: Vec<f32> = vecs.iter().map(|v| norm(v)).collect();
    let min_norm = norms.iter().cloned().fold(f32::INFINITY, f32::min);
    let max_norm = norms.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
    println!(
        "vue_shaped batched {} texts: non_finite={}, zero_norm={}, norm range=[{:.6},{:.6}]",
        texts.len(),
        nf,
        zero_count,
        min_norm,
        max_norm
    );

    assert_eq!(nf, 0, "{nf} vue-shaped batched vectors contain NaN");
    assert_eq!(
        zero_count, 0,
        "{zero_count} vue-shaped batched vectors had zero norm — Metal kernel NaN leaked past sanitize; dispatch path not routing correctly"
    );
}
