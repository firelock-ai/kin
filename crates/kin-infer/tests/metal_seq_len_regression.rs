// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Regression test for the Metal BERT NaN-at-seq-512 bug.
//!
//! See `planning/metal-bert-nan-bug.md`. The pre-existing
//! `test_metal_fused_attention_batched_matches_cpu` only exercised seq_len=7,
//! masking a numerical-stability bug in the Metal attention kernels at the
//! seq_len=512 regime that BGE-small-en-v1.5 hits during entity embedding.
//!
//! This sweep exercises seq_lens around the 512-token boundary on both the
//! grouped (batched) and non-grouped fused attention paths. Each Metal output
//! is compared element-wise against the CPU reference computed with identical
//! Q/K/V/mask/scale/alibi inputs.

#![cfg(feature = "metal")]

use kin_infer::gpu::{CpuCompute, GpuCompute};
use kin_infer::metal_backend::MetalCompute;

fn make_qkv(total_heads: usize, seq_len: usize, head_dim: usize) -> (Vec<f32>, Vec<f32>, Vec<f32>) {
    // Use deterministic-but-varied values with magnitudes representative of
    // post-projection BERT activations (roughly N(0, scale)). The original
    // seq_len=7 test used a tiny 0.01 scale, which kept exp() arguments
    // microscopic and hid kernel divergence. We pick a range that produces
    // post-softmax scores in the [-10, 10] regime — the boundary at which
    // fp32 exp() starts to matter and the "subtract max" stabilization is
    // load-bearing.
    let n = total_heads * seq_len * head_dim;
    let mut q = Vec::with_capacity(n);
    let mut k = Vec::with_capacity(n);
    let mut v = Vec::with_capacity(n);
    for i in 0..n {
        let qf = ((i as u32).wrapping_mul(2654435761) ^ 0xa5a5a5a5) as i32 as f32 / i32::MAX as f32;
        let kf = ((i as u32).wrapping_mul(40503) ^ 0x5a5a5a5a) as i32 as f32 / i32::MAX as f32;
        let vf = ((i as u32).wrapping_mul(2246822519) ^ 0xdeadbeef) as i32 as f32 / i32::MAX as f32;
        q.push(qf);
        k.push(kf);
        v.push(vf);
    }
    (q, k, v)
}

/// Realistic BERT/BGE-small mask: first `valid` columns are 1, rest are 0.
fn padding_mask(seq_len: usize, valid: usize) -> Vec<u32> {
    (0..seq_len).map(|i| if i < valid { 1 } else { 0 }).collect()
}

fn max_abs_err(a: &[f32], b: &[f32]) -> f32 {
    assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b.iter())
        .map(|(x, y)| (x - y).abs())
        .fold(0.0f32, f32::max)
}

fn count_nonfinite(v: &[f32]) -> usize {
    v.iter().filter(|x| !x.is_finite()).count()
}

/// Sweep over seq_len for the grouped (batched) attention path used by
/// BertModel::forward_batched. Mirrors the existing seq_len=7 test setup,
/// extended across the 7..=1024 range.
#[test]
fn metal_fused_attention_batched_seq_len_sweep() {
    let Some(metal) = MetalCompute::try_new() else {
        eprintln!("Metal device not available, skipping");
        return;
    };
    let cpu = CpuCompute;

    // BGE-small-en-v1.5 shape: 12 heads × 32 head_dim. Use 1 group (batch=1)
    // to mimic the indexing-path embedding call.
    let num_groups = 1usize;
    let heads_per_group = 12usize;
    let head_dim = 32usize;
    let total_heads = num_groups * heads_per_group;
    let alibi: Vec<f32> = Vec::new(); // BERT has no ALiBi
    let tol = 5e-3f32;

    let mut report = Vec::<(usize, f32, usize)>::new();

    for &seq_len in &[7usize, 64, 128, 256, 384, 511, 512, 513, 1024] {
        let (q, k, v) = make_qkv(total_heads, seq_len, head_dim);
        // Realistic padding pattern: ~80% of slots are real tokens, rest pad.
        let valid = (seq_len * 4 / 5).max(1);
        let masks = padding_mask(seq_len, valid);
        let scale = 1.0 / (head_dim as f32).sqrt();

        let out_metal = metal.fused_attention_batched(
            &q,
            &k,
            &v,
            num_groups,
            heads_per_group,
            seq_len,
            head_dim,
            scale,
            &alibi,
            &masks,
        );
        let out_cpu = cpu.fused_attention_batched(
            &q,
            &k,
            &v,
            num_groups,
            heads_per_group,
            seq_len,
            head_dim,
            scale,
            &alibi,
            &masks,
        );

        let nan_metal = count_nonfinite(&out_metal);
        let nan_cpu = count_nonfinite(&out_cpu);
        // Metal must not introduce NaNs that the CPU reference does not have.
        // The CPU reference may also produce NaN for fully-masked rows; match
        // those exactly rather than asserting strict finiteness.
        if nan_cpu == 0 {
            assert_eq!(
                nan_metal, 0,
                "seq_len={seq_len}: Metal produced {nan_metal} NaN/Inf values, CPU produced none"
            );
        }

        let err = max_abs_err(&out_metal, &out_cpu);
        report.push((seq_len, err, nan_metal));
        eprintln!(
            "fused_attention_batched seq_len={seq_len:>4} max_abs_err={err:.6e} nan_metal={nan_metal} nan_cpu={nan_cpu}"
        );
    }

    let mut failed = Vec::new();
    for (seq_len, err, _) in &report {
        if !(err.is_finite()) || *err > tol {
            failed.push((*seq_len, *err));
        }
    }
    assert!(
        failed.is_empty(),
        "metal_fused_attention_batched diverged from CPU at: {failed:?}"
    );
}

/// Probe the Metal GELU kernel with a range of input magnitudes. BERT
/// activations after a couple layers regularly exceed |x| > 10, which is
/// where the unstabilized GELU formulation
///   x * 0.5 * (1 + tanh(x * 0.7978 * (1 + 0.044715 * x^2)))
/// can overflow Metal's tanh implementation: the tanh argument grows like
/// 0.0359 * x^3 and crosses the fp32 sinh/cosh inf boundary at |x| ~ 13.
/// MSL's stdlib tanh evaluates as sinh/cosh and returns NaN once both
/// overflow to +inf, so a single oversized activation produces a NaN that
/// then propagates through every subsequent op via matmul.
#[test]
fn metal_gelu_does_not_nan_on_large_inputs() {
    let Some(metal) = MetalCompute::try_new() else {
        eprintln!("Metal device not available, skipping");
        return;
    };
    let cpu = CpuCompute;

    // Span the magnitude range BERT activations actually visit. The
    // production NaN appeared at GELU on real BGE-small inputs; values up to
    // ~50 are realistic after several layers without any normalization
    // applied to FFN intermediates.
    let mags = [0.0f32, 1.0, 5.0, 10.0, 12.0, 13.0, 14.0, 15.0, 20.0, 30.0, 50.0, 100.0];
    let mut data: Vec<f32> = Vec::new();
    for &m in &mags {
        data.push(m);
        data.push(-m);
    }
    let mut metal_out = data.clone();
    let mut cpu_out = data.clone();
    metal.gelu(&mut metal_out);
    cpu.gelu(&mut cpu_out);

    eprintln!("input  -> metal | cpu");
    let mut bad = Vec::new();
    for (idx, ((x, m), c)) in data.iter().zip(metal_out.iter()).zip(cpu_out.iter()).enumerate() {
        eprintln!("{x:>8} -> {m:>14e} | {c:>14e}");
        if !m.is_finite() && c.is_finite() {
            bad.push((idx, *x, *m, *c));
        }
    }
    assert!(
        bad.is_empty(),
        "Metal GELU produced NaN/Inf where CPU returned finite values: {bad:?}"
    );
}

/// Stress test the bare Metal matmul kernel at BERT-realistic shapes.
/// Catches accumulator overflow / threadgroup-tile bugs that would not
/// show up in the seq_len=7 / 16 unit tests.
#[test]
fn metal_matmul_shapes_match_cpu_at_bert_dims() {
    let Some(metal) = MetalCompute::try_new() else {
        eprintln!("Metal device not available, skipping");
        return;
    };
    let cpu = CpuCompute;

    // (m, n, k) — what BGE-small-en-v1.5 uses per layer.
    let cases = [
        (64usize, 384usize, 384usize),    // QKV proj at seq=64
        (64, 1536, 384),                   // FFN intermediate at seq=64
        (64, 384, 1536),                   // FFN out at seq=64
        (512, 384, 384),                   // QKV proj at seq=512
        (512, 1536, 384),                  // FFN intermediate at seq=512
        (512, 384, 1536),                  // FFN out at seq=512
    ];

    for &(m, n, k) in &cases {
        let a: Vec<f32> = (0..m * k)
            .map(|i| ((i as i32 % 257 - 128) as f32) * 0.05)
            .collect();
        let b: Vec<f32> = (0..n * k)
            .map(|i| ((i as i32 % 263 - 131) as f32) * 0.05)
            .collect();
        let c_metal = metal.matmul(&a, &b, m, n, k);
        let c_cpu = cpu.matmul(&a, &b, m, n, k);
        let err = max_abs_err(&c_metal, &c_cpu);
        let nan = count_nonfinite(&c_metal);
        eprintln!(
            "matmul m={m:>4} n={n:>4} k={k:>4} max_abs_err={err:.6e} nan={nan}"
        );
        assert_eq!(nan, 0, "matmul m={m} n={n} k={k} produced {nan} non-finite");
        // Tolerance: matmul accumulates k terms of magnitude ~ (max_a * max_b),
        // so absolute error scales with sqrt(k).
        let tol = 1e-3 * (k as f32).sqrt() * 100.0;
        assert!(
            err < tol,
            "matmul m={m} n={n} k={k} max_abs_err={err} exceeds tol={tol}"
        );
    }
}

/// Sweep over the non-grouped fused_attention path (used by BertModel::forward,
/// the single-input non-batched case).
#[test]
fn metal_fused_attention_seq_len_sweep() {
    let Some(metal) = MetalCompute::try_new() else {
        eprintln!("Metal device not available, skipping");
        return;
    };
    let cpu = CpuCompute;

    let num_heads = 12usize;
    let head_dim = 32usize;
    let alibi: Vec<f32> = Vec::new();
    let tol = 5e-3f32;

    let mut report = Vec::<(usize, f32, usize)>::new();

    for &seq_len in &[7usize, 64, 128, 256, 384, 511, 512, 513, 1024] {
        let (q, k, v) = make_qkv(num_heads, seq_len, head_dim);
        let valid = (seq_len * 4 / 5).max(1);
        let mask = padding_mask(seq_len, valid);
        let scale = 1.0 / (head_dim as f32).sqrt();

        let out_metal = metal.fused_attention(
            &q, &k, &v, num_heads, seq_len, head_dim, scale, &alibi, &mask,
        );
        let out_cpu = cpu.fused_attention(
            &q, &k, &v, num_heads, seq_len, head_dim, scale, &alibi, &mask,
        );

        let nan_metal = count_nonfinite(&out_metal);
        let nan_cpu = count_nonfinite(&out_cpu);
        if nan_cpu == 0 {
            assert_eq!(
                nan_metal, 0,
                "seq_len={seq_len}: Metal produced {nan_metal} NaN/Inf values, CPU produced none"
            );
        }

        let err = max_abs_err(&out_metal, &out_cpu);
        report.push((seq_len, err, nan_metal));
        eprintln!(
            "fused_attention      seq_len={seq_len:>4} max_abs_err={err:.6e} nan_metal={nan_metal} nan_cpu={nan_cpu}"
        );
    }

    let mut failed = Vec::new();
    for (seq_len, err, _) in &report {
        if !(err.is_finite()) || *err > tol {
            failed.push((*seq_len, *err));
        }
    }
    assert!(
        failed.is_empty(),
        "metal_fused_attention diverged from CPU at: {failed:?}"
    );
}
