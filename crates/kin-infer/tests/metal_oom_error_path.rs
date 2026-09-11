// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Runtime proof of the Metal GPU out-of-memory error path.
//!
//! Background: the Metal backend used to wrap `newBufferWithLength:`'s return
//! straight into a non-null `Buffer`, so an out-of-memory `nil` became
//! undefined behaviour on first use rather than a recoverable error. The
//! fallible-alloc refactor (ba39a7c) routes every device allocation through
//! `try_new_buffer`, which messages the device directly, nil-checks the raw
//! pointer, and returns `None` so callers surface `InferError::OutOfMemory` and
//! let the embedding dispatcher degrade to CPU instead of corrupting the
//! process.
//!
//! That path was previously only logic/compile-verified. This test proves it at
//! runtime the SAFE, DETERMINISTIC way: it drives the backend to request a
//! buffer LARGER than the device's `maxBufferLength`. Per Metal's contract,
//! `newBufferWithLength:` returns `nil` *immediately* for such a request,
//! WITHOUT allocating that memory — so the machine is never put under real
//! memory pressure and the test is deterministic regardless of how much RAM is
//! free. We assert the allocation surfaces `Err(InferError::OutOfMemory)` and
//! does NOT panic or hand back a wrapped-nil `Buffer`.
//!
//! Why this faithfully exercises `try_new_buffer`, despite it being a private
//! module function (and `MetalCompute.device` being private, so neither is
//! reachable from an integration-test crate): the output buffer of `matmul`
//! and `batched_matmul` is sized from the `m`/`n`/`seq_len` *parameters* via
//! `buf_zeros_pooled -> BufferPool::acquire_zeroed -> try_new_buffer`,
//! decoupled from the (tiny) host input slices. So an impossible *parameter*
//! size makes the production `try_new_buffer` hit its nil path with no large
//! host allocation and no kernel dispatch — the `?` returns the error before
//! any GPU work begins.
//!
//! The clean `Err` is itself positive proof that `try_new_buffer` returned
//! `None`: if it had instead wrapped the nil into a `Buffer`, `acquire_zeroed`
//! would immediately `std::ptr::write_bytes(buf.contents(), 0, class)` —
//! zero-filling tens of gigabytes through a NULL pointer — and the process
//! would SIGSEGV instead of returning a recoverable `Err`. Reaching the
//! assertion at all means the nil was caught at the allocation boundary.

#![cfg(feature = "metal")]

use kin_infer::gpu::GpuCompute;
use kin_infer::metal_backend::MetalCompute;
use kin_infer::InferError;
use metal::Device;

/// The device's hard buffer-length cap, in bytes. Any single-buffer request
/// strictly above this value makes Metal return `nil` from
/// `newBufferWithLength:` without allocating.
fn max_buffer_length() -> u64 {
    Device::system_default()
        .expect("a system-default Metal device")
        .max_buffer_length()
}

/// A count of f32 elements whose byte footprint strictly exceeds the device's
/// `maxBufferLength`, so the backing buffer allocation is guaranteed to fail
/// with a nil return. 1 GiB of slack keeps it clear of the cap even after the
/// pool's `size_class` rounding, while staying far below `usize` overflow — the
/// cap is RAM-bounded (tens of GiB at most), so `count * 4` is a modest u64.
fn impossible_f32_count() -> usize {
    let bytes = max_buffer_length().saturating_add(1 << 30); // + 1 GiB slack
                                                             // ceil(bytes / 4) + 1, so `count * 4 > max_buffer_length` with margin.
    ((bytes / 4) + 1) as usize
}

/// 1. `try_new_buffer`'s nil path surfaces as `Err(InferError::OutOfMemory)`
///    rather than a wrapped-nil `Buffer` or a panic.
///
/// `matmul` with `n == k == 1` keeps both input buffers a single f32 each, so
/// the only large allocation is the `m * n == m`-element output, which routes
/// straight through `buf_zeros_pooled -> acquire_zeroed -> try_new_buffer`.
#[test]
fn try_new_buffer_oom_surfaces_outofmemory_not_panic() {
    let Some(metal) = MetalCompute::try_new() else {
        eprintln!("Metal device not available, skipping");
        return;
    };

    let m = impossible_f32_count();
    let tiny = [0.0f32];

    // matmul(a=[m,k], b=[n,k], m, n=1, k=1): output is `m * 1` f32 — its backing
    // buffer is `m * 4` bytes, which exceeds maxBufferLength by design.
    let result = metal.matmul(&tiny, &tiny, m, 1, 1);

    match result {
        Err(InferError::OutOfMemory(msg)) => {
            eprintln!("OOM correctly surfaced (m={m}): {msg}");
        }
        Err(other) => panic!("expected OutOfMemory, got a different error: {other:?}"),
        Ok(out) => panic!(
            "expected OutOfMemory for a {m}-element ({} byte) output buffer, but matmul \
             returned Ok with {} elements — a nil allocation was not caught",
            (m as u64) * 4,
            out.len()
        ),
    }
}

/// 2. Through the `GpuCompute` *trait* surface (the production dispatch path the
///    embedding engine actually calls), an allocating method returns
///    `Err(InferError::OutOfMemory)` for an impossible size WITHOUT panicking,
///    and the backend stays usable for a normal call afterwards.
///
/// Exercises two distinct allocation sites — the GEMM output (`matmul`) and the
/// attention-scores buffer (`batched_matmul`, sized `heads * seq_len^2`) — to
/// show the `Result` propagates cleanly regardless of which buffer hits the cap.
#[test]
fn gpucompute_methods_return_oom_without_panic() {
    let Some(metal) = MetalCompute::try_new() else {
        eprintln!("Metal device not available, skipping");
        return;
    };
    let gpu: &dyn GpuCompute = &metal;

    let tiny = [0.0f32];

    // GEMM output path.
    let m = impossible_f32_count();
    assert!(
        matches!(
            gpu.matmul(&tiny, &tiny, m, 1, 1),
            Err(InferError::OutOfMemory(_))
        ),
        "matmul via &dyn GpuCompute must return OutOfMemory for an impossible output size"
    );

    // Attention-scores path: buf_c is `num_heads * seq_len * seq_len` f32, so
    // pick seq_len with seq_len^2 >= impossible_f32_count() and heads = head_dim = 1.
    let seq_len = (impossible_f32_count() as f64).sqrt().ceil() as usize + 1;
    assert!(
        matches!(
            gpu.batched_matmul(&tiny, &tiny, 1, seq_len, 1),
            Err(InferError::OutOfMemory(_))
        ),
        "batched_matmul via &dyn GpuCompute must return OutOfMemory for an impossible \
         scores buffer (seq_len={seq_len})"
    );

    // The backend survived both failed allocations cleanly — a real, in-bounds
    // GEMM still succeeds, proving no poisoned state and no leaked panic.
    let a = [1.0f32, 2.0, 3.0, 4.0]; // [m=2, k=2]
    let b = [1.0f32, 0.0, 0.0, 1.0]; // [n=2, k=2] (identity), transb
    let out = gpu
        .matmul(&a, &b, 2, 2, 2)
        .expect("a normal in-bounds matmul must still succeed after OOM errors");
    assert_eq!(out.len(), 4, "post-OOM matmul output shape");
}
