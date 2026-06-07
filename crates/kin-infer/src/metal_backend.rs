// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Metal GPU compute backend for macOS (Apple Silicon).
//!
//! Custom MSL compute shaders for transformer operations.
//! No candle, no ONNX, no MPS — direct Metal API via objc2-metal.

#![cfg(feature = "metal")]

use crate::gpu::{GpuBackend, GpuCompute, GpuDeviceInfo, LayerTensors, LayerConfig};
use crate::InferError;
use metal::{
    Buffer, CommandBufferRef, CommandQueue, CompileOptions, ComputePipelineState, Device,
    MTLLanguageVersion, MTLResourceOptions, MTLSize,
};
use objc2::rc::autoreleasepool;
use parking_lot::{Condvar, Mutex};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Host-stall profiling (opt-in, zero-overhead when off)
// ---------------------------------------------------------------------------
//
// When `KIN_INFER_METAL_PROFILE` is set, `commit_bounded` bumps a submission
// counter on every commit and accumulates the wall-clock the host actually
// spends PARKED on the in-flight backpressure condvar into the host-stall
// accumulator. Because commits no longer block on `wait_until_completed`, the
// measured stall reflects real backpressure (the host waiting for an in-flight
// slot) rather than every round-trip, so a benchmark can report the stall-vs-
// kernel split and the number of GPU submissions per forward pass. Reads via a
// relaxed atomic; the env var is sampled once per process.

static STALL_NANOS: AtomicU64 = AtomicU64::new(0);
static SUBMISSIONS: AtomicU64 = AtomicU64::new(0);

// Per-phase wall-clock accumulators (ns), bucketed by kernel class so a forward
// pass reports where the time actually goes — matmul vs attention vs norm/softmax
// vs activation, plus the host↔device copy/readback overhead that wraps every op.
// Only written when `profile_enabled()`; relaxed atomics, zero cost when off.
static MATMUL_NANOS: AtomicU64 = AtomicU64::new(0);
static ATTENTION_NANOS: AtomicU64 = AtomicU64::new(0);
static NORM_NANOS: AtomicU64 = AtomicU64::new(0);
static ACTIVATION_NANOS: AtomicU64 = AtomicU64::new(0);
static COPY_NANOS: AtomicU64 = AtomicU64::new(0);

// Per-phase GPU-execution accumulators (ns), measured from each command
// buffer's MTLCommandBuffer.GPUStartTime/GPUEndTime (the actual on-GPU window,
// valid after completion). Unlike the host wall-clock buckets above, these are
// build-INVARIANT — debug vs release shifts host dispatch/encode overhead but
// not how long the GPU spends executing a kernel — so a profiler arm can trust
// them across an unoptimized test binary and an optimized embed. Only written
// when `profile_enabled()`; relaxed atomics, zero cost when off.
static GPU_MATMUL_NANOS: AtomicU64 = AtomicU64::new(0);
static GPU_ATTENTION_NANOS: AtomicU64 = AtomicU64::new(0);
static GPU_NORM_NANOS: AtomicU64 = AtomicU64::new(0);
static GPU_ACTIVATION_NANOS: AtomicU64 = AtomicU64::new(0);
static GPU_COPY_NANOS: AtomicU64 = AtomicU64::new(0);

thread_local! {
    // The phase whose GPU command buffers should be attributed at the next
    // commit/wait boundary. Set by `time_phase` for the duration of its closure
    // (save/restore so nested phases compose), read by `commit_wait`. Only
    // touched when `profile_enabled()`.
    static CURRENT_PHASE: std::cell::Cell<Option<Phase>> = const { std::cell::Cell::new(None) };
}

/// Kernel-class buckets for per-phase profiling.
#[derive(Clone, Copy)]
enum Phase {
    Matmul,
    Attention,
    Norm,
    Activation,
    Copy,
}

impl Phase {
    #[inline]
    fn counter(self) -> &'static AtomicU64 {
        match self {
            Phase::Matmul => &MATMUL_NANOS,
            Phase::Attention => &ATTENTION_NANOS,
            Phase::Norm => &NORM_NANOS,
            Phase::Activation => &ACTIVATION_NANOS,
            Phase::Copy => &COPY_NANOS,
        }
    }

    #[inline]
    fn gpu_counter(self) -> &'static AtomicU64 {
        match self {
            Phase::Matmul => &GPU_MATMUL_NANOS,
            Phase::Attention => &GPU_ATTENTION_NANOS,
            Phase::Norm => &GPU_NORM_NANOS,
            Phase::Activation => &GPU_ACTIVATION_NANOS,
            Phase::Copy => &GPU_COPY_NANOS,
        }
    }
}

/// Run `f`, attributing its wall-clock to `phase` when profiling is enabled.
/// Zero overhead (no Instant, no atomic) when profiling is off.
#[inline]
fn time_phase<T>(phase: Phase, f: impl FnOnce() -> T) -> T {
    if profile_enabled() {
        // Publish this phase so any command buffer committed inside `f` is
        // attributed to it by GPU timestamp (see `commit_wait`). Save/restore
        // the outer phase so nested `time_phase` calls compose correctly.
        let prev = CURRENT_PHASE.with(|p| p.replace(Some(phase)));
        let start = std::time::Instant::now();
        let out = f();
        phase
            .counter()
            .fetch_add(start.elapsed().as_nanos() as u64, Ordering::Relaxed);
        CURRENT_PHASE.with(|p| p.set(prev));
        out
    } else {
        f()
    }
}

/// GPU-execution nanoseconds of a *completed* command buffer, from its
/// `GPUStartTime`/`GPUEndTime` (CFTimeInterval, seconds). Returns 0 if the window
/// is unavailable/degenerate (e.g. a command buffer that never ran GPU work).
#[inline]
fn cmd_gpu_nanos(cmd: &CommandBufferRef) -> u64 {
    // `metal` 0.29 wraps no timing accessor, so message the live ObjC object
    // directly. Use the modern `objc2` runtime (already a dep) rather than the
    // `objc` 0.2 the `metal` crate re-exports — the legacy `sel_impl!` macro
    // trips rustc's check-cfg lint. `cmd.as_ptr()` is the underlying
    // MTLCommandBuffer; reinterpret it as an `AnyObject` for the send.
    use metal::foreign_types::ForeignTypeRef;
    use objc2::msg_send;
    use objc2::runtime::AnyObject;
    let obj = cmd.as_ptr() as *const AnyObject;
    if obj.is_null() {
        return 0;
    }
    let (start, end): (f64, f64) = unsafe {
        let obj = &*obj;
        (msg_send![obj, GPUStartTime], msg_send![obj, GPUEndTime])
    };
    let dt = end - start;
    if dt.is_finite() && dt > 0.0 {
        (dt * 1.0e9) as u64
    } else {
        0
    }
}

fn profile_enabled() -> bool {
    use std::sync::OnceLock;
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("KIN_INFER_METAL_PROFILE").is_some())
}

/// Whether the simdgroup_matrix MMA GEMM kernels are enabled. Default ON: the
/// kernels pass the Metal-vs-CPU cosine + swerank parity gate on Apple Silicon
/// and are the throughput path. Disable with `KIN_INFER_MMA=0` to force the
/// proven scalar tile. Sampled once per process.
fn mma_enabled() -> bool {
    use std::sync::OnceLock;
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        !matches!(
            std::env::var("KIN_INFER_MMA").ok().as_deref(),
            Some("0") | Some("false") | Some("no") | Some("off")
        )
    })
}

/// Whether the simdgroup MMA pipelines actually compiled on this device. Set
/// once by `MetalCompute::try_new`. The MMA kernels require the
/// `simdgroup_matrix` intrinsics; if a target's Metal toolchain fails to build
/// them, this stays false and `use_mma` routes every GEMM to the scalar tile —
/// Metal stays alive (the scalar path is always built), only the MMA fast path
/// is disabled. Defaults to true so a process that never constructs a Metal
/// context (e.g. CPU-only) still honors the `mma_enabled` gate.
static MMA_AVAILABLE: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(true);

/// Route a GEMM of shape (m, n, k) to the simdgroup MMA kernel only when it is
/// enabled, the MMA pipelines compiled on this device, AND the shape fills the
/// 32x32 register tile usefully — small or ragged-only shapes (e.g. very short
/// attention) waste the MMA on zero-pad and stay on the scalar kernel.
#[inline]
fn use_mma(m: usize, n: usize, k: usize) -> bool {
    mma_enabled()
        && MMA_AVAILABLE.load(Ordering::Relaxed)
        && m >= 32
        && n >= 32
        && k >= 16
}

/// Whether the wider 64x64 MMA tile (Lever #5 phase 1) is selected. OPT-IN for
/// now (`KIN_INFER_MMA_WIDE=1`): default OFF keeps every GEMM on the proven 32x32
/// MMA so the parity gate stays green untouched. Flip the default ON only after
/// the wider tile clears the cosine/swerank gate (it is numerically identical, so
/// it should), keeping the OFF override as the safe fallback — the MMA-flip
/// pattern. Sampled once per process.
fn mma_wide_enabled() -> bool {
    use std::sync::OnceLock;
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        matches!(
            std::env::var("KIN_INFER_MMA_WIDE").ok().as_deref(),
            Some("1") | Some("true") | Some("yes") | Some("on")
        )
    })
}

/// Whether the wider-tile MMA pipelines actually compiled on this device. Set
/// once by `try_new` after attempting to build the `*_wide` kernels. Defaults
/// false: if they fail to build (or were never built), `use_wide_mma` stays off
/// and every GEMM uses the standard 32x32 MMA — no Metal-dead state.
static WIDE_MMA_AVAILABLE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Route a GEMM to the wider 64x64 MMA tile only when it is opt-in enabled, the
/// wide pipelines compiled, the standard MMA gate already passes, AND the output
/// is large enough to fill the 64x64 tile usefully (else the wider tile wastes
/// more on zero-pad than the 32x32 — keep those on the standard MMA).
#[inline]
fn use_wide_mma(m: usize, n: usize, k: usize) -> bool {
    mma_wide_enabled()
        && WIDE_MMA_AVAILABLE.load(Ordering::Relaxed)
        && use_mma(m, n, k)
        && m >= 64
        && n >= 64
}

/// Whether the fp16-operand MMA path (Lever #4) is selected. OPT-IN
/// (`KIN_INFER_GEMM_FP16=1`): default OFF keeps every GEMM on the proven
/// fp32-operand MMA so the strict cosine gate stays green untouched. fp16
/// operands lose ~half the mantissa, so this is EXPECTED to lower cosine and may
/// fail the strict 1e-7 floor on projection GEMMs — it is measured on its own and
/// only flipped on (or restricted to error-absorbing GEMMs) once a parity number
/// exists. Sampled once per process.
fn mma_fp16_enabled() -> bool {
    use std::sync::OnceLock;
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        matches!(
            std::env::var("KIN_INFER_GEMM_FP16").ok().as_deref(),
            Some("1") | Some("true") | Some("yes") | Some("on")
        )
    })
}

/// Whether the fp16 MMA pipelines compiled on this device. Set once by `try_new`
/// after compiling the SEPARATE fp16 shader library. Defaults false: if the
/// heterogeneous half*half->float overload is rejected by the toolchain (the
/// fp16 library fails to build), this stays false and every GEMM uses the fp32
/// MMA — Metal and the main library are unaffected.
static FP16_MMA_AVAILABLE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Route a GEMM to the fp16-operand MMA tile only when it is opt-in enabled, the
/// fp16 pipelines compiled, AND the standard MMA gate already passes. The fp16
/// variants are 32x32 (the wider tile composes with fp16 only in Lever #5 phase
/// 2), so when both `KIN_INFER_GEMM_FP16` and `KIN_INFER_MMA_WIDE` are set the
/// fp16 32x32 path takes precedence — they are alternative experiments for now.
#[inline]
fn use_fp16_mma(m: usize, n: usize, k: usize) -> bool {
    mma_fp16_enabled() && FP16_MMA_AVAILABLE.load(Ordering::Relaxed) && use_mma(m, n, k)
}

/// Whether the steel double-buffered K-loop MMA path (Step 1) is selected. OPT-IN
/// (`KIN_INFER_STEEL=1`): default OFF keeps every GEMM on the proven single-buffer
/// 32x32 MMA so the parity gate stays green untouched. The steel kernels overlap
/// the next K-tile's global load with the current tile's MMA (2-stage software
/// pipeline) but are numerically IDENTICAL to the single-buffer path (same fp32
/// accumulate, same per-fragment 8-wide reduction order — only WHEN the loads are
/// issued changes), so the cosine/swerank gate should be unchanged; any drift is a
/// barrier/ordering bug, not precision. Flip the default ON only after the gate is
/// green AND a measured ent/s win — the MMA-flip pattern. Sampled once per process.
fn steel_enabled() -> bool {
    use std::sync::OnceLock;
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        matches!(
            std::env::var("KIN_INFER_STEEL").ok().as_deref(),
            Some("1") | Some("true") | Some("yes") | Some("on")
        )
    })
}

/// Whether the steel double-buffered MMA pipelines actually compiled on this
/// device. Set once by `try_new` after attempting to build the `*_steel` kernels.
/// Defaults false: if they fail to build, `use_steel` stays off and every GEMM
/// uses the single-buffer 32x32 MMA — a bad steel overload can NEVER disable the
/// main library or Metal (the whole point of the fallback flag).
static STEEL_MMA_AVAILABLE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Route a GEMM to the steel double-buffered 32x32 MMA tile only when it is opt-in
/// enabled, the steel pipelines compiled, AND the standard 32x32 MMA gate already
/// passes. Same tile geometry as the single-buffer MMA (BM=BN=32, 128 threads), so
/// `use_mma`'s shape floor is exactly the right gate — no extra floor needed.
#[inline]
fn use_steel(m: usize, n: usize, k: usize) -> bool {
    steel_enabled() && STEEL_MMA_AVAILABLE.load(Ordering::Relaxed) && use_mma(m, n, k)
}

/// Total nanoseconds the host spent blocked in `wait_until_completed` since the
/// last `reset_profile`. Only meaningful when `KIN_INFER_METAL_PROFILE` is set.
pub fn profile_stall_nanos() -> u64 {
    STALL_NANOS.load(Ordering::Relaxed)
}

/// Number of GPU command-buffer submissions (commit+wait) since the last reset.
pub fn profile_submissions() -> u64 {
    SUBMISSIONS.load(Ordering::Relaxed)
}

/// Per-phase wall-clock breakdown (ns) since the last reset, as
/// (matmul, attention, norm_softmax, activation, copy_readback). Only meaningful
/// when `KIN_INFER_METAL_PROFILE` is set. Lets a benchmark print where the
/// forward pass actually spends its time so optimization targets the measured
/// bottleneck rather than an assumed one.
pub fn profile_phase_nanos() -> (u64, u64, u64, u64, u64) {
    (
        MATMUL_NANOS.load(Ordering::Relaxed),
        ATTENTION_NANOS.load(Ordering::Relaxed),
        NORM_NANOS.load(Ordering::Relaxed),
        ACTIVATION_NANOS.load(Ordering::Relaxed),
        COPY_NANOS.load(Ordering::Relaxed),
    )
}

/// Per-phase GPU-execution breakdown (ns) since the last reset, tagged by kernel
/// class. Measured from each command buffer's `GPUStartTime`/`GPUEndTime`, so the
/// numbers reflect actual on-GPU time and are build-INVARIANT (debug vs release
/// changes host overhead, not GPU kernel execution) — the contract a profiler
/// arm consumes to compare an unoptimized test binary against an optimized embed
/// without the debug-vs-release skew that misdirects host wall-clock numbers.
/// Only meaningful when `KIN_INFER_METAL_PROFILE` is set. `"copy"` reads ~0: host
/// memcpy on unified memory commits no command buffer, so it is not GPU-timed.
pub fn profile_gpu_phase_nanos() -> Vec<(&'static str, u64)> {
    vec![
        ("matmul", GPU_MATMUL_NANOS.load(Ordering::Relaxed)),
        ("attention", GPU_ATTENTION_NANOS.load(Ordering::Relaxed)),
        ("norm", GPU_NORM_NANOS.load(Ordering::Relaxed)),
        ("activation", GPU_ACTIVATION_NANOS.load(Ordering::Relaxed)),
        ("copy", GPU_COPY_NANOS.load(Ordering::Relaxed)),
    ]
}

/// Zero the host-stall and per-phase accumulators. Call before a timed region.
pub fn reset_profile() {
    STALL_NANOS.store(0, Ordering::Relaxed);
    SUBMISSIONS.store(0, Ordering::Relaxed);
    MATMUL_NANOS.store(0, Ordering::Relaxed);
    ATTENTION_NANOS.store(0, Ordering::Relaxed);
    NORM_NANOS.store(0, Ordering::Relaxed);
    ACTIVATION_NANOS.store(0, Ordering::Relaxed);
    COPY_NANOS.store(0, Ordering::Relaxed);
    GPU_MATMUL_NANOS.store(0, Ordering::Relaxed);
    GPU_ATTENTION_NANOS.store(0, Ordering::Relaxed);
    GPU_NORM_NANOS.store(0, Ordering::Relaxed);
    GPU_ACTIVATION_NANOS.store(0, Ordering::Relaxed);
    GPU_COPY_NANOS.store(0, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// MSL shader source — all transformer ops in one library
// ---------------------------------------------------------------------------

const SHADER_SOURCE: &str = r#"
#include <metal_stdlib>
using namespace metal;

// ---- Matrix multiply: C = A × B^T ----
// A is [M, K], B is [N, K] (row-major), C is [M, N]
// Threadgroup-tiled kernel for projection-heavy transformer workloads.
kernel void matmul_transb(
    device const float* A       [[buffer(0)]],
    device const float* B       [[buffer(1)]],
    device float* C             [[buffer(2)]],
    constant uint& M            [[buffer(3)]],
    constant uint& N            [[buffer(4)]],
    constant uint& K            [[buffer(5)]],
    uint2 gid                   [[thread_position_in_grid]],
    uint2 tid                   [[thread_position_in_threadgroup]],
    uint2 tgs                   [[threads_per_threadgroup]]
) {
    constexpr uint TILE = 16;
    threadgroup float a_tile[TILE][TILE];
    threadgroup float b_tile[TILE][TILE];

    uint row = gid.y;
    uint col = gid.x;

    float sum = 0.0;
    for (uint tile = 0; tile < K; tile += TILE) {
        for (uint a_local = tid.x; a_local < TILE; a_local += tgs.x) {
            uint a_col = tile + a_local;
            if (row < M && a_col < K) {
                a_tile[tid.y][a_local] = A[row * K + a_col];
            } else {
                a_tile[tid.y][a_local] = 0.0;
            }
        }

        for (uint b_local = tid.y; b_local < TILE; b_local += tgs.y) {
            uint b_k = tile + b_local;
            if (col < N && b_k < K) {
                b_tile[b_local][tid.x] = B[col * K + b_k];
            } else {
                b_tile[b_local][tid.x] = 0.0;
            }
        }

        threadgroup_barrier(mem_flags::mem_threadgroup);
        for (uint i = 0; i < TILE; i++) {
            sum += a_tile[tid.y][i] * b_tile[i][tid.x];
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }

    if (row < M && col < N) {
        C[row * N + col] = sum;
    }
}

// ---- simdgroup_matrix MMA GEMM ("steel" tile) ----
// C[M,N] = A[M,K] * op(B), where op(B) = B^T when TRANSB (B is [N,K] row-major),
// or B as-is when !TRANSB (B is [K,N] row-major). FP32 accumulate throughout —
// the simdgroup_float8x8 accumulator is load-bearing for the 1e-6 cosine parity;
// do NOT switch to half accumulate. Block tile BM=BN=32, BK=16; one threadgroup
// is WM*WN = 2*2 = 4 simdgroups = 128 threads. Each simdgroup owns a TM*TN = 2*2
// register tile of 8x8 fragments. The threadgroup stage is zero-padded on ragged
// edges so the MMA always runs full 8x8 fragments, and the epilogue bounds-guards
// the store — no separate tail kernel.
// MMA block tile constants (shared by the kernels that declare the threadgroup
// stage and the helper that consumes it). The default 32x32 tile and the wider
// 64x64 tile (Lever #5 phase 1) both run WM*WN = 2*2 = 4 simdgroups = 128
// threads; the wide tile only grows the per-simdgroup fragment grid (TM=TN: 2->4)
// and the As/Bs stage rows (32->64), raising C-reuse per loaded A/B element.
constant uint MMA_BM = 32, MMA_BN = 32, MMA_BK = 16, MMA_WM = 2, MMA_WN = 2, MMA_F = 8;
// The wide tile uses literal 64 for both the stage array sizes and the block_mma
// template args (NOT a `constant`-address-space symbol): a literal is an
// unambiguous core-constant-expression in every MSL version, so it is always a
// valid non-type template argument. The proven code only ever used `constant`
// vars as array sizes, never as template args — keeping the wide tile on literals
// removes any risk that the MAIN shader library fails to compile (which would
// disable Metal entirely).

// `As`/`Bs`/`store_tile` are declared in the calling KERNEL (threadgroup-address
// variables cannot be declared in a non-kernel helper) and passed in by pointer.
// BM/BN are template parameters (default to the 32x32 tile) so the same body
// serves both the standard kernels and the wider-tile variants; the codegen for
// `block_mma<TRANSB>` is byte-identical to the pre-templatization 32x32 form.
template <bool TRANSB, uint BM = 32, uint BN = 32>
static inline void block_mma(
    device const float* A,
    device const float* B,
    device float* C,
    uint M, uint N, uint K,
    uint3 tgid, uint sgid, uint lane,
    threadgroup float (*As)[MMA_BK],
    threadgroup float (*Bs)[MMA_BK],
    threadgroup float (*store_tile)[MMA_F][MMA_F])
{
    constexpr uint BK = 16, WM = 2, WN = 2, F = 8;
    constexpr uint TM = BM / (F * WM);   // fragment-rows per simdgroup (2 @32, 4 @64)
    constexpr uint TN = BN / (F * WN);   // fragment-cols per simdgroup (2 @32, 4 @64)

    const uint sm = sgid / WN;           // simdgroup row in the 2x2 grid
    const uint sn = sgid % WN;           // simdgroup col
    const uint block_row = tgid.y * BM;  // M offset of this block
    const uint block_col = tgid.x * BN;  // N offset of this block
    const uint tid = sgid * 32u + lane;  // flat thread index 0..127

    simdgroup_float8x8 acc[TM][TN];
    for (uint i = 0; i < TM; i++)
        for (uint j = 0; j < TN; j++)
            acc[i][j] = make_filled_simdgroup_matrix<float, 8, 8>(0.0f);

    for (uint k0 = 0; k0 < K; k0 += BK) {
        // Cooperatively load the A and B K-blocks, zero-padding past M/N/K.
        for (uint idx = tid; idx < BM * BK; idx += 128u) {
            uint r = idx / BK, c = idx % BK;
            uint gr = block_row + r, gc = k0 + c;
            As[r][c] = (gr < M && gc < K) ? A[gr * K + gc] : 0.0f;
        }
        for (uint idx = tid; idx < BN * BK; idx += 128u) {
            uint r = idx / BK, c = idx % BK;          // r in [0,BN), c in [0,BK)
            uint gn = block_col + r, gk = k0 + c;
            if (TRANSB) {
                // B is [N,K] row-major: element (n,k) = B[n*K + k].
                Bs[r][c] = (gn < N && gk < K) ? B[gn * K + gk] : 0.0f;
            } else {
                // B is [K,N] row-major: element (k,n) = B[k*N + n].
                Bs[r][c] = (gn < N && gk < K) ? B[gk * N + gn] : 0.0f;
            }
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);

        // MMA over this BK in 8-wide K-slices.
        for (uint kk = 0; kk < BK; kk += F) {
            simdgroup_float8x8 a_frag[TM];
            simdgroup_float8x8 b_frag[TN];
            for (uint i = 0; i < TM; i++)
                simdgroup_load(a_frag[i], &As[sm * F * TM + i * F][kk], BK, ulong2(0, 0), false);
            // Bs is staged as [n][k]; the MMA needs an 8(K) x 8(N) operand, so
            // load with transpose=true to read the k-major view of each n-block.
            for (uint j = 0; j < TN; j++)
                simdgroup_load(b_frag[j], &Bs[sn * F * TN + j * F][kk], BK, ulong2(0, 0), true);
            for (uint i = 0; i < TM; i++)
                for (uint j = 0; j < TN; j++)
                    simdgroup_multiply_accumulate(acc[i][j], a_frag[i], b_frag[j], acc[i][j]);
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }

    // Epilogue: store each fragment, bounds-guarded on ragged edges. Each
    // simdgroup gets its OWN scratch row (indexed by sgid) so the ragged-tile
    // staging never races across the 4 simdgroups in the threadgroup.
    // Epilogue: store each fragment. If the entire threadgroup tile is fully
    // in-bounds, we use the fast path (simdgroup_store directly to C, no barriers).
    // Otherwise, we take the ragged path uniformly across the threadgroup.
    if (block_row + BM <= M && block_col + BN <= N) {
        for (uint i = 0; i < TM; i++) {
            for (uint j = 0; j < TN; j++) {
                uint cr = block_row + sm * F * TM + i * F;
                uint cc = block_col + sn * F * TN + j * F;
                simdgroup_store(acc[i][j], &C[cr * N + cc], N, ulong2(0, 0), false);
            }
        }
    } else {
        for (uint i = 0; i < TM; i++) {
            for (uint j = 0; j < TN; j++) {
                uint cr = block_row + sm * F * TM + i * F;
                uint cc = block_col + sn * F * TN + j * F;
                threadgroup float* scratch = &store_tile[sgid][0][0];
                simdgroup_store(acc[i][j], scratch, F, ulong2(0, 0), false);
                threadgroup_barrier(mem_flags::mem_threadgroup);
                for (uint e = lane; e < F * F; e += 32u) {
                    uint er = e / F, ec = e % F;
                    uint gr = cr + er, gc = cc + ec;
                    if (gr < M && gc < N) {
                        C[gr * N + gc] = scratch[er * F + ec];
                    }
                }
                threadgroup_barrier(mem_flags::mem_threadgroup);
            }
        }
    }
}

// C[M,N] = A[M,K] * B[N,K]^T (transb projection convention).
kernel void matmul_transb_simdgroup(
    device const float* A   [[buffer(0)]],
    device const float* B   [[buffer(1)]],
    device float*       C   [[buffer(2)]],
    constant uint& M        [[buffer(3)]],
    constant uint& N        [[buffer(4)]],
    constant uint& K        [[buffer(5)]],
    uint3 tgid              [[threadgroup_position_in_grid]],
    uint  sgid             [[simdgroup_index_in_threadgroup]],
    uint  lane             [[thread_index_in_simdgroup]])
{
    threadgroup float As[MMA_BM][MMA_BK];
    threadgroup float Bs[MMA_BN][MMA_BK];
    threadgroup float store_tile[MMA_WM * MMA_WN][MMA_F][MMA_F];
    block_mma<true>(A, B, C, M, N, K, tgid, sgid, lane, As, Bs, store_tile);
}

// Batched QK^T: per head (gid.z) C[h] = Q[h][seq,dim] * K[h][seq,dim]^T.
// A=Q[h] [seq,dim], B=K[h] [seq,dim], output [seq,seq], contraction K=dim.
kernel void batched_matmul_transb_simdgroup(
    device const float* Q   [[buffer(0)]],
    device const float* Kk  [[buffer(1)]],
    device float*       C   [[buffer(2)]],
    constant uint& seq      [[buffer(3)]],
    constant uint& dim      [[buffer(4)]],
    constant uint& hpg      [[buffer(5)]],
    uint3 tgid              [[threadgroup_position_in_grid]],
    uint  sgid             [[simdgroup_index_in_threadgroup]],
    uint  lane             [[thread_index_in_simdgroup]])
{
    uint h = tgid.z;
    uint kv_h = h / hpg;
    device const float* Ah = Q  + h * seq * dim;
    device const float* Bh = Kk + kv_h * seq * dim;
    device float*       Ch = C  + h * seq * seq;
    threadgroup float As[MMA_BM][MMA_BK];
    threadgroup float Bs[MMA_BN][MMA_BK];
    threadgroup float store_tile[MMA_WM * MMA_WN][MMA_F][MMA_F];
    block_mma<true>(Ah, Bh, Ch, seq, seq, dim, uint3(tgid.x, tgid.y, 0), sgid, lane, As, Bs, store_tile);
}

// Batched scores*V: per head (gid.z) C[h] = S[h][seq,seq] * V[h][seq,dim].
// A=S[h] [seq,seq], B=V[h] [seq,dim] (NON-transposed), output [seq,dim], K=seq.
kernel void batched_matmul_ab_simdgroup(
    device const float* S   [[buffer(0)]],
    device const float* V   [[buffer(1)]],
    device float*       C   [[buffer(2)]],
    constant uint& seq      [[buffer(3)]],
    constant uint& dim      [[buffer(4)]],
    constant uint& hpg      [[buffer(5)]],
    uint3 tgid              [[threadgroup_position_in_grid]],
    uint  sgid             [[simdgroup_index_in_threadgroup]],
    uint  lane             [[thread_index_in_simdgroup]])
{
    uint h = tgid.z;
    uint kv_h = h / hpg;
    device const float* Ah = S + h * seq * seq;
    device const float* Bh = V + kv_h * seq * dim;
    device float*       Ch = C + h * seq * dim;
    threadgroup float As[MMA_BM][MMA_BK];
    threadgroup float Bs[MMA_BN][MMA_BK];
    threadgroup float store_tile[MMA_WM * MMA_WN][MMA_F][MMA_F];
    block_mma<false>(Ah, Bh, Ch, seq, dim, seq, uint3(tgid.x, tgid.y, 0), sgid, lane, As, Bs, store_tile);
}

// ---- Wider 64x64 MMA tile variants (Lever #5 phase 1) ----
// Same 128-thread / 4-simdgroup threadgroup as the 32x32 kernels, but each
// simdgroup owns a 4x4 fragment grid (TM=TN=4) over a 64x64 output block, raising
// arithmetic intensity per loaded A/B element. Numerically identical to the
// 32x32 path (same fp32 accumulate, same per-fragment 8-wide reduction order) —
// the only difference is how the output is blocked, so parity is preserved by
// construction. Selected behind KIN_INFER_MMA_WIDE for shapes that fill 64x64;
// the dispatch grid uses BM=BN=64.
kernel void matmul_transb_simdgroup_wide(
    device const float* A   [[buffer(0)]],
    device const float* B   [[buffer(1)]],
    device float*       C   [[buffer(2)]],
    constant uint& M        [[buffer(3)]],
    constant uint& N        [[buffer(4)]],
    constant uint& K        [[buffer(5)]],
    uint3 tgid              [[threadgroup_position_in_grid]],
    uint  sgid             [[simdgroup_index_in_threadgroup]],
    uint  lane             [[thread_index_in_simdgroup]])
{
    threadgroup float As[64][MMA_BK];
    threadgroup float Bs[64][MMA_BK];
    threadgroup float store_tile[MMA_WM * MMA_WN][MMA_F][MMA_F];
    block_mma<true, 64, 64>(A, B, C, M, N, K, tgid, sgid, lane, As, Bs, store_tile);
}

kernel void batched_matmul_transb_simdgroup_wide(
    device const float* Q   [[buffer(0)]],
    device const float* Kk  [[buffer(1)]],
    device float*       C   [[buffer(2)]],
    constant uint& seq      [[buffer(3)]],
    constant uint& dim      [[buffer(4)]],
    constant uint& hpg      [[buffer(5)]],
    uint3 tgid              [[threadgroup_position_in_grid]],
    uint  sgid             [[simdgroup_index_in_threadgroup]],
    uint  lane             [[thread_index_in_simdgroup]])
{
    uint h = tgid.z;
    uint kv_h = h / hpg;
    device const float* Ah = Q  + h * seq * dim;
    device const float* Bh = Kk + kv_h * seq * dim;
    device float*       Ch = C  + h * seq * seq;
    threadgroup float As[64][MMA_BK];
    threadgroup float Bs[64][MMA_BK];
    threadgroup float store_tile[MMA_WM * MMA_WN][MMA_F][MMA_F];
    block_mma<true, 64, 64>(Ah, Bh, Ch, seq, seq, dim, uint3(tgid.x, tgid.y, 0), sgid, lane, As, Bs, store_tile);
}

kernel void batched_matmul_ab_simdgroup_wide(
    device const float* S   [[buffer(0)]],
    device const float* V   [[buffer(1)]],
    device float*       C   [[buffer(2)]],
    constant uint& seq      [[buffer(3)]],
    constant uint& dim      [[buffer(4)]],
    constant uint& hpg      [[buffer(5)]],
    uint3 tgid              [[threadgroup_position_in_grid]],
    uint  sgid             [[simdgroup_index_in_threadgroup]],
    uint  lane             [[thread_index_in_simdgroup]])
{
    uint h = tgid.z;
    uint kv_h = h / hpg;
    device const float* Ah = S + h * seq * seq;
    device const float* Bh = V + kv_h * seq * dim;
    device float*       Ch = C + h * seq * dim;
    threadgroup float As[64][MMA_BK];
    threadgroup float Bs[64][MMA_BK];
    threadgroup float store_tile[MMA_WM * MMA_WN][MMA_F][MMA_F];
    block_mma<false, 64, 64>(Ah, Bh, Ch, seq, dim, seq, uint3(tgid.x, tgid.y, 0), sgid, lane, As, Bs, store_tile);
}

// ---- Steel double-buffered K-loop MMA (Step 1) ----
// Same proven 32x32 tile as block_mma (128 threads, 4 simdgroups, TM=TN=2 -> 4
// fp32 accumulators per simdgroup; NO register-pressure change vs the wide tile
// that spilled). The only structural change is the K-loop: the stage tiles are
// 2-deep ping-pong [2][32][MMA_BK], and each iteration issues the NEXT K-tile's
// global loads into the OTHER buffer BEFORE the MMA — so the load latency overlaps
// the MMA instead of being fully exposed by a pre-MMA barrier. Net: 2 barriers per
// K-iteration -> 1. Numerically IDENTICAL to the single-buffer block_mma (same
// fp32 accumulate, same per-fragment 8-wide reduction order) — only WHEN the loads
// are issued changes, so parity is preserved by construction; any drift is a
// barrier/ordering bug, not precision. Selected behind KIN_INFER_STEEL.
//
// As/Bs/store_tile are declared in the calling KERNEL (threadgroup-address
// variables cannot be declared in a non-kernel helper) and passed in by pointer.
// The stage arrays are 2-deep with a LITERAL outer dim (2) and LITERAL tile dim
// (32) — never a `constant`-address symbol as an array bound — so the helper
// signature is unambiguous in every MSL version.
template <bool TRANSB>
static inline void block_mma_db(
    device const float* A,
    device const float* B,
    device float* C,
    uint M, uint N, uint K,
    uint3 tgid, uint sgid, uint lane,
    threadgroup float (*As)[32][MMA_BK],      // As[2][32][MMA_BK] ping-pong
    threadgroup float (*Bs)[32][MMA_BK],      // Bs[2][32][MMA_BK] ping-pong
    threadgroup float (*store_tile)[MMA_F][MMA_F])
{
    constexpr uint BM = 32, BN = 32, BK = 16, WM = 2, WN = 2, F = 8;
    constexpr uint TM = BM / (F * WM);   // fragment-rows per simdgroup (2)
    constexpr uint TN = BN / (F * WN);   // fragment-cols per simdgroup (2)

    const uint sm = sgid / WN;           // simdgroup row in the 2x2 grid
    const uint sn = sgid % WN;           // simdgroup col
    const uint block_row = tgid.y * BM;  // M offset of this block
    const uint block_col = tgid.x * BN;  // N offset of this block
    const uint tid = sgid * 32u + lane;  // flat thread index 0..127

    simdgroup_float8x8 acc[TM][TN];
    for (uint i = 0; i < TM; i++)
        for (uint j = 0; j < TN; j++)
            acc[i][j] = make_filled_simdgroup_matrix<float, 8, 8>(0.0f);

    // PROLOGUE: cooperatively stage K-tile 0 into buffer 0, zero-padding past
    // M/N/K. Identical staging math to block_mma; only the buffer index (0) and
    // the 2-deep array shape differ.
    for (uint idx = tid; idx < BM * BK; idx += 128u) {
        uint r = idx / BK, c = idx % BK;
        uint gr = block_row + r, gc = c;
        As[0][r][c] = (gr < M && gc < K) ? A[gr * K + gc] : 0.0f;
    }
    for (uint idx = tid; idx < BN * BK; idx += 128u) {
        uint r = idx / BK, c = idx % BK;
        uint gn = block_col + r, gk = c;
        if (TRANSB) {
            Bs[0][r][c] = (gn < N && gk < K) ? B[gn * K + gk] : 0.0f;
        } else {
            Bs[0][r][c] = (gn < N && gk < K) ? B[gk * N + gn] : 0.0f;
        }
    }
    threadgroup_barrier(mem_flags::mem_threadgroup);

    uint cur = 0;
    for (uint k0 = 0; k0 < K; k0 += BK) {
        uint nxt = cur ^ 1u;
        uint k1 = k0 + BK;

        // Issue the NEXT K-tile's global loads into the OTHER buffer FIRST. No
        // barrier before the MMA: the MMA reads As[cur]/Bs[cur] (filled and
        // barrier'd by the prologue or the previous iteration), which the writes
        // to buffer `nxt` never touch — so the loads are in flight while the MMA
        // computes. WAR on `cur` is safe: `cur` is only overwritten two iters
        // later, after a barrier, by which point this iter's reads are long done.
        if (k1 < K) {
            for (uint idx = tid; idx < BM * BK; idx += 128u) {
                uint r = idx / BK, c = idx % BK;
                uint gr = block_row + r, gc = k1 + c;
                As[nxt][r][c] = (gr < M && gc < K) ? A[gr * K + gc] : 0.0f;
            }
            for (uint idx = tid; idx < BN * BK; idx += 128u) {
                uint r = idx / BK, c = idx % BK;
                uint gn = block_col + r, gk = k1 + c;
                if (TRANSB) {
                    Bs[nxt][r][c] = (gn < N && gk < K) ? B[gn * K + gk] : 0.0f;
                } else {
                    Bs[nxt][r][c] = (gn < N && gk < K) ? B[gk * N + gn] : 0.0f;
                }
            }
        }

        // MMA on the CURRENT buffer, over this BK in 8-wide K-slices. Identical to
        // block_mma's inner loop, just indexed through the ping-pong `cur` buffer.
        for (uint kk = 0; kk < BK; kk += F) {
            simdgroup_float8x8 a_frag[TM];
            simdgroup_float8x8 b_frag[TN];
            for (uint i = 0; i < TM; i++)
                simdgroup_load(a_frag[i], &As[cur][sm * F * TM + i * F][kk], BK, ulong2(0, 0), false);
            // Bs is staged as [n][k]; load with transpose=true to read the k-major
            // view of each n-block (same as block_mma).
            for (uint j = 0; j < TN; j++)
                simdgroup_load(b_frag[j], &Bs[cur][sn * F * TN + j * F][kk], BK, ulong2(0, 0), true);
            for (uint i = 0; i < TM; i++)
                for (uint j = 0; j < TN; j++)
                    simdgroup_multiply_accumulate(acc[i][j], a_frag[i], b_frag[j], acc[i][j]);
        }

        // ONE barrier per iteration (was two in block_mma): (a) publishes the
        // next-tile writes to buffer `nxt` before the next iter reads them as
        // `cur` (RAW), AND (b) ensures this iter's MMA reads of buffer `cur`
        // finished before a future iter overwrites it (WAR).
        threadgroup_barrier(mem_flags::mem_threadgroup);
        cur = nxt;
    }

    // EPILOGUE: identical to block_mma — store each fragment, bounds-guarded on
    // ragged edges, ragged path via this simdgroup's own store_tile scratch row.
    if (block_row + BM <= M && block_col + BN <= N) {
        for (uint i = 0; i < TM; i++) {
            for (uint j = 0; j < TN; j++) {
                uint cr = block_row + sm * F * TM + i * F;
                uint cc = block_col + sn * F * TN + j * F;
                simdgroup_store(acc[i][j], &C[cr * N + cc], N, ulong2(0, 0), false);
            }
        }
    } else {
        for (uint i = 0; i < TM; i++) {
            for (uint j = 0; j < TN; j++) {
                uint cr = block_row + sm * F * TM + i * F;
                uint cc = block_col + sn * F * TN + j * F;
                threadgroup float* scratch = &store_tile[sgid][0][0];
                simdgroup_store(acc[i][j], scratch, F, ulong2(0, 0), false);
                threadgroup_barrier(mem_flags::mem_threadgroup);
                for (uint e = lane; e < F * F; e += 32u) {
                    uint er = e / F, ec = e % F;
                    uint gr = cr + er, gc = cc + ec;
                    if (gr < M && gc < N) {
                        C[gr * N + gc] = scratch[er * F + ec];
                    }
                }
                threadgroup_barrier(mem_flags::mem_threadgroup);
            }
        }
    }
}

// C[M,N] = A[M,K] * B[N,K]^T (transb projection convention), double-buffered.
kernel void matmul_transb_simdgroup_steel(
    device const float* A   [[buffer(0)]],
    device const float* B   [[buffer(1)]],
    device float*       C   [[buffer(2)]],
    constant uint& M        [[buffer(3)]],
    constant uint& N        [[buffer(4)]],
    constant uint& K        [[buffer(5)]],
    uint3 tgid              [[threadgroup_position_in_grid]],
    uint  sgid             [[simdgroup_index_in_threadgroup]],
    uint  lane             [[thread_index_in_simdgroup]])
{
    threadgroup float As[2][32][MMA_BK];
    threadgroup float Bs[2][32][MMA_BK];
    threadgroup float store_tile[MMA_WM * MMA_WN][MMA_F][MMA_F];
    block_mma_db<true>(A, B, C, M, N, K, tgid, sgid, lane, As, Bs, store_tile);
}

// Batched QK^T per head, double-buffered (see batched_matmul_transb_simdgroup).
kernel void batched_matmul_transb_simdgroup_steel(
    device const float* Q   [[buffer(0)]],
    device const float* Kk  [[buffer(1)]],
    device float*       C   [[buffer(2)]],
    constant uint& seq      [[buffer(3)]],
    constant uint& dim      [[buffer(4)]],
    constant uint& hpg      [[buffer(5)]],
    uint3 tgid              [[threadgroup_position_in_grid]],
    uint  sgid             [[simdgroup_index_in_threadgroup]],
    uint  lane             [[thread_index_in_simdgroup]])
{
    uint h = tgid.z;
    uint kv_h = h / hpg;
    device const float* Ah = Q  + h * seq * dim;
    device const float* Bh = Kk + kv_h * seq * dim;
    device float*       Ch = C  + h * seq * seq;
    threadgroup float As[2][32][MMA_BK];
    threadgroup float Bs[2][32][MMA_BK];
    threadgroup float store_tile[MMA_WM * MMA_WN][MMA_F][MMA_F];
    block_mma_db<true>(Ah, Bh, Ch, seq, seq, dim, uint3(tgid.x, tgid.y, 0), sgid, lane, As, Bs, store_tile);
}

// Batched scores*V per head, double-buffered (see batched_matmul_ab_simdgroup).
kernel void batched_matmul_ab_simdgroup_steel(
    device const float* S   [[buffer(0)]],
    device const float* V   [[buffer(1)]],
    device float*       C   [[buffer(2)]],
    constant uint& seq      [[buffer(3)]],
    constant uint& dim      [[buffer(4)]],
    constant uint& hpg      [[buffer(5)]],
    uint3 tgid              [[threadgroup_position_in_grid]],
    uint  sgid             [[simdgroup_index_in_threadgroup]],
    uint  lane             [[thread_index_in_simdgroup]])
{
    uint h = tgid.z;
    uint kv_h = h / hpg;
    device const float* Ah = S + h * seq * seq;
    device const float* Bh = V + kv_h * seq * dim;
    device float*       Ch = C + h * seq * dim;
    threadgroup float As[2][32][MMA_BK];
    threadgroup float Bs[2][32][MMA_BK];
    threadgroup float store_tile[MMA_WM * MMA_WN][MMA_F][MMA_F];
    block_mma_db<false>(Ah, Bh, Ch, seq, dim, seq, uint3(tgid.x, tgid.y, 0), sgid, lane, As, Bs, store_tile);
}

// ---- Softmax over rows ----
// data is [rows, cols], normalize each row independently
kernel void softmax_rows(
    device float* data          [[buffer(0)]],
    constant uint& cols         [[buffer(1)]],
    uint gid                    [[thread_position_in_grid]]
) {
    uint row_offset = gid * cols;

    // Find max
    float max_val = -INFINITY;
    for (uint j = 0; j < cols; j++) {
        max_val = max(max_val, data[row_offset + j]);
    }

    // Exp and sum
    float sum = 0.0;
    for (uint j = 0; j < cols; j++) {
        float v = exp(data[row_offset + j] - max_val);
        data[row_offset + j] = v;
        sum += v;
    }

    // Normalize
    if (sum > 0.0) {
        float inv_sum = 1.0 / sum;
        for (uint j = 0; j < cols; j++) {
            data[row_offset + j] *= inv_sum;
        }
    }
}

// ---- LayerNorm ----
kernel void layer_norm(
    device float* data          [[buffer(0)]],
    device const float* gamma   [[buffer(1)]],
    device const float* beta    [[buffer(2)]],
    constant uint& cols         [[buffer(3)]],
    constant float& eps         [[buffer(4)]],
    uint gid                    [[thread_position_in_grid]]
) {
    uint off = gid * cols;
    float len = float(cols);

    // Mean
    float mean = 0.0;
    for (uint j = 0; j < cols; j++) mean += data[off + j];
    mean /= len;

    // Variance
    float var = 0.0;
    for (uint j = 0; j < cols; j++) {
        float d = data[off + j] - mean;
        var += d * d;
    }
    var /= len;

    float inv_std = rsqrt(var + eps);
    for (uint j = 0; j < cols; j++) {
        data[off + j] = (data[off + j] - mean) * inv_std * gamma[j] + beta[j];
    }
}

// ---- RMSNorm ----
kernel void rms_norm(
    device float* data          [[buffer(0)]],
    device const float* weight  [[buffer(1)]],
    constant uint& cols         [[buffer(2)]],
    constant float& eps         [[buffer(3)]],
    uint gid                    [[thread_position_in_grid]]
) {
    uint off = gid * cols;
    float len = float(cols);

    float sq_sum = 0.0;
    for (uint j = 0; j < cols; j++) {
        float v = data[off + j];
        sq_sum += v * v;
    }
    float inv_rms = rsqrt(sq_sum / len + eps);

    for (uint j = 0; j < cols; j++) {
        data[off + j] = data[off + j] * inv_rms * weight[j];
    }
}

// ---- GELU activation (in-place) ----
// Tanh-approximation GELU: 0.5 * x * (1 + tanh(sqrt(2/pi) * (x + 0.044715 * x^3))).
// MSL's stdlib `tanh` evaluates as sinh(t)/cosh(t); for |t| > ~88 both sinh and
// cosh overflow to +inf in fp32 and the ratio is NaN. The tanh argument here
// grows like 0.0359 * x^3, so any |x| > ~13 corrupts the activation with NaN —
// which is what manifested as 100%-NaN BERT embeddings on Metal at long
// sequences (the deeper layers' FFN intermediates regularly visit |x| > 13).
//
// tanh saturates to ±1 well before |t| = 10, so clamping the argument is exact
// to ULP for the magnitudes that previously NaN'd while keeping the small-x
// branch identical to the CPU reference.
kernel void gelu_activation(
    device float* data          [[buffer(0)]],
    uint gid                    [[thread_position_in_grid]]
) {
    float x = data[gid];
    float arg = x * 0.7978845608f * (1.0f + 0.044715f * x * x);
    arg = clamp(arg, -10.0f, 10.0f);
    data[gid] = x * 0.5f * (1.0f + tanh(arg));
}

// ---- SiLU activation (in-place) ----
kernel void silu_activation(
    device float* data          [[buffer(0)]],
    uint gid                    [[thread_position_in_grid]]
) {
    float x = data[gid];
    data[gid] = x / (1.0 + exp(-x));
}

// ---- Element-wise multiply (in-place): a *= b ----
kernel void elementwise_mul(
    device float* a             [[buffer(0)]],
    device const float* b       [[buffer(1)]],
    uint gid                    [[thread_position_in_grid]]
) {
    a[gid] *= b[gid];
}

// ---- Element-wise add (in-place): a += b ----
// Used by the residency folds to apply the residual connection on-device,
// keeping the activation resident between the projection matmul and the norm
// so the residual sum never round-trips through host memory.
kernel void elementwise_add(
    device float* a             [[buffer(0)]],
    device const float* b       [[buffer(1)]],
    uint gid                    [[thread_position_in_grid]]
) {
    a[gid] += b[gid];
}

// ---- Element-wise add broadcast (in-place): a[i] += b[i % dim] ----
kernel void elementwise_add_broadcast(
    device float* a             [[buffer(0)]],
    device const float* b       [[buffer(1)]],
    constant uint& dim          [[buffer(2)]],
    uint gid                    [[thread_position_in_grid]]
) {
    a[gid] += b[gid % dim];
}



// ---- Split packed QKV into separate head-major chunks ----
// Packed input QKV layout: [batch*seq, q_dim + k_dim + v_dim]
// Separates the columns for Q, K, and V into dedicated buffers for reshaping.
kernel void split_qkv_packed(
    device const float* qkv     [[buffer(0)]],
    device float* q             [[buffer(1)]],
    device float* k             [[buffer(2)]],
    device float* v             [[buffer(3)]],
    constant uint& q_dim        [[buffer(4)]],
    constant uint& k_dim        [[buffer(5)]],
    constant uint& v_dim        [[buffer(6)]],
    uint2 gid                   [[thread_position_in_grid]]
) {
    uint col = gid.x;
    uint row = gid.y;
    uint total_dim = q_dim + k_dim + v_dim;
    uint src_idx = row * total_dim + col;
    
    if (col < q_dim) {
        q[row * q_dim + col] = qkv[src_idx];
    } else if (col < q_dim + k_dim) {
        k[row * k_dim + (col - q_dim)] = qkv[src_idx];
    } else if (col < total_dim) {
        v[row * v_dim + (col - q_dim - k_dim)] = qkv[src_idx];
    }
}

// ---- Fused SwiGLU activation: out = silu(gate) * up ----
// Single pass over the gate/up intermediates, writing the activated product.
// silu(x) = x / (1 + e^-x); identical math to the two-step silu-then-mul path
// but with one kernel dispatch and one fewer buffer round-trip.
kernel void swiglu_activation(
    device const float* gate    [[buffer(0)]],
    device const float* up      [[buffer(1)]],
    device float* out           [[buffer(2)]],
    uint gid                    [[thread_position_in_grid]]
) {
    float g = gate[gid];
    out[gid] = (g / (1.0 + exp(-g))) * up[gid];
}

// ---- Fused SwiGLU over an interleaved gate|up fat-GEMM output ----
// `fat` is [rows, 2*inter] = the single concatenated gate|up projection: per
// row, gate occupies columns [0, inter) and up columns [inter, 2*inter).
// out is the contiguous [rows, inter] activated product. Identical math to
// `swiglu_activation`, just reading the two operands from one strided buffer so
// the gate and up projections fold into one wide matmul.
kernel void swiglu_activation_fat(
    device const float* fat     [[buffer(0)]],
    device float* out           [[buffer(1)]],
    constant uint& inter        [[buffer(2)]],
    uint gid                    [[thread_position_in_grid]]
) {
    uint row = gid / inter;
    uint col = gid % inter;
    uint base = row * 2u * inter;
    float g = fat[base + col];
    float u = fat[base + inter + col];
    out[gid] = (g / (1.0 + exp(-g))) * u;
}

// ---- RoPE (rotary position encoding, in-place) ----
// data is [seq_len, total_dim], cos/sin tables are [max_seq, half_head_dim]
kernel void rope_apply(
    device float* data              [[buffer(0)]],
    device const float* cos_table   [[buffer(1)]],
    device const float* sin_table   [[buffer(2)]],
    constant uint& seq_offset       [[buffer(3)]],
    constant uint& head_dim         [[buffer(4)]],
    constant uint& total_dim        [[buffer(5)]],
    constant uint& half_dim         [[buffer(6)]],
    uint2 gid                       [[thread_position_in_grid]]
) {
    // gid.y = position in sequence, gid.x = pair index within total_dim
    uint pos = gid.y;
    uint pair = gid.x;

    // Which head does this pair belong to?
    uint head = pair / (head_dim / 2);
    uint d = pair % (head_dim / 2);
    uint base = pos * total_dim + head * head_dim;

    uint table_off = (seq_offset + pos) * half_dim + d;
    float cos_val = cos_table[table_off];
    float sin_val = sin_table[table_off];

    float x0 = data[base + d];
    float x1 = data[base + head_dim / 2 + d];
    data[base + d]              = x0 * cos_val - x1 * sin_val;
    data[base + head_dim / 2 + d] = x1 * cos_val + x0 * sin_val;
}

// ---- Batched RoPE: all inputs in [batch*max_len, total_dim] in ONE dispatch ----
// Positions restart at 0 for every input (same cos/sin tables), so the per-row
// sequence position is (global_row % max_len). This collapses the per-batch-
// element RoPE loop (~batch_size submissions/layer) into a single submission.
kernel void rope_apply_batched(
    device float* data              [[buffer(0)]],
    device const float* cos_table   [[buffer(1)]],
    device const float* sin_table   [[buffer(2)]],
    constant uint& max_len          [[buffer(3)]],
    constant uint& head_dim         [[buffer(4)]],
    constant uint& total_dim        [[buffer(5)]],
    constant uint& half_dim         [[buffer(6)]],
    constant uint& actual           [[buffer(7)]],
    uint2 gid                       [[thread_position_in_grid]]
) {
    // gid.y = global row over the whole batch, gid.x = pair index within total_dim.
    uint row = gid.y;
    uint pos = row % max_len;   // position resets per input block
    // Match the per-element path: only positions covered by the cos/sin table
    // (< actual) are rotated; later positions of a block are left untouched.
    if (pos >= actual) {
        return;
    }
    uint pair = gid.x;
    uint head = pair / (head_dim / 2);
    uint d = pair % (head_dim / 2);
    uint base = row * total_dim + head * head_dim;

    uint table_off = pos * half_dim + d;
    float cos_val = cos_table[table_off];
    float sin_val = sin_table[table_off];

    float x0 = data[base + d];
    float x1 = data[base + head_dim / 2 + d];
    data[base + d]              = x0 * cos_val - x1 * sin_val;
    data[base + head_dim / 2 + d] = x1 * cos_val + x0 * sin_val;
}

// ---- Batched matmul: C[h] = A[h] × B[h]^T for all heads ----
// A is [num_heads, seq_len, head_dim] flattened (head-major)
// B is [num_heads, seq_len, head_dim] flattened (head-major)
// C is [num_heads, seq_len, seq_len] flattened
// 3D grid: (seq_len, seq_len, num_heads)
// Threadgroup-tiled to keep attention Q×K^T from falling back to a naive dot
// product per output element.
kernel void batched_matmul_transb(
    device const float* A       [[buffer(0)]],
    device const float* B       [[buffer(1)]],
    device float* C             [[buffer(2)]],
    constant uint& seq_len      [[buffer(3)]],
    constant uint& head_dim     [[buffer(4)]],
    constant uint& hpg          [[buffer(5)]],
    uint3 gid                   [[thread_position_in_grid]],
    uint3 tid                   [[thread_position_in_threadgroup]],
    uint3 tgs                   [[threads_per_threadgroup]]
) {
    constexpr uint TILE = 16;
    threadgroup float a_tile[TILE][TILE];
    threadgroup float b_tile[TILE][TILE];

    uint col  = gid.x;  // j in [0, seq_len)
    uint row  = gid.y;  // i in [0, seq_len)
    uint head = gid.z;  // h in [0, num_heads)
    uint kv_head = head / hpg;

    device const float* A_head = A + head * seq_len * head_dim;
    device const float* B_head = B + kv_head * seq_len * head_dim;
    device float* C_head = C + head * seq_len * seq_len;
    uint c_off = row * seq_len + col;

    float sum = 0.0;
    for (uint tile = 0; tile < head_dim; tile += TILE) {
        for (uint a_local = tid.x; a_local < TILE; a_local += tgs.x) {
            uint d = tile + a_local;
            if (row < seq_len && d < head_dim) {
                a_tile[tid.y][a_local] = A_head[row * head_dim + d];
            } else {
                a_tile[tid.y][a_local] = 0.0;
            }
        }

        for (uint b_local = tid.y; b_local < TILE; b_local += tgs.y) {
            uint d = tile + b_local;
            if (col < seq_len && d < head_dim) {
                b_tile[b_local][tid.x] = B_head[col * head_dim + d];
            } else {
                b_tile[b_local][tid.x] = 0.0;
            }
        }

        threadgroup_barrier(mem_flags::mem_threadgroup);
        for (uint i = 0; i < TILE; i++) {
            sum += a_tile[tid.y][i] * b_tile[i][tid.x];
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }

    if (row < seq_len && col < seq_len) {
        C_head[c_off] = sum;
    }
}

// ---- Batched matmul (non-transposed): C[h] = A[h] × B[h] ----
// For scores × V: A is [num_heads, seq_len, seq_len], B is [num_heads, seq_len, head_dim]
// C is [num_heads, seq_len, head_dim]
// 3D grid: (head_dim, seq_len, num_heads)
// Threadgroup-tiled to keep attention scores×V on the same optimized path.
kernel void batched_matmul_ab(
    device const float* A       [[buffer(0)]],
    device const float* B       [[buffer(1)]],
    device float* C             [[buffer(2)]],
    constant uint& seq_len      [[buffer(3)]],
    constant uint& head_dim     [[buffer(4)]],
    constant uint& hpg          [[buffer(5)]],
    uint3 gid                   [[thread_position_in_grid]],
    uint3 tid                   [[thread_position_in_threadgroup]],
    uint3 tgs                   [[threads_per_threadgroup]]
) {
    constexpr uint TILE = 16;
    threadgroup float a_tile[TILE][TILE];
    threadgroup float b_tile[TILE][TILE];

    uint col  = gid.x;  // j in [0, head_dim)
    uint row  = gid.y;  // i in [0, seq_len)
    uint head = gid.z;  // h in [0, num_heads)
    uint kv_head = head / hpg;

    device const float* A_head = A + head * seq_len * seq_len;
    device const float* B_head = B + kv_head * seq_len * head_dim;
    device float* C_head = C + head * seq_len * head_dim;
    uint c_off = row * head_dim + col;

    float sum = 0.0;
    for (uint tile = 0; tile < seq_len; tile += TILE) {
        for (uint a_local = tid.x; a_local < TILE; a_local += tgs.x) {
            uint k = tile + a_local;
            if (row < seq_len && k < seq_len) {
                a_tile[tid.y][a_local] = A_head[row * seq_len + k];
            } else {
                a_tile[tid.y][a_local] = 0.0;
            }
        }

        for (uint b_local = tid.y; b_local < TILE; b_local += tgs.y) {
            uint k = tile + b_local;
            if (col < head_dim && k < seq_len) {
                b_tile[b_local][tid.x] = B_head[k * head_dim + col];
            } else {
                b_tile[b_local][tid.x] = 0.0;
            }
        }

        threadgroup_barrier(mem_flags::mem_threadgroup);
        for (uint i = 0; i < TILE; i++) {
            sum += a_tile[tid.y][i] * b_tile[i][tid.x];
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }

    if (row < seq_len && col < head_dim) {
        C_head[c_off] = sum;
    }
}

// ---- Attention layout reshape (host-scatter elimination, "Lever A") ----
// The forward pass holds Q/K/V position-major: [num_groups*seq, heads_per_group*head_dim]
// (i.e. [batch*seq, hidden]). The batched attention kernels above consume
// head-major: [(num_groups*heads_per_group), seq, head_dim]. These two kernels
// do that transpose on-device so the per-layer scatter never round-trips to the
// host. Pure data movement — every output element is written exactly once from
// the matching input element, so the result is bit-identical to the host loop.

// Position-major Q/K/V -> head-major qf/kf/vf, all three in one dispatch.
// Grid: (head_dim, seq, num_groups*heads_per_group).
kernel void reshape_qkv_pos_to_head(
    device const float* qsrc        [[buffer(0)]],
    device const float* ksrc        [[buffer(1)]],
    device const float* vsrc        [[buffer(2)]],
    device float*       qdst        [[buffer(3)]],
    device float*       kdst        [[buffer(4)]],
    device float*       vdst        [[buffer(5)]],
    constant uint& heads_per_group  [[buffer(6)]],
    constant uint& seq              [[buffer(7)]],
    constant uint& dim              [[buffer(8)]],
    uint3 gid                       [[thread_position_in_grid]]
) {
    uint d = gid.x;   // [0, dim)
    uint s = gid.y;   // [0, seq)
    uint h = gid.z;   // [0, num_groups*heads_per_group)
    if (d >= dim || s >= seq) return;
    uint b        = h / heads_per_group;
    uint hd_local = h % heads_per_group;
    uint total_dim = heads_per_group * dim;
    uint src = (b * seq + s) * total_dim + hd_local * dim + d;
    uint dst = (h * seq + s) * dim + d;
    qdst[dst] = qsrc[src];
    kdst[dst] = ksrc[src];
    vdst[dst] = vsrc[src];
}

// Head-major attention output -> position-major. Grid same as above.
kernel void reshape_qkv_pos_to_head_gqa(
    device const float* qsrc        [[buffer(0)]],
    device const float* ksrc        [[buffer(1)]],
    device const float* vsrc        [[buffer(2)]],
    device float*       qdst        [[buffer(3)]],
    device float*       kdst        [[buffer(4)]],
    device float*       vdst        [[buffer(5)]],
    constant uint& heads_per_group  [[buffer(6)]],
    constant uint& seq              [[buffer(7)]],
    constant uint& dim              [[buffer(8)]],
    constant uint& kv_heads_per_group [[buffer(9)]],
    uint3 gid                       [[thread_position_in_grid]]
) {
    uint d = gid.x;
    uint s = gid.y;
    uint h = gid.z;
    if (d >= dim || s >= seq) return;
    
    uint b = h / heads_per_group;
    uint hd_local = h % heads_per_group;
    
    uint total_q_dim = heads_per_group * dim;
    uint src_q = (b * seq + s) * total_q_dim + hd_local * dim + d;
    
    uint kv_repeat = heads_per_group / kv_heads_per_group;
    uint kv_hd_local = hd_local / kv_repeat;
    uint total_kv_dim = kv_heads_per_group * dim;
    uint src_kv = (b * seq + s) * total_kv_dim + kv_hd_local * dim + d;
    
    uint dst = (h * seq + s) * dim + d;
    qdst[dst] = qsrc[src_q];
    kdst[dst] = ksrc[src_kv];
    vdst[dst] = vsrc[src_kv];
}

// Head-major attention output -> position-major. Grid same as above.
kernel void reshape_head_to_pos(
    device const float* src         [[buffer(0)]],
    device float*       dst         [[buffer(1)]],
    constant uint& heads_per_group  [[buffer(2)]],
    constant uint& seq              [[buffer(3)]],
    constant uint& dim              [[buffer(4)]],
    uint3 gid                       [[thread_position_in_grid]]
) {
    uint d = gid.x;
    uint s = gid.y;
    uint h = gid.z;
    if (d >= dim || s >= seq) return;
    uint b        = h / heads_per_group;
    uint hd_local = h % heads_per_group;
    uint total_dim = heads_per_group * dim;
    uint srci = (h * seq + s) * dim + d;
    uint dsti = (b * seq + s) * total_dim + hd_local * dim + d;
    dst[dsti] = src[srci];
}

// ---- Scale + ALiBi + mask (fused, in-place on scores) ----
// scores is [num_heads, seq_len, seq_len] flattened
// alibi_slopes is [num_heads] (or empty if no ALiBi)
// mask is [seq_len] (1 = keep, 0 = mask out)
kernel void scale_mask_alibi(
    device float* scores            [[buffer(0)]],
    device const float* alibi       [[buffer(1)]],
    device const uint* mask         [[buffer(2)]],
    constant float& scale           [[buffer(3)]],
    constant uint& seq_len          [[buffer(4)]],
    constant uint& has_alibi        [[buffer(5)]],
    uint3 gid                       [[thread_position_in_grid]]
) {
    uint col  = gid.x;  // j
    uint row  = gid.y;  // i
    uint head = gid.z;  // h

    if (row >= seq_len || col >= seq_len) return;

    uint idx = head * seq_len * seq_len + row * seq_len + col;
    float val = scores[idx] * scale;

    if (has_alibi) {
        float slope = alibi[head];
        int dist = (int)col - (int)row;
        val += slope * abs(dist);
    }

    if (mask[col] == 0) {
        val = -INFINITY;
    }

    scores[idx] = val;
}

// ---- Scale + ALiBi + grouped mask (fused, in-place on scores) ----
// scores is [num_groups * heads_per_group, seq_len, seq_len] flattened
// alibi is [heads_per_group] (or empty if no ALiBi)
// mask is [num_groups, seq_len] flattened row-major
kernel void scale_mask_alibi_grouped(
    device float* scores            [[buffer(0)]],
    device const float* alibi       [[buffer(1)]],
    device const uint* mask         [[buffer(2)]],
    constant float& scale           [[buffer(3)]],
    constant uint& seq_len          [[buffer(4)]],
    constant uint& has_alibi        [[buffer(5)]],
    constant uint& heads_per_group  [[buffer(6)]],
    uint3 gid                       [[thread_position_in_grid]]
) {
    uint col  = gid.x;  // j
    uint row  = gid.y;  // i
    uint head = gid.z;  // grouped head index

    if (row >= seq_len || col >= seq_len) return;

    uint idx = head * seq_len * seq_len + row * seq_len + col;
    float val = scores[idx] * scale;

    uint head_in_group = head % heads_per_group;
    uint group = head / heads_per_group;

    if (has_alibi) {
        float slope = alibi[head_in_group];
        int dist = (int)col - (int)row;
        val += slope * abs(dist);
    }

    if (mask[group * seq_len + col] == 0) {
        val = -INFINITY;
    }

    scores[idx] = val;
}
"#;

// ---------------------------------------------------------------------------
// fp16-operand / fp32-accumulate MMA GEMM (Lever #4) — SEPARATE shader library
// ---------------------------------------------------------------------------
// Compiled in its own `new_library_with_source` call so that if a toolchain
// rejects the heterogeneous half*half->float `simdgroup_multiply_accumulate`
// overload (it is MSL-version dependent), ONLY this library fails to build — the
// main library and Metal itself stay alive, and FP16_MMA_AVAILABLE just stays
// false. A/B are read from the existing fp32 device buffers and narrowed to half
// on the threadgroup stage (no Rust buffer-plumbing change); the MMA fragments
// are `simdgroup_half8x8` for the faster half issue rate + halved stage
// footprint, but the ACCUMULATOR stays `simdgroup_float8x8`. fp32 accumulate is
// the load-bearing parity invariant and is deliberately NOT changed here.
const FP16_SHADER_SOURCE: &str = r#"
#include <metal_stdlib>
using namespace metal;

constant uint MMA_BK = 16, MMA_F = 8;

// 32x32 tile, 4 simdgroups / 128 threads — same geometry as the fp32
// `block_mma`; the only differences are the half stage/operands (see header).
template <bool TRANSB>
static inline void block_mma_fp16(
    device const float* A,
    device const float* B,
    device float* C,
    uint M, uint N, uint K,
    uint3 tgid, uint sgid, uint lane,
    threadgroup half (*As)[MMA_BK],
    threadgroup half (*Bs)[MMA_BK],
    threadgroup float (*store_tile)[MMA_F][MMA_F])
{
    constexpr uint BM = 32, BN = 32, BK = 16, WM = 2, WN = 2, F = 8;
    constexpr uint TM = BM / (F * WM);
    constexpr uint TN = BN / (F * WN);

    const uint sm = sgid / WN;
    const uint sn = sgid % WN;
    const uint block_row = tgid.y * BM;
    const uint block_col = tgid.x * BN;
    const uint tid = sgid * 32u + lane;

    // fp32 accumulator — the parity invariant. Do NOT switch to half.
    simdgroup_float8x8 acc[TM][TN];
    for (uint i = 0; i < TM; i++)
        for (uint j = 0; j < TN; j++)
            acc[i][j] = make_filled_simdgroup_matrix<float, 8, 8>(0.0f);

    for (uint k0 = 0; k0 < K; k0 += BK) {
        // Read A/B from fp32 device memory, narrow to half on the stage.
        for (uint idx = tid; idx < BM * BK; idx += 128u) {
            uint r = idx / BK, c = idx % BK;
            uint gr = block_row + r, gc = k0 + c;
            As[r][c] = (half)((gr < M && gc < K) ? A[gr * K + gc] : 0.0f);
        }
        for (uint idx = tid; idx < BN * BK; idx += 128u) {
            uint r = idx / BK, c = idx % BK;
            uint gn = block_col + r, gk = k0 + c;
            if (TRANSB) {
                Bs[r][c] = (half)((gn < N && gk < K) ? B[gn * K + gk] : 0.0f);
            } else {
                Bs[r][c] = (half)((gn < N && gk < K) ? B[gk * N + gn] : 0.0f);
            }
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);

        for (uint kk = 0; kk < BK; kk += F) {
            simdgroup_half8x8 a_frag[TM];
            simdgroup_half8x8 b_frag[TN];
            for (uint i = 0; i < TM; i++)
                simdgroup_load(a_frag[i], &As[sm * F * TM + i * F][kk], BK, ulong2(0, 0), false);
            for (uint j = 0; j < TN; j++)
                simdgroup_load(b_frag[j], &Bs[sn * F * TN + j * F][kk], BK, ulong2(0, 0), true);
            // half * half -> fp32 accumulate (acc stays simdgroup_float8x8).
            for (uint i = 0; i < TM; i++)
                for (uint j = 0; j < TN; j++)
                    simdgroup_multiply_accumulate(acc[i][j], a_frag[i], b_frag[j], acc[i][j]);
        }
        threadgroup_barrier(mem_flags::mem_threadgroup);
    }

    if (block_row + BM <= M && block_col + BN <= N) {
        for (uint i = 0; i < TM; i++) {
            for (uint j = 0; j < TN; j++) {
                uint cr = block_row + sm * F * TM + i * F;
                uint cc = block_col + sn * F * TN + j * F;
                simdgroup_store(acc[i][j], &C[cr * N + cc], N, ulong2(0, 0), false);
            }
        }
    } else {
        for (uint i = 0; i < TM; i++) {
            for (uint j = 0; j < TN; j++) {
                uint cr = block_row + sm * F * TM + i * F;
                uint cc = block_col + sn * F * TN + j * F;
                threadgroup float* scratch = &store_tile[sgid][0][0];
                simdgroup_store(acc[i][j], scratch, F, ulong2(0, 0), false);
                threadgroup_barrier(mem_flags::mem_threadgroup);
                for (uint e = lane; e < F * F; e += 32u) {
                    uint er = e / F, ec = e % F;
                    uint gr = cr + er, gc = cc + ec;
                    if (gr < M && gc < N) {
                        C[gr * N + gc] = scratch[er * F + ec];
                    }
                }
                threadgroup_barrier(mem_flags::mem_threadgroup);
            }
        }
    }
}

kernel void matmul_transb_simdgroup_fp16(
    device const float* A   [[buffer(0)]],
    device const float* B   [[buffer(1)]],
    device float*       C   [[buffer(2)]],
    constant uint& M        [[buffer(3)]],
    constant uint& N        [[buffer(4)]],
    constant uint& K        [[buffer(5)]],
    uint3 tgid              [[threadgroup_position_in_grid]],
    uint  sgid             [[simdgroup_index_in_threadgroup]],
    uint  lane             [[thread_index_in_simdgroup]])
{
    threadgroup half As[32][MMA_BK];
    threadgroup half Bs[32][MMA_BK];
    threadgroup float store_tile[2 * 2][MMA_F][MMA_F];
    block_mma_fp16<true>(A, B, C, M, N, K, tgid, sgid, lane, As, Bs, store_tile);
}

kernel void batched_matmul_transb_simdgroup_fp16(
    device const float* Q   [[buffer(0)]],
    device const float* Kk  [[buffer(1)]],
    device float*       C   [[buffer(2)]],
    constant uint& seq      [[buffer(3)]],
    constant uint& dim      [[buffer(4)]],
    uint3 tgid              [[threadgroup_position_in_grid]],
    uint  sgid             [[simdgroup_index_in_threadgroup]],
    uint  lane             [[thread_index_in_simdgroup]])
{
    uint h = tgid.z;
    device const float* Ah = Q  + h * seq * dim;
    device const float* Bh = Kk + h * seq * dim;
    device float*       Ch = C  + h * seq * seq;
    threadgroup half As[32][MMA_BK];
    threadgroup half Bs[32][MMA_BK];
    threadgroup float store_tile[2 * 2][MMA_F][MMA_F];
    block_mma_fp16<true>(Ah, Bh, Ch, seq, seq, dim, uint3(tgid.x, tgid.y, 0), sgid, lane, As, Bs, store_tile);
}

kernel void batched_matmul_ab_simdgroup_fp16(
    device const float* S   [[buffer(0)]],
    device const float* V   [[buffer(1)]],
    device float*       C   [[buffer(2)]],
    constant uint& seq      [[buffer(3)]],
    constant uint& dim      [[buffer(4)]],
    uint3 tgid              [[threadgroup_position_in_grid]],
    uint  sgid             [[simdgroup_index_in_threadgroup]],
    uint  lane             [[thread_index_in_simdgroup]])
{
    uint h = tgid.z;
    device const float* Ah = S + h * seq * seq;
    device const float* Bh = V + h * seq * dim;
    device float*       Ch = C + h * seq * dim;
    threadgroup half As[32][MMA_BK];
    threadgroup half Bs[32][MMA_BK];
    threadgroup float store_tile[2 * 2][MMA_F][MMA_F];
    block_mma_fp16<false>(Ah, Bh, Ch, seq, dim, seq, uint3(tgid.x, tgid.y, 0), sgid, lane, As, Bs, store_tile);
}
"#;

// ---------------------------------------------------------------------------
// Bounded in-flight submission
// ---------------------------------------------------------------------------
//
// The naive per-op path commits a command buffer and immediately blocks in
// `wait_until_completed`, so ~145 of these round-trips serialize the host
// against the GPU per forward pass (measured ~69% of wall on M5 Max). The
// bounded submitter instead commits WITHOUT waiting and registers a completion
// handler; a depth counter capped at `MAX_INFLIGHT` keeps at most a few command
// buffers (and their resident intermediates) outstanding. When the cap is hit
// the submitter PARKS on a condvar — it does not busy-spin (the unbounded
// busy-spin pile-up is exactly what hung large cold embeds). This caps resident
// intermediate memory at ~MAX_INFLIGHT× a layer's working set regardless of
// repo size.

/// Maximum number of committed-but-incomplete command buffers. 2–3 is the
/// documented sweet spot: low enough to bound resident memory, high enough to
/// overlap host encoding with GPU execution.
const MAX_INFLIGHT: u32 = 3;

/// Shared in-flight depth counter + condvar. The submitter increments on commit
/// and parks while depth ≥ MAX_INFLIGHT; the completion handler decrements and
/// notifies — on BOTH success and Error, so an errored buffer can never deadlock
/// the submitter.
type InflightGate = Arc<(Mutex<u32>, Condvar)>;

/// A size-classed free-list of `StorageModeShared` buffers. Recycling a buffer
/// back onto the list avoids the per-op `new_buffer` churn that otherwise mints
/// a fresh MTLBuffer for every activation/output tensor. Buffers only return to
/// the list once the GPU is done with them (recycling is tied to the completion
/// handler that owns the `PooledBuffer`, never to Rust scope exit while the
/// buffer may still be GPU-resident).
struct BufferPool {
    device: Device,
    free: Mutex<HashMap<usize, Vec<Buffer>>>,
}

/// Round a byte count up to its allocation size-class. Powers of two up to 64KB,
/// then 64KB-aligned, so distinct-but-similar tensor sizes share a free-list slot
/// without unbounded class fragmentation.
#[inline]
fn size_class(bytes: usize) -> usize {
    let bytes = bytes.max(1);
    const CHUNK: usize = 64 * 1024;
    if bytes <= CHUNK {
        bytes.next_power_of_two()
    } else {
        bytes.div_ceil(CHUNK) * CHUNK
    }
}

/// Diagnostic gate (`KIN_INFER_NO_POOL_REUSE`): when ON, the pool never recycles
/// — every acquire allocates a fresh buffer, so no buffer is ever reused while a
/// prior command buffer might still be retiring. Default OFF (normal recycling).
/// Used to test whether the intermittent batched-embed corruption is a
/// buffer-reuse-timing race.
fn no_pool_reuse() -> bool {
    use std::sync::OnceLock;
    static V: OnceLock<bool> = OnceLock::new();
    *V.get_or_init(|| std::env::var_os("KIN_INFER_NO_POOL_REUSE").is_some())
}

/// Diagnostic gate (`KIN_INFER_ZERO_ALL`): force `acquire_with` to also zero its
/// size-class tail and `acquire_uninit` to zero the whole buffer, so no read can
/// observe stale recycled/dirty bytes. Default OFF (byte-identical). A/B test for
/// whether a stale / under-written buffer read is the corruption source.
fn zero_all_buffers() -> bool {
    use std::sync::OnceLock;
    static E: OnceLock<bool> = OnceLock::new();
    *E.get_or_init(|| {
        matches!(
            std::env::var("KIN_INFER_ZERO_ALL").ok().as_deref(),
            Some("1") | Some("true") | Some("yes") | Some("on")
        )
    })
}

/// Fallibly allocate a `StorageModeShared` Metal buffer of `length` bytes.
///
/// `metal` 0.29's `Device::new_buffer*` wrap the raw `id` straight into a
/// non-null `Buffer`, so an out-of-memory `nil` return becomes undefined
/// behaviour on first use rather than a recoverable error. Messaging the device
/// directly (the objc2 path `cmd_gpu_nanos` already uses) makes a `nil`
/// allocation observable: `None` here surfaces as `InferError::OutOfMemory` and
/// lets the embedding dispatcher degrade to CPU instead of corrupting the
/// process. Contents are uninitialised, exactly like `new_buffer` — callers zero
/// or copy in as before.
fn try_new_buffer(device: &Device, length: u64) -> Option<Buffer> {
    use metal::foreign_types::ForeignType;
    use objc2::msg_send;
    use objc2::runtime::AnyObject;
    let dev = device.as_ptr() as *const AnyObject;
    if dev.is_null() {
        return None;
    }
    let options = MTLResourceOptions::StorageModeShared.bits();
    let raw: *mut AnyObject =
        unsafe { msg_send![&*dev, newBufferWithLength: length, options: options] };
    if raw.is_null() {
        None
    } else {
        // `newBuffer…` returns a +1-retained object; `from_ptr` takes that
        // ownership without an extra retain, so it balances on drop.
        Some(unsafe { Buffer::from_ptr(raw as *mut _) })
    }
}

/// Allocate a `StorageModeShared` buffer of `bytes` bytes and copy `bytes` from
/// `src` into its head. Returns `None` on allocation failure.
fn try_new_buffer_with_bytes(device: &Device, src: *const u8, bytes: usize) -> Option<Buffer> {
    let buf = try_new_buffer(device, bytes as u64)?;
    unsafe {
        std::ptr::copy_nonoverlapping(src, buf.contents() as *mut u8, bytes);
    }
    Some(buf)
}

impl BufferPool {
    fn new(device: Device) -> Self {
        Self {
            device,
            free: Mutex::new(HashMap::new()),
        }
    }

    /// Acquire a buffer of at least `bytes`, zero-filled. Pops a recycled buffer
    /// of the matching size-class and re-zeros it (preserving the `buf_zeros`
    /// determinism guarantee), else allocates a fresh `StorageModeShared` buffer
    /// of the class size — also zeroed, because Metal does NOT guarantee
    /// `new_buffer` memory is zero (small allocations come back from Metal's
    /// recycled internal heap holding a previous allocation's bytes). Without this
    /// the FIRST use of any new size-class returns dirty memory while every warm
    /// reuse is zeroed — a shape-dependent cold-start corruption for any consumer
    /// that relies on the zero fill.
    fn acquire_zeroed(self: &Arc<Self>, bytes: usize) -> Result<PooledBuffer, InferError> {
        let class = size_class(bytes);
        let buf = self.free.lock().get_mut(&class).and_then(|v| v.pop());
        let buf = match buf {
            Some(buf) => buf,
            None => try_new_buffer(&self.device, class as u64)
                .ok_or_else(|| InferError::OutOfMemory(format!("metal buffer alloc failed: {class} bytes")))?,
        };
        unsafe {
            std::ptr::write_bytes(buf.contents() as *mut u8, 0, class);
        }
        Ok(PooledBuffer {
            buf,
            class,
            pool: Arc::clone(self),
        })
    }

    /// Acquire a buffer initialised from `data`. Pops a recycled buffer of the
    /// matching size-class (or allocates) and copies `data` into its head.
    fn acquire_with(self: &Arc<Self>, data: &[f32]) -> Result<PooledBuffer, InferError> {
        let bytes = std::mem::size_of_val(data);
        let class = size_class(bytes);
        let buf = self.free.lock().get_mut(&class).and_then(|v| v.pop());
        let buf = match buf {
            Some(buf) => buf,
            None => try_new_buffer(&self.device, class as u64)
                .ok_or_else(|| InferError::OutOfMemory(format!("metal buffer alloc failed: {class} bytes")))?,
        };
        unsafe {
            std::ptr::copy_nonoverlapping(
                data.as_ptr() as *const u8,
                buf.contents() as *mut u8,
                bytes,
            );
            if zero_all_buffers() && class > bytes {
                std::ptr::write_bytes((buf.contents() as *mut u8).add(bytes), 0, class - bytes);
            }
        }
        Ok(PooledBuffer {
            buf,
            class,
            pool: Arc::clone(self),
        })
    }

    /// Acquire a buffer of at least `bytes` with UNSPECIFIED contents. For
    /// intermediates a kernel fully overwrites before any read (e.g. the
    /// on-device attention reshape targets) — skips the re-zero `acquire_zeroed`
    /// pays. The caller is responsible for ensuring every byte read downstream
    /// was written by the producing kernel first.
    fn acquire_uninit(self: &Arc<Self>, bytes: usize) -> Result<PooledBuffer, InferError> {
        let class = size_class(bytes);
        let buf = self.free.lock().get_mut(&class).and_then(|v| v.pop());
        let buf = match buf {
            Some(buf) => buf,
            None => try_new_buffer(&self.device, class as u64)
                .ok_or_else(|| InferError::OutOfMemory(format!("metal buffer alloc failed: {class} bytes")))?,
        };
        if zero_all_buffers() {
            unsafe { std::ptr::write_bytes(buf.contents() as *mut u8, 0, class); }
        }
        Ok(PooledBuffer {
            buf,
            class,
            pool: Arc::clone(self),
        })
    }

    fn recycle(&self, class: usize, buf: Buffer) {
        if no_pool_reuse() {
            return;
        }
        self.free.lock().entry(class).or_default().push(buf);
    }
}

/// RAII handle to a pooled buffer. On drop the underlying `Buffer` returns to
/// the free-list. Drop is the recycling point, but pooled buffers used by an
/// async-committed command buffer are MOVED into the completion-handler closure
/// (`commit_bounded`'s `retain` vec), so they only drop — and only recycle —
/// after the GPU signals completion. Buffers read back synchronously drop after
/// the method's own `wait_until_completed`, which is likewise GPU-safe.
struct PooledBuffer {
    buf: Buffer,
    class: usize,
    pool: Arc<BufferPool>,
}

impl PooledBuffer {
    #[inline]
    fn buffer(&self) -> &Buffer {
        &self.buf
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        self.pool.recycle(self.class, self.buf.clone());
    }
}

// ---------------------------------------------------------------------------
// Metal compute context
// ---------------------------------------------------------------------------

pub struct MetalCompute {
    device: Device,
    queue: CommandQueue,
    pipelines: HashMap<&'static str, ComputePipelineState>,
    device_name: String,
    /// Cache weight buffers on GPU keyed by (data_ptr, len). Weight matrices
    /// are the same across all forward passes, so allocating once and reusing
    /// eliminates ~100GB of redundant copies for a typical embedding run.
    weight_cache: Mutex<HashMap<(usize, usize), Buffer>>,
    /// Cache row-concatenated weight buffers (e.g. q|k|v, gate|up) keyed by the
    /// component weights' stable (ptr, len) pairs, so the fat GEMM uploads the
    /// concatenation once and reuses it across every forward pass.
    concat_cache: Mutex<HashMap<Vec<(usize, usize)>, Buffer>>,
    /// Bounded in-flight depth gate shared with completion handlers.
    inflight: InflightGate,
    /// Size-classed activation/output buffer pool.
    pool: Arc<BufferPool>,
}

impl MetalCompute {
    /// Try to create a Metal compute context. Returns None if Metal is unavailable.
    pub fn try_new() -> Option<Self> {
        let _span = tracing::info_span!("kin_infer.metal.try_new").entered();
        let device = Device::system_default()?;
        let queue = device.new_command_queue();
        let device_name = device.name().to_string();

        let opts = CompileOptions::new();
        // MSL 2.4 guarantees the `simdgroup_matrix` intrinsics (simdgroup_float8x8,
        // simdgroup_multiply_accumulate, make_filled_simdgroup_matrix) the MMA
        // GEMM kernels use, independent of the toolchain's default version.
        // KIN_INFER_MSL_VERSION lets us exercise a different runtime-compiler codegen
        // path (driver-miscompile probe); unset = V2_4 default (byte-identical).
        let lang = match std::env::var("KIN_INFER_MSL_VERSION").as_deref() {
            Ok("30") => MTLLanguageVersion::V3_0,
            Ok("31") => MTLLanguageVersion::V3_1,
            _ => MTLLanguageVersion::V2_4,
        };
        opts.set_language_version(lang);
        // KIN_INFER_FAST_MATH=0 disables MSL fast-math (no float reassociation /
        // assume-finite); unset = toolchain default (fast-math on, byte-identical).
        if std::env::var("KIN_INFER_FAST_MATH").as_deref() == Ok("0") {
            opts.set_fast_math_enabled(false);
        }
        let library = match device.new_library_with_source(SHADER_SOURCE, &opts) {
            Ok(library) => library,
            Err(err) => {
                eprintln!("kin-infer: Metal shader compile failed: {err}");
                return None;
            }
        };

        // Required scalar kernels — Metal cannot run without these, so a build
        // failure here disables the backend (caller falls back to CPU).
        let kernel_names: &[&str] = &[
            "matmul_transb",
            "batched_matmul_transb",
            "batched_matmul_ab",
            "reshape_qkv_pos_to_head",
            "reshape_qkv_pos_to_head_gqa",
            "reshape_head_to_pos",
            "scale_mask_alibi",
            "scale_mask_alibi_grouped",
            "softmax_rows",
            "layer_norm",
            "rms_norm",
            "gelu_activation",
            "silu_activation",
            "swiglu_activation",
            "swiglu_activation_fat",
            "elementwise_mul",
            "elementwise_add",
            "elementwise_add_broadcast",
            "rope_apply",
            "rope_apply_batched",
            "split_qkv_packed",
        ];

        let mut pipelines = HashMap::new();
        for &name in kernel_names {
            let func = match library.get_function(name, None) {
                Ok(func) => func,
                Err(err) => {
                    eprintln!("kin-infer: Metal function lookup failed for {name}: {err}");
                    return None;
                }
            };
            let pipeline = match device.new_compute_pipeline_state_with_function(&func) {
                Ok(pipeline) => pipeline,
                Err(err) => {
                    eprintln!("kin-infer: Metal pipeline build failed for {name}: {err}");
                    return None;
                }
            };
            pipelines.insert(name, pipeline);
        }

        // simdgroup MMA fast-path kernels — OPTIONAL. They require the
        // `simdgroup_matrix` intrinsics; if a target's toolchain fails to build
        // any one of them, leave them out and disable the MMA route process-wide
        // so every GEMM falls back to the scalar tile above. Metal stays alive.
        let mma_kernel_names: &[&str] = &[
            "matmul_transb_simdgroup",
            "batched_matmul_transb_simdgroup",
            "batched_matmul_ab_simdgroup",
        ];
        let mut mma_available = true;
        for &name in mma_kernel_names {
            let pipeline = library
                .get_function(name, None)
                .and_then(|func| device.new_compute_pipeline_state_with_function(&func));
            match pipeline {
                Ok(pipeline) => {
                    pipelines.insert(name, pipeline);
                }
                Err(err) => {
                    eprintln!(
                        "kin-infer: Metal MMA kernel {name} unavailable ({err}); \
                         falling back to scalar GEMM (Metal stays enabled)"
                    );
                    mma_available = false;
                    break;
                }
            }
        }
        MMA_AVAILABLE.store(mma_available, Ordering::Relaxed);

        // Wider 64x64 MMA tile (Lever #5 phase 1) — OPTIONAL, only attempted when
        // the standard MMA built. Same fallback discipline: if any `*_wide` kernel
        // fails to compile (e.g. register-spill rejection on a constrained
        // target), leave WIDE_MMA_AVAILABLE false and every GEMM stays on the
        // proven 32x32 MMA. Metal stays alive.
        let wide_mma_kernel_names: &[&str] = &[
            "matmul_transb_simdgroup_wide",
            "batched_matmul_transb_simdgroup_wide",
            "batched_matmul_ab_simdgroup_wide",
        ];
        let mut wide_mma_available = mma_available;
        if mma_available {
            for &name in wide_mma_kernel_names {
                let pipeline = library
                    .get_function(name, None)
                    .and_then(|func| device.new_compute_pipeline_state_with_function(&func));
                match pipeline {
                    Ok(pipeline) => {
                        pipelines.insert(name, pipeline);
                    }
                    Err(err) => {
                        eprintln!(
                            "kin-infer: Metal wide-MMA kernel {name} unavailable ({err}); \
                             falling back to 32x32 MMA (Metal stays enabled)"
                        );
                        wide_mma_available = false;
                        break;
                    }
                }
            }
        }
        WIDE_MMA_AVAILABLE.store(wide_mma_available, Ordering::Relaxed);

        // Steel double-buffered K-loop MMA (Step 1) — OPTIONAL, only attempted
        // when the standard MMA built. The `*_steel` kernels live in the SAME main
        // library (already compiled above — no extra library compile, just three
        // pipeline-creation calls), so attempting them is cheap. Same fallback
        // discipline as `*_wide`: if any `*_steel` kernel fails to build (e.g. a
        // bad MSL overload or a threadgroup-memory overflow on a constrained
        // target — the pipeline-state creation returns Err), leave
        // STEEL_MMA_AVAILABLE false and every GEMM stays on the proven
        // single-buffer MMA. A bad steel overload can NEVER disable Metal or the
        // main library — that is the whole point of the flag. Built unconditionally
        // (independent of `steel_enabled()`) so the pipelines are ready the instant
        // KIN_INFER_STEEL flips on and the direct-dispatch parity test can run.
        let steel_mma_kernel_names: &[&str] = &[
            "matmul_transb_simdgroup_steel",
            "batched_matmul_transb_simdgroup_steel",
            "batched_matmul_ab_simdgroup_steel",
        ];
        let mut steel_mma_available = mma_available;
        if mma_available {
            for &name in steel_mma_kernel_names {
                let pipeline = library
                    .get_function(name, None)
                    .and_then(|func| device.new_compute_pipeline_state_with_function(&func));
                match pipeline {
                    Ok(pipeline) => {
                        pipelines.insert(name, pipeline);
                    }
                    Err(err) => {
                        eprintln!(
                            "kin-infer: Metal steel-MMA kernel {name} unavailable ({err}); \
                             falling back to single-buffer MMA (Metal stays enabled)"
                        );
                        steel_mma_available = false;
                        break;
                    }
                }
            }
        }
        STEEL_MMA_AVAILABLE.store(steel_mma_available, Ordering::Relaxed);

        // fp16-operand MMA (Lever #4) — OPTIONAL, compiled as a SEPARATE library
        // so a toolchain that rejects the half*half->float `simdgroup_matrix`
        // overload only loses the fp16 path (this whole library fails to build),
        // never the main library or Metal. Only compiled when fp16 is opt-in
        // enabled AND the fp32 MMA built — so the default (flag-off) scoring path
        // never even attempts the extra library compile (zero added startup cost,
        // zero fp16 risk surface). If the library compiles, register its three
        // kernels; any failure (compile, lookup, or pipeline) leaves
        // FP16_MMA_AVAILABLE false and every GEMM uses the fp32 MMA.
        let mut fp16_mma_available = false;
        if mma_available && mma_fp16_enabled() {
            match device.new_library_with_source(FP16_SHADER_SOURCE, &opts) {
                Ok(fp16_library) => {
                    let fp16_kernel_names: &[&str] = &[
                        "matmul_transb_simdgroup_fp16",
                        "batched_matmul_transb_simdgroup_fp16",
                        "batched_matmul_ab_simdgroup_fp16",
                    ];
                    let mut ok = true;
                    for &name in fp16_kernel_names {
                        let pipeline = fp16_library
                            .get_function(name, None)
                            .and_then(|func| {
                                device.new_compute_pipeline_state_with_function(&func)
                            });
                        match pipeline {
                            Ok(pipeline) => {
                                pipelines.insert(name, pipeline);
                            }
                            Err(err) => {
                                eprintln!(
                                    "kin-infer: Metal fp16 MMA kernel {name} unavailable \
                                     ({err}); fp16 GEMM disabled (fp32 MMA stays enabled)"
                                );
                                ok = false;
                                break;
                            }
                        }
                    }
                    fp16_mma_available = ok;
                }
                Err(err) => {
                    eprintln!(
                        "kin-infer: Metal fp16 shader library failed to compile ({err}); \
                         fp16 GEMM disabled (fp32 MMA stays enabled)"
                    );
                }
            }
        }
        FP16_MMA_AVAILABLE.store(fp16_mma_available, Ordering::Relaxed);

        let pool = Arc::new(BufferPool::new(device.clone()));
        Some(Self {
            device,
            queue,
            pipelines,
            device_name,
            weight_cache: Mutex::new(HashMap::new()),
            concat_cache: Mutex::new(HashMap::new()),
            inflight: Arc::new((Mutex::new(0), Condvar::new())),
            pool,
        })
    }

    /// Create a Metal buffer from a slice and copy data in.
    fn buf_from_slice(&self, data: &[f32]) -> Result<Buffer, InferError> {
        let bytes = data.len() * std::mem::size_of::<f32>();
        try_new_buffer_with_bytes(&self.device, data.as_ptr() as *const u8, bytes)
            .ok_or_else(|| InferError::OutOfMemory(format!("metal buffer alloc failed: {bytes} bytes")))
    }

    /// Acquire a zero-filled transient buffer of `count` floats from the pool.
    /// Returns an RAII `PooledBuffer` that recycles on drop; safe to drop only
    /// after the GPU work touching it has completed (every caller waits before
    /// readback / scope-exit). Re-zeroed on reuse, preserving the determinism
    /// guarantee `buf_zeros` documents.
    #[inline]
    fn buf_zeros_pooled(&self, count: usize) -> Result<PooledBuffer, InferError> {
        time_phase(Phase::Copy, || {
            self.pool.acquire_zeroed(count * std::mem::size_of::<f32>())
        })
    }

    /// Acquire a transient buffer initialised from `data` from the pool. The
    /// host→device copy is timed into the copy/readback phase.
    #[inline]
    fn buf_slice_pooled(&self, data: &[f32]) -> Result<PooledBuffer, InferError> {
        time_phase(Phase::Copy, || self.pool.acquire_with(data))
    }

    /// Acquire a transient buffer of `count` floats with UNSPECIFIED contents.
    /// For intermediates that a kernel fully overwrites before any read.
    #[inline]
    fn buf_uninit_pooled(&self, count: usize) -> Result<PooledBuffer, InferError> {
        time_phase(Phase::Copy, || {
            self.pool.acquire_uninit(count * std::mem::size_of::<f32>())
        })
    }

    /// Create a buffer containing a single u32 value.
    fn buf_u32(&self, val: u32) -> Result<Buffer, InferError> {
        let data = [val];
        try_new_buffer_with_bytes(
            &self.device,
            data.as_ptr() as *const u8,
            std::mem::size_of::<u32>(),
        )
        .ok_or_else(|| InferError::OutOfMemory("metal scalar u32 buffer alloc failed".into()))
    }

    /// Create a buffer containing a single f32 value.
    fn buf_f32(&self, val: f32) -> Result<Buffer, InferError> {
        let data = [val];
        try_new_buffer_with_bytes(
            &self.device,
            data.as_ptr() as *const u8,
            std::mem::size_of::<f32>(),
        )
        .ok_or_else(|| InferError::OutOfMemory("metal scalar f32 buffer alloc failed".into()))
    }

    /// Get or create a cached buffer for persistent data (weight matrices).
    /// Keyed by (pointer, len) — weight Array2 data pointers are stable
    /// across forward passes, so this hits on every call after the first.
    fn buf_cached(&self, data: &[f32]) -> Result<Buffer, InferError> {
        let key = (data.as_ptr() as usize, data.len());
        let mut cache = self.weight_cache.lock();
        if let Some(buf) = cache.get(&key) {
            return Ok(buf.clone());
        }
        let buf = self.buf_from_slice(data)?;
        cache.insert(key, buf.clone());
        Ok(buf)
    }

    /// Get or create a cached GPU buffer holding `weights` concatenated
    /// row-major in order. The weight Array2 data pointers are stable across
    /// forward passes, so the concatenation — built once — is keyed by the
    /// component (ptr, len) pairs and reused on every subsequent call. Used to
    /// fold the q/k/v (and gate/up) projections into one fat GEMM.
    fn buf_cached_concat(&self, weights: &[&[f32]]) -> Result<Buffer, InferError> {
        let key: Vec<(usize, usize)> = weights
            .iter()
            .map(|w| (w.as_ptr() as usize, w.len()))
            .collect();
        let mut cache = self.concat_cache.lock();
        if let Some(buf) = cache.get(&key) {
            return Ok(buf.clone());
        }
        let total: usize = weights.iter().map(|w| w.len()).sum();
        let mut concat = Vec::with_capacity(total);
        for w in weights {
            concat.extend_from_slice(w);
        }
        let buf = self.buf_from_slice(&concat)?;
        cache.insert(key, buf.clone());
        Ok(buf)
    }

    /// Upload a fresh device buffer for a TRANSIENT u32 payload (e.g. an
    /// attention mask). Deliberately NOT cached: the previous `(ptr, len)` cache
    /// keyed on the slice's heap address, which is only valid for stable weight
    /// pointers (`buf_cached`). Attention masks are rebuilt every call as a fresh
    /// `Vec<u32>` whose pointer the allocator recycles, so a later call landing on
    /// the same `(ptr, len)` would alias an earlier call's stale mask buffer and
    /// silently apply the WRONG mask. Masks are tiny (`batch*max_len` u32s), so a
    /// fresh upload per attention call is negligible and strictly correct.
    fn buf_u32_slice(&self, data: &[u32]) -> Result<Buffer, InferError> {
        let bytes = data.len() * std::mem::size_of::<u32>();
        try_new_buffer_with_bytes(&self.device, data.as_ptr() as *const u8, bytes)
            .ok_or_else(|| InferError::OutOfMemory(format!("metal u32 buffer alloc failed: {bytes} bytes")))
    }

    /// Read floats back from a Metal buffer. Timed into the copy/readback phase.
    fn read_buf(buf: &Buffer, count: usize) -> Vec<f32> {
        time_phase(Phase::Copy, || {
            let ptr = buf.contents() as *const f32;
            let slice = unsafe { std::slice::from_raw_parts(ptr, count) };
            slice.to_vec()
        })
    }

    /// Debug helper: count NaN/Inf values in a slice. Hot path; only gated
    /// behind the `KIN_INFER_METAL_NAN_CHECK` env var so production has zero
    /// overhead.
    #[inline]
    #[allow(dead_code)]
    fn count_nonfinite(name: &str, data: &[f32]) -> usize {
        if std::env::var_os("KIN_INFER_METAL_NAN_CHECK").is_none() {
            return 0;
        }
        let n = data.iter().filter(|x| !x.is_finite()).count();
        if n > 0 {
            eprintln!(
                "[kin_infer.metal.nan_check] op={name} non_finite={n}/{} first_nan_idx={:?}",
                data.len(),
                data.iter().position(|x| !x.is_finite())
            );
        }
        n
    }

    /// Read floats from a shared buffer in-place into a mutable slice. Timed into
    /// the copy/readback phase.
    fn read_buf_into(buf: &Buffer, dst: &mut [f32]) {
        time_phase(Phase::Copy, || {
            let ptr = buf.contents() as *const f32;
            let src = unsafe { std::slice::from_raw_parts(ptr, dst.len()) };
            dst.copy_from_slice(src);
        });
    }

    /// Commit `cmd` for asynchronous GPU execution under a bounded in-flight cap.
    ///
    /// Unlike `commit_and_wait`, this does NOT block on `wait_until_completed`:
    /// it registers a completion handler that decrements the in-flight depth and
    /// recycles the `retain`ed pooled buffers once the GPU is done, then commits.
    /// The submitter parks (does not spin) when depth reaches `MAX_INFLIGHT`, so
    /// at most a few command buffers — and their resident intermediates — are
    /// outstanding at once. `retain` must hold every pooled buffer the command
    /// buffer reads or writes, so none is recycled while still GPU-resident.
    fn commit_bounded(&self, cmd: &CommandBufferRef, retain: Vec<PooledBuffer>) {
        // Backpressure: park until an in-flight slot frees. parking_lot's Condvar
        // parks the OS thread (idle-detectable) rather than busy-spinning. A
        // 30s watchdog turns a leaked completion handler (which would otherwise
        // deadlock the submitter forever) into an observable warning instead of
        // a silent hang.
        let blocked_start = profile_enabled().then(std::time::Instant::now);
        {
            let (lock, cvar) = &*self.inflight;
            let mut depth = lock.lock();
            while *depth >= MAX_INFLIGHT {
                let timed_out = cvar
                    .wait_for(&mut depth, std::time::Duration::from_secs(30))
                    .timed_out();
                if timed_out && *depth >= MAX_INFLIGHT {
                    tracing::warn!(
                        depth = *depth,
                        max_inflight = MAX_INFLIGHT,
                        "kin_infer.metal.commit_bounded: in-flight depth has not drained for 30s — a completion handler may have failed to fire"
                    );
                }
            }
            *depth += 1;
            debug_assert!(*depth <= MAX_INFLIGHT, "in-flight depth exceeded the cap");
        }
        if let Some(start) = blocked_start {
            STALL_NANOS.fetch_add(start.elapsed().as_nanos() as u64, Ordering::Relaxed);
        }

        // Completion handler: runs on a GPU-driver thread when the buffer
        // finishes. Decrement + notify on BOTH success and Error so an errored
        // buffer can never deadlock the submitter; dropping `retain` here returns
        // the pooled buffers to the free-list only after the GPU is done. The
        // `block` 0.1 crate requires a `Fn` closure, so the once-fired `take` of
        // the retained buffers goes through a Mutex for interior mutability.
        let inflight = Arc::clone(&self.inflight);
        let retain = Mutex::new(Some(retain));
        let handler = block::ConcreteBlock::new(move |cb: &CommandBufferRef| {
            if cb.status() == metal::MTLCommandBufferStatus::Error {
                tracing::warn!("kin_infer.metal.commit_bounded: command buffer completed in Error state");
            }
            // Recycle retained buffers (drop returns them to the pool) before
            // releasing the in-flight slot.
            retain.lock().take();
            let (lock, cvar) = &*inflight;
            let mut depth = lock.lock();
            *depth = depth.saturating_sub(1);
            cvar.notify_one();
        })
        .copy();
        cmd.add_completed_handler(&handler);

        cmd.commit();
        if profile_enabled() {
            SUBMISSIONS.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Commit `cmd` (bounded) and block until the GPU finishes — the synchronous
    /// boundary every per-op dispatch uses before reading its output back. When
    /// profiling is on, attribute the command buffer's *GPU-execution* window
    /// (`GPUStartTime`/`GPUEndTime`, valid only after completion) to the phase
    /// published by the enclosing `time_phase`. Behaviour is byte-identical to
    /// the inlined `commit_bounded(cmd, Vec::new()); wait_until_completed()` it
    /// replaces; the timestamp read is gated and side-effect-free.
    #[inline]
    fn commit_wait(&self, cmd: &CommandBufferRef) {
        self.commit_bounded(cmd, Vec::new());
        cmd.wait_until_completed();
        if profile_enabled() {
            if let Some(phase) = CURRENT_PHASE.with(|p| p.get()) {
                phase
                    .gpu_counter()
                    .fetch_add(cmd_gpu_nanos(cmd), Ordering::Relaxed);
            }
        }
    }

    /// Dispatch a 1D compute kernel.

    fn encode_1d(
        &self,
        cmd: &CommandBufferRef,
        pipeline_name: &str,
        buffers: &[&Buffer],
        total_threads: usize,
    ) {
        let pipeline = &self.pipelines[pipeline_name];
        let enc = cmd.new_compute_command_encoder();
        enc.set_compute_pipeline_state(pipeline);
        for (i, buf) in buffers.iter().enumerate() {
            enc.set_buffer(i as u64, Some(buf), 0);
        }
        let thread_w = pipeline.thread_execution_width() as usize;
        let threads = MTLSize::new(total_threads as u64, 1, 1);
        let tg_size = MTLSize::new(thread_w.min(total_threads) as u64, 1, 1);
        enc.dispatch_threads(threads, tg_size);
        enc.end_encoding();
    }

    fn encode_3d(
        &self,
        cmd: &CommandBufferRef,
        pipeline_name: &str,
        buffers: &[&Buffer],
        width: usize,
        height: usize,
        depth: usize,
    ) {
        let pipeline = &self.pipelines[pipeline_name];
        let enc = cmd.new_compute_command_encoder();
        enc.set_compute_pipeline_state(pipeline);
        for (i, buf) in buffers.iter().enumerate() {
            enc.set_buffer(i as u64, Some(buf), 0);
        }
        let threads = MTLSize::new(width as u64, height as u64, depth as u64);
        let tg_size = MTLSize::new(
            8.min(width) as u64,
            8.min(height) as u64,
            1.min(depth) as u64,
        );
        enc.dispatch_threads(threads, tg_size);
        enc.end_encoding();
    }

    /// Dispatch a 1D compute kernel.
    fn dispatch_1d(&self, pipeline_name: &str, buffers: &[&Buffer], total_threads: usize) {
        let _span = tracing::info_span!(
            "kin_infer.metal.dispatch_1d",
            pipeline = pipeline_name,
            buffer_count = buffers.len(),
            total_threads = total_threads
        )
        .entered();
        let pipeline = &self.pipelines[pipeline_name];
        // The command buffer and encoder are autoreleased (+0) by the metal
        // crate. On a worker thread with no ambient pool (e.g. tokio
        // spawn_blocking, where embedding runs) they would otherwise accumulate
        // for the thread's whole life and back the queue up against its
        // in-flight cap. Drain them per dispatch.
        autoreleasepool(|_| {
            let cmd = self.queue.new_command_buffer();
            let enc = cmd.new_compute_command_encoder();
            enc.set_compute_pipeline_state(pipeline);
            for (i, buf) in buffers.iter().enumerate() {
                enc.set_buffer(i as u64, Some(buf), 0);
            }

            let thread_w = pipeline.thread_execution_width() as usize;
            let threads = MTLSize::new(total_threads as u64, 1, 1);
            let tg_size = MTLSize::new(thread_w.min(total_threads) as u64, 1, 1);
            enc.dispatch_threads(threads, tg_size);
            enc.end_encoding();
            // The buffers are caller-owned (read back after this returns), so no
            // pooled buffers to retain; commit bounded-async then sync at the
            // data-consuming boundary.
            self.commit_wait(cmd);
        });
    }

    /// Dispatch a 3D compute kernel (for batched multi-head attention).
    fn dispatch_3d(
        &self,
        pipeline_name: &str,
        buffers: &[&Buffer],
        width: usize,
        height: usize,
        depth: usize,
    ) {
        let _span = tracing::info_span!(
            "kin_infer.metal.dispatch_3d",
            pipeline = pipeline_name,
            buffer_count = buffers.len(),
            width = width,
            height = height,
            depth = depth
        )
        .entered();
        let pipeline = &self.pipelines[pipeline_name];
        autoreleasepool(|_| {
            let cmd = self.queue.new_command_buffer();
            let enc = cmd.new_compute_command_encoder();
            enc.set_compute_pipeline_state(pipeline);
            for (i, buf) in buffers.iter().enumerate() {
                enc.set_buffer(i as u64, Some(buf), 0);
            }

            let threads = MTLSize::new(width as u64, height as u64, depth as u64);
            let tg_size = MTLSize::new(
                8.min(width) as u64,
                8.min(height) as u64,
                1.min(depth) as u64,
            );
            enc.dispatch_threads(threads, tg_size);
            enc.end_encoding();
            self.commit_wait(cmd);
        });
    }

    /// Encode a single `matmul_transb` dispatch into an existing command buffer
    /// without committing. `width`/`height` are the 2D grid (N, M). Used to chain
    /// several dependent matmuls into one submission (e.g. the fused FFN).
    #[allow(clippy::too_many_arguments)]
    fn encode_matmul(
        cmd: &CommandBufferRef,
        pipeline: &ComputePipelineState,
        buf_a: &Buffer,
        buf_b: &Buffer,
        buf_c: &Buffer,
        buf_m: &Buffer,
        buf_n: &Buffer,
        buf_k: &Buffer,
        width: usize,
        height: usize,
    ) {
        let enc = cmd.new_compute_command_encoder();
        enc.set_compute_pipeline_state(pipeline);
        enc.set_buffer(0, Some(buf_a), 0);
        enc.set_buffer(1, Some(buf_b), 0);
        enc.set_buffer(2, Some(buf_c), 0);
        enc.set_buffer(3, Some(buf_m), 0);
        enc.set_buffer(4, Some(buf_n), 0);
        enc.set_buffer(5, Some(buf_k), 0);
        let threads = MTLSize::new(width as u64, height as u64, 1);
        let tg_size = MTLSize::new(16.min(width) as u64, 16.min(height) as u64, 1);
        enc.dispatch_threads(threads, tg_size);
        enc.end_encoding();
    }

    /// Dispatch a 2D compute kernel.
    fn dispatch_2d(&self, pipeline_name: &str, buffers: &[&Buffer], width: usize, height: usize) {
        let _span = tracing::info_span!(
            "kin_infer.metal.dispatch_2d",
            pipeline = pipeline_name,
            buffer_count = buffers.len(),
            width = width,
            height = height
        )
        .entered();
        let pipeline = &self.pipelines[pipeline_name];
        autoreleasepool(|_| {
            let cmd = self.queue.new_command_buffer();
            let enc = cmd.new_compute_command_encoder();
            enc.set_compute_pipeline_state(pipeline);
            for (i, buf) in buffers.iter().enumerate() {
                enc.set_buffer(i as u64, Some(buf), 0);
            }

            let threads = MTLSize::new(width as u64, height as u64, 1);
            let tg_size = MTLSize::new(16.min(width) as u64, 16.min(height) as u64, 1);
            enc.dispatch_threads(threads, tg_size);
            enc.end_encoding();
            self.commit_wait(cmd);
        });
    }

    /// Encode one MMA GEMM into `cmd` without committing. `base_name` is the
    /// standard `*_simdgroup` kernel; when `use_wide_mma(m,n,k)` holds this
    /// transparently routes to its `*_wide` 64x64 variant (Lever #5 phase 1) and
    /// blocks the grid at 64 instead of 32 — otherwise the proven 32x32 tile with
    /// an identical grid to the pre-Lever-#5 code (so the flag-OFF path is
    /// byte-identical). The MMA kernels REQUIRE full 32-lane simdgroups, so this
    /// uses `dispatch_thread_groups` with one 128-thread threadgroup per output
    /// block, NOT `dispatch_threads`. `m`/`n`/`k` are the matmul dimensions;
    /// `depth` is the batch (head) count (1 for the 2D projections).
    #[allow(clippy::too_many_arguments)]
    fn encode_mma(
        &self,
        cmd: &CommandBufferRef,
        base_name: &str,
        bufs: &[&Buffer],
        m: usize,
        n: usize,
        k: usize,
        depth: usize,
    ) {
        let (pipeline, block) = if use_fp16_mma(m, n, k) {
            // fp16 operands, fp32 accumulate (32x32 tile). Takes precedence over
            // the wider tile — they don't compose until Lever #5 phase 2.
            (&self.pipelines[fp16_mma_name(base_name)], 32usize)
        } else if use_wide_mma(m, n, k) {
            (&self.pipelines[wide_mma_name(base_name)], 64usize)
        } else if use_steel(m, n, k) {
            // Steel double-buffered K-loop, same proven 32x32 tile/grid as the
            // single-buffer MMA — only the K-loop staging differs (fp32 accumulate
            // unchanged). Distinct experiment from fp16/wide; routed when only
            // KIN_INFER_STEEL is set.
            (&self.pipelines[steel_mma_name(base_name)], 32usize)
        } else {
            (&self.pipelines[base_name], 32usize)
        };
        let enc = cmd.new_compute_command_encoder();
        enc.set_compute_pipeline_state(pipeline);
        for (i, buf) in bufs.iter().enumerate() {
            enc.set_buffer(i as u64, Some(buf), 0);
        }
        let groups = MTLSize::new(
            n.div_ceil(block) as u64,
            m.div_ceil(block) as u64,
            depth as u64,
        );
        let tg = MTLSize::new(128, 1, 1);
        enc.dispatch_thread_groups(groups, tg);
        enc.end_encoding();
    }

    /// Dispatch a standalone MMA GEMM through the bounded submitter, syncing
    /// before the caller reads `bufs[2]` (the C output).
    fn dispatch_mma(
        &self,
        base_name: &str,
        bufs: &[&Buffer],
        m: usize,
        n: usize,
        k: usize,
        depth: usize,
    ) {
        let _span = tracing::info_span!(
            "kin_infer.metal.dispatch_mma",
            pipeline = base_name,
            m = m,
            n = n,
            depth = depth
        )
        .entered();
        autoreleasepool(|_| {
            let cmd = self.queue.new_command_buffer();
            self.encode_mma(cmd, base_name, bufs, m, n, k, depth);
            self.commit_wait(cmd);
        });
    }
}

/// Map a base `*_simdgroup` MMA kernel name to its `*_wide` 64x64 variant.
/// Lever #5 phase 1 registers exactly these three wide kernels; the fallback
/// returns the input unchanged (only the three known names ever reach here via
/// `use_wide_mma`'s shape gate).
#[inline]
fn wide_mma_name(base: &str) -> &str {
    match base {
        "matmul_transb_simdgroup" => "matmul_transb_simdgroup_wide",
        "batched_matmul_transb_simdgroup" => "batched_matmul_transb_simdgroup_wide",
        "batched_matmul_ab_simdgroup" => "batched_matmul_ab_simdgroup_wide",
        other => other,
    }
}

/// Map a base `*_simdgroup` MMA kernel name to its `*_fp16` variant (Lever #4).
#[inline]
fn fp16_mma_name(base: &str) -> &str {
    match base {
        "matmul_transb_simdgroup" => "matmul_transb_simdgroup_fp16",
        "batched_matmul_transb_simdgroup" => "batched_matmul_transb_simdgroup_fp16",
        "batched_matmul_ab_simdgroup" => "batched_matmul_ab_simdgroup_fp16",
        other => other,
    }
}

/// Map a base `*_simdgroup` MMA kernel name to its `*_steel` double-buffered
/// variant (Step 1). The three steel kernels mirror the three single-buffer
/// shapes; the fallback returns the input unchanged (only the three known names
/// reach here via `use_steel`'s shape gate).
#[inline]
fn steel_mma_name(base: &str) -> &str {
    match base {
        "matmul_transb_simdgroup" => "matmul_transb_simdgroup_steel",
        "batched_matmul_transb_simdgroup" => "batched_matmul_transb_simdgroup_steel",
        "batched_matmul_ab_simdgroup" => "batched_matmul_ab_simdgroup_steel",
        other => other,
    }
}

impl GpuCompute for MetalCompute {

    fn forward_layer_batched(
        &self,
        hidden: &[f32],
        masks: &[u32],
        weights: &LayerTensors,
        config: &LayerConfig,
        rope_cos: &[f32],
        rope_sin: &[f32],
    ) -> Result<Option<Vec<f32>>, InferError> {
        autoreleasepool(|_| {
            let kv_heads = if let Some(k) = weights.k_weight {
            k.len() / (config.hidden_size * config.head_dim)
        } else if let Some(qkv) = weights.qkv_weight {
            let total_qkv_dim = qkv.len() / config.hidden_size;
            let q_dim = config.num_heads * config.head_dim;
            (total_qkv_dim - q_dim) / (2 * config.head_dim)
        } else {
            config.num_heads
        };

        let _span = tracing::info_span!("kin_infer.metal.forward_layer_batched").entered();

        let batch_size = config.batch_size;
        let max_len = config.max_len;
        let total_rows = batch_size * max_len;
        let h = config.hidden_size;
        let heads = config.num_heads;
        let head_dim = config.head_dim;
        let inter = config.inter_size;
        let q_dim = heads * head_dim;
        let kv_dim = kv_heads * head_dim;

        let current_hidden = self.buf_slice_pooled(hidden)?;
        
        // ---------------------------------------------------------
        // Command Buffer 1: Norm 1 + QKV Projections
        // ---------------------------------------------------------
        let cmd1 = self.queue.new_command_buffer();
        let mut retains1 = Vec::new();
        
        let buf_rows = self.buf_u32(total_rows as u32)?;
        let buf_h = self.buf_u32(h as u32)?;
        let buf_eps = self.buf_f32(if config.use_rms { config.rms_eps } else { config.eps })?;
        
        // Layer norm 1
        let mut buf_normed1 = None;
        let mut qkv_in = current_hidden.buffer();
        if config.pre_ln {
            let buf = self.pool.acquire_uninit(total_rows * h * 4)?;
            {
                let blit = cmd1.new_blit_command_encoder();
                blit.copy_from_buffer(current_hidden.buffer(), 0, buf.buffer(), 0, (total_rows * h * 4) as u64);
                blit.end_encoding();
            }
            let buf_norm1_w = self.buf_cached(weights.norm1_weight)?;
            if config.use_rms {
                self.encode_1d(cmd1, "rms_norm", &[buf.buffer(), &buf_norm1_w, &buf_h, &buf_eps], total_rows);
            } else {
                let buf_norm1_b = self.buf_cached(weights.norm1_bias.unwrap_or(&[]))?;
                self.encode_1d(cmd1, "layer_norm", &[buf.buffer(), &buf_norm1_w, &buf_norm1_b, &buf_h, &buf_eps], total_rows);
            }
            buf_normed1 = Some(buf);
            qkv_in = buf_normed1.as_ref().unwrap().buffer();
        }
        
        let buf_q_dim = self.buf_u32(q_dim as u32)?;
        let buf_kv_dim = self.buf_u32(kv_dim as u32)?;
        let buf_q = self.pool.acquire_uninit(total_rows * q_dim * 4)?;
        let buf_k = self.pool.acquire_uninit(total_rows * kv_dim * 4)?;
        let buf_v = self.pool.acquire_uninit(total_rows * kv_dim * 4)?;
        
        if let Some(qkv_weight) = weights.qkv_weight {
            let total_qkv = q_dim + 2 * kv_dim;
            let buf_qkv_dim = self.buf_u32(total_qkv as u32)?;
            let buf_qkv = self.pool.acquire_uninit(total_rows * total_qkv * 4)?;
            let buf_qkv_w = self.buf_cached(qkv_weight)?;
            
            if use_mma(total_rows, total_qkv, h) {
                self.encode_mma(cmd1, "matmul_transb_simdgroup", &[qkv_in, &buf_qkv_w, buf_qkv.buffer(), &buf_rows, &buf_qkv_dim, &buf_h], total_rows, total_qkv, h, 1);
            } else {
                Self::encode_matmul(cmd1, &self.pipelines["matmul_transb"], qkv_in, &buf_qkv_w, buf_qkv.buffer(), &buf_rows, &buf_qkv_dim, &buf_h, total_qkv, total_rows);
            }

            if let Some(qkv_bias) = weights.qkv_bias {
                let b_bias = self.buf_cached(qkv_bias)?;
                self.encode_1d(cmd1, "elementwise_add_broadcast", &[buf_qkv.buffer(), &b_bias, &buf_qkv_dim], total_rows * total_qkv);
            }
            
            let split_p = &self.pipelines["split_qkv_packed"];
            let enc = cmd1.new_compute_command_encoder();
            enc.set_compute_pipeline_state(split_p);
            enc.set_buffer(0, Some(buf_qkv.buffer()), 0);
            enc.set_buffer(1, Some(buf_q.buffer()), 0);
            enc.set_buffer(2, Some(buf_k.buffer()), 0);
            enc.set_buffer(3, Some(buf_v.buffer()), 0);
            enc.set_buffer(4, Some(&buf_q_dim), 0);
            enc.set_buffer(5, Some(&buf_kv_dim), 0);
            enc.set_buffer(6, Some(&buf_kv_dim), 0);
            let threads = metal::MTLSize::new(total_qkv as u64, total_rows as u64, 1);
            let tw = split_p.thread_execution_width() as u64;
            let tg = metal::MTLSize::new(tw.min(total_qkv as u64).max(1), 16.min(total_rows as u64).max(1), 1);
            enc.dispatch_threads(threads, tg);
            enc.end_encoding();

            if let Some(q_ln_w) = weights.q_ln_weight {
                let q_ln_w_buf = self.buf_cached(q_ln_w)?;
                let q_ln_b_buf = self.buf_cached(weights.q_ln_bias.unwrap_or(&[]))?;
                self.encode_1d(cmd1, "layer_norm", &[buf_q.buffer(), &q_ln_w_buf, &q_ln_b_buf, &buf_q_dim, &buf_eps], total_rows);
            }
            if let Some(k_ln_w) = weights.k_ln_weight {
                let k_ln_w_buf = self.buf_cached(k_ln_w)?;
                let k_ln_b_buf = self.buf_cached(weights.k_ln_bias.unwrap_or(&[]))?;
                self.encode_1d(cmd1, "layer_norm", &[buf_k.buffer(), &k_ln_w_buf, &k_ln_b_buf, &buf_kv_dim, &buf_eps], total_rows);
            }
            retains1.push(buf_qkv);
        } else {
            let buf_qw = self.buf_cached(weights.q_weight.unwrap())?;
            let buf_kw = self.buf_cached(weights.k_weight.unwrap())?;
            let buf_vw = self.buf_cached(weights.v_weight.unwrap())?;
            if use_mma(total_rows, q_dim, h) {
                self.encode_mma(cmd1, "matmul_transb_simdgroup", &[qkv_in, &buf_qw, buf_q.buffer(), &buf_rows, &buf_q_dim, &buf_h], total_rows, q_dim, h, 1);
            } else {
                Self::encode_matmul(cmd1, &self.pipelines["matmul_transb"], qkv_in, &buf_qw, buf_q.buffer(), &buf_rows, &buf_q_dim, &buf_h, q_dim, total_rows);
            }
            if use_mma(total_rows, kv_dim, h) {
                self.encode_mma(cmd1, "matmul_transb_simdgroup", &[qkv_in, &buf_kw, buf_k.buffer(), &buf_rows, &buf_kv_dim, &buf_h], total_rows, kv_dim, h, 1);
                self.encode_mma(cmd1, "matmul_transb_simdgroup", &[qkv_in, &buf_vw, buf_v.buffer(), &buf_rows, &buf_kv_dim, &buf_h], total_rows, kv_dim, h, 1);
            } else {
                Self::encode_matmul(cmd1, &self.pipelines["matmul_transb"], qkv_in, &buf_kw, buf_k.buffer(), &buf_rows, &buf_kv_dim, &buf_h, kv_dim, total_rows);
                Self::encode_matmul(cmd1, &self.pipelines["matmul_transb"], qkv_in, &buf_vw, buf_v.buffer(), &buf_rows, &buf_kv_dim, &buf_h, kv_dim, total_rows);
            }
            if let Some(q_bias) = weights.q_bias {
                let b = self.buf_cached(q_bias)?;
                self.encode_1d(cmd1, "elementwise_add_broadcast", &[buf_q.buffer(), &b, &buf_q_dim], total_rows * q_dim);
            }
            if let Some(k_bias) = weights.k_bias {
                let b = self.buf_cached(k_bias)?;
                self.encode_1d(cmd1, "elementwise_add_broadcast", &[buf_k.buffer(), &b, &buf_kv_dim], total_rows * kv_dim);
            }
            if let Some(v_bias) = weights.v_bias {
                let b = self.buf_cached(v_bias)?;
                self.encode_1d(cmd1, "elementwise_add_broadcast", &[buf_v.buffer(), &b, &buf_kv_dim], total_rows * kv_dim);
            }
        }
        
        if let Some(b) = buf_normed1 {
            retains1.push(b);
        }
        self.commit_bounded(cmd1, retains1);
        
        // ---------------------------------------------------------
        // Command Buffer 2: RoPE + Fused Attention Posmajor + Attn Out Projection + Add Residual
        // ---------------------------------------------------------
        let cmd2 = self.queue.new_command_buffer();
        let mut retains2 = Vec::new();
        
        // Only apply RoPE if cos/sin are provided
        if !rope_cos.is_empty() {
            let buf_cos = self.buf_cached(rope_cos)?;
            let buf_sin = self.buf_cached(rope_sin)?;
            let buf_max_len = self.buf_u32(max_len as u32)?;
            let buf_head_dim = self.buf_u32(head_dim as u32)?;
            let buf_actual = self.buf_u32(max_len as u32)?;
            
            let rope_p = &self.pipelines["rope_apply_batched"];
            
            // Q RoPE
            {
                let enc = cmd2.new_compute_command_encoder();
                let num_pairs = q_dim / head_dim * (head_dim / 2);
                enc.set_compute_pipeline_state(rope_p);
                enc.set_buffer(0, Some(buf_q.buffer()), 0);
                enc.set_buffer(1, Some(&buf_cos), 0);
                enc.set_buffer(2, Some(&buf_sin), 0);
                enc.set_buffer(3, Some(&buf_max_len), 0);
                enc.set_buffer(4, Some(&buf_head_dim), 0);
                enc.set_buffer(5, Some(&buf_q_dim), 0);
                enc.set_buffer(6, Some(&buf_head_dim), 0);
                enc.set_buffer(7, Some(&buf_actual), 0);
                let threads = metal::MTLSize::new(num_pairs as u64, total_rows as u64, 1);
                let tg = metal::MTLSize::new(16.min(num_pairs) as u64, 16.min(total_rows) as u64, 1);
                enc.dispatch_threads(threads, tg);
                enc.end_encoding();
            }
            
            // K RoPE
            {
                let enc = cmd2.new_compute_command_encoder();
                let num_pairs = kv_dim / head_dim * (head_dim / 2);
                enc.set_compute_pipeline_state(rope_p);
                enc.set_buffer(0, Some(buf_k.buffer()), 0);
                enc.set_buffer(1, Some(&buf_cos), 0);
                enc.set_buffer(2, Some(&buf_sin), 0);
                enc.set_buffer(3, Some(&buf_max_len), 0);
                enc.set_buffer(4, Some(&buf_head_dim), 0);
                enc.set_buffer(5, Some(&buf_kv_dim), 0);
                enc.set_buffer(6, Some(&buf_head_dim), 0);
                enc.set_buffer(7, Some(&buf_actual), 0);
                let threads = metal::MTLSize::new(num_pairs as u64, total_rows as u64, 1);
                let tg = metal::MTLSize::new(16.min(num_pairs) as u64, 16.min(total_rows) as u64, 1);
                enc.dispatch_threads(threads, tg);
                enc.end_encoding();
            }
        }
        
        let buf_q_reshaped = self.pool.acquire_uninit(total_rows * q_dim * 4)?;
        let buf_k_reshaped = self.pool.acquire_uninit(total_rows * q_dim * 4)?;
        let buf_v_reshaped = self.pool.acquire_uninit(total_rows * q_dim * 4)?;
        let buf_heads = self.buf_u32(heads as u32)?;
        let buf_seq = self.buf_u32(max_len as u32)?;
        let buf_head_dim = self.buf_u32(head_dim as u32)?;
        let total_q_heads = batch_size * heads;
        
        if kv_heads == heads {
            self.encode_3d(cmd2, "reshape_qkv_pos_to_head", &[
                buf_q.buffer(), buf_k.buffer(), buf_v.buffer(),
                buf_q_reshaped.buffer(), buf_k_reshaped.buffer(), buf_v_reshaped.buffer(),
                &buf_heads, &buf_seq, &buf_head_dim
            ], head_dim, max_len, total_q_heads);
        } else {
            let buf_kv_heads = self.buf_u32(kv_heads as u32)?;
            let p = &self.pipelines["reshape_qkv_pos_to_head_gqa"];
            let enc = cmd2.new_compute_command_encoder();
            enc.set_compute_pipeline_state(p);
            enc.set_buffer(0, Some(buf_q.buffer()), 0);
            enc.set_buffer(1, Some(buf_k.buffer()), 0);
            enc.set_buffer(2, Some(buf_v.buffer()), 0);
            enc.set_buffer(3, Some(buf_q_reshaped.buffer()), 0);
            enc.set_buffer(4, Some(buf_k_reshaped.buffer()), 0);
            enc.set_buffer(5, Some(buf_v_reshaped.buffer()), 0);
            enc.set_buffer(6, Some(&buf_heads), 0);
            enc.set_buffer(7, Some(&buf_seq), 0);
            enc.set_buffer(8, Some(&buf_head_dim), 0);
            enc.set_buffer(9, Some(&buf_kv_heads), 0);
            
            let threads = metal::MTLSize::new(head_dim as u64, max_len as u64, total_q_heads as u64);
            let tg = metal::MTLSize::new(16.min(head_dim) as u64, 16.min(max_len) as u64, 1);
            enc.dispatch_threads(threads, tg);
            enc.end_encoding();
        }
        
        let buf_scores = self.pool.acquire_uninit(total_q_heads * max_len * max_len * 4)?;
        let buf_scale = self.buf_f32(config.scale)?;
        let buf_masks = self.buf_u32_slice(masks)?;
        let buf_has_alibi = self.buf_u32(0)?;
        let buf_alibi = self.buf_slice_pooled(&[0.0f32])?;
        let buf_out_reshaped = self.pool.acquire_uninit(total_rows * q_dim * 4)?;
        
        let qk_bufs = [
            buf_q_reshaped.buffer(), buf_k_reshaped.buffer(), buf_scores.buffer(), &buf_seq, &buf_head_dim, &self.buf_u32(1)?
        ];
        if use_mma(max_len, max_len, head_dim) {
            self.encode_mma(cmd2, "batched_matmul_transb_simdgroup", &qk_bufs, max_len, max_len, head_dim, total_q_heads);
        } else {
            self.encode_3d(cmd2, "batched_matmul_transb", &qk_bufs, max_len, max_len, total_q_heads);
        }
        
        self.encode_3d(cmd2, "scale_mask_alibi_grouped", &[
            buf_scores.buffer(), buf_alibi.buffer(), &buf_masks, &buf_scale, &buf_seq, &buf_has_alibi, &buf_heads
        ], max_len, max_len, total_q_heads);
        
        self.encode_1d(cmd2, "softmax_rows", &[
            buf_scores.buffer(), &buf_seq
        ], total_q_heads * max_len);
        
        let sv_bufs = [
            buf_scores.buffer(), buf_v_reshaped.buffer(), buf_out_reshaped.buffer(), &buf_seq, &buf_head_dim, &self.buf_u32(1)?
        ];
        if use_mma(max_len, head_dim, max_len) {
            self.encode_mma(cmd2, "batched_matmul_ab_simdgroup", &sv_bufs, max_len, head_dim, max_len, total_q_heads);
        } else {
            self.encode_3d(cmd2, "batched_matmul_ab", &sv_bufs, head_dim, max_len, total_q_heads);
        }
        
        let buf_attn_out = self.pool.acquire_uninit(total_rows * q_dim * 4)?;
        self.encode_3d(cmd2, "reshape_head_to_pos", &[
            buf_out_reshaped.buffer(), buf_attn_out.buffer(), &buf_heads, &buf_seq, &buf_head_dim
        ], head_dim, max_len, total_q_heads);
        
        let buf_proj_out = self.pool.acquire_uninit(total_rows * h * 4)?;
        let buf_out_w = self.buf_cached(weights.attn_out_weight)?;
        
        if use_mma(total_rows, h, q_dim) {
            self.encode_mma(cmd2, "matmul_transb_simdgroup", &[buf_attn_out.buffer(), &buf_out_w, buf_proj_out.buffer(), &buf_rows, &buf_h, &buf_q_dim], total_rows, h, q_dim, 1);
        } else {
            Self::encode_matmul(cmd2, &self.pipelines["matmul_transb"], buf_attn_out.buffer(), &buf_out_w, buf_proj_out.buffer(), &buf_rows, &buf_h, &buf_q_dim, h, total_rows);
        }

        if let Some(attn_out_bias) = weights.attn_out_bias {
            let b = self.buf_cached(attn_out_bias)?;
            self.encode_1d(cmd2, "elementwise_add_broadcast", &[buf_proj_out.buffer(), &b, &buf_h], total_rows * h);
        }
        
        self.encode_1d(cmd2, "elementwise_add", &[current_hidden.buffer(), buf_proj_out.buffer()], total_rows * h);
        
        if !config.pre_ln {
            let buf_norm1_w = self.buf_cached(weights.norm1_weight)?;
            if config.use_rms {
                self.encode_1d(cmd2, "rms_norm", &[current_hidden.buffer(), &buf_norm1_w, &buf_h, &buf_eps], total_rows);
            } else {
                let buf_norm1_b = self.buf_cached(weights.norm1_bias.unwrap_or(&[]))?;
                self.encode_1d(cmd2, "layer_norm", &[current_hidden.buffer(), &buf_norm1_w, &buf_norm1_b, &buf_h, &buf_eps], total_rows);
            }
        }
        
        retains2.push(buf_q);
        retains2.push(buf_k);
        retains2.push(buf_v);
        retains2.push(buf_alibi);
        retains2.push(buf_q_reshaped);
        retains2.push(buf_k_reshaped);
        retains2.push(buf_v_reshaped);
        retains2.push(buf_scores);
        retains2.push(buf_out_reshaped);
        retains2.push(buf_attn_out);
        retains2.push(buf_proj_out);
        self.commit_bounded(cmd2, retains2);
        
        // ---------------------------------------------------------
        // Command Buffer 3: Norm 2 + FFN + Residual
        // ---------------------------------------------------------
        let cmd3 = self.queue.new_command_buffer();
        let mut retains3 = Vec::new();
        
        // Layer norm 2
        let mut buf_normed2 = None;
        if config.pre_ln {
            let buf = self.pool.acquire_uninit(total_rows * h * 4)?;
            {
                let blit = cmd3.new_blit_command_encoder();
                blit.copy_from_buffer(current_hidden.buffer(), 0, buf.buffer(), 0, (total_rows * h * 4) as u64);
                blit.end_encoding();
            }
            let buf_norm2_w = self.buf_cached(weights.norm2_weight)?;
            if config.use_rms {
                self.encode_1d(cmd3, "rms_norm", &[buf.buffer(), &buf_norm2_w, &buf_h, &buf_eps], total_rows);
            } else {
                let buf_norm2_b = self.buf_cached(weights.norm2_bias.unwrap_or(&[]))?;
                self.encode_1d(cmd3, "layer_norm", &[buf.buffer(), &buf_norm2_w, &buf_norm2_b, &buf_h, &buf_eps], total_rows);
            }
            buf_normed2 = Some(buf);
        }
        
        let ffn_in = if let Some(ref b) = buf_normed2 { b.buffer() } else { current_hidden.buffer() };
        let buf_inter = self.buf_u32(inter as u32)?;
        let buf_ffn_out = self.pool.acquire_uninit(total_rows * h * 4)?;
        let buf_wdown = self.buf_cached(weights.ffn_down_weight)?;

        if let Some(gate_weight) = weights.ffn_gate_weight {
            // SwiGLU FFN
            let up_weight = weights.ffn_up_weight.unwrap();
            let buf_wgateup = {
                let key = vec![
                    (gate_weight.as_ptr() as usize, gate_weight.len()),
                    (up_weight.as_ptr() as usize, up_weight.len()),
                ];
                let mut guard = self.concat_cache.lock();
                if let Some(buf) = guard.get(&key) {
                    buf.clone()
                } else {
                    let mut cat = Vec::with_capacity(gate_weight.len() + up_weight.len());
                    for row in 0..h {
                        cat.extend_from_slice(&gate_weight[row * inter..(row + 1) * inter]);
                        cat.extend_from_slice(&up_weight[row * inter..(row + 1) * inter]);
                    }
                    let buf = self.buf_from_slice(&cat)?;
                    guard.insert(key, buf.clone());
                    buf
                }
            };
            
            let buf_gateup = self.pool.acquire_uninit(total_rows * 2 * inter * 4)?;
            let buf_act = self.pool.acquire_uninit(total_rows * inter * 4)?;
            let buf_two_inter = self.buf_u32((2 * inter) as u32)?;
            
            if use_mma(total_rows, inter, h) {
                self.encode_mma(cmd3, "matmul_transb_simdgroup", &[ffn_in, &buf_wgateup, buf_gateup.buffer(), &buf_rows, &buf_two_inter, &buf_h], total_rows, 2 * inter, h, 1);
            } else {
                Self::encode_matmul(cmd3, &self.pipelines["matmul_transb"], ffn_in, &buf_wgateup, buf_gateup.buffer(), &buf_rows, &buf_two_inter, &buf_h, 2 * inter, total_rows);
            }
            
            self.encode_1d(cmd3, "swiglu_activation_fat", &[buf_gateup.buffer(), buf_act.buffer(), &buf_inter], total_rows * inter);
            
            if use_mma(total_rows, h, inter) {
                self.encode_mma(cmd3, "matmul_transb_simdgroup", &[buf_act.buffer(), &buf_wdown, buf_ffn_out.buffer(), &buf_rows, &buf_h, &buf_inter], total_rows, h, inter, 1);
            } else {
                Self::encode_matmul(cmd3, &self.pipelines["matmul_transb"], buf_act.buffer(), &buf_wdown, buf_ffn_out.buffer(), &buf_rows, &buf_h, &buf_inter, h, total_rows);
            }
            
            retains3.push(buf_gateup);
            retains3.push(buf_act);
        } else {
            // Standard GELU FFN
            let up_weight = weights.ffn_up_weight.unwrap();
            let buf_wup = self.buf_cached(up_weight)?;
            let buf_up = self.pool.acquire_uninit(total_rows * inter * 4)?;
            
            if use_mma(total_rows, inter, h) {
                self.encode_mma(cmd3, "matmul_transb_simdgroup", &[ffn_in, &buf_wup, buf_up.buffer(), &buf_rows, &buf_inter, &buf_h], total_rows, inter, h, 1);
            } else {
                Self::encode_matmul(cmd3, &self.pipelines["matmul_transb"], ffn_in, &buf_wup, buf_up.buffer(), &buf_rows, &buf_inter, &buf_h, inter, total_rows);
            }
            
            if let Some(up_bias) = weights.ffn_up_bias {
                let b = self.buf_cached(up_bias)?;
                self.encode_1d(cmd3, "elementwise_add_broadcast", &[buf_up.buffer(), &b, &buf_inter], total_rows * inter);
            }
            
            self.encode_1d(cmd3, "gelu_activation", &[buf_up.buffer()], total_rows * inter);
            
            if use_mma(total_rows, h, inter) {
                self.encode_mma(cmd3, "matmul_transb_simdgroup", &[buf_up.buffer(), &buf_wdown, buf_ffn_out.buffer(), &buf_rows, &buf_h, &buf_inter], total_rows, h, inter, 1);
            } else {
                Self::encode_matmul(cmd3, &self.pipelines["matmul_transb"], buf_up.buffer(), &buf_wdown, buf_ffn_out.buffer(), &buf_rows, &buf_h, &buf_inter, h, total_rows);
            }
            retains3.push(buf_up);
        }
        
        if let Some(down_bias) = weights.ffn_down_bias {
            let b = self.buf_cached(down_bias)?;
            self.encode_1d(cmd3, "elementwise_add_broadcast", &[buf_ffn_out.buffer(), &b, &buf_h], total_rows * h);
        }
        
        self.encode_1d(cmd3, "elementwise_add", &[current_hidden.buffer(), buf_ffn_out.buffer()], total_rows * h);
        
        if !config.pre_ln {
            let buf_norm2_w = self.buf_cached(weights.norm2_weight)?;
            if config.use_rms {
                self.encode_1d(cmd3, "rms_norm", &[current_hidden.buffer(), &buf_norm2_w, &buf_h, &buf_eps], total_rows);
            } else {
                let buf_norm2_b = self.buf_cached(weights.norm2_bias.unwrap_or(&[]))?;
                self.encode_1d(cmd3, "layer_norm", &[current_hidden.buffer(), &buf_norm2_w, &buf_norm2_b, &buf_h, &buf_eps], total_rows);
            }
        }
        
        if let Some(b) = buf_normed2 {
            retains3.push(b);
        }
        retains3.push(buf_ffn_out);
        
        self.commit_wait(&cmd3);
        
            let out = Self::read_buf(current_hidden.buffer(), total_rows * h);
            Ok(Some(out))
        })
    }
    fn matmul(&self, a: &[f32], b: &[f32], m: usize, n: usize, k: usize) -> Result<Vec<f32>, InferError> {
        let _span = tracing::info_span!("kin_infer.metal.matmul", m = m, n = n, k = k).entered();
        let buf_a = self.buf_slice_pooled(a)?;
        // Cache B (weight matrix): stable pointers across forward passes
        let buf_b = self.buf_cached(b)?;
        let buf_c = self.buf_zeros_pooled(m * n)?;
        let buf_m = self.buf_u32(m as u32)?;
        let buf_n = self.buf_u32(n as u32)?;
        let buf_k = self.buf_u32(k as u32)?;

        let bufs = [
            buf_a.buffer(),
            &buf_b,
            buf_c.buffer(),
            &buf_m,
            &buf_n,
            &buf_k,
        ];
        time_phase(Phase::Matmul, || {
            if use_mma(m, n, k) {
                self.dispatch_mma("matmul_transb_simdgroup", &bufs, m, n, k, 1);
            } else {
                self.dispatch_2d("matmul_transb", &bufs, n, m);
            }
        });

        let out = Self::read_buf(buf_c.buffer(), m * n);
        Self::count_nonfinite(&format!("matmul m={m} n={n} k={k}"), &out);
        Ok(out)
    }

    fn matmul_many(
        &self,
        a: &[f32],
        weights: &[&[f32]],
        m: usize,
        ns: &[usize],
        k: usize,
    ) -> Result<Vec<Vec<f32>>, InferError> {
        let _span = tracing::info_span!(
            "kin_infer.metal.matmul_many",
            m = m,
            k = k,
            outputs = weights.len()
        )
        .entered();
        if weights.is_empty() {
            return Ok(Vec::new());
        }

        // Fat GEMM: concatenate the weights row-major into one [sum_n, k] matrix
        // and run a SINGLE matmul producing [m, sum_n], then slice the output
        // columns back per weight. Column slices are independent outputs, so this
        // is numerically identical to the per-weight matmuls (no reassociation),
        // but it fills the GPU with one wide dispatch instead of several thin
        // ones. The concatenation is cached on the device by component pointers.
        let total_n: usize = ns.iter().sum();
        let buf_a = self.buf_slice_pooled(a)?;
        let buf_b = self.buf_cached_concat(weights)?;
        let buf_c = self.buf_zeros_pooled(m * total_n)?;
        let buf_m = self.buf_u32(m as u32)?;
        let buf_n = self.buf_u32(total_n as u32)?;
        let buf_k = self.buf_u32(k as u32)?;

        let bufs = [
            buf_a.buffer(),
            &buf_b,
            buf_c.buffer(),
            &buf_m,
            &buf_n,
            &buf_k,
        ];
        time_phase(Phase::Matmul, || {
            if use_mma(m, total_n, k) {
                self.dispatch_mma("matmul_transb_simdgroup", &bufs, m, total_n, k, 1);
            } else {
                self.dispatch_2d("matmul_transb", &bufs, total_n, m);
            }
        });

        let fat = Self::read_buf(buf_c.buffer(), m * total_n);
        let mut outputs = Vec::with_capacity(weights.len());
        let mut col_off = 0usize;
        for &n in ns {
            let mut out = Vec::with_capacity(m * n);
            for row in 0..m {
                let base = row * total_n + col_off;
                out.extend_from_slice(&fat[base..base + n]);
            }
            Self::count_nonfinite(&format!("matmul_many m={m} n={n} k={k}"), &out);
            outputs.push(out);
            col_off += n;
        }
        Ok(outputs)
    }

    fn batched_matmul(
        &self,
        q: &[f32],
        k: &[f32],
        num_heads: usize,
        seq_len: usize,
        head_dim: usize,
    ) -> Result<Vec<f32>, InferError> {
        let _span = tracing::info_span!(
            "kin_infer.metal.batched_matmul",
            num_heads = num_heads,
            seq_len = seq_len,
            head_dim = head_dim
        )
        .entered();
        // Single 3D dispatch: all heads computed in one GPU submission.
        let buf_q = self.buf_slice_pooled(q)?;
        let buf_k = self.buf_slice_pooled(k)?;
        let buf_c = self.buf_zeros_pooled(num_heads * seq_len * seq_len)?;
        let buf_seq = self.buf_u32(seq_len as u32)?;
        let buf_dim = self.buf_u32(head_dim as u32)?;

        let buf_hpg = self.buf_u32(1)?;

        // QK^T: m=seq, n=seq, k=head_dim.
        let bufs = [
            buf_q.buffer(),
            buf_k.buffer(),
            buf_c.buffer(),
            &buf_seq,
            &buf_dim,
            &buf_hpg,
        ];
        time_phase(Phase::Attention, || {
            if use_mma(seq_len, seq_len, head_dim) {
                self.dispatch_mma(
                    "batched_matmul_transb_simdgroup",
                    &bufs,
                    seq_len,
                    seq_len,
                    head_dim,
                    num_heads,
                );
            } else {
                self.dispatch_3d("batched_matmul_transb", &bufs, seq_len, seq_len, num_heads);
            }
        });

        Ok(Self::read_buf(buf_c.buffer(), num_heads * seq_len * seq_len))
    }

    fn batched_attn_values(
        &self,
        scores: &[f32],
        v: &[f32],
        num_heads: usize,
        seq_len: usize,
        head_dim: usize,
    ) -> Result<Vec<f32>, InferError> {
        let _span = tracing::info_span!(
            "kin_infer.metal.batched_attn_values",
            num_heads = num_heads,
            seq_len = seq_len,
            head_dim = head_dim
        )
        .entered();
        // Single 3D dispatch: scores[h] × V[h] for all heads.
        let buf_s = self.buf_slice_pooled(scores)?;
        let buf_v = self.buf_slice_pooled(v)?;
        let buf_c = self.buf_zeros_pooled(num_heads * seq_len * head_dim)?;
        let buf_seq = self.buf_u32(seq_len as u32)?;
        let buf_dim = self.buf_u32(head_dim as u32)?;
        let buf_hpg = self.buf_u32(1)?;

        // scores*V: m=seq, n=head_dim, k=seq.
        let bufs = [
            buf_s.buffer(),
            buf_v.buffer(),
            buf_c.buffer(),
            &buf_seq,
            &buf_dim,
            &buf_hpg,
        ];
        time_phase(Phase::Attention, || {
            if use_mma(seq_len, head_dim, seq_len) {
                self.dispatch_mma(
                    "batched_matmul_ab_simdgroup",
                    &bufs,
                    seq_len,
                    head_dim,
                    seq_len,
                    num_heads,
                );
            } else {
                self.dispatch_3d("batched_matmul_ab", &bufs, head_dim, seq_len, num_heads);
            }
        });

        Ok(Self::read_buf(buf_c.buffer(), num_heads * seq_len * head_dim))
    }

    fn softmax(&self, data: &mut [f32], rows: usize, cols: usize) -> Result<(), InferError> {
        let _span =
            tracing::info_span!("kin_infer.metal.softmax", rows = rows, cols = cols).entered();
        Self::count_nonfinite(&format!("softmax_in rows={rows} cols={cols}"), data);
        let buf = self.buf_slice_pooled(data)?;
        let buf_cols = self.buf_u32(cols as u32)?;
        time_phase(Phase::Norm, || {
            self.dispatch_1d("softmax_rows", &[buf.buffer(), &buf_cols], rows)
        });
        Self::read_buf_into(buf.buffer(), data);
        Self::count_nonfinite(&format!("softmax_out rows={rows} cols={cols}"), data);
        Ok(())
    }

    fn layer_norm(
        &self,
        data: &mut [f32],
        gamma: &[f32],
        beta: &[f32],
        rows: usize,
        cols: usize,
        eps: f32,
    ) -> Result<(), InferError> {
        let _span = tracing::info_span!(
            "kin_infer.metal.layer_norm",
            rows = rows,
            cols = cols,
            eps = eps
        )
        .entered();
        let buf = self.buf_slice_pooled(data)?;
        let buf_gamma = self.buf_cached(gamma)?;
        let buf_beta = self.buf_cached(beta)?;
        let buf_cols = self.buf_u32(cols as u32)?;
        let buf_eps = self.buf_f32(eps)?;
        time_phase(Phase::Norm, || {
            self.dispatch_1d(
                "layer_norm",
                &[buf.buffer(), &buf_gamma, &buf_beta, &buf_cols, &buf_eps],
                rows,
            )
        });
        Self::read_buf_into(buf.buffer(), data);
        Self::count_nonfinite(&format!("layer_norm rows={rows} cols={cols}"), data);
        Ok(())
    }

    fn rms_norm(&self, data: &mut [f32], weight: &[f32], rows: usize, cols: usize, eps: f32) -> Result<(), InferError> {
        let _span = tracing::info_span!(
            "kin_infer.metal.rms_norm",
            rows = rows,
            cols = cols,
            eps = eps
        )
        .entered();
        let buf = self.buf_slice_pooled(data)?;
        let buf_weight = self.buf_cached(weight)?;
        let buf_cols = self.buf_u32(cols as u32)?;
        let buf_eps = self.buf_f32(eps)?;
        time_phase(Phase::Norm, || {
            self.dispatch_1d("rms_norm", &[buf.buffer(), &buf_weight, &buf_cols, &buf_eps], rows)
        });
        Self::read_buf_into(buf.buffer(), data);
        Ok(())
    }

    fn gelu(&self, data: &mut [f32]) -> Result<(), InferError> {
        let _span = tracing::info_span!("kin_infer.metal.gelu", len = data.len()).entered();
        Self::count_nonfinite(&format!("gelu_in len={}", data.len()), data);
        let buf = self.buf_slice_pooled(data)?;
        time_phase(Phase::Activation, || {
            self.dispatch_1d("gelu_activation", &[buf.buffer()], data.len())
        });
        Self::read_buf_into(buf.buffer(), data);
        Self::count_nonfinite(&format!("gelu_out len={}", data.len()), data);
        Ok(())
    }

    fn silu(&self, data: &mut [f32]) -> Result<(), InferError> {
        let _span = tracing::info_span!("kin_infer.metal.silu", len = data.len()).entered();
        let buf = self.buf_slice_pooled(data)?;
        time_phase(Phase::Activation, || {
            self.dispatch_1d("silu_activation", &[buf.buffer()], data.len())
        });
        Self::read_buf_into(buf.buffer(), data);
        Ok(())
    }

    fn elementwise_mul(&self, a: &mut [f32], b: &[f32]) -> Result<(), InferError> {
        let _span = tracing::info_span!("kin_infer.metal.elementwise_mul", len = a.len()).entered();
        let buf_a = self.buf_slice_pooled(a)?;
        let buf_b = self.buf_slice_pooled(b)?;
        time_phase(Phase::Activation, || {
            self.dispatch_1d("elementwise_mul", &[buf_a.buffer(), buf_b.buffer()], a.len())
        });
        Self::read_buf_into(buf_a.buffer(), a);
        Ok(())
    }

    fn fused_ffn_swiglu(
        &self,
        x: &[f32],
        w_gate: &[f32],
        w_up: &[f32],
        w_down: &[f32],
        rows: usize,
        hidden: usize,
        inter: usize,
    ) -> Result<Vec<f32>, InferError> {
        let _span = tracing::info_span!(
            "kin_infer.metal.fused_ffn_swiglu",
            rows = rows,
            hidden = hidden,
            inter = inter
        )
        .entered();

        // Inputs/weights uploaded once; weights hit the persistent cache. Gate
        // and up are folded into one [rows, 2*inter] fat GEMM (cached concat of
        // w_gate|w_up), then a strided swiglu reads both halves. The
        // gate-up/activated/down intermediates are pooled transients that stay
        // resident across the chain and recycle after the readback below.
        let buf_x = self.buf_slice_pooled(x)?;
        let buf_wgateup = self.buf_cached_concat(&[w_gate, w_up])?;
        let buf_wdown = self.buf_cached(w_down)?;
        let buf_gateup = self.buf_zeros_pooled(rows * 2 * inter)?;
        let buf_act = self.buf_zeros_pooled(rows * inter)?;
        let buf_out = self.buf_zeros_pooled(rows * hidden)?;
        let buf_rows = self.buf_u32(rows as u32)?;
        let buf_inter = self.buf_u32(inter as u32)?;
        let buf_two_inter = self.buf_u32((2 * inter) as u32)?;
        let buf_hidden = self.buf_u32(hidden as u32)?;

        let mm = &self.pipelines["matmul_transb"];
        let mm_mma = "matmul_transb_simdgroup";
        let swi = &self.pipelines["swiglu_activation_fat"];
        let gateup_mma = use_mma(rows, 2 * inter, hidden);
        let down_mma = use_mma(rows, hidden, inter);

        // All ops in one command buffer inside an autorelease pool: the buffer
        // plus its encoders are autoreleased (+0); on a pool-less worker thread
        // (tokio spawn_blocking) they would otherwise pile up across every layer
        // of every batch. The pooled input/output buffers recycle on Rust drop
        // after the synchronous readback; the autorelease pool only drains the
        // ObjC command-buffer/encoder temporaries.
        let out = autoreleasepool(|_| {
            let cmd = self.queue.new_command_buffer();

            // gateup = x @ [w_gate|w_up]^T -> [rows, 2*inter]  (M=rows, N=2*inter, K=hidden)
            if gateup_mma {
                self.encode_mma(cmd, mm_mma, &[buf_x.buffer(), &buf_wgateup, buf_gateup.buffer(), &buf_rows, &buf_two_inter, &buf_hidden], rows, 2 * inter, hidden, 1);
            } else {
                Self::encode_matmul(cmd, mm, buf_x.buffer(), &buf_wgateup, buf_gateup.buffer(), &buf_rows, &buf_two_inter, &buf_hidden, 2 * inter, rows);
            }

            // act = silu(gate) * up -> [rows, inter], reading the interleaved fat buffer
            {
                let enc = cmd.new_compute_command_encoder();
                enc.set_compute_pipeline_state(swi);
                enc.set_buffer(0, Some(buf_gateup.buffer()), 0);
                enc.set_buffer(1, Some(buf_act.buffer()), 0);
                enc.set_buffer(2, Some(&buf_inter), 0);
                let total = (rows * inter) as u64;
                let tw = swi.thread_execution_width() as u64;
                enc.dispatch_threads(MTLSize::new(total, 1, 1), MTLSize::new(tw.min(total).max(1), 1, 1));
                enc.end_encoding();
            }

            // out = act @ w_down^T -> [rows, hidden]  (M=rows, N=hidden, K=inter)
            if down_mma {
                self.encode_mma(cmd, mm_mma, &[buf_act.buffer(), &buf_wdown, buf_out.buffer(), &buf_rows, &buf_hidden, &buf_inter], rows, hidden, inter, 1);
            } else {
                Self::encode_matmul(cmd, mm, buf_act.buffer(), &buf_wdown, buf_out.buffer(), &buf_rows, &buf_hidden, &buf_inter, hidden, rows);
            }

            time_phase(Phase::Matmul, || {
                self.commit_wait(cmd);
            });
            Self::read_buf(buf_out.buffer(), rows * hidden)
        });
        Self::count_nonfinite(&format!("fused_ffn_swiglu rows={rows} hidden={hidden} inter={inter}"), &out);
        Ok(out)
    }

    fn fused_ffn_swiglu_add_norm(
        &self,
        x: &[f32],
        w_gate: &[f32],
        w_up: &[f32],
        w_down: &[f32],
        residual: &[f32],
        gamma: &[f32],
        beta: &[f32],
        rows: usize,
        hidden: usize,
        inter: usize,
        eps: f32,
    ) -> Result<Vec<f32>, InferError> {
        let _span = tracing::info_span!(
            "kin_infer.metal.fused_ffn_swiglu_add_norm",
            rows = rows,
            hidden = hidden,
            inter = inter
        )
        .entered();

        // Identical to `fused_ffn_swiglu` up to the down-projection, then the
        // residual add and LayerNorm are appended to the SAME command buffer so
        // the FFN output never round-trips to host memory un-normed — the post-LN
        // norm2 boundary folds into the FFN's existing single submission.
        let buf_x = self.buf_slice_pooled(x)?;
        let buf_wgateup = self.buf_cached_concat(&[w_gate, w_up])?;
        let buf_wdown = self.buf_cached(w_down)?;
        let buf_residual = self.buf_slice_pooled(residual)?;
        let buf_gateup = self.buf_zeros_pooled(rows * 2 * inter)?;
        let buf_act = self.buf_zeros_pooled(rows * inter)?;
        let buf_out = self.buf_zeros_pooled(rows * hidden)?;
        let buf_gamma = self.buf_cached(gamma)?;
        let buf_beta = self.buf_cached(beta)?;
        let buf_rows = self.buf_u32(rows as u32)?;
        let buf_inter = self.buf_u32(inter as u32)?;
        let buf_two_inter = self.buf_u32((2 * inter) as u32)?;
        let buf_hidden = self.buf_u32(hidden as u32)?;
        let buf_eps = self.buf_f32(eps)?;

        let mm = &self.pipelines["matmul_transb"];
        let mm_mma = "matmul_transb_simdgroup";
        let swi = &self.pipelines["swiglu_activation_fat"];
        let add = &self.pipelines["elementwise_add"];
        let ln = &self.pipelines["layer_norm"];
        let gateup_mma = use_mma(rows, 2 * inter, hidden);
        let down_mma = use_mma(rows, hidden, inter);

        let out = autoreleasepool(|_| {
            let cmd = self.queue.new_command_buffer();

            // gateup = x @ [w_gate|w_up]^T -> [rows, 2*inter]
            if gateup_mma {
                self.encode_mma(cmd, mm_mma, &[buf_x.buffer(), &buf_wgateup, buf_gateup.buffer(), &buf_rows, &buf_two_inter, &buf_hidden], rows, 2 * inter, hidden, 1);
            } else {
                Self::encode_matmul(cmd, mm, buf_x.buffer(), &buf_wgateup, buf_gateup.buffer(), &buf_rows, &buf_two_inter, &buf_hidden, 2 * inter, rows);
            }

            // act = silu(gate) * up -> [rows, inter]
            {
                let enc = cmd.new_compute_command_encoder();
                enc.set_compute_pipeline_state(swi);
                enc.set_buffer(0, Some(buf_gateup.buffer()), 0);
                enc.set_buffer(1, Some(buf_act.buffer()), 0);
                enc.set_buffer(2, Some(&buf_inter), 0);
                let total = (rows * inter) as u64;
                let tw = swi.thread_execution_width() as u64;
                enc.dispatch_threads(MTLSize::new(total, 1, 1), MTLSize::new(tw.min(total).max(1), 1, 1));
                enc.end_encoding();
            }

            // out = act @ w_down^T -> [rows, hidden]
            if down_mma {
                self.encode_mma(cmd, mm_mma, &[buf_act.buffer(), &buf_wdown, buf_out.buffer(), &buf_rows, &buf_hidden, &buf_inter], rows, hidden, inter, 1);
            } else {
                Self::encode_matmul(cmd, mm, buf_act.buffer(), &buf_wdown, buf_out.buffer(), &buf_rows, &buf_hidden, &buf_inter, hidden, rows);
            }

            // out += residual (resident)
            {
                let enc = cmd.new_compute_command_encoder();
                enc.set_compute_pipeline_state(add);
                enc.set_buffer(0, Some(buf_out.buffer()), 0);
                enc.set_buffer(1, Some(buf_residual.buffer()), 0);
                let total = (rows * hidden) as u64;
                let tw = add.thread_execution_width() as u64;
                enc.dispatch_threads(MTLSize::new(total, 1, 1), MTLSize::new(tw.min(total).max(1), 1, 1));
                enc.end_encoding();
            }

            // out = layer_norm(out, gamma, beta, eps) (in-place)
            {
                let enc = cmd.new_compute_command_encoder();
                enc.set_compute_pipeline_state(ln);
                enc.set_buffer(0, Some(buf_out.buffer()), 0);
                enc.set_buffer(1, Some(&buf_gamma), 0);
                enc.set_buffer(2, Some(&buf_beta), 0);
                enc.set_buffer(3, Some(&buf_hidden), 0);
                enc.set_buffer(4, Some(&buf_eps), 0);
                let tw = ln.thread_execution_width() as u64;
                let rows_u = rows as u64;
                enc.dispatch_threads(MTLSize::new(rows_u, 1, 1), MTLSize::new(tw.min(rows_u).max(1), 1, 1));
                enc.end_encoding();
            }

            time_phase(Phase::Matmul, || {
                self.commit_wait(cmd);
            });
            Self::read_buf(buf_out.buffer(), rows * hidden)
        });
        Self::count_nonfinite(&format!("fused_ffn_swiglu_add_norm rows={rows} hidden={hidden} inter={inter}"), &out);
        Ok(out)
    }

    fn fused_linear_add_norm(
        &self,
        x: &[f32],
        weight: &[f32],
        residual: &[f32],
        gamma: &[f32],
        beta: &[f32],
        rows: usize,
        cols: usize,
        hidden: usize,
        eps: f32,
    ) -> Result<Vec<f32>, InferError> {
        let _span = tracing::info_span!(
            "kin_infer.metal.fused_linear_add_norm",
            rows = rows,
            cols = cols,
            hidden = hidden
        )
        .entered();

        // x uploaded once; weight/gamma/beta hit the persistent cache. The
        // projection output stays resident, the residual is added on-device, and
        // the LayerNorm runs in-place on the same buffer — one command buffer, one
        // readback. The proj buffer is a pooled transient that recycles after the
        // readback below.
        let buf_x = self.buf_slice_pooled(x)?;
        let buf_w = self.buf_cached(weight)?;
        let buf_residual = self.buf_slice_pooled(residual)?;
        let buf_proj = self.buf_zeros_pooled(rows * hidden)?;
        let buf_gamma = self.buf_cached(gamma)?;
        let buf_beta = self.buf_cached(beta)?;
        let buf_rows = self.buf_u32(rows as u32)?;
        let buf_hidden = self.buf_u32(hidden as u32)?;
        let buf_cols = self.buf_u32(cols as u32)?;
        let buf_eps = self.buf_f32(eps)?;

        let mm = &self.pipelines["matmul_transb"];
        let mm_mma = "matmul_transb_simdgroup";
        let add = &self.pipelines["elementwise_add"];
        let ln = &self.pipelines["layer_norm"];
        let proj_mma = use_mma(rows, hidden, cols);

        let out = autoreleasepool(|_| {
            let cmd = self.queue.new_command_buffer();

            // proj = x @ weight^T -> [rows, hidden]  (M=rows, N=hidden, K=cols)
            if proj_mma {
                self.encode_mma(cmd, mm_mma, &[buf_x.buffer(), &buf_w, buf_proj.buffer(), &buf_rows, &buf_hidden, &buf_cols], rows, hidden, cols, 1);
            } else {
                Self::encode_matmul(cmd, mm, buf_x.buffer(), &buf_w, buf_proj.buffer(), &buf_rows, &buf_hidden, &buf_cols, hidden, rows);
            }

            // proj += residual (in-place on the resident projection buffer)
            {
                let enc = cmd.new_compute_command_encoder();
                enc.set_compute_pipeline_state(add);
                enc.set_buffer(0, Some(buf_proj.buffer()), 0);
                enc.set_buffer(1, Some(buf_residual.buffer()), 0);
                let total = (rows * hidden) as u64;
                let tw = add.thread_execution_width() as u64;
                enc.dispatch_threads(MTLSize::new(total, 1, 1), MTLSize::new(tw.min(total).max(1), 1, 1));
                enc.end_encoding();
            }

            // out = layer_norm(proj, gamma, beta, eps) (in-place)
            {
                let enc = cmd.new_compute_command_encoder();
                enc.set_compute_pipeline_state(ln);
                enc.set_buffer(0, Some(buf_proj.buffer()), 0);
                enc.set_buffer(1, Some(&buf_gamma), 0);
                enc.set_buffer(2, Some(&buf_beta), 0);
                enc.set_buffer(3, Some(&buf_hidden), 0);
                enc.set_buffer(4, Some(&buf_eps), 0);
                let tw = ln.thread_execution_width() as u64;
                let rows_u = rows as u64;
                enc.dispatch_threads(MTLSize::new(rows_u, 1, 1), MTLSize::new(tw.min(rows_u).max(1), 1, 1));
                enc.end_encoding();
            }

            time_phase(Phase::Matmul, || {
                self.commit_wait(cmd);
            });
            Self::read_buf(buf_proj.buffer(), rows * hidden)
        });
        Self::count_nonfinite(&format!("fused_linear_add_norm rows={rows} hidden={hidden}"), &out);
        Ok(out)
    }

    fn rope(
        &self,
        data: &mut [f32],
        cos_table: &[f32],
        sin_table: &[f32],
        seq_offset: usize,
        seq_len: usize,
        head_dim: usize,
        total_dim: usize,
    ) -> Result<(), InferError> {
        let _span = tracing::info_span!(
            "kin_infer.metal.rope",
            seq_offset = seq_offset,
            seq_len = seq_len,
            head_dim = head_dim,
            total_dim = total_dim
        )
        .entered();
        let half = head_dim / 2;
        let num_pairs = total_dim / head_dim * half;

        let buf = self.buf_slice_pooled(data)?;
        let buf_cos = self.buf_slice_pooled(cos_table)?;
        let buf_sin = self.buf_slice_pooled(sin_table)?;
        let buf_offset = self.buf_u32(seq_offset as u32)?;
        let buf_head_dim = self.buf_u32(head_dim as u32)?;
        let buf_total_dim = self.buf_u32(total_dim as u32)?;
        let buf_half = self.buf_u32(half as u32)?;

        time_phase(Phase::Activation, || {
            self.dispatch_2d(
                "rope_apply",
                &[
                    buf.buffer(),
                    buf_cos.buffer(),
                    buf_sin.buffer(),
                    &buf_offset,
                    &buf_head_dim,
                    &buf_total_dim,
                    &buf_half,
                ],
                num_pairs,
                seq_len,
            )
        });
        Self::read_buf_into(buf.buffer(), data);
        Ok(())
    }

    fn rope_pair(
        &self,
        q: &mut [f32],
        k: &mut [f32],
        cos_table: &[f32],
        sin_table: &[f32],
        seq_offset: usize,
        seq_len: usize,
        head_dim: usize,
        total_dim: usize,
    ) -> Result<(), InferError> {
        let _span = tracing::info_span!(
            "kin_infer.metal.rope_pair",
            seq_offset = seq_offset,
            seq_len = seq_len,
            head_dim = head_dim,
            total_dim = total_dim
        )
        .entered();
        let half = head_dim / 2;
        let num_pairs = total_dim / head_dim * half;

        // Shared scalar + table buffers; Q and K differ only in the data buffer.
        let buf_q = self.buf_slice_pooled(q)?;
        let buf_k = self.buf_slice_pooled(k)?;
        let buf_cos = self.buf_slice_pooled(cos_table)?;
        let buf_sin = self.buf_slice_pooled(sin_table)?;
        let buf_offset = self.buf_u32(seq_offset as u32)?;
        let buf_head_dim = self.buf_u32(head_dim as u32)?;
        let buf_total_dim = self.buf_u32(total_dim as u32)?;
        let buf_half = self.buf_u32(half as u32)?;

        let pipeline = &self.pipelines["rope_apply"];
        autoreleasepool(|_| {
            let cmd = self.queue.new_command_buffer();
            for data_buf in [buf_q.buffer(), buf_k.buffer()] {
                let enc = cmd.new_compute_command_encoder();
                enc.set_compute_pipeline_state(pipeline);
                enc.set_buffer(0, Some(data_buf), 0);
                enc.set_buffer(1, Some(buf_cos.buffer()), 0);
                enc.set_buffer(2, Some(buf_sin.buffer()), 0);
                enc.set_buffer(3, Some(&buf_offset), 0);
                enc.set_buffer(4, Some(&buf_head_dim), 0);
                enc.set_buffer(5, Some(&buf_total_dim), 0);
                enc.set_buffer(6, Some(&buf_half), 0);
                let threads = MTLSize::new(num_pairs as u64, seq_len as u64, 1);
                let tg = MTLSize::new(16.min(num_pairs) as u64, 16.min(seq_len) as u64, 1);
                enc.dispatch_threads(threads, tg);
                enc.end_encoding();
            }
            time_phase(Phase::Activation, || {
                self.commit_wait(cmd);
            });
        });
        Self::read_buf_into(buf_q.buffer(), q);
        Self::read_buf_into(buf_k.buffer(), k);
        Ok(())
    }

    fn rope_pair_batched(
        &self,
        q: &mut [f32],
        k: &mut [f32],
        cos_table: &[f32],
        sin_table: &[f32],
        batch_size: usize,
        max_len: usize,
        actual: usize,
        head_dim: usize,
        total_dim: usize,
    ) -> Result<(), InferError> {
        let _span = tracing::info_span!(
            "kin_infer.metal.rope_pair_batched",
            batch_size = batch_size,
            max_len = max_len,
            actual = actual,
            head_dim = head_dim,
            total_dim = total_dim
        )
        .entered();
        let half = head_dim / 2;
        let num_pairs = total_dim / head_dim * half;
        let total_rows = batch_size * max_len;

        // Whole-batch Q and K in one submission: the position resets per `max_len`
        // inside the kernel (row % max_len), so all inputs' RoPE is one dispatch
        // each for Q and K instead of one per input.
        let buf_q = self.buf_slice_pooled(q)?;
        let buf_k = self.buf_slice_pooled(k)?;
        let buf_cos = self.buf_slice_pooled(cos_table)?;
        let buf_sin = self.buf_slice_pooled(sin_table)?;
        let buf_max_len = self.buf_u32(max_len as u32)?;
        let buf_head_dim = self.buf_u32(head_dim as u32)?;
        let buf_total_dim = self.buf_u32(total_dim as u32)?;
        let buf_half = self.buf_u32(half as u32)?;
        let buf_actual = self.buf_u32(actual as u32)?;

        let pipeline = &self.pipelines["rope_apply_batched"];
        autoreleasepool(|_| {
            let cmd = self.queue.new_command_buffer();
            for data_buf in [buf_q.buffer(), buf_k.buffer()] {
                let enc = cmd.new_compute_command_encoder();
                enc.set_compute_pipeline_state(pipeline);
                enc.set_buffer(0, Some(data_buf), 0);
                enc.set_buffer(1, Some(buf_cos.buffer()), 0);
                enc.set_buffer(2, Some(buf_sin.buffer()), 0);
                enc.set_buffer(3, Some(&buf_max_len), 0);
                enc.set_buffer(4, Some(&buf_head_dim), 0);
                enc.set_buffer(5, Some(&buf_total_dim), 0);
                enc.set_buffer(6, Some(&buf_half), 0);
                enc.set_buffer(7, Some(&buf_actual), 0);
                let threads = MTLSize::new(num_pairs as u64, total_rows as u64, 1);
                let tg = MTLSize::new(16.min(num_pairs) as u64, 16.min(total_rows) as u64, 1);
                enc.dispatch_threads(threads, tg);
                enc.end_encoding();
            }
            time_phase(Phase::Activation, || {
                self.commit_wait(cmd);
            });
        });
        Self::read_buf_into(buf_q.buffer(), q);
        Self::read_buf_into(buf_k.buffer(), k);
        Ok(())
    }

    fn fused_attention(
        &self,
        q: &[f32],
        k: &[f32],
        v: &[f32],
        num_heads: usize,
        seq_len: usize,
        head_dim: usize,
        scale: f32,
        alibi_slopes: &[f32],
        mask: &[u32],
    ) -> Result<Vec<f32>, InferError> {
        let _span = tracing::info_span!(
            "kin_infer.metal.fused_attention",
            num_heads = num_heads,
            seq_len = seq_len,
            head_dim = head_dim,
            has_alibi = !alibi_slopes.is_empty()
        )
        .entered();
        // All 4 ops in ONE command buffer — 1 commit+wait instead of 4.
        let buf_q = self.buf_slice_pooled(q)?;
        let buf_k = self.buf_slice_pooled(k)?;
        let buf_v = self.buf_slice_pooled(v)?;
        let buf_scores = self.buf_zeros_pooled(num_heads * seq_len * seq_len)?;
        let buf_out = self.buf_zeros_pooled(num_heads * seq_len * head_dim)?;
        let buf_seq = self.buf_u32(seq_len as u32)?;
        let buf_dim = self.buf_u32(head_dim as u32)?;
        let buf_scale = self.buf_f32(scale)?;
        let has_alibi = !alibi_slopes.is_empty();
        let alibi_ref = if has_alibi { alibi_slopes } else { &[0.0f32] };
        let pooled_alibi = self.buf_slice_pooled(alibi_ref)?;
        let mask_u32: Vec<u32> = mask.to_vec();
        let buf_mask = self.buf_u32_slice(&mask_u32)?;
        let buf_has_alibi = self.buf_u32(has_alibi as u32)?;

        // All four ops + commit + readback inside one autorelease pool: the
        // command buffer and its encoders are autoreleased (+0) and would
        // otherwise accumulate on a pool-less worker thread across every layer.
        let out = autoreleasepool(|_| -> Result<Vec<f32>, InferError> {
            let cmd = self.queue.new_command_buffer();

            // Op 1: Q × K^T → scores
            {
                let _op_span =
                    tracing::info_span!("kin_infer.metal.fused_attention.qk_scores").entered();
                let qk_bufs = [
                    buf_q.buffer(),
                    buf_k.buffer(),
                    buf_scores.buffer(),
                    &buf_seq,
                    &buf_dim,
                    &self.buf_u32(1)?, // hpg=1
                ];
                if use_mma(seq_len, seq_len, head_dim) {
                    self.encode_mma(
                        cmd,
                        "batched_matmul_transb_simdgroup",
                        &qk_bufs,
                        seq_len,
                        seq_len,
                        head_dim,
                        num_heads,
                    );
                } else {
                    let p = &self.pipelines["batched_matmul_transb"];
                    let enc = cmd.new_compute_command_encoder();
                    enc.set_compute_pipeline_state(p);
                    for (i, b) in qk_bufs.iter().enumerate() {
                        enc.set_buffer(i as u64, Some(*b), 0);
                    }
                    let threads = MTLSize::new(seq_len as u64, seq_len as u64, num_heads as u64);
                    let tg = MTLSize::new(16.min(seq_len) as u64, 16.min(seq_len) as u64, 1);
                    enc.dispatch_threads(threads, tg);
                    enc.end_encoding();
                }
            }

            // Op 2: scale + ALiBi + mask (in-place on scores)
            {
                let _op_span =
                    tracing::info_span!("kin_infer.metal.fused_attention.scale_mask").entered();
                let p = &self.pipelines["scale_mask_alibi"];
                let enc = cmd.new_compute_command_encoder();
                enc.set_compute_pipeline_state(p);
                enc.set_buffer(0, Some(buf_scores.buffer()), 0);
                enc.set_buffer(1, Some(pooled_alibi.buffer()), 0);
                enc.set_buffer(2, Some(&buf_mask), 0);
                enc.set_buffer(3, Some(&buf_scale), 0);
                enc.set_buffer(4, Some(&buf_seq), 0);
                enc.set_buffer(5, Some(&buf_has_alibi), 0);
                let threads = MTLSize::new(seq_len as u64, seq_len as u64, num_heads as u64);
                let tg = MTLSize::new(8.min(seq_len) as u64, 8.min(seq_len) as u64, 1);
                enc.dispatch_threads(threads, tg);
                enc.end_encoding();
            }

            // Op 3: softmax (in-place on scores)
            {
                let _op_span =
                    tracing::info_span!("kin_infer.metal.fused_attention.softmax_rows").entered();
                let p = &self.pipelines["softmax_rows"];
                let enc = cmd.new_compute_command_encoder();
                enc.set_compute_pipeline_state(p);
                enc.set_buffer(0, Some(buf_scores.buffer()), 0);
                let buf_cols = self.buf_u32(seq_len as u32)?;
                enc.set_buffer(1, Some(&buf_cols), 0);
                let total_rows = num_heads * seq_len;
                let tw = p.thread_execution_width() as usize;
                let threads = MTLSize::new(total_rows as u64, 1, 1);
                let tg = MTLSize::new(tw.min(total_rows) as u64, 1, 1);
                enc.dispatch_threads(threads, tg);
                enc.end_encoding();
            }

            // Op 4: scores × V → output
            {
                let _op_span =
                    tracing::info_span!("kin_infer.metal.fused_attention.value_mix").entered();
                let av_bufs = [
                    buf_scores.buffer(),
                    buf_v.buffer(),
                    buf_out.buffer(),
                    &buf_seq,
                    &buf_dim,
                    &self.buf_u32(1)?, // hpg=1
                ];
                if use_mma(seq_len, head_dim, seq_len) {
                    self.encode_mma(
                        cmd,
                        "batched_matmul_ab_simdgroup",
                        &av_bufs,
                        seq_len,
                        head_dim,
                        seq_len,
                        num_heads,
                    );
                } else {
                    let p = &self.pipelines["batched_matmul_ab"];
                    let enc = cmd.new_compute_command_encoder();
                    enc.set_compute_pipeline_state(p);
                    for (i, b) in av_bufs.iter().enumerate() {
                        enc.set_buffer(i as u64, Some(*b), 0);
                    }
                    let threads = MTLSize::new(head_dim as u64, seq_len as u64, num_heads as u64);
                    let tg = MTLSize::new(16.min(head_dim) as u64, 16.min(seq_len) as u64, 1);
                    enc.dispatch_threads(threads, tg);
                    enc.end_encoding();
                }
            }

            // ONE bounded-async commit for all 4 ops, then the single sync point
            // before this region's readback.
            {
                let _commit_span =
                    tracing::info_span!("kin_infer.metal.fused_attention.commit_wait").entered();
                time_phase(Phase::Attention, || {
                    self.commit_wait(cmd);
                });
            }

            Ok(Self::read_buf(buf_out.buffer(), num_heads * seq_len * head_dim))
        })?;
        Self::count_nonfinite(
            &format!("fused_attention seq_len={seq_len} num_heads={num_heads}"),
            &out,
        );
        Ok(out)
    }

    fn fused_attention_batched(
        &self,
        q: &[f32],
        k: &[f32],
        v: &[f32],
        num_groups: usize,
        heads_per_group: usize,
        seq_len: usize,
        head_dim: usize,
        scale: f32,
        alibi_slopes: &[f32],
        masks: &[u32],
    ) -> Result<Vec<f32>, InferError> {
        let _span = tracing::info_span!(
            "kin_infer.metal.fused_attention_batched",
            num_groups = num_groups,
            heads_per_group = heads_per_group,
            seq_len = seq_len,
            head_dim = head_dim,
            has_alibi = !alibi_slopes.is_empty()
        )
        .entered();
        let total_heads = num_groups * heads_per_group;
        let buf_q = self.buf_slice_pooled(q)?;
        let buf_k = self.buf_slice_pooled(k)?;
        let buf_v = self.buf_slice_pooled(v)?;
        let buf_scores = self.buf_zeros_pooled(total_heads * seq_len * seq_len)?;
        let buf_out = self.buf_zeros_pooled(total_heads * seq_len * head_dim)?;
        let buf_seq = self.buf_u32(seq_len as u32)?;
        let buf_dim = self.buf_u32(head_dim as u32)?;
        let buf_scale = self.buf_f32(scale)?;
        let has_alibi = !alibi_slopes.is_empty();
        let alibi_ref = if has_alibi { alibi_slopes } else { &[0.0f32] };
        let pooled_alibi = self.buf_slice_pooled(alibi_ref)?;
        let buf_masks = self.buf_u32_slice(masks)?;
        let buf_has_alibi = self.buf_u32(has_alibi as u32)?;
        let buf_heads_per_group = self.buf_u32(heads_per_group as u32)?;

        // All four ops + commit + readback inside one autorelease pool: the
        // command buffer and its encoders are autoreleased (+0) and would
        // otherwise accumulate on a pool-less worker thread across every layer
        // of every batch — the heaviest contributor in a large cold embed.
        let out = autoreleasepool(|_| -> Result<Vec<f32>, InferError> {
            let cmd = self.queue.new_command_buffer();

            {
                let _op_span =
                    tracing::info_span!("kin_infer.metal.fused_attention_batched.qk_scores")
                        .entered();
                let qk_bufs = [
                    buf_q.buffer(),
                    buf_k.buffer(),
                    buf_scores.buffer(),
                    &buf_seq,
                    &buf_dim,
                    &self.buf_u32(1)?,
                ];
                if use_mma(seq_len, seq_len, head_dim) {
                    self.encode_mma(
                        cmd,
                        "batched_matmul_transb_simdgroup",
                        &qk_bufs,
                        seq_len,
                        seq_len,
                        head_dim,
                        total_heads,
                    );
                } else {
                    let p = &self.pipelines["batched_matmul_transb"];
                    let enc = cmd.new_compute_command_encoder();
                    enc.set_compute_pipeline_state(p);
                    for (i, b) in qk_bufs.iter().enumerate() {
                        enc.set_buffer(i as u64, Some(*b), 0);
                    }
                    let threads = MTLSize::new(seq_len as u64, seq_len as u64, total_heads as u64);
                    let tg = MTLSize::new(16.min(seq_len) as u64, 16.min(seq_len) as u64, 1);
                    enc.dispatch_threads(threads, tg);
                    enc.end_encoding();
                }
            }

            {
                let _op_span =
                    tracing::info_span!("kin_infer.metal.fused_attention_batched.scale_mask")
                        .entered();
                let p = &self.pipelines["scale_mask_alibi_grouped"];
                let enc = cmd.new_compute_command_encoder();
                enc.set_compute_pipeline_state(p);
                enc.set_buffer(0, Some(buf_scores.buffer()), 0);
                enc.set_buffer(1, Some(pooled_alibi.buffer()), 0);
                enc.set_buffer(2, Some(&buf_masks), 0);
                enc.set_buffer(3, Some(&buf_scale), 0);
                enc.set_buffer(4, Some(&buf_seq), 0);
                enc.set_buffer(5, Some(&buf_has_alibi), 0);
                enc.set_buffer(6, Some(&buf_heads_per_group), 0);
                let threads = MTLSize::new(seq_len as u64, seq_len as u64, total_heads as u64);
                let tg = MTLSize::new(8.min(seq_len) as u64, 8.min(seq_len) as u64, 1);
                enc.dispatch_threads(threads, tg);
                enc.end_encoding();
            }

            {
                let _op_span =
                    tracing::info_span!("kin_infer.metal.fused_attention_batched.softmax_rows")
                        .entered();
                let p = &self.pipelines["softmax_rows"];
                let enc = cmd.new_compute_command_encoder();
                enc.set_compute_pipeline_state(p);
                enc.set_buffer(0, Some(buf_scores.buffer()), 0);
                let buf_cols = self.buf_u32(seq_len as u32)?;
                enc.set_buffer(1, Some(&buf_cols), 0);
                let total_rows = total_heads * seq_len;
                let tw = p.thread_execution_width() as usize;
                let threads = MTLSize::new(total_rows as u64, 1, 1);
                let tg = MTLSize::new(tw.min(total_rows) as u64, 1, 1);
                enc.dispatch_threads(threads, tg);
                enc.end_encoding();
            }

            {
                let _op_span =
                    tracing::info_span!("kin_infer.metal.fused_attention_batched.value_mix")
                        .entered();
                let av_bufs = [
                    buf_scores.buffer(),
                    buf_v.buffer(),
                    buf_out.buffer(),
                    &buf_seq,
                    &buf_dim,
                    &self.buf_u32(1)?,
                ];
                if use_mma(seq_len, head_dim, seq_len) {
                    self.encode_mma(
                        cmd,
                        "batched_matmul_ab_simdgroup",
                        &av_bufs,
                        seq_len,
                        head_dim,
                        seq_len,
                        total_heads,
                    );
                } else {
                    let p = &self.pipelines["batched_matmul_ab"];
                    let enc = cmd.new_compute_command_encoder();
                    enc.set_compute_pipeline_state(p);
                    for (i, b) in av_bufs.iter().enumerate() {
                        enc.set_buffer(i as u64, Some(*b), 0);
                    }
                    let threads = MTLSize::new(head_dim as u64, seq_len as u64, total_heads as u64);
                    let tg = MTLSize::new(16.min(head_dim) as u64, 16.min(seq_len) as u64, 1);
                    enc.dispatch_threads(threads, tg);
                    enc.end_encoding();
                }
            }

            {
                let _commit_span =
                    tracing::info_span!("kin_infer.metal.fused_attention_batched.commit_wait")
                        .entered();
                time_phase(Phase::Attention, || {
                    self.commit_wait(cmd);
                });
            }

            Ok(Self::read_buf(buf_out.buffer(), total_heads * seq_len * head_dim))
        })?;
        Self::count_nonfinite(
            &format!(
                "fused_attention_batched seq_len={seq_len} total_heads={total_heads}"
            ),
            &out,
        );
        Ok(out)
    }

    /// Position-major fused attention ("Lever A"): consume Q/K/V straight from
    /// the `[num_groups*seq, heads_per_group*head_dim]` (i.e. `[batch*seq,
    /// hidden]`) forward-pass layout and return the attention output in the same
    /// position-major layout — the per-layer head-major scatter that
    /// `fused_attention_batched` requires the host to build never round-trips to
    /// the CPU. Two on-device reshape kernels bracket the *unchanged* QK^T →
    /// scale/mask → softmax → ×V pipeline, so the GEMM bytes (and thus parity)
    /// are identical to the head-major path; only the data movement moves to the
    /// GPU. Everything stays inside one command buffer / one autorelease pool.
    fn fused_attention_batched_posmajor(
        &self,
        q_pos: &[f32],
        k_pos: &[f32],
        v_pos: &[f32],
        num_groups: usize,
        heads_per_group: usize,
        seq_len: usize,
        head_dim: usize,
        scale: f32,
        alibi_slopes: &[f32],
        masks: &[u32],
    ) -> Result<Vec<f32>, InferError> {
        let _span = tracing::info_span!(
            "kin_infer.metal.fused_attention_batched_posmajor",
            num_groups = num_groups,
            heads_per_group = heads_per_group,
            seq_len = seq_len,
            head_dim = head_dim,
            has_alibi = !alibi_slopes.is_empty()
        )
        .entered();
        let total_heads = num_groups * heads_per_group;
        // head-major elem count == position-major elem count (same tensor, two views)
        let elems = total_heads * seq_len * head_dim;

        // Position-major operands uploaded once (contiguous copy, no host scatter).
        let buf_q_pos = self.buf_slice_pooled(q_pos)?;
        let buf_k_pos = self.buf_slice_pooled(k_pos)?;
        let buf_v_pos = self.buf_slice_pooled(v_pos)?;
        // Head-major reshape targets — fully overwritten by the reshape kernel.
        let buf_q = self.buf_uninit_pooled(elems)?;
        let buf_k = self.buf_uninit_pooled(elems)?;
        let buf_v = self.buf_uninit_pooled(elems)?;
        let buf_scores = self.buf_zeros_pooled(total_heads * seq_len * seq_len)?;
        let buf_out = self.buf_zeros_pooled(elems)?;
        // Position-major output — fully overwritten by the un-reshape kernel.
        let buf_out_pos = self.buf_uninit_pooled(elems)?;

        let buf_seq = self.buf_u32(seq_len as u32)?;
        let buf_dim = self.buf_u32(head_dim as u32)?;
        let buf_hpg = self.buf_u32(heads_per_group as u32)?;
        let buf_scale = self.buf_f32(scale)?;
        let has_alibi = !alibi_slopes.is_empty();
        let alibi_ref = if has_alibi { alibi_slopes } else { &[0.0f32] };
        let pooled_alibi = self.buf_slice_pooled(alibi_ref)?;
        let buf_masks = self.buf_u32_slice(masks)?;
        let buf_has_alibi = self.buf_u32(has_alibi as u32)?;
        let buf_heads_per_group = self.buf_u32(heads_per_group as u32)?;

        let out = autoreleasepool(|_| -> Result<Vec<f32>, InferError> {
            let cmd = self.queue.new_command_buffer();

            // (0) Reshape position-major Q/K/V -> head-major qf/kf/vf on-device.
            {
                let _op_span = tracing::info_span!(
                    "kin_infer.metal.fused_attention_batched_posmajor.reshape_in"
                )
                .entered();
                let p = &self.pipelines["reshape_qkv_pos_to_head"];
                let enc = cmd.new_compute_command_encoder();
                enc.set_compute_pipeline_state(p);
                enc.set_buffer(0, Some(buf_q_pos.buffer()), 0);
                enc.set_buffer(1, Some(buf_k_pos.buffer()), 0);
                enc.set_buffer(2, Some(buf_v_pos.buffer()), 0);
                enc.set_buffer(3, Some(buf_q.buffer()), 0);
                enc.set_buffer(4, Some(buf_k.buffer()), 0);
                enc.set_buffer(5, Some(buf_v.buffer()), 0);
                enc.set_buffer(6, Some(&buf_hpg), 0);
                enc.set_buffer(7, Some(&buf_seq), 0);
                enc.set_buffer(8, Some(&buf_dim), 0);
                let threads =
                    MTLSize::new(head_dim as u64, seq_len as u64, total_heads as u64);
                let tg = MTLSize::new(
                    8.min(head_dim) as u64,
                    8.min(seq_len) as u64,
                    1.min(total_heads) as u64,
                );
                enc.dispatch_threads(threads, tg);
                enc.end_encoding();
            }

            {
                let _op_span = tracing::info_span!(
                    "kin_infer.metal.fused_attention_batched_posmajor.qk_scores"
                )
                .entered();
                let qk_bufs = [
                    buf_q.buffer(),
                    buf_k.buffer(),
                    buf_scores.buffer(),
                    &buf_seq,
                    &buf_dim,
                    &self.buf_u32(1)?,
                ];
                if use_mma(seq_len, seq_len, head_dim) {
                    self.encode_mma(
                        cmd,
                        "batched_matmul_transb_simdgroup",
                        &qk_bufs,
                        seq_len,
                        seq_len,
                        head_dim,
                        total_heads,
                    );
                } else {
                    let p = &self.pipelines["batched_matmul_transb"];
                    let enc = cmd.new_compute_command_encoder();
                    enc.set_compute_pipeline_state(p);
                    for (i, b) in qk_bufs.iter().enumerate() {
                        enc.set_buffer(i as u64, Some(*b), 0);
                    }
                    let threads = MTLSize::new(seq_len as u64, seq_len as u64, total_heads as u64);
                    let tg = MTLSize::new(16.min(seq_len) as u64, 16.min(seq_len) as u64, 1);
                    enc.dispatch_threads(threads, tg);
                    enc.end_encoding();
                }
            }

            {
                let _op_span = tracing::info_span!(
                    "kin_infer.metal.fused_attention_batched_posmajor.scale_mask"
                )
                .entered();
                let p = &self.pipelines["scale_mask_alibi_grouped"];
                let enc = cmd.new_compute_command_encoder();
                enc.set_compute_pipeline_state(p);
                enc.set_buffer(0, Some(buf_scores.buffer()), 0);
                enc.set_buffer(1, Some(pooled_alibi.buffer()), 0);
                enc.set_buffer(2, Some(&buf_masks), 0);
                enc.set_buffer(3, Some(&buf_scale), 0);
                enc.set_buffer(4, Some(&buf_seq), 0);
                enc.set_buffer(5, Some(&buf_has_alibi), 0);
                enc.set_buffer(6, Some(&buf_heads_per_group), 0);
                let threads = MTLSize::new(seq_len as u64, seq_len as u64, total_heads as u64);
                let tg = MTLSize::new(8.min(seq_len) as u64, 8.min(seq_len) as u64, 1);
                enc.dispatch_threads(threads, tg);
                enc.end_encoding();
            }

            {
                let _op_span = tracing::info_span!(
                    "kin_infer.metal.fused_attention_batched_posmajor.softmax_rows"
                )
                .entered();
                let p = &self.pipelines["softmax_rows"];
                let enc = cmd.new_compute_command_encoder();
                enc.set_compute_pipeline_state(p);
                enc.set_buffer(0, Some(buf_scores.buffer()), 0);
                let buf_cols = self.buf_u32(seq_len as u32)?;
                enc.set_buffer(1, Some(&buf_cols), 0);
                let total_rows = total_heads * seq_len;
                let tw = p.thread_execution_width() as usize;
                let threads = MTLSize::new(total_rows as u64, 1, 1);
                let tg = MTLSize::new(tw.min(total_rows) as u64, 1, 1);
                enc.dispatch_threads(threads, tg);
                enc.end_encoding();
            }

            {
                let _op_span = tracing::info_span!(
                    "kin_infer.metal.fused_attention_batched_posmajor.value_mix"
                )
                .entered();
                let av_bufs = [
                    buf_scores.buffer(),
                    buf_v.buffer(),
                    buf_out.buffer(),
                    &buf_seq,
                    &buf_dim,
                    &self.buf_u32(1)?,
                ];
                if use_mma(seq_len, head_dim, seq_len) {
                    self.encode_mma(
                        cmd,
                        "batched_matmul_ab_simdgroup",
                        &av_bufs,
                        seq_len,
                        head_dim,
                        seq_len,
                        total_heads,
                    );
                } else {
                    let p = &self.pipelines["batched_matmul_ab"];
                    let enc = cmd.new_compute_command_encoder();
                    enc.set_compute_pipeline_state(p);
                    for (i, b) in av_bufs.iter().enumerate() {
                        enc.set_buffer(i as u64, Some(*b), 0);
                    }
                    let threads = MTLSize::new(head_dim as u64, seq_len as u64, total_heads as u64);
                    let tg = MTLSize::new(16.min(head_dim) as u64, 16.min(seq_len) as u64, 1);
                    enc.dispatch_threads(threads, tg);
                    enc.end_encoding();
                }
            }

            // (5) Un-reshape head-major attention output -> position-major.
            {
                let _op_span = tracing::info_span!(
                    "kin_infer.metal.fused_attention_batched_posmajor.reshape_out"
                )
                .entered();
                let p = &self.pipelines["reshape_head_to_pos"];
                let enc = cmd.new_compute_command_encoder();
                enc.set_compute_pipeline_state(p);
                enc.set_buffer(0, Some(buf_out.buffer()), 0);
                enc.set_buffer(1, Some(buf_out_pos.buffer()), 0);
                enc.set_buffer(2, Some(&buf_hpg), 0);
                enc.set_buffer(3, Some(&buf_seq), 0);
                enc.set_buffer(4, Some(&buf_dim), 0);
                let threads =
                    MTLSize::new(head_dim as u64, seq_len as u64, total_heads as u64);
                let tg = MTLSize::new(
                    8.min(head_dim) as u64,
                    8.min(seq_len) as u64,
                    1.min(total_heads) as u64,
                );
                enc.dispatch_threads(threads, tg);
                enc.end_encoding();
            }

            {
                let _commit_span = tracing::info_span!(
                    "kin_infer.metal.fused_attention_batched_posmajor.commit_wait"
                )
                .entered();
                time_phase(Phase::Attention, || {
                    self.commit_wait(cmd);
                });
            }

            Ok(Self::read_buf(buf_out_pos.buffer(), elems))
        })?;
        Self::count_nonfinite(
            &format!(
                "fused_attention_batched_posmajor seq_len={seq_len} total_heads={total_heads}"
            ),
            &out,
        );
        Ok(out)
    }

    fn backend(&self) -> GpuBackend {
        GpuBackend::Metal
    }

    fn device_name(&self) -> &str {
        &self.device_name
    }
}

// ---------------------------------------------------------------------------
// Device discovery
// ---------------------------------------------------------------------------

pub fn discover_devices() -> Vec<GpuDeviceInfo> {
    let mut devices = Vec::new();
    if let Some(device) = Device::system_default() {
        let name = device.name().to_string();
        // Apple Silicon has unified memory — report recommended working set
        let memory = device.recommended_max_working_set_size();
        devices.push(GpuDeviceInfo {
            backend: GpuBackend::Metal,
            name,
            memory_bytes: memory,
            unified_memory: true,
        });
    }
    devices
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn get_metal() -> Option<MetalCompute> {
        MetalCompute::try_new()
    }

    #[test]
    fn test_metal_discovery() {
        let devices = discover_devices();
        // On macOS, should find at least one Metal device
        if cfg!(target_os = "macos") {
            assert!(!devices.is_empty(), "No Metal devices found on macOS");
            println!("Metal device: {}", devices[0]);
        }
    }

    #[test]
    fn test_profile_gpu_phase_nanos_contract() {
        // Interface contract consumed by the profile harness (#8): exactly the
        // five kernel-class buckets, in this order, with these tags. Shape only —
        // the values depend on whether KIN_INFER_METAL_PROFILE was set this
        // process and on prior GPU work in the suite.
        let phases = profile_gpu_phase_nanos();
        let tags: Vec<&str> = phases.iter().map(|(t, _)| *t).collect();
        assert_eq!(tags, vec!["matmul", "attention", "norm", "activation", "copy"]);
    }

    #[test]
    fn test_rope_pair_batched_matches_per_block() {
        let Some(metal) = get_metal() else { return };
        let batch_size = 3usize;
        let max_len = 5usize;
        let head_dim = 4usize;
        let total_dim = 8usize; // 2 heads
        let half = head_dim / 2;
        let actual = max_len;
        // Compact cos/sin tables [actual, half].
        let mut cos = vec![0.0f32; actual * half];
        let mut sin = vec![0.0f32; actual * half];
        for p in 0..actual {
            for d in 0..half {
                let theta = (p as f32 + 1.0) * 0.1 + d as f32 * 0.3;
                cos[p * half + d] = theta.cos();
                sin[p * half + d] = theta.sin();
            }
        }
        // Synthetic q/k over the whole batch.
        let n = batch_size * max_len * total_dim;
        let q0: Vec<f32> = (0..n).map(|i| (i as f32 * 0.017).sin()).collect();
        let k0: Vec<f32> = (0..n).map(|i| (i as f32 * 0.013).cos()).collect();

        // Reference: per-block rope_pair (the proven path).
        let mut q_ref = q0.clone();
        let mut k_ref = k0.clone();
        for b in 0..batch_size {
            let base = b * max_len * total_dim;
            let rows = actual * total_dim;
            let mut qb = q_ref[base..base + rows].to_vec();
            let mut kb = k_ref[base..base + rows].to_vec();
            metal.rope_pair(&mut qb, &mut kb, &cos, &sin, 0, actual, head_dim, total_dim).unwrap();
            q_ref[base..base + rows].copy_from_slice(&qb);
            k_ref[base..base + rows].copy_from_slice(&kb);
        }

        // Candidate: single-dispatch rope_pair_batched.
        let mut q_bat = q0.clone();
        let mut k_bat = k0.clone();
        metal.rope_pair_batched(
            &mut q_bat, &mut k_bat, &cos, &sin, batch_size, max_len, actual, head_dim, total_dim,
        ).unwrap();

        let max_q = q_ref
            .iter()
            .zip(&q_bat)
            .map(|(a, b)| (a - b).abs())
            .fold(0.0f32, f32::max);
        let max_k = k_ref
            .iter()
            .zip(&k_bat)
            .map(|(a, b)| (a - b).abs())
            .fold(0.0f32, f32::max);
        let first_diff = q_ref
            .iter()
            .zip(&q_bat)
            .position(|(a, b)| (a - b).abs() > 1e-4);
        eprintln!(
            "[rope_pair_batched] max_q_err={max_q:.3e} max_k_err={max_k:.3e} first_diff_idx={first_diff:?}"
        );
        assert!(max_q < 1e-4 && max_k < 1e-4, "rope_pair_batched diverges from per-block: q={max_q} k={max_k}");
    }

    #[test]
    fn test_metal_matmul() {
        let Some(metal) = get_metal() else { return };
        let a = vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0];
        let b = vec![7.0, 8.0, 9.0, 10.0, 11.0, 12.0];
        let c = metal.matmul(&a, &b, 2, 2, 3).unwrap();
        assert!((c[0] - 50.0).abs() < 1e-3, "got {}", c[0]);
        assert!((c[1] - 68.0).abs() < 1e-3, "got {}", c[1]);
        assert!((c[2] - 122.0).abs() < 1e-3, "got {}", c[2]);
        assert!((c[3] - 167.0).abs() < 1e-3, "got {}", c[3]);
    }

    #[test]
    fn test_metal_softmax() {
        let Some(metal) = get_metal() else { return };
        let mut data = vec![1.0, 2.0, 3.0];
        metal.softmax(&mut data, 1, 3).unwrap();
        let sum: f32 = data.iter().sum();
        assert!((sum - 1.0).abs() < 1e-4, "sum={}", sum);
    }

    #[test]
    fn test_metal_gelu() {
        let Some(metal) = get_metal() else { return };
        let mut data = vec![0.0, 1.0, -1.0];
        metal.gelu(&mut data).unwrap();
        assert!(data[0].abs() < 1e-5);
        assert!((data[1] - 0.8413).abs() < 0.01);
    }

    #[test]
    fn test_metal_layer_norm() {
        let Some(metal) = get_metal() else { return };
        let mut data = vec![1.0, 2.0, 3.0, 4.0];
        let gamma = vec![1.0; 4];
        let beta = vec![0.0; 4];
        metal.layer_norm(&mut data, &gamma, &beta, 1, 4, 1e-5).unwrap();
        let mean: f32 = data.iter().sum::<f32>() / 4.0;
        assert!(mean.abs() < 1e-3, "mean={}", mean);
    }

    #[test]
    fn test_metal_silu() {
        let Some(metal) = get_metal() else { return };
        let mut data = vec![0.0, 1.0];
        metal.silu(&mut data).unwrap();
        assert!(data[0].abs() < 1e-5);
        assert!((data[1] - 0.7311).abs() < 0.01);
    }

    #[test]
    fn test_metal_matches_cpu() {
        let Some(metal) = get_metal() else { return };
        let cpu = crate::gpu::CpuCompute;

        // Test matmul consistency with larger matrix
        let m = 32;
        let n = 64;
        let k = 128;
        let a: Vec<f32> = (0..m * k).map(|i| (i as f32) * 0.01).collect();
        let b: Vec<f32> = (0..n * k).map(|i| (i as f32) * 0.01).collect();

        let c_metal = metal.matmul(&a, &b, m, n, k).unwrap();
        let c_cpu = cpu.matmul(&a, &b, m, n, k).unwrap();

        // Check relative error — accumulation order differs between GPU and CPU,
        // so absolute diff grows with magnitude. Relative error should be < 1e-4.
        let max_rel_err: f32 = c_metal
            .iter()
            .zip(c_cpu.iter())
            .map(|(a, b)| {
                let denom = a.abs().max(b.abs()).max(1e-6);
                (a - b).abs() / denom
            })
            .fold(0.0f32, f32::max);

        assert!(
            max_rel_err < 1e-4,
            "Metal vs CPU matmul max relative error: {} (should be < 1e-4)",
            max_rel_err
        );
    }

    #[test]
    fn test_metal_batched_matmul_matches_cpu() {
        let Some(metal) = get_metal() else { return };
        let cpu = crate::gpu::CpuCompute;

        let num_heads = 4;
        let seq_len = 16;
        let head_dim = 32;
        let total = num_heads * seq_len * head_dim;
        let q: Vec<f32> = (0..total)
            .map(|i| ((i % 97) as f32 - 48.0) * 0.01)
            .collect();
        let k: Vec<f32> = (0..total)
            .map(|i| ((i % 83) as f32 - 41.0) * 0.01)
            .collect();

        let scores_metal = metal.batched_matmul(&q, &k, num_heads, seq_len, head_dim).unwrap();
        let scores_cpu = cpu.batched_matmul(&q, &k, num_heads, seq_len, head_dim).unwrap();

        assert_eq!(scores_metal.len(), num_heads * seq_len * seq_len);
        let max_err: f32 = scores_metal
            .iter()
            .zip(scores_cpu.iter())
            .map(|(a, b)| (a - b).abs() / a.abs().max(b.abs()).max(1e-6))
            .fold(0.0f32, f32::max);
        assert!(max_err < 1e-3, "batched_matmul max err: {}", max_err);
    }

    #[test]
    fn test_metal_batched_attn_values_matches_cpu() {
        let Some(metal) = get_metal() else { return };
        let cpu = crate::gpu::CpuCompute;

        let num_heads = 4;
        let seq_len = 16;
        let head_dim = 32;

        // Scores: [num_heads, seq_len, seq_len] — make them look like softmax output
        let mut scores: Vec<f32> = (0..num_heads * seq_len * seq_len)
            .map(|i| ((i % 67) as f32) * 0.01)
            .collect();
        // Normalize each row so it sums to ~1
        for h in 0..num_heads {
            for i in 0..seq_len {
                let base = h * seq_len * seq_len + i * seq_len;
                let sum: f32 = scores[base..base + seq_len].iter().sum();
                if sum > 0.0 {
                    for j in 0..seq_len {
                        scores[base + j] /= sum;
                    }
                }
            }
        }

        let v: Vec<f32> = (0..num_heads * seq_len * head_dim)
            .map(|i| ((i % 71) as f32 - 35.0) * 0.01)
            .collect();

        let out_metal = metal.batched_attn_values(&scores, &v, num_heads, seq_len, head_dim).unwrap();
        let out_cpu = cpu.batched_attn_values(&scores, &v, num_heads, seq_len, head_dim).unwrap();

        assert_eq!(out_metal.len(), num_heads * seq_len * head_dim);
        let max_err: f32 = out_metal
            .iter()
            .zip(out_cpu.iter())
            .map(|(a, b)| (a - b).abs() / a.abs().max(b.abs()).max(1e-6))
            .fold(0.0f32, f32::max);
        assert!(max_err < 5e-3, "batched_attn_values max err: {}", max_err);
    }

    #[test]
    fn test_metal_fused_attention_batched_matches_cpu() {
        let Some(metal) = get_metal() else { return };
        let cpu = crate::gpu::CpuCompute;

        let num_groups = 3;
        let heads_per_group = 2;
        let seq_len = 7;
        let head_dim = 16;
        let total_heads = num_groups * heads_per_group;

        let q: Vec<f32> = (0..total_heads * seq_len * head_dim)
            .map(|i| ((i % 89) as f32 - 44.0) * 0.01)
            .collect();
        let k: Vec<f32> = (0..total_heads * seq_len * head_dim)
            .map(|i| ((i % 73) as f32 - 36.0) * 0.01)
            .collect();
        let v: Vec<f32> = (0..total_heads * seq_len * head_dim)
            .map(|i| ((i % 61) as f32 - 30.0) * 0.01)
            .collect();

        let masks = vec![
            1, 1, 1, 1, 1, 0, 0, // group 0
            1, 1, 1, 1, 1, 1, 1, // group 1
            1, 1, 1, 0, 0, 0, 0, // group 2
        ];
        let alibi = vec![0.0, 0.0625];
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
        ).unwrap();
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
        ).unwrap();

        assert_eq!(out_metal.len(), total_heads * seq_len * head_dim);
        let max_err: f32 = out_metal
            .iter()
            .zip(out_cpu.iter())
            .map(|(a, b)| (a - b).abs() / a.abs().max(b.abs()).max(1e-6))
            .fold(0.0f32, f32::max);
        assert!(
            max_err < 5e-3,
            "fused_attention_batched max err: {}",
            max_err
        );
    }

    /// Production-shape `fused_attention_batched` localizer for the intermittent
    /// batched-path nondeterminism. The existing matches-cpu test runs num_groups=3,
    /// seq=7, head_dim=16 — tiny AND below the MMA gate (use_mma needs ≥32/32/16),
    /// so it exercises only the scalar tile at seq 7 and never the production shape
    /// (batch 40 × seq 64 × head_dim 64 = total_heads 480, MMA path) where the
    /// corruption fires. This test reproduces that shape with a mixed len-32/len-64
    /// mask and asserts BOTH determinism (20× Metal must be bit-identical) AND
    /// correctness vs CPU. If it fails, the bug is inside fused_attention_batched at
    /// scale; if it passes, the bug is cross-layer/cross-op in forward_batched.
    #[test]
    fn test_metal_fused_attention_batched_production_dims() {
        let Some(metal) = get_metal() else { return };
        let cpu = crate::gpu::CpuCompute;

        let num_groups = 40; // batch_size (bin-64 corrupting shape)
        let heads_per_group = 12;
        let seq_len = 64;
        let head_dim = 64;
        let total_heads = num_groups * heads_per_group;
        let elems = total_heads * seq_len * head_dim;

        let q: Vec<f32> = (0..elems).map(|i| ((i % 257) as f32 - 128.0) * 0.003).collect();
        let k: Vec<f32> = (0..elems).map(|i| ((i % 251) as f32 - 125.0) * 0.003).collect();
        let v: Vec<f32> = (0..elems).map(|i| ((i % 241) as f32 - 120.0) * 0.003).collect();

        // Mixed mask: even groups are len-32 padded to 64, odd groups are full 64
        // (the len-32-padded-into-a-small-max_len case that corrupts).
        let mut masks = vec![0u32; num_groups * seq_len];
        for b in 0..num_groups {
            let real = if b % 2 == 0 { 32 } else { 64 };
            for s in 0..real {
                masks[b * seq_len + s] = 1;
            }
        }
        let alibi: Vec<f32> = vec![]; // RoPE model → no ALiBi
        let scale = 1.0 / (head_dim as f32).sqrt();

        let first = metal.fused_attention_batched(
            &q, &k, &v, num_groups, heads_per_group, seq_len, head_dim, scale, &alibi, &masks,
        ).unwrap();
        assert_eq!(first.len(), elems);

        // Determinism: 20 repeats must be bit-identical to the first run.
        for run in 0..20 {
            let out = metal.fused_attention_batched(
                &q, &k, &v, num_groups, heads_per_group, seq_len, head_dim, scale, &alibi, &masks,
            ).unwrap();
            let max_abs: f32 = first
                .iter()
                .zip(out.iter())
                .map(|(a, b)| (a - b).abs())
                .fold(0.0f32, f32::max);
            assert!(
                max_abs == 0.0,
                "fused_attention_batched NONDETERMINISTIC at production dims (run {run}): max_abs_diff {max_abs}"
            );
        }

        // Correctness vs CPU reference.
        let out_cpu = cpu.fused_attention_batched(
            &q, &k, &v, num_groups, heads_per_group, seq_len, head_dim, scale, &alibi, &masks,
        ).unwrap();
        let max_err: f32 = first
            .iter()
            .zip(out_cpu.iter())
            .map(|(a, b)| (a - b).abs() / a.abs().max(b.abs()).max(1e-6))
            .fold(0.0f32, f32::max);
        assert!(
            max_err < 1.5e-2,
            "fused_attention_batched Metal vs CPU mismatch at production dims: max_err {max_err}"
        );
    }

    // ---- Per-kernel determinism at PRODUCTION SCALE (rows=2560) ----
    // Non-perturbing localizers for the batched Heisenbug: a tight 20× loop with
    // the SAME inputs and NO inter-op host work, so nothing changes GPU occupancy
    // between runs (unlike the per-layer dump / zero / no-reuse probes, which
    // suppressed the race). These exercise the SHARED per-op kernels at the
    // batched rows=2560 single-forward never reaches (it runs rows≤512). Run each
    // under BOTH KIN_INFER_MMA=1 (block_mma) and KIN_INFER_MMA=0 (scalar tile) —
    // the env is OnceLock-sampled per process, so the harness toggles it across
    // separate invocations. If a kernel is bit-nondeterministic here, it is the
    // batched corruption source; the MMA-on/off split says whether it's a
    // block_mma-vs-scalar-common (occupancy/barrier) issue or one kernel.

    fn max_abs_diff(a: &[f32], b: &[f32]) -> f32 {
        a.iter()
            .zip(b.iter())
            .map(|(x, y)| (x - y).abs())
            .fold(0.0f32, f32::max)
    }

    /// Projection GEMM at production scale: C[m,n] = A[m,k]·B[n,k]^T, m=2560
    /// (batch40 × max_len64), depth=1 — the shape the per-head attention test
    /// (depth=480, m=n=seq=64) never covered.
    #[test]
    fn test_metal_matmul_determinism_prod_scale() {
        let Some(metal) = get_metal() else { return };
        let (m, n, k) = (2560usize, 768usize, 768usize);
        let a: Vec<f32> = (0..m * k).map(|i| ((i % 257) as f32 - 128.0) * 0.003).collect();
        let b: Vec<f32> = (0..n * k).map(|i| ((i % 251) as f32 - 125.0) * 0.003).collect();
        let first = metal.matmul(&a, &b, m, n, k).unwrap();
        assert_eq!(first.len(), m * n);
        for run in 0..20 {
            let out = metal.matmul(&a, &b, m, n, k).unwrap();
            let d = max_abs_diff(&first, &out);
            assert!(
                d == 0.0,
                "matmul NONDETERMINISTIC at m={m},n={n},k={k} (run {run}; MMA per KIN_INFER_MMA): max_abs_diff {d}"
            );
        }
    }

    /// Fat QKV GEMM (matmul_many) at production scale: 3 weights concatenated.
    #[test]
    fn test_metal_matmul_many_determinism_prod_scale() {
        let Some(metal) = get_metal() else { return };
        let (m, k) = (2560usize, 768usize);
        let a: Vec<f32> = (0..m * k).map(|i| ((i % 257) as f32 - 128.0) * 0.003).collect();
        let w: Vec<f32> = (0..768 * k).map(|i| ((i % 251) as f32 - 125.0) * 0.003).collect();
        let weights: Vec<&[f32]> = vec![&w, &w, &w];
        let ns = vec![768usize, 768, 768];
        let first = metal.matmul_many(&a, &weights, m, &ns, k).unwrap();
        for run in 0..20 {
            let out = metal.matmul_many(&a, &weights, m, &ns, k).unwrap();
            let mut d = 0.0f32;
            for (fo, oo) in first.iter().zip(out.iter()) {
                d = d.max(max_abs_diff(fo, oo));
            }
            assert!(
                d == 0.0,
                "matmul_many NONDETERMINISTIC at m={m},k={k} (run {run}; MMA per KIN_INFER_MMA): max_abs_diff {d}"
            );
        }
    }

    /// Fused SwiGLU FFN at production scale (the multi-encoder chained op).
    #[test]
    fn test_metal_fused_ffn_swiglu_determinism_prod_scale() {
        let Some(metal) = get_metal() else { return };
        let (rows, hidden, inter) = (2560usize, 768usize, 3072usize);
        let x: Vec<f32> = (0..rows * hidden).map(|i| ((i % 257) as f32 - 128.0) * 0.003).collect();
        let wg: Vec<f32> = (0..inter * hidden).map(|i| ((i % 251) as f32 - 125.0) * 0.002).collect();
        let wu: Vec<f32> = (0..inter * hidden).map(|i| ((i % 241) as f32 - 120.0) * 0.002).collect();
        let wd: Vec<f32> = (0..hidden * inter).map(|i| ((i % 239) as f32 - 119.0) * 0.002).collect();
        let first = metal.fused_ffn_swiglu(&x, &wg, &wu, &wd, rows, hidden, inter).unwrap();
        assert_eq!(first.len(), rows * hidden);
        for run in 0..20 {
            let out = metal.fused_ffn_swiglu(&x, &wg, &wu, &wd, rows, hidden, inter).unwrap();
            let d = max_abs_diff(&first, &out);
            assert!(
                d == 0.0,
                "fused_ffn_swiglu NONDETERMINISTIC at rows={rows},hidden={hidden},inter={inter} (run {run}; MMA per KIN_INFER_MMA): max_abs_diff {d}"
            );
        }
    }

    /// CONTROL: layer_norm at production scale — it is one-thread-per-row,
    /// register-only (no threadgroup memory/barrier), so it SHOULD be deterministic.
    /// If this fails, the "register-only ⇒ race-free" reasoning is wrong.
    #[test]
    fn test_metal_layer_norm_determinism_prod_scale() {
        let Some(metal) = get_metal() else { return };
        let (rows, cols) = (2560usize, 768usize);
        let base: Vec<f32> = (0..rows * cols).map(|i| ((i % 257) as f32 - 128.0) * 0.01).collect();
        let gamma: Vec<f32> = (0..cols).map(|i| 1.0 + (i % 13) as f32 * 0.01).collect();
        let beta: Vec<f32> = (0..cols).map(|i| (i % 7) as f32 * 0.01).collect();
        let eps = 1e-12f32;
        let mut first = base.clone();
        metal.layer_norm(&mut first, &gamma, &beta, rows, cols, eps).unwrap();
        for run in 0..20 {
            let mut out = base.clone();
            metal.layer_norm(&mut out, &gamma, &beta, rows, cols, eps).unwrap();
            let d = max_abs_diff(&first, &out);
            assert!(
                d == 0.0,
                "layer_norm NONDETERMINISTIC at rows={rows},cols={cols} (run {run}): max_abs_diff {d}"
            );
        }
    }

    #[test]
    fn test_metal_fused_attention_batched_posmajor_matches_head_major() {
        // Lever A parity: the on-device position-major reshape path must be a
        // pure relayout of the head-major path — same GPU kernels, same input
        // bytes — so the (un-reshaped) outputs must match bit-for-bit.
        let Some(metal) = get_metal() else { return };

        let num_groups = 3;
        let heads_per_group = 2;
        let seq_len = 7;
        let head_dim = 16;
        let total_dim = heads_per_group * head_dim;
        let total_heads = num_groups * heads_per_group;
        let elems = total_heads * seq_len * head_dim;

        let qh: Vec<f32> = (0..elems).map(|i| ((i % 89) as f32 - 44.0) * 0.01).collect();
        let kh: Vec<f32> = (0..elems).map(|i| ((i % 73) as f32 - 36.0) * 0.01).collect();
        let vh: Vec<f32> = (0..elems).map(|i| ((i % 61) as f32 - 30.0) * 0.01).collect();
        let masks = vec![
            1, 1, 1, 1, 1, 0, 0, // group 0
            1, 1, 1, 1, 1, 1, 1, // group 1
            1, 1, 1, 0, 0, 0, 0, // group 2
        ];
        let alibi = vec![0.0, 0.0625];
        let scale = 1.0 / (head_dim as f32).sqrt();

        // Scatter head-major -> position-major to feed the posmajor entry point.
        let mut qp = vec![0.0f32; elems];
        let mut kp = vec![0.0f32; elems];
        let mut vp = vec![0.0f32; elems];
        for b in 0..num_groups {
            for s in 0..seq_len {
                for hd in 0..heads_per_group {
                    let src = (b * heads_per_group + hd) * seq_len * head_dim + s * head_dim;
                    let dst = (b * seq_len + s) * total_dim + hd * head_dim;
                    qp[dst..dst + head_dim].copy_from_slice(&qh[src..src + head_dim]);
                    kp[dst..dst + head_dim].copy_from_slice(&kh[src..src + head_dim]);
                    vp[dst..dst + head_dim].copy_from_slice(&vh[src..src + head_dim]);
                }
            }
        }

        let out_pos = metal.fused_attention_batched_posmajor(
            &qp, &kp, &vp, num_groups, heads_per_group, seq_len, head_dim, scale, &alibi, &masks,
        ).unwrap();
        let out_head = metal.fused_attention_batched(
            &qh, &kh, &vh, num_groups, heads_per_group, seq_len, head_dim, scale, &alibi, &masks,
        ).unwrap();

        assert_eq!(out_pos.len(), elems);
        let mut max_err = 0.0f32;
        for b in 0..num_groups {
            for s in 0..seq_len {
                for hd in 0..heads_per_group {
                    let pos = (b * seq_len + s) * total_dim + hd * head_dim;
                    let head = (b * heads_per_group + hd) * seq_len * head_dim + s * head_dim;
                    for d in 0..head_dim {
                        max_err = max_err.max((out_pos[pos + d] - out_head[head + d]).abs());
                    }
                }
            }
        }
        // Pure data movement — identical kernels, identical inputs — so the
        // result is bit-identical; allow only float-noise slack.
        assert!(
            max_err < 1e-6,
            "fused_attention_batched_posmajor vs head-major max err: {}",
            max_err
        );
    }

    #[test]
    fn test_metal_wide_mma_matches_cpu() {
        // Lever #5 phase 1: the wider 64x64 MMA tile must compute the same GEMM
        // as the reference. Direct-dispatch the `*_wide` kernel (bypassing the
        // KIN_INFER_MMA_WIDE flag, which is OnceLock-sampled and can't be toggled
        // mid-process) on a shape that fills the 64x64 tile, and compare against
        // CPU. Skips if the wide pipelines didn't build on this device.
        let Some(metal) = get_metal() else { return };
        if !WIDE_MMA_AVAILABLE.load(Ordering::Relaxed) {
            return;
        }
        let cpu = crate::gpu::CpuCompute;

        // matmul_transb: C[M,N] = A[M,K] * B[N,K]^T; M,N > 64 to exercise both a
        // full 64x64 block and a ragged remainder.
        let (m, n, k) = (80usize, 96usize, 64usize);
        let a: Vec<f32> = (0..m * k).map(|i| ((i % 89) as f32 - 44.0) * 0.01).collect();
        let b: Vec<f32> = (0..n * k).map(|i| ((i % 73) as f32 - 36.0) * 0.01).collect();

        let buf_a = metal.buf_slice_pooled(&a).unwrap();
        let buf_b = metal.buf_cached(&b).unwrap();
        let buf_c = metal.buf_zeros_pooled(m * n).unwrap();
        let buf_m = metal.buf_u32(m as u32).unwrap();
        let buf_n = metal.buf_u32(n as u32).unwrap();
        let buf_k = metal.buf_u32(k as u32).unwrap();
        let bufs = [buf_a.buffer(), &buf_b, buf_c.buffer(), &buf_m, &buf_n, &buf_k];
        autoreleasepool(|_| {
            let cmd = metal.queue.new_command_buffer();
            let pipeline = &metal.pipelines["matmul_transb_simdgroup_wide"];
            let enc = cmd.new_compute_command_encoder();
            enc.set_compute_pipeline_state(pipeline);
            for (i, bb) in bufs.iter().enumerate() {
                enc.set_buffer(i as u64, Some(*bb), 0);
            }
            let groups = MTLSize::new(n.div_ceil(64) as u64, m.div_ceil(64) as u64, 1);
            enc.dispatch_thread_groups(groups, MTLSize::new(128, 1, 1));
            enc.end_encoding();
            metal.commit_wait(cmd);
        });
        let wide_out = MetalCompute::read_buf(buf_c.buffer(), m * n);
        let cpu_out = cpu.matmul(&a, &b, m, n, k).unwrap();

        assert_eq!(wide_out.len(), m * n);
        let max_err: f32 = wide_out
            .iter()
            .zip(cpu_out.iter())
            .map(|(x, y)| (x - y).abs() / x.abs().max(y.abs()).max(1e-6))
            .fold(0.0f32, f32::max);
        assert!(max_err < 5e-3, "wide MMA vs CPU matmul max err: {}", max_err);
    }

    #[test]
    fn test_metal_steel_mma_matches_cpu() {
        // Step 1: the steel double-buffered K-loop must compute the SAME GEMM as
        // the reference — it is fp32-accumulate identical to the single-buffer MMA,
        // so the only thing that can break is a barrier/ordering bug in the
        // ping-pong, which would corrupt the result (not just add fp noise).
        // Direct-dispatch the `*_steel` kernel (bypassing KIN_INFER_STEEL, which is
        // OnceLock-sampled and can't be toggled mid-process) on a ragged shape
        // spanning multiple K-tiles, and compare against CPU. K=80 -> 5 K-tiles of
        // BK=16, so the loop runs the ping-pong ≥3 times; M=80,N=96 leave ragged
        // remainders past the 32x32 blocks to exercise the bounds-guarded epilogue.
        // A single-K-tile shape would never trip a double-buffer bug. Skips if the
        // steel pipelines didn't build on this device.
        let Some(metal) = get_metal() else { return };
        if !STEEL_MMA_AVAILABLE.load(Ordering::Relaxed) {
            return;
        }
        let cpu = crate::gpu::CpuCompute;

        // matmul_transb: C[M,N] = A[M,K] * B[N,K]^T.
        let (m, n, k) = (80usize, 96usize, 80usize);
        let a: Vec<f32> = (0..m * k).map(|i| ((i % 89) as f32 - 44.0) * 0.01).collect();
        let b: Vec<f32> = (0..n * k).map(|i| ((i % 73) as f32 - 36.0) * 0.01).collect();

        let buf_a = metal.buf_slice_pooled(&a).unwrap();
        let buf_b = metal.buf_cached(&b).unwrap();
        let buf_c = metal.buf_zeros_pooled(m * n).unwrap();
        let buf_m = metal.buf_u32(m as u32).unwrap();
        let buf_n = metal.buf_u32(n as u32).unwrap();
        let buf_k = metal.buf_u32(k as u32).unwrap();
        let bufs = [buf_a.buffer(), &buf_b, buf_c.buffer(), &buf_m, &buf_n, &buf_k];
        autoreleasepool(|_| {
            let cmd = metal.queue.new_command_buffer();
            let pipeline = &metal.pipelines["matmul_transb_simdgroup_steel"];
            let enc = cmd.new_compute_command_encoder();
            enc.set_compute_pipeline_state(pipeline);
            for (i, bb) in bufs.iter().enumerate() {
                enc.set_buffer(i as u64, Some(*bb), 0);
            }
            let groups = MTLSize::new(n.div_ceil(32) as u64, m.div_ceil(32) as u64, 1);
            enc.dispatch_thread_groups(groups, MTLSize::new(128, 1, 1));
            enc.end_encoding();
            metal.commit_wait(cmd);
        });
        let steel_out = MetalCompute::read_buf(buf_c.buffer(), m * n);
        let cpu_out = cpu.matmul(&a, &b, m, n, k).unwrap();

        assert_eq!(steel_out.len(), m * n);
        assert!(
            steel_out.iter().all(|x| x.is_finite()),
            "steel MMA produced non-finite output"
        );
        // Tight: fp32 accumulate, same reduction order as the single-buffer MMA —
        // matches the wide-tile bound (same numeric path, only K-staging differs).
        let max_err: f32 = steel_out
            .iter()
            .zip(cpu_out.iter())
            .map(|(x, y)| (x - y).abs() / x.abs().max(y.abs()).max(1e-6))
            .fold(0.0f32, f32::max);
        assert!(max_err < 5e-3, "steel MMA vs CPU matmul max err: {}", max_err);
    }

    #[test]
    fn test_metal_fp16_mma_close_to_cpu() {
        // Lever #4: the fp16-operand MMA must compute the right GEMM to within
        // fp16 precision (NOT the strict fp32 gate — fp16 operands lose ~half the
        // mantissa). Direct-dispatch the `*_fp16` kernel (flag-independent) and
        // assert it lands CLOSE to the CPU fp32 reference — this guards against
        // gross index/overload bugs (which would blow up far past fp16 noise or
        // produce NaN), not the embedding-level cosine (profiler #7 measures
        // that). Skips if the fp16 library didn't build on this device.
        let Some(metal) = get_metal() else { return };
        if !FP16_MMA_AVAILABLE.load(Ordering::Relaxed) {
            return;
        }
        let cpu = crate::gpu::CpuCompute;

        let (m, n, k) = (40usize, 48usize, 64usize);
        let a: Vec<f32> = (0..m * k).map(|i| ((i % 89) as f32 - 44.0) * 0.01).collect();
        let b: Vec<f32> = (0..n * k).map(|i| ((i % 73) as f32 - 36.0) * 0.01).collect();

        let buf_a = metal.buf_slice_pooled(&a).unwrap();
        let buf_b = metal.buf_cached(&b).unwrap();
        let buf_c = metal.buf_zeros_pooled(m * n).unwrap();
        let buf_m = metal.buf_u32(m as u32).unwrap();
        let buf_n = metal.buf_u32(n as u32).unwrap();
        let buf_k = metal.buf_u32(k as u32).unwrap();
        let bufs = [buf_a.buffer(), &buf_b, buf_c.buffer(), &buf_m, &buf_n, &buf_k];
        autoreleasepool(|_| {
            let cmd = metal.queue.new_command_buffer();
            let pipeline = &metal.pipelines["matmul_transb_simdgroup_fp16"];
            let enc = cmd.new_compute_command_encoder();
            enc.set_compute_pipeline_state(pipeline);
            for (i, bb) in bufs.iter().enumerate() {
                enc.set_buffer(i as u64, Some(*bb), 0);
            }
            let groups = MTLSize::new(n.div_ceil(32) as u64, m.div_ceil(32) as u64, 1);
            enc.dispatch_thread_groups(groups, MTLSize::new(128, 1, 1));
            enc.end_encoding();
            metal.commit_wait(cmd);
        });
        let fp16_out = MetalCompute::read_buf(buf_c.buffer(), m * n);
        let cpu_out = cpu.matmul(&a, &b, m, n, k).unwrap();

        assert_eq!(fp16_out.len(), m * n);
        assert!(
            fp16_out.iter().all(|x| x.is_finite()),
            "fp16 MMA produced non-finite output"
        );
        // Loose: fp16 operands (11-bit mantissa) over a K=64 contraction.
        let max_err: f32 = fp16_out
            .iter()
            .zip(cpu_out.iter())
            .map(|(x, y)| (x - y).abs() / x.abs().max(y.abs()).max(1e-6))
            .fold(0.0f32, f32::max);
        assert!(max_err < 5e-2, "fp16 MMA vs CPU matmul max err: {}", max_err);
    }

    #[test]
    fn test_metal_matmul_many_matches_individual_calls() {
        let Some(metal) = get_metal() else { return };

        let m = 16;
        let n = 24;
        let k = 32;
        let a: Vec<f32> = (0..m * k).map(|i| (i as f32) * 0.01).collect();
        let b0: Vec<f32> = (0..n * k)
            .map(|i| ((i % 29) as f32 - 14.0) * 0.01)
            .collect();
        let b1: Vec<f32> = (0..n * k)
            .map(|i| ((i % 31) as f32 - 15.0) * 0.01)
            .collect();
        let b2: Vec<f32> = (0..n * k)
            .map(|i| ((i % 37) as f32 - 18.0) * 0.01)
            .collect();

        let many = metal.matmul_many(&a, &[&b0, &b1, &b2], m, &[n, n, n], k).unwrap();
        let single = vec![
            metal.matmul(&a, &b0, m, n, k).unwrap(),
            metal.matmul(&a, &b1, m, n, k).unwrap(),
            metal.matmul(&a, &b2, m, n, k).unwrap(),
        ];

        assert_eq!(many.len(), single.len());
        for (many_mat, single_mat) in many.iter().zip(single.iter()) {
            let max_err: f32 = many_mat
                .iter()
                .zip(single_mat.iter())
                .map(|(a, b)| (a - b).abs() / a.abs().max(b.abs()).max(1e-6))
                .fold(0.0f32, f32::max);
            assert!(max_err < 1e-4, "matmul_many max err: {}", max_err);
        }
    }
}
