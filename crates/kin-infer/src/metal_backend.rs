// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Metal GPU compute backend for macOS (Apple Silicon).
//!
//! Custom MSL compute shaders for transformer operations.
//! No candle, no ONNX, no MPS — direct Metal API via objc2-metal.

#![cfg(feature = "metal")]

use crate::gpu::{GpuBackend, GpuCompute, GpuDeviceInfo};
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
}

/// Run `f`, attributing its wall-clock to `phase` when profiling is enabled.
/// Zero overhead (no Instant, no atomic) when profiling is off.
#[inline]
fn time_phase<T>(phase: Phase, f: impl FnOnce() -> T) -> T {
    if profile_enabled() {
        let start = std::time::Instant::now();
        let out = f();
        phase
            .counter()
            .fetch_add(start.elapsed().as_nanos() as u64, Ordering::Relaxed);
        out
    } else {
        f()
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

/// Zero the host-stall and per-phase accumulators. Call before a timed region.
pub fn reset_profile() {
    STALL_NANOS.store(0, Ordering::Relaxed);
    SUBMISSIONS.store(0, Ordering::Relaxed);
    MATMUL_NANOS.store(0, Ordering::Relaxed);
    ATTENTION_NANOS.store(0, Ordering::Relaxed);
    NORM_NANOS.store(0, Ordering::Relaxed);
    ACTIVATION_NANOS.store(0, Ordering::Relaxed);
    COPY_NANOS.store(0, Ordering::Relaxed);
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
// stage and the helper that consumes it).
constant uint MMA_BM = 32, MMA_BN = 32, MMA_BK = 16, MMA_WM = 2, MMA_WN = 2, MMA_F = 8;

// `As`/`Bs`/`store_tile` are declared in the calling KERNEL (threadgroup-address
// variables cannot be declared in a non-kernel helper) and passed in by pointer.
template <bool TRANSB>
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
    constexpr uint BM = 32, BN = 32, BK = 16, WM = 2, WN = 2, F = 8;
    constexpr uint TM = BM / (F * WM);   // 2 fragment-rows per simdgroup
    constexpr uint TN = BN / (F * WN);   // 2 fragment-cols per simdgroup

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
    for (uint i = 0; i < TM; i++) {
        for (uint j = 0; j < TN; j++) {
            uint cr = block_row + sm * F * TM + i * F;
            uint cc = block_col + sn * F * TN + j * F;
            if (cr + F <= M && cc + F <= N) {
                simdgroup_store(acc[i][j], &C[cr * N + cc], N, ulong2(0, 0), false);
            } else {
                // Ragged tile: store to this simdgroup's scratch then copy the
                // in-bounds elements out per lane.
                threadgroup float* scratch = &store_tile[sgid][0][0];
                simdgroup_store(acc[i][j], scratch, F, ulong2(0, 0), false);
                simdgroup_barrier(mem_flags::mem_threadgroup);
                for (uint e = lane; e < F * F; e += 32u) {
                    uint er = e / F, ec = e % F;
                    uint gr = cr + er, gc = cc + ec;
                    if (gr < M && gc < N) {
                        C[gr * N + gc] = scratch[er * F + ec];
                    }
                }
                simdgroup_barrier(mem_flags::mem_threadgroup);
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
    uint3 tgid              [[threadgroup_position_in_grid]],
    uint  sgid             [[simdgroup_index_in_threadgroup]],
    uint  lane             [[thread_index_in_simdgroup]])
{
    uint h = tgid.z;
    device const float* Ah = Q  + h * seq * dim;
    device const float* Bh = Kk + h * seq * dim;
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
    uint3 tgid              [[threadgroup_position_in_grid]],
    uint  sgid             [[simdgroup_index_in_threadgroup]],
    uint  lane             [[thread_index_in_simdgroup]])
{
    uint h = tgid.z;
    device const float* Ah = S + h * seq * seq;
    device const float* Bh = V + h * seq * dim;
    device float*       Ch = C + h * seq * dim;
    threadgroup float As[MMA_BM][MMA_BK];
    threadgroup float Bs[MMA_BN][MMA_BK];
    threadgroup float store_tile[MMA_WM * MMA_WN][MMA_F][MMA_F];
    block_mma<false>(Ah, Bh, Ch, seq, dim, seq, uint3(tgid.x, tgid.y, 0), sgid, lane, As, Bs, store_tile);
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

    uint head_off = head * seq_len * head_dim;
    uint c_off = head * seq_len * seq_len + row * seq_len + col;

    float sum = 0.0;
    for (uint tile = 0; tile < head_dim; tile += TILE) {
        for (uint a_local = tid.x; a_local < TILE; a_local += tgs.x) {
            uint d = tile + a_local;
            if (row < seq_len && d < head_dim) {
                a_tile[tid.y][a_local] = A[head_off + row * head_dim + d];
            } else {
                a_tile[tid.y][a_local] = 0.0;
            }
        }

        for (uint b_local = tid.y; b_local < TILE; b_local += tgs.y) {
            uint d = tile + b_local;
            if (col < seq_len && d < head_dim) {
                b_tile[b_local][tid.x] = B[head_off + col * head_dim + d];
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
        C[c_off] = sum;
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

    uint a_head_off = head * seq_len * seq_len;
    uint b_head_off = head * seq_len * head_dim;
    uint c_off = b_head_off + row * head_dim + col;

    float sum = 0.0;
    for (uint tile = 0; tile < seq_len; tile += TILE) {
        for (uint a_local = tid.x; a_local < TILE; a_local += tgs.x) {
            uint k = tile + a_local;
            if (row < seq_len && k < seq_len) {
                a_tile[tid.y][a_local] = A[a_head_off + row * seq_len + k];
            } else {
                a_tile[tid.y][a_local] = 0.0;
            }
        }

        for (uint b_local = tid.y; b_local < TILE; b_local += tgs.y) {
            uint k = tile + b_local;
            if (col < head_dim && k < seq_len) {
                b_tile[b_local][tid.x] = B[b_head_off + k * head_dim + col];
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
        C[c_off] = sum;
    }
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
    /// of the class size.
    fn acquire_zeroed(self: &Arc<Self>, bytes: usize) -> PooledBuffer {
        let class = size_class(bytes);
        let buf = self.free.lock().get_mut(&class).and_then(|v| v.pop());
        let buf = match buf {
            Some(buf) => {
                unsafe {
                    std::ptr::write_bytes(buf.contents() as *mut u8, 0, class);
                }
                buf
            }
            None => self
                .device
                .new_buffer(class as u64, MTLResourceOptions::StorageModeShared),
        };
        PooledBuffer {
            buf,
            class,
            pool: Arc::clone(self),
        }
    }

    /// Acquire a buffer initialised from `data`. Pops a recycled buffer of the
    /// matching size-class and copies `data` into its head, else allocates.
    fn acquire_with(self: &Arc<Self>, data: &[f32]) -> PooledBuffer {
        let bytes = std::mem::size_of_val(data);
        let class = size_class(bytes);
        let buf = self.free.lock().get_mut(&class).and_then(|v| v.pop());
        let buf = match buf {
            Some(buf) => {
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        data.as_ptr() as *const u8,
                        buf.contents() as *mut u8,
                        bytes,
                    );
                }
                buf
            }
            None => {
                let buf = self
                    .device
                    .new_buffer(class as u64, MTLResourceOptions::StorageModeShared);
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        data.as_ptr() as *const u8,
                        buf.contents() as *mut u8,
                        bytes,
                    );
                }
                buf
            }
        };
        PooledBuffer {
            buf,
            class,
            pool: Arc::clone(self),
        }
    }

    fn recycle(&self, class: usize, buf: Buffer) {
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
    /// Cache stable u32 buffers like flattened masks that are reused across
    /// every layer in a batch.
    u32_cache: Mutex<HashMap<(usize, usize), Buffer>>,
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
        opts.set_language_version(MTLLanguageVersion::V2_4);
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
            "rope_apply",
            "rope_apply_batched",
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

        let pool = Arc::new(BufferPool::new(device.clone()));
        Some(Self {
            device,
            queue,
            pipelines,
            device_name,
            weight_cache: Mutex::new(HashMap::new()),
            u32_cache: Mutex::new(HashMap::new()),
            concat_cache: Mutex::new(HashMap::new()),
            inflight: Arc::new((Mutex::new(0), Condvar::new())),
            pool,
        })
    }

    /// Create a Metal buffer from a slice and copy data in.
    fn buf_from_slice(&self, data: &[f32]) -> Buffer {
        let bytes = data.len() * std::mem::size_of::<f32>();
        self.device.new_buffer_with_data(
            data.as_ptr() as *const _,
            bytes as u64,
            MTLResourceOptions::StorageModeShared,
        )
    }

    /// Acquire a zero-filled transient buffer of `count` floats from the pool.
    /// Returns an RAII `PooledBuffer` that recycles on drop; safe to drop only
    /// after the GPU work touching it has completed (every caller waits before
    /// readback / scope-exit). Re-zeroed on reuse, preserving the determinism
    /// guarantee `buf_zeros` documents.
    #[inline]
    fn buf_zeros_pooled(&self, count: usize) -> PooledBuffer {
        time_phase(Phase::Copy, || {
            self.pool.acquire_zeroed(count * std::mem::size_of::<f32>())
        })
    }

    /// Acquire a transient buffer initialised from `data` from the pool. The
    /// host→device copy is timed into the copy/readback phase.
    #[inline]
    fn buf_slice_pooled(&self, data: &[f32]) -> PooledBuffer {
        time_phase(Phase::Copy, || self.pool.acquire_with(data))
    }

    /// Create a buffer containing a single u32 value.
    fn buf_u32(&self, val: u32) -> Buffer {
        let data = [val];
        self.device.new_buffer_with_data(
            data.as_ptr() as *const _,
            std::mem::size_of::<u32>() as u64,
            MTLResourceOptions::StorageModeShared,
        )
    }

    /// Create a buffer containing a single f32 value.
    fn buf_f32(&self, val: f32) -> Buffer {
        let data = [val];
        self.device.new_buffer_with_data(
            data.as_ptr() as *const _,
            std::mem::size_of::<f32>() as u64,
            MTLResourceOptions::StorageModeShared,
        )
    }

    /// Get or create a cached buffer for persistent data (weight matrices).
    /// Keyed by (pointer, len) — weight Array2 data pointers are stable
    /// across forward passes, so this hits on every call after the first.
    fn buf_cached(&self, data: &[f32]) -> Buffer {
        let key = (data.as_ptr() as usize, data.len());
        let mut cache = self.weight_cache.lock();
        if let Some(buf) = cache.get(&key) {
            return buf.clone();
        }
        let buf = self.buf_from_slice(data);
        cache.insert(key, buf.clone());
        buf
    }

    /// Get or create a cached GPU buffer holding `weights` concatenated
    /// row-major in order. The weight Array2 data pointers are stable across
    /// forward passes, so the concatenation — built once — is keyed by the
    /// component (ptr, len) pairs and reused on every subsequent call. Used to
    /// fold the q/k/v (and gate/up) projections into one fat GEMM.
    fn buf_cached_concat(&self, weights: &[&[f32]]) -> Buffer {
        let key: Vec<(usize, usize)> = weights
            .iter()
            .map(|w| (w.as_ptr() as usize, w.len()))
            .collect();
        let mut cache = self.concat_cache.lock();
        if let Some(buf) = cache.get(&key) {
            return buf.clone();
        }
        let total: usize = weights.iter().map(|w| w.len()).sum();
        let mut concat = Vec::with_capacity(total);
        for w in weights {
            concat.extend_from_slice(w);
        }
        let buf = self.buf_from_slice(&concat);
        cache.insert(key, buf.clone());
        buf
    }

    /// Get or create a cached buffer for stable u32 payloads.
    fn buf_cached_u32(&self, data: &[u32]) -> Buffer {
        let key = (data.as_ptr() as usize, data.len());
        let mut cache = self.u32_cache.lock();
        if let Some(buf) = cache.get(&key) {
            return buf.clone();
        }
        let bytes = data.len() * std::mem::size_of::<u32>();
        let buf = self.device.new_buffer_with_data(
            data.as_ptr() as *const _,
            bytes as u64,
            MTLResourceOptions::StorageModeShared,
        );
        cache.insert(key, buf.clone());
        buf
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
            self.commit_bounded(cmd, Vec::new());
            cmd.wait_until_completed();
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
            self.commit_bounded(cmd, Vec::new());
            cmd.wait_until_completed();
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
            self.commit_bounded(cmd, Vec::new());
            cmd.wait_until_completed();
        });
    }

    /// Encode one MMA GEMM (`pipeline` is a `*_simdgroup` kernel) into `cmd`
    /// without committing. The MMA kernels REQUIRE full 32-lane simdgroups, so
    /// this uses `dispatch_thread_groups` with one 128-thread threadgroup per
    /// 32x32 output block, NOT `dispatch_threads`. `m`/`n`/`k` are the matmul
    /// dimensions; `depth` is the batch (head) count (1 for the 2D projections).
    #[allow(clippy::too_many_arguments)]
    fn encode_mma(
        cmd: &CommandBufferRef,
        pipeline: &ComputePipelineState,
        bufs: &[&Buffer],
        m: usize,
        n: usize,
        depth: usize,
    ) {
        const BM: usize = 32;
        const BN: usize = 32;
        let enc = cmd.new_compute_command_encoder();
        enc.set_compute_pipeline_state(pipeline);
        for (i, buf) in bufs.iter().enumerate() {
            enc.set_buffer(i as u64, Some(buf), 0);
        }
        let groups = MTLSize::new(
            n.div_ceil(BN) as u64,
            m.div_ceil(BM) as u64,
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
        pipeline_name: &str,
        bufs: &[&Buffer],
        m: usize,
        n: usize,
        depth: usize,
    ) {
        let _span = tracing::info_span!(
            "kin_infer.metal.dispatch_mma",
            pipeline = pipeline_name,
            m = m,
            n = n,
            depth = depth
        )
        .entered();
        let pipeline = &self.pipelines[pipeline_name];
        autoreleasepool(|_| {
            let cmd = self.queue.new_command_buffer();
            Self::encode_mma(cmd, pipeline, bufs, m, n, depth);
            self.commit_bounded(cmd, Vec::new());
            cmd.wait_until_completed();
        });
    }
}

impl GpuCompute for MetalCompute {
    fn matmul(&self, a: &[f32], b: &[f32], m: usize, n: usize, k: usize) -> Vec<f32> {
        let _span = tracing::info_span!("kin_infer.metal.matmul", m = m, n = n, k = k).entered();
        let buf_a = self.buf_slice_pooled(a);
        // Cache B (weight matrix): stable pointers across forward passes
        let buf_b = self.buf_cached(b);
        let buf_c = self.buf_zeros_pooled(m * n);
        let buf_m = self.buf_u32(m as u32);
        let buf_n = self.buf_u32(n as u32);
        let buf_k = self.buf_u32(k as u32);

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
                self.dispatch_mma("matmul_transb_simdgroup", &bufs, m, n, 1);
            } else {
                self.dispatch_2d("matmul_transb", &bufs, n, m);
            }
        });

        let out = Self::read_buf(buf_c.buffer(), m * n);
        Self::count_nonfinite(&format!("matmul m={m} n={n} k={k}"), &out);
        out
    }

    fn matmul_many(
        &self,
        a: &[f32],
        weights: &[&[f32]],
        m: usize,
        ns: &[usize],
        k: usize,
    ) -> Vec<Vec<f32>> {
        let _span = tracing::info_span!(
            "kin_infer.metal.matmul_many",
            m = m,
            k = k,
            outputs = weights.len()
        )
        .entered();
        if weights.is_empty() {
            return Vec::new();
        }

        // Fat GEMM: concatenate the weights row-major into one [sum_n, k] matrix
        // and run a SINGLE matmul producing [m, sum_n], then slice the output
        // columns back per weight. Column slices are independent outputs, so this
        // is numerically identical to the per-weight matmuls (no reassociation),
        // but it fills the GPU with one wide dispatch instead of several thin
        // ones. The concatenation is cached on the device by component pointers.
        let total_n: usize = ns.iter().sum();
        let buf_a = self.buf_slice_pooled(a);
        let buf_b = self.buf_cached_concat(weights);
        let buf_c = self.buf_zeros_pooled(m * total_n);
        let buf_m = self.buf_u32(m as u32);
        let buf_n = self.buf_u32(total_n as u32);
        let buf_k = self.buf_u32(k as u32);

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
                self.dispatch_mma("matmul_transb_simdgroup", &bufs, m, total_n, 1);
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
        outputs
    }

    fn batched_matmul(
        &self,
        q: &[f32],
        k: &[f32],
        num_heads: usize,
        seq_len: usize,
        head_dim: usize,
    ) -> Vec<f32> {
        let _span = tracing::info_span!(
            "kin_infer.metal.batched_matmul",
            num_heads = num_heads,
            seq_len = seq_len,
            head_dim = head_dim
        )
        .entered();
        // Single 3D dispatch: all heads computed in one GPU submission.
        let buf_q = self.buf_slice_pooled(q);
        let buf_k = self.buf_slice_pooled(k);
        let buf_c = self.buf_zeros_pooled(num_heads * seq_len * seq_len);
        let buf_seq = self.buf_u32(seq_len as u32);
        let buf_dim = self.buf_u32(head_dim as u32);

        // QK^T: m=seq, n=seq, k=head_dim.
        let bufs = [
            buf_q.buffer(),
            buf_k.buffer(),
            buf_c.buffer(),
            &buf_seq,
            &buf_dim,
        ];
        time_phase(Phase::Attention, || {
            if use_mma(seq_len, seq_len, head_dim) {
                self.dispatch_mma(
                    "batched_matmul_transb_simdgroup",
                    &bufs,
                    seq_len,
                    seq_len,
                    num_heads,
                );
            } else {
                self.dispatch_3d("batched_matmul_transb", &bufs, seq_len, seq_len, num_heads);
            }
        });

        Self::read_buf(buf_c.buffer(), num_heads * seq_len * seq_len)
    }

    fn batched_attn_values(
        &self,
        scores: &[f32],
        v: &[f32],
        num_heads: usize,
        seq_len: usize,
        head_dim: usize,
    ) -> Vec<f32> {
        let _span = tracing::info_span!(
            "kin_infer.metal.batched_attn_values",
            num_heads = num_heads,
            seq_len = seq_len,
            head_dim = head_dim
        )
        .entered();
        // Single 3D dispatch: scores[h] × V[h] for all heads.
        let buf_s = self.buf_slice_pooled(scores);
        let buf_v = self.buf_slice_pooled(v);
        let buf_c = self.buf_zeros_pooled(num_heads * seq_len * head_dim);
        let buf_seq = self.buf_u32(seq_len as u32);
        let buf_dim = self.buf_u32(head_dim as u32);

        // scores*V: m=seq, n=head_dim, k=seq.
        let bufs = [
            buf_s.buffer(),
            buf_v.buffer(),
            buf_c.buffer(),
            &buf_seq,
            &buf_dim,
        ];
        time_phase(Phase::Attention, || {
            if use_mma(seq_len, head_dim, seq_len) {
                self.dispatch_mma(
                    "batched_matmul_ab_simdgroup",
                    &bufs,
                    seq_len,
                    head_dim,
                    num_heads,
                );
            } else {
                self.dispatch_3d("batched_matmul_ab", &bufs, head_dim, seq_len, num_heads);
            }
        });

        Self::read_buf(buf_c.buffer(), num_heads * seq_len * head_dim)
    }

    fn softmax(&self, data: &mut [f32], rows: usize, cols: usize) {
        let _span =
            tracing::info_span!("kin_infer.metal.softmax", rows = rows, cols = cols).entered();
        Self::count_nonfinite(&format!("softmax_in rows={rows} cols={cols}"), data);
        let buf = self.buf_slice_pooled(data);
        let buf_cols = self.buf_u32(cols as u32);
        time_phase(Phase::Norm, || {
            self.dispatch_1d("softmax_rows", &[buf.buffer(), &buf_cols], rows)
        });
        Self::read_buf_into(buf.buffer(), data);
        Self::count_nonfinite(&format!("softmax_out rows={rows} cols={cols}"), data);
    }

    fn layer_norm(
        &self,
        data: &mut [f32],
        gamma: &[f32],
        beta: &[f32],
        rows: usize,
        cols: usize,
        eps: f32,
    ) {
        let _span = tracing::info_span!(
            "kin_infer.metal.layer_norm",
            rows = rows,
            cols = cols,
            eps = eps
        )
        .entered();
        let buf = self.buf_slice_pooled(data);
        let buf_gamma = self.buf_cached(gamma);
        let buf_beta = self.buf_cached(beta);
        let buf_cols = self.buf_u32(cols as u32);
        let buf_eps = self.buf_f32(eps);
        time_phase(Phase::Norm, || {
            self.dispatch_1d(
                "layer_norm",
                &[buf.buffer(), &buf_gamma, &buf_beta, &buf_cols, &buf_eps],
                rows,
            )
        });
        Self::read_buf_into(buf.buffer(), data);
        Self::count_nonfinite(&format!("layer_norm rows={rows} cols={cols}"), data);
    }

    fn rms_norm(&self, data: &mut [f32], weight: &[f32], rows: usize, cols: usize, eps: f32) {
        let _span = tracing::info_span!(
            "kin_infer.metal.rms_norm",
            rows = rows,
            cols = cols,
            eps = eps
        )
        .entered();
        let buf = self.buf_slice_pooled(data);
        let buf_weight = self.buf_cached(weight);
        let buf_cols = self.buf_u32(cols as u32);
        let buf_eps = self.buf_f32(eps);
        time_phase(Phase::Norm, || {
            self.dispatch_1d("rms_norm", &[buf.buffer(), &buf_weight, &buf_cols, &buf_eps], rows)
        });
        Self::read_buf_into(buf.buffer(), data);
    }

    fn gelu(&self, data: &mut [f32]) {
        let _span = tracing::info_span!("kin_infer.metal.gelu", len = data.len()).entered();
        Self::count_nonfinite(&format!("gelu_in len={}", data.len()), data);
        let buf = self.buf_slice_pooled(data);
        time_phase(Phase::Activation, || {
            self.dispatch_1d("gelu_activation", &[buf.buffer()], data.len())
        });
        Self::read_buf_into(buf.buffer(), data);
        Self::count_nonfinite(&format!("gelu_out len={}", data.len()), data);
    }

    fn silu(&self, data: &mut [f32]) {
        let _span = tracing::info_span!("kin_infer.metal.silu", len = data.len()).entered();
        let buf = self.buf_slice_pooled(data);
        time_phase(Phase::Activation, || {
            self.dispatch_1d("silu_activation", &[buf.buffer()], data.len())
        });
        Self::read_buf_into(buf.buffer(), data);
    }

    fn elementwise_mul(&self, a: &mut [f32], b: &[f32]) {
        let _span = tracing::info_span!("kin_infer.metal.elementwise_mul", len = a.len()).entered();
        let buf_a = self.buf_slice_pooled(a);
        let buf_b = self.buf_slice_pooled(b);
        time_phase(Phase::Activation, || {
            self.dispatch_1d("elementwise_mul", &[buf_a.buffer(), buf_b.buffer()], a.len())
        });
        Self::read_buf_into(buf_a.buffer(), a);
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
    ) -> Vec<f32> {
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
        let buf_x = self.buf_slice_pooled(x);
        let buf_wgateup = self.buf_cached_concat(&[w_gate, w_up]);
        let buf_wdown = self.buf_cached(w_down);
        let buf_gateup = self.buf_zeros_pooled(rows * 2 * inter);
        let buf_act = self.buf_zeros_pooled(rows * inter);
        let buf_out = self.buf_zeros_pooled(rows * hidden);
        let buf_rows = self.buf_u32(rows as u32);
        let buf_inter = self.buf_u32(inter as u32);
        let buf_two_inter = self.buf_u32((2 * inter) as u32);
        let buf_hidden = self.buf_u32(hidden as u32);

        let mm = &self.pipelines["matmul_transb"];
        let mm_mma = &self.pipelines["matmul_transb_simdgroup"];
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
                Self::encode_mma(cmd, mm_mma, &[buf_x.buffer(), &buf_wgateup, buf_gateup.buffer(), &buf_rows, &buf_two_inter, &buf_hidden], rows, 2 * inter, 1);
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
                Self::encode_mma(cmd, mm_mma, &[buf_act.buffer(), &buf_wdown, buf_out.buffer(), &buf_rows, &buf_hidden, &buf_inter], rows, hidden, 1);
            } else {
                Self::encode_matmul(cmd, mm, buf_act.buffer(), &buf_wdown, buf_out.buffer(), &buf_rows, &buf_hidden, &buf_inter, hidden, rows);
            }

            time_phase(Phase::Matmul, || {
                self.commit_bounded(cmd, Vec::new());
                cmd.wait_until_completed();
            });
            Self::read_buf(buf_out.buffer(), rows * hidden)
        });
        Self::count_nonfinite(&format!("fused_ffn_swiglu rows={rows} hidden={hidden} inter={inter}"), &out);
        out
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
    ) {
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

        let buf = self.buf_slice_pooled(data);
        let buf_cos = self.buf_cached(cos_table);
        let buf_sin = self.buf_cached(sin_table);
        let buf_offset = self.buf_u32(seq_offset as u32);
        let buf_head_dim = self.buf_u32(head_dim as u32);
        let buf_total_dim = self.buf_u32(total_dim as u32);
        let buf_half = self.buf_u32(half as u32);

        time_phase(Phase::Activation, || {
            self.dispatch_2d(
                "rope_apply",
                &[
                    buf.buffer(),
                    &buf_cos,
                    &buf_sin,
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
    ) {
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
        let buf_q = self.buf_slice_pooled(q);
        let buf_k = self.buf_slice_pooled(k);
        let buf_cos = self.buf_cached(cos_table);
        let buf_sin = self.buf_cached(sin_table);
        let buf_offset = self.buf_u32(seq_offset as u32);
        let buf_head_dim = self.buf_u32(head_dim as u32);
        let buf_total_dim = self.buf_u32(total_dim as u32);
        let buf_half = self.buf_u32(half as u32);

        let pipeline = &self.pipelines["rope_apply"];
        autoreleasepool(|_| {
            let cmd = self.queue.new_command_buffer();
            for data_buf in [buf_q.buffer(), buf_k.buffer()] {
                let enc = cmd.new_compute_command_encoder();
                enc.set_compute_pipeline_state(pipeline);
                enc.set_buffer(0, Some(data_buf), 0);
                enc.set_buffer(1, Some(&buf_cos), 0);
                enc.set_buffer(2, Some(&buf_sin), 0);
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
                self.commit_bounded(cmd, Vec::new());
                cmd.wait_until_completed();
            });
        });
        Self::read_buf_into(buf_q.buffer(), q);
        Self::read_buf_into(buf_k.buffer(), k);
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
    ) {
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
        let buf_q = self.buf_slice_pooled(q);
        let buf_k = self.buf_slice_pooled(k);
        let buf_cos = self.buf_cached(cos_table);
        let buf_sin = self.buf_cached(sin_table);
        let buf_max_len = self.buf_u32(max_len as u32);
        let buf_head_dim = self.buf_u32(head_dim as u32);
        let buf_total_dim = self.buf_u32(total_dim as u32);
        let buf_half = self.buf_u32(half as u32);
        let buf_actual = self.buf_u32(actual as u32);

        let pipeline = &self.pipelines["rope_apply_batched"];
        autoreleasepool(|_| {
            let cmd = self.queue.new_command_buffer();
            for data_buf in [buf_q.buffer(), buf_k.buffer()] {
                let enc = cmd.new_compute_command_encoder();
                enc.set_compute_pipeline_state(pipeline);
                enc.set_buffer(0, Some(data_buf), 0);
                enc.set_buffer(1, Some(&buf_cos), 0);
                enc.set_buffer(2, Some(&buf_sin), 0);
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
                self.commit_bounded(cmd, Vec::new());
                cmd.wait_until_completed();
            });
        });
        Self::read_buf_into(buf_q.buffer(), q);
        Self::read_buf_into(buf_k.buffer(), k);
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
    ) -> Vec<f32> {
        let _span = tracing::info_span!(
            "kin_infer.metal.fused_attention",
            num_heads = num_heads,
            seq_len = seq_len,
            head_dim = head_dim,
            has_alibi = !alibi_slopes.is_empty()
        )
        .entered();
        // All 4 ops in ONE command buffer — 1 commit+wait instead of 4.
        let buf_q = self.buf_slice_pooled(q);
        let buf_k = self.buf_slice_pooled(k);
        let buf_v = self.buf_slice_pooled(v);
        let buf_scores = self.buf_zeros_pooled(num_heads * seq_len * seq_len);
        let buf_out = self.buf_zeros_pooled(num_heads * seq_len * head_dim);
        let buf_seq = self.buf_u32(seq_len as u32);
        let buf_dim = self.buf_u32(head_dim as u32);
        let buf_scale = self.buf_f32(scale);
        let has_alibi = !alibi_slopes.is_empty();
        let buf_alibi = if has_alibi {
            self.buf_cached(alibi_slopes)
        } else {
            self.buf_from_slice(&[0.0f32])
        };
        let mask_u32: Vec<u32> = mask.to_vec();
        let buf_mask = self.buf_cached_u32(&mask_u32);
        let buf_has_alibi = self.buf_u32(has_alibi as u32);

        // All four ops + commit + readback inside one autorelease pool: the
        // command buffer and its encoders are autoreleased (+0) and would
        // otherwise accumulate on a pool-less worker thread across every layer.
        let out = autoreleasepool(|_| {
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
                ];
                if use_mma(seq_len, seq_len, head_dim) {
                    Self::encode_mma(
                        cmd,
                        &self.pipelines["batched_matmul_transb_simdgroup"],
                        &qk_bufs,
                        seq_len,
                        seq_len,
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
                enc.set_buffer(1, Some(&buf_alibi), 0);
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
                let buf_cols = self.buf_u32(seq_len as u32);
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
                ];
                if use_mma(seq_len, head_dim, seq_len) {
                    Self::encode_mma(
                        cmd,
                        &self.pipelines["batched_matmul_ab_simdgroup"],
                        &av_bufs,
                        seq_len,
                        head_dim,
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
                    self.commit_bounded(cmd, Vec::new());
                    cmd.wait_until_completed();
                });
            }

            Self::read_buf(buf_out.buffer(), num_heads * seq_len * head_dim)
        });
        Self::count_nonfinite(
            &format!("fused_attention seq_len={seq_len} num_heads={num_heads}"),
            &out,
        );
        out
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
    ) -> Vec<f32> {
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
        let buf_q = self.buf_slice_pooled(q);
        let buf_k = self.buf_slice_pooled(k);
        let buf_v = self.buf_slice_pooled(v);
        let buf_scores = self.buf_zeros_pooled(total_heads * seq_len * seq_len);
        let buf_out = self.buf_zeros_pooled(total_heads * seq_len * head_dim);
        let buf_seq = self.buf_u32(seq_len as u32);
        let buf_dim = self.buf_u32(head_dim as u32);
        let buf_scale = self.buf_f32(scale);
        let has_alibi = !alibi_slopes.is_empty();
        let buf_alibi = if has_alibi {
            self.buf_cached(alibi_slopes)
        } else {
            self.buf_from_slice(&[0.0f32])
        };
        let buf_masks = self.buf_cached_u32(masks);
        let buf_has_alibi = self.buf_u32(has_alibi as u32);
        let buf_heads_per_group = self.buf_u32(heads_per_group as u32);

        // All four ops + commit + readback inside one autorelease pool: the
        // command buffer and its encoders are autoreleased (+0) and would
        // otherwise accumulate on a pool-less worker thread across every layer
        // of every batch — the heaviest contributor in a large cold embed.
        let out = autoreleasepool(|_| {
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
                ];
                if use_mma(seq_len, seq_len, head_dim) {
                    Self::encode_mma(
                        cmd,
                        &self.pipelines["batched_matmul_transb_simdgroup"],
                        &qk_bufs,
                        seq_len,
                        seq_len,
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
                enc.set_buffer(1, Some(&buf_alibi), 0);
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
                let buf_cols = self.buf_u32(seq_len as u32);
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
                ];
                if use_mma(seq_len, head_dim, seq_len) {
                    Self::encode_mma(
                        cmd,
                        &self.pipelines["batched_matmul_ab_simdgroup"],
                        &av_bufs,
                        seq_len,
                        head_dim,
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
                    self.commit_bounded(cmd, Vec::new());
                    cmd.wait_until_completed();
                });
            }

            Self::read_buf(buf_out.buffer(), total_heads * seq_len * head_dim)
        });
        Self::count_nonfinite(
            &format!(
                "fused_attention_batched seq_len={seq_len} total_heads={total_heads}"
            ),
            &out,
        );
        out
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
            metal.rope_pair(&mut qb, &mut kb, &cos, &sin, 0, actual, head_dim, total_dim);
            q_ref[base..base + rows].copy_from_slice(&qb);
            k_ref[base..base + rows].copy_from_slice(&kb);
        }

        // Candidate: single-dispatch rope_pair_batched.
        let mut q_bat = q0.clone();
        let mut k_bat = k0.clone();
        metal.rope_pair_batched(
            &mut q_bat, &mut k_bat, &cos, &sin, batch_size, max_len, actual, head_dim, total_dim,
        );

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
        let c = metal.matmul(&a, &b, 2, 2, 3);
        assert!((c[0] - 50.0).abs() < 1e-3, "got {}", c[0]);
        assert!((c[1] - 68.0).abs() < 1e-3, "got {}", c[1]);
        assert!((c[2] - 122.0).abs() < 1e-3, "got {}", c[2]);
        assert!((c[3] - 167.0).abs() < 1e-3, "got {}", c[3]);
    }

    #[test]
    fn test_metal_softmax() {
        let Some(metal) = get_metal() else { return };
        let mut data = vec![1.0, 2.0, 3.0];
        metal.softmax(&mut data, 1, 3);
        let sum: f32 = data.iter().sum();
        assert!((sum - 1.0).abs() < 1e-4, "sum={}", sum);
    }

    #[test]
    fn test_metal_gelu() {
        let Some(metal) = get_metal() else { return };
        let mut data = vec![0.0, 1.0, -1.0];
        metal.gelu(&mut data);
        assert!(data[0].abs() < 1e-5);
        assert!((data[1] - 0.8413).abs() < 0.01);
    }

    #[test]
    fn test_metal_layer_norm() {
        let Some(metal) = get_metal() else { return };
        let mut data = vec![1.0, 2.0, 3.0, 4.0];
        let gamma = vec![1.0; 4];
        let beta = vec![0.0; 4];
        metal.layer_norm(&mut data, &gamma, &beta, 1, 4, 1e-5);
        let mean: f32 = data.iter().sum::<f32>() / 4.0;
        assert!(mean.abs() < 1e-3, "mean={}", mean);
    }

    #[test]
    fn test_metal_silu() {
        let Some(metal) = get_metal() else { return };
        let mut data = vec![0.0, 1.0];
        metal.silu(&mut data);
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

        let c_metal = metal.matmul(&a, &b, m, n, k);
        let c_cpu = cpu.matmul(&a, &b, m, n, k);

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

        let scores_metal = metal.batched_matmul(&q, &k, num_heads, seq_len, head_dim);
        let scores_cpu = cpu.batched_matmul(&q, &k, num_heads, seq_len, head_dim);

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

        let out_metal = metal.batched_attn_values(&scores, &v, num_heads, seq_len, head_dim);
        let out_cpu = cpu.batched_attn_values(&scores, &v, num_heads, seq_len, head_dim);

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

        let many = metal.matmul_many(&a, &[&b0, &b1, &b2], m, &[n, n, n], k);
        let single = vec![
            metal.matmul(&a, &b0, m, n, k),
            metal.matmul(&a, &b1, m, n, k),
            metal.matmul(&a, &b2, m, n, k),
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
