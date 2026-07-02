// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Metal GPU compute backend for macOS (Apple Silicon).
//!
//! Custom MSL compute shaders for transformer operations.
//! No candle, no ONNX, no MPS — direct Metal API via objc2-metal.

#![cfg(feature = "metal")]

use crate::gpu::{
    EmbeddingPrelude, GpuBackend, GpuCompute, GpuDeviceInfo, LayerConfig, LayerTensors, PoolingMode,
};
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
// counter on every commit and accumulates the wall-clock the host spends PARKED
// on the in-flight backpressure condvar. `commit_wait` adds the explicit
// `wait_until_completed` boundary, so benchmarks can report both command-buffer
// count and host-blocked time while we collapse per-op round-trips.

static STALL_NANOS: AtomicU64 = AtomicU64::new(0);
static SUBMISSIONS: AtomicU64 = AtomicU64::new(0);
static ROUND_TRIPS: AtomicU64 = AtomicU64::new(0);
static FORWARD_CALLS: AtomicU64 = AtomicU64::new(0);

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

// In-process GPU utilization. `GPU_BUSY_NANOS` accumulates every command
// buffer's on-GPU execution window (`GPUStartTime`/`GPUEndTime`) across BOTH the
// synchronous `commit_wait` path AND the async `commit_bounded` completion
// handler — so deferred-readback pipelined submissions, which never block the
// host, still contribute their GPU-busy time. Divided by the wall-clock since
// `reset_profile` (the `UtilSampler.anchor` below), this is a graph-native,
// in-process util% — the trustworthy alternative to the harness's external
// `ioreg` "Device Utilization %" sampler. Only written when `profile_enabled()`;
// relaxed atomics + a lock taken only on the completion boundary, zero cost off.
static GPU_BUSY_NANOS: AtomicU64 = AtomicU64::new(0);

// Fixed-window utilization bucketer for the MEDIAN util%, mirroring the external
// sampler (which medians fixed-interval samples rather than reporting one global
// ratio). Each command buffer's GPU-busy window is attributed — split across
// boundaries — into `UTIL_WINDOW_NANOS`-wide wall-clock buckets measured from the
// reset anchor; `profile_gpu_util_median_pct` then medians the per-bucket
// busy-fraction. A median resists a single front/tail-loaded burst skewing the
// aggregate ratio. Guarded by the same `profile_enabled()` gate.
const UTIL_WINDOW_NANOS: u64 = 50_000_000; // 50ms sampling window

thread_local! {
    // The phase whose GPU command buffers should be attributed at the next
    // commit/wait boundary. Set by `time_phase` for the duration of its closure
    // (save/restore so nested phases compose), read by `commit_wait`. Only
    // touched when `profile_enabled()`.
    static CURRENT_PHASE: std::cell::Cell<Option<Phase>> = const { std::cell::Cell::new(None) };
}

/// Wall-clock + per-window state for in-process GPU-util sampling. Kept behind a
/// single `Mutex` because `Instant` and the per-window busy-ns vector are not
/// atomics; only touched on `reset_profile` and on each command-buffer completion
/// boundary, and only when `profile_enabled()`, so the lock is never on a hot
/// per-element path.
struct UtilSampler {
    /// Wall-clock origin set by the last `reset_profile`. `None` until the first
    /// reset, in which case util% reads as 0 (no timed region established).
    anchor: Option<std::time::Instant>,
    /// GPU-busy nanoseconds accumulated per fixed `UTIL_WINDOW_NANOS` wall window,
    /// indexed by window number measured from `anchor`. Grown sparsely as buffers
    /// complete; a window with no GPU work stays implicitly 0.
    windows: Vec<u64>,
}

impl UtilSampler {
    const fn new() -> Self {
        UtilSampler {
            anchor: None,
            windows: Vec::new(),
        }
    }

    /// Attribute a command buffer's GPU-busy window `[start_ns, end_ns)` (both
    /// measured from `anchor`) across the fixed wall-clock buckets it overlaps, so
    /// a buffer that straddles a window boundary contributes to each window in
    /// proportion to its overlap — the same accounting a fixed-interval external
    /// sampler would produce. No-op if no anchor is set or the window is empty.
    fn attribute(&mut self, start_ns: u64, busy_ns: u64) {
        if self.anchor.is_none() || busy_ns == 0 {
            return;
        }
        let end_ns = start_ns.saturating_add(busy_ns);
        let mut cursor = start_ns;
        while cursor < end_ns {
            let window_idx = (cursor / UTIL_WINDOW_NANOS) as usize;
            let window_end = (window_idx as u64 + 1) * UTIL_WINDOW_NANOS;
            let slice_end = end_ns.min(window_end);
            let slice = slice_end - cursor;
            if window_idx >= self.windows.len() {
                self.windows.resize(window_idx + 1, 0);
            }
            self.windows[window_idx] = self.windows[window_idx].saturating_add(slice);
            cursor = slice_end;
        }
    }
}

fn util_sampler() -> &'static Mutex<UtilSampler> {
    use std::sync::OnceLock;
    static SAMPLER: OnceLock<Mutex<UtilSampler>> = OnceLock::new();
    SAMPLER.get_or_init(|| Mutex::new(UtilSampler::new()))
}

/// Record a completed command buffer's GPU-busy time into the total
/// [`GPU_BUSY_NANOS`] accumulator and the fixed-window median sampler. Called
/// from both the synchronous (`commit_wait`) and asynchronous (`commit_bounded`
/// completion handler) boundaries so the pipelined, deferred-readback path is
/// counted too. The window position uses the host monotonic clock (`now -
/// anchor`) — the same timebase as the reset anchor — rather than the GPU's
/// separate `GPUStartTime` clock, so the busy window is placed where the host
/// observed it complete (accurate well within a 50ms window). No-op when
/// profiling is off or the GPU window is degenerate.
#[inline]
fn record_gpu_busy(cmd: &CommandBufferRef) {
    if !profile_enabled() {
        return;
    }
    let busy_ns = cmd_gpu_nanos(cmd);
    if busy_ns == 0 {
        return;
    }
    GPU_BUSY_NANOS.fetch_add(busy_ns, Ordering::Relaxed);
    let mut sampler = util_sampler().lock();
    if let Some(anchor) = sampler.anchor {
        // Place the busy window so it ENDS at the observed completion instant.
        let end_ns = anchor.elapsed().as_nanos() as u64;
        let start_ns = end_ns.saturating_sub(busy_ns);
        sampler.attribute(start_ns, busy_ns);
    }
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
    mma_enabled() && MMA_AVAILABLE.load(Ordering::Relaxed) && m >= 32 && n >= 32 && k >= 16
}

/// Whether the wider 64x64 MMA tile is selected. Selected by the throughput
/// resource profile (the kernel is numerically identical to the 32x32 MMA);
/// `KIN_INFER_MMA_WIDE=1/0` overrides the profile in either direction. Off
/// everywhere else, including proof, so the bit-identical path is untouched.
/// Sampled once per process.
fn mma_wide_enabled() -> bool {
    use std::sync::OnceLock;
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        crate::resource::env_flag_override("KIN_INFER_MMA_WIDE")
            .unwrap_or_else(|| crate::resource::active_gpu_kernel_plan().mma_wide)
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

/// Whether the fp16-operand MMA path is selected. Selected by the throughput
/// resource profile; `KIN_INFER_GEMM_FP16=1/0` overrides the profile in either
/// direction. fp16 operands lose ~half the mantissa, so this is a throughput-only
/// path and stays off under proof (the bit-identical fp32 MMA). Sampled once per
/// process; gates whether the separate fp16 shader library is compiled in
/// `try_new`.
fn mma_fp16_enabled() -> bool {
    use std::sync::OnceLock;
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        crate::resource::env_flag_override("KIN_INFER_GEMM_FP16")
            .unwrap_or_else(|| crate::resource::active_gpu_kernel_plan().gemm_fp16)
    })
}

/// Whether the fp16 MMA pipelines compiled on this device. Set once by `try_new`
/// after compiling the SEPARATE fp16 shader library. Defaults false: if the
/// heterogeneous half*half->float overload is rejected by the toolchain (the
/// fp16 library fails to build), this stays false and every GEMM uses the fp32
/// MMA — Metal and the main library are unaffected.
static FP16_MMA_AVAILABLE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Whether the fp16-operand WIDE (64x64) projection-GEMM pipeline compiled
/// (Lever #5 phase 2). Gated separately from [`FP16_MMA_AVAILABLE`] so a
/// composed-tile pipeline failure only disables the composed path; the proven
/// 32x32 fp16 MMA stays available.
static WIDE_FP16_MMA_AVAILABLE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Route a GEMM to the fp16-operand MMA tile only when it is opt-in enabled, the
/// fp16 pipelines compiled, AND the standard MMA gate already passes. The base
/// fp16 variants are 32x32; the fp16 + 64x64 composition (Lever #5 phase 2) is
/// preferred for the projection GEMM via [`use_fp16_wide_mma`] when both flags
/// are set, and this 32x32 path is the fallback for the remaining shapes.
#[inline]
fn use_fp16_mma(m: usize, n: usize, k: usize) -> bool {
    mma_fp16_enabled() && FP16_MMA_AVAILABLE.load(Ordering::Relaxed) && use_mma(m, n, k)
}

/// Route the projection GEMM to the fp16-operand 64x64 tile only when BOTH fp16
/// and wide are opt-in enabled, the composed pipeline compiled, the standard MMA
/// gate passes, AND the output fills the 64x64 tile. fp32 accumulate is unchanged
/// (same parity invariant as the fp32 wide and 32x32 fp16 paths).
#[inline]
fn use_fp16_wide_mma(m: usize, n: usize, k: usize) -> bool {
    mma_fp16_enabled()
        && mma_wide_enabled()
        && WIDE_FP16_MMA_AVAILABLE.load(Ordering::Relaxed)
        && use_mma(m, n, k)
        && m >= 64
        && n >= 64
}

/// Whether the C7 flash-attention path is selected. Default OFF: selected only
/// by the resource plan or `KIN_INFER_FLASH_ATTENTION=1`. Runtime dispatch still
/// requires the optional C7 library to compile and the shape gate to pass.
fn c7_flash_attention_enabled() -> bool {
    use std::sync::OnceLock;
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        crate::resource::env_flag_override("KIN_INFER_FLASH_ATTENTION")
            .unwrap_or_else(|| crate::resource::active_gpu_kernel_plan().flash_attention)
    })
}

/// Whether the optional C7 flash-attention pipelines compiled on this device.
/// Defaults false so the baseline Metal attention path stays authoritative when
/// C7 is disabled, absent, or rejected by the Metal toolchain.
static C7_FLASH_ATTENTION_AVAILABLE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Route only conservative shapes through the optional C7 fused-attention path.
/// The first C7 cut is default-off and parity-first: it supports the public
/// head-major batched attention layout and grouped masks, while ALiBi and
/// resident-stack routing stay on the proven baseline until direct parity clears.
#[inline]
fn c7_flash_attention_shape_supported(
    num_groups: usize,
    seq_len: usize,
    head_dim: usize,
    heads_per_group: usize,
    has_alibi: bool,
    scale: f32,
    masks: &[u32],
) -> bool {
    num_groups > 0
        && seq_len > 0
        && head_dim > 0
        && heads_per_group > 0
        && !has_alibi
        && scale.is_finite()
        && (64..=1024).contains(&seq_len)
        && matches!(head_dim, 32 | 64)
        && num_groups.checked_mul(seq_len) == Some(masks.len())
        && masks
            .chunks(seq_len)
            .all(|group_mask| group_mask.iter().any(|&keep| keep != 0))
}

#[inline]
fn use_c7_flash_attention(
    num_groups: usize,
    seq_len: usize,
    head_dim: usize,
    heads_per_group: usize,
    has_alibi: bool,
    scale: f32,
    masks: &[u32],
) -> bool {
    c7_flash_attention_enabled()
        && C7_FLASH_ATTENTION_AVAILABLE.load(Ordering::Relaxed)
        && c7_flash_attention_shape_supported(
            num_groups,
            seq_len,
            head_dim,
            heads_per_group,
            has_alibi,
            scale,
            masks,
        )
}

/// Whether the steel double-buffered K-loop MMA path is selected. The steel
/// kernels overlap the next K-tile's global load with the current tile's MMA
/// (2-stage software pipeline) but are numerically IDENTICAL to the single-buffer
/// path (same fp32 accumulate, same per-fragment 8-wide reduction order — only
/// WHEN the loads are issued changes). Selected by the throughput resource
/// profile; `KIN_INFER_STEEL=1/0` overrides the profile in either direction. Off
/// under proof. Sampled once per process.
fn steel_enabled() -> bool {
    use std::sync::OnceLock;
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        crate::resource::env_flag_override("KIN_INFER_STEEL")
            .unwrap_or_else(|| crate::resource::active_gpu_kernel_plan().steel)
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

/// Total nanoseconds the host spent blocked by Metal submission backpressure or
/// explicit `wait_until_completed` calls since the last `reset_profile`. Only
/// meaningful when `KIN_INFER_METAL_PROFILE` is set.
pub fn profile_stall_nanos() -> u64 {
    STALL_NANOS.load(Ordering::Relaxed)
}

/// Alias for the total host-blocked time reported in the Metal profile output.
pub fn profile_host_blocked_nanos() -> u64 {
    STALL_NANOS.load(Ordering::Relaxed)
}

/// Number of GPU command-buffer submissions since the last reset.
pub fn profile_submissions() -> u64 {
    SUBMISSIONS.load(Ordering::Relaxed)
}

/// Number of blocking host↔GPU completion waits since the last reset.
pub fn profile_round_trips() -> u64 {
    ROUND_TRIPS.load(Ordering::Relaxed)
}

/// Number of model forward boundaries since the last reset.
pub fn profile_forward_calls() -> u64 {
    FORWARD_CALLS.load(Ordering::Relaxed)
}

/// Record model forward boundaries so profile output can normalize round-trips
/// and host-blocked time per forward without inferring from corpus size.
pub fn record_forward_calls(count: usize) {
    if count > 0 && profile_enabled() {
        FORWARD_CALLS.fetch_add(count as u64, Ordering::Relaxed);
    }
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

/// Total nanoseconds the GPU spent EXECUTING command buffers since the last
/// `reset_profile`, summed from every buffer's `GPUStartTime`/`GPUEndTime` across
/// both the synchronous and deferred-readback submission paths. Only meaningful
/// when `KIN_INFER_METAL_PROFILE` is set. The numerator of the in-process util%.
pub fn profile_gpu_busy_nanos() -> u64 {
    GPU_BUSY_NANOS.load(Ordering::Relaxed)
}

/// Wall-clock nanoseconds elapsed since the last `reset_profile`, measured on the
/// host monotonic clock (the same anchor the util windows use). 0 until the first
/// reset establishes a timed region. The denominator of the aggregate util%.
pub fn profile_wall_nanos() -> u64 {
    util_sampler()
        .lock()
        .anchor
        .map(|a| a.elapsed().as_nanos() as u64)
        .unwrap_or(0)
}

/// In-process GPU utilization since the last `reset_profile`, as a percentage in
/// `[0, 100]`: total GPU-busy time / wall-clock time. This is the graph-native,
/// in-process answer to "is the GPU saturated" — computed from Metal's own
/// per-command-buffer execution timestamps rather than the harness's external
/// `ioreg` "Device Utilization %" sampler. Pipelined, deferred-readback
/// submissions are included (they are attributed in the completion handler), so a
/// well-pipelined forward that keeps several command buffers in flight reads near
/// 100% even though no single host thread is ever blocked on the GPU. Returns 0.0
/// when profiling is off or no timed region has run. Clamped to 100 because the
/// busy windows of concurrently in-flight buffers can overlap in wall time.
pub fn profile_gpu_util_pct() -> f64 {
    let busy = GPU_BUSY_NANOS.load(Ordering::Relaxed);
    let wall = profile_wall_nanos();
    if wall == 0 {
        return 0.0;
    }
    (busy as f64 / wall as f64 * 100.0).min(100.0)
}

/// Median per-window GPU utilization (%) since the last `reset_profile`, the
/// in-process analog of the external sampler's median-of-fixed-interval-samples.
/// Each `UTIL_WINDOW_NANOS`-wide wall window from the reset anchor up to now
/// (including trailing windows with no GPU work, counted as 0%) yields one
/// busy-fraction sample; the median of those samples is returned, clamped to
/// `[0, 100]`. A median resists a single front- or tail-loaded burst inflating
/// the aggregate ratio, so it is the honest "sustained saturation" number the
/// ≥80% gate wants. Returns 0.0 when profiling is off or no window has elapsed.
pub fn profile_gpu_util_median_pct() -> f64 {
    let sampler = util_sampler().lock();
    let Some(anchor) = sampler.anchor else {
        return 0.0;
    };
    // Number of fully- or partially-elapsed windows in the timed region, so a run
    // that idled the GPU late still contributes those windows as 0% samples.
    let elapsed_ns = anchor.elapsed().as_nanos() as u64;
    let window_count = (elapsed_ns / UTIL_WINDOW_NANOS + 1) as usize;
    if window_count == 0 {
        return 0.0;
    }
    let mut samples: Vec<f64> = (0..window_count)
        .map(|i| {
            let busy = sampler.windows.get(i).copied().unwrap_or(0);
            (busy as f64 / UTIL_WINDOW_NANOS as f64 * 100.0).min(100.0)
        })
        .collect();
    drop(sampler);
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let mid = samples.len() / 2;
    if samples.len().is_multiple_of(2) {
        (samples[mid - 1] + samples[mid]) / 2.0
    } else {
        samples[mid]
    }
}

/// Zero the host-stall and per-phase accumulators. Call before a timed region.
pub fn reset_profile() {
    STALL_NANOS.store(0, Ordering::Relaxed);
    SUBMISSIONS.store(0, Ordering::Relaxed);
    ROUND_TRIPS.store(0, Ordering::Relaxed);
    FORWARD_CALLS.store(0, Ordering::Relaxed);
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
    // In-process util%: zero the busy accumulator, drop prior windows, and start
    // the wall-clock anchor NOW so util% covers exactly the upcoming timed region.
    GPU_BUSY_NANOS.store(0, Ordering::Relaxed);
    {
        let mut sampler = util_sampler().lock();
        sampler.windows.clear();
        sampler.anchor = Some(std::time::Instant::now());
    }
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
    uint3 tgid, uint sgid, uint lane, uint tpsg,
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
    const uint tid = sgid * tpsg + lane;  // flat thread index 0..127

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
                for (uint e = lane; e < F * F; e += tpsg) {
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
    uint  lane             [[thread_index_in_simdgroup]],
    uint  tpsg             [[threads_per_simdgroup]])
{
    threadgroup float As[MMA_BM][MMA_BK];
    threadgroup float Bs[MMA_BN][MMA_BK];
    threadgroup float store_tile[MMA_WM * MMA_WN][MMA_F][MMA_F];
    block_mma<true>(A, B, C, M, N, K, tgid, sgid, lane, tpsg, As, Bs, store_tile);
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
    uint  lane             [[thread_index_in_simdgroup]],
    uint  tpsg             [[threads_per_simdgroup]])
{
    uint h = tgid.z;
    uint kv_h = h / hpg;
    device const float* Ah = Q  + h * seq * dim;
    device const float* Bh = Kk + kv_h * seq * dim;
    device float*       Ch = C  + h * seq * seq;
    threadgroup float As[MMA_BM][MMA_BK];
    threadgroup float Bs[MMA_BN][MMA_BK];
    threadgroup float store_tile[MMA_WM * MMA_WN][MMA_F][MMA_F];
    block_mma<true>(Ah, Bh, Ch, seq, seq, dim, uint3(tgid.x, tgid.y, 0), sgid, lane, tpsg, As, Bs, store_tile);
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
    uint  lane             [[thread_index_in_simdgroup]],
    uint  tpsg             [[threads_per_simdgroup]])
{
    uint h = tgid.z;
    uint kv_h = h / hpg;
    device const float* Ah = S + h * seq * seq;
    device const float* Bh = V + kv_h * seq * dim;
    device float*       Ch = C + h * seq * dim;
    threadgroup float As[MMA_BM][MMA_BK];
    threadgroup float Bs[MMA_BN][MMA_BK];
    threadgroup float store_tile[MMA_WM * MMA_WN][MMA_F][MMA_F];
    block_mma<false>(Ah, Bh, Ch, seq, dim, seq, uint3(tgid.x, tgid.y, 0), sgid, lane, tpsg, As, Bs, store_tile);
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
    uint  lane             [[thread_index_in_simdgroup]],
    uint  tpsg             [[threads_per_simdgroup]])
{
    threadgroup float As[64][MMA_BK];
    threadgroup float Bs[64][MMA_BK];
    threadgroup float store_tile[MMA_WM * MMA_WN][MMA_F][MMA_F];
    block_mma<true, 64, 64>(A, B, C, M, N, K, tgid, sgid, lane, tpsg, As, Bs, store_tile);
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
    uint  lane             [[thread_index_in_simdgroup]],
    uint  tpsg             [[threads_per_simdgroup]])
{
    uint h = tgid.z;
    uint kv_h = h / hpg;
    device const float* Ah = Q  + h * seq * dim;
    device const float* Bh = Kk + kv_h * seq * dim;
    device float*       Ch = C  + h * seq * seq;
    threadgroup float As[64][MMA_BK];
    threadgroup float Bs[64][MMA_BK];
    threadgroup float store_tile[MMA_WM * MMA_WN][MMA_F][MMA_F];
    block_mma<true, 64, 64>(Ah, Bh, Ch, seq, seq, dim, uint3(tgid.x, tgid.y, 0), sgid, lane, tpsg, As, Bs, store_tile);
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
    uint  lane             [[thread_index_in_simdgroup]],
    uint  tpsg             [[threads_per_simdgroup]])
{
    uint h = tgid.z;
    uint kv_h = h / hpg;
    device const float* Ah = S + h * seq * seq;
    device const float* Bh = V + kv_h * seq * dim;
    device float*       Ch = C + h * seq * dim;
    threadgroup float As[64][MMA_BK];
    threadgroup float Bs[64][MMA_BK];
    threadgroup float store_tile[MMA_WM * MMA_WN][MMA_F][MMA_F];
    block_mma<false, 64, 64>(Ah, Bh, Ch, seq, dim, seq, uint3(tgid.x, tgid.y, 0), sgid, lane, tpsg, As, Bs, store_tile);
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
    uint3 tgid, uint sgid, uint lane, uint tpsg,
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
    const uint tid = sgid * tpsg + lane;  // flat thread index 0..127

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
                for (uint e = lane; e < F * F; e += tpsg) {
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
    uint  lane             [[thread_index_in_simdgroup]],
    uint  tpsg             [[threads_per_simdgroup]])
{
    threadgroup float As[2][32][MMA_BK];
    threadgroup float Bs[2][32][MMA_BK];
    threadgroup float store_tile[MMA_WM * MMA_WN][MMA_F][MMA_F];
    block_mma_db<true>(A, B, C, M, N, K, tgid, sgid, lane, tpsg, As, Bs, store_tile);
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
    uint  lane             [[thread_index_in_simdgroup]],
    uint  tpsg             [[threads_per_simdgroup]])
{
    uint h = tgid.z;
    uint kv_h = h / hpg;
    device const float* Ah = Q  + h * seq * dim;
    device const float* Bh = Kk + kv_h * seq * dim;
    device float*       Ch = C  + h * seq * seq;
    threadgroup float As[2][32][MMA_BK];
    threadgroup float Bs[2][32][MMA_BK];
    threadgroup float store_tile[MMA_WM * MMA_WN][MMA_F][MMA_F];
    block_mma_db<true>(Ah, Bh, Ch, seq, seq, dim, uint3(tgid.x, tgid.y, 0), sgid, lane, tpsg, As, Bs, store_tile);
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
    uint  lane             [[thread_index_in_simdgroup]],
    uint  tpsg             [[threads_per_simdgroup]])
{
    uint h = tgid.z;
    uint kv_h = h / hpg;
    device const float* Ah = S + h * seq * seq;
    device const float* Bh = V + kv_h * seq * dim;
    device float*       Ch = C + h * seq * dim;
    threadgroup float As[2][32][MMA_BK];
    threadgroup float Bs[2][32][MMA_BK];
    threadgroup float store_tile[MMA_WM * MMA_WN][MMA_F][MMA_F];
    block_mma_db<false>(Ah, Bh, Ch, seq, dim, seq, uint3(tgid.x, tgid.y, 0), sgid, lane, tpsg, As, Bs, store_tile);
}

// ---- Softmax over rows (SIMD-reduced) ----
// 1 threadgroup (size tw) per row.
kernel void softmax_rows(
    device float* data          [[buffer(0)]],
    constant uint& cols         [[buffer(1)]],
    uint tgid                   [[threadgroup_position_in_grid]],
    uint tiitg                  [[thread_index_in_threadgroup]],
    uint tptg                   [[threads_per_threadgroup]]
) {
    uint row_offset = tgid * cols;

    // Find max
    float max_val = -INFINITY;
    for (uint j = tiitg; j < cols; j += tptg) {
        max_val = max(max_val, data[row_offset + j]);
    }
    max_val = simd_max(max_val);

    // Fully-masked row (every score is -inf): emit zeros instead of computing
    // exp(-inf - -inf) = NaN, which the sum>0 guard below cannot scrub.
    if (!isfinite(max_val)) {
        for (uint j = tiitg; j < cols; j += tptg) {
            data[row_offset + j] = 0.0;
        }
        return;
    }

    // Exp and sum
    float sum = 0.0;
    for (uint j = tiitg; j < cols; j += tptg) {
        float v = exp(data[row_offset + j] - max_val);
        data[row_offset + j] = v;
        sum += v;
    }
    sum = simd_sum(sum);

    // Normalize
    if (sum > 0.0) {
        float inv_sum = 1.0 / sum;
        for (uint j = tiitg; j < cols; j += tptg) {
            data[row_offset + j] *= inv_sum;
        }
    }
}

// Pool final hidden states to one embedding per input.
// Lane 0 intentionally follows the host pooling/reduction order for parity.
kernel void pool_rows(
    device const float* hidden   [[buffer(0)]],
    device const uint*  masks    [[buffer(1)]],
    device float*       out      [[buffer(2)]],
    constant uint& max_len       [[buffer(3)]],
    constant uint& hidden_size   [[buffer(4)]],
    constant uint& cls_pooling   [[buffer(5)]],
    uint batch                   [[threadgroup_position_in_grid]],
    uint lane                    [[thread_index_in_threadgroup]]
) {
    if (lane != 0) {
        return;
    }
    uint base_row = batch * max_len;
    uint out_base = batch * hidden_size;
    uint count = 0;
    if (cls_pooling == 0) {
        for (uint s = 0; s < max_len; s++) {
            count += masks[base_row + s] != 0 ? 1 : 0;
        }
    }
    float denom = count > 0 ? float(count) : 1.0;

    for (uint j = 0; j < hidden_size; j++) {
        float v = 0.0;
        if (cls_pooling != 0) {
            v = hidden[base_row * hidden_size + j];
        } else {
            for (uint s = 0; s < max_len; s++) {
                if (masks[base_row + s] != 0) {
                    v += hidden[(base_row + s) * hidden_size + j];
                }
            }
            v /= denom;
        }
        out[out_base + j] = v;
    }
}

// ---- LayerNorm (SIMD-reduced) ----
// 1 threadgroup (size tw) per row.
kernel void layer_norm(
    device float* data          [[buffer(0)]],
    device const float* gamma   [[buffer(1)]],
    device const float* beta    [[buffer(2)]],
    constant uint& cols         [[buffer(3)]],
    constant float& eps         [[buffer(4)]],
    uint tgid                   [[threadgroup_position_in_grid]],
    uint tiitg                  [[thread_index_in_threadgroup]],
    uint tptg                   [[threads_per_threadgroup]]
) {
    uint off = tgid * cols;
    float len = float(cols);

    // Mean
    float local_sum = 0.0;
    for (uint j = tiitg; j < cols; j += tptg) local_sum += data[off + j];
    float mean = simd_sum(local_sum) / len;

    // Variance
    float local_var = 0.0;
    for (uint j = tiitg; j < cols; j += tptg) {
        float d = data[off + j] - mean;
        local_var += d * d;
    }
    float var = simd_sum(local_var) / len;

    float inv_std = rsqrt(var + eps);
    for (uint j = tiitg; j < cols; j += tptg) {
        data[off + j] = (data[off + j] - mean) * inv_std * gamma[j] + beta[j];
    }
}

// ---- RMSNorm (SIMD-reduced) ----
// 1 threadgroup (size tw) per row.
kernel void rms_norm(
    device float* data          [[buffer(0)]],
    device const float* weight  [[buffer(1)]],
    constant uint& cols         [[buffer(2)]],
    constant float& eps         [[buffer(3)]],
    uint tgid                   [[threadgroup_position_in_grid]],
    uint tiitg                  [[thread_index_in_threadgroup]],
    uint tptg                   [[threads_per_threadgroup]]
) {
    uint off = tgid * cols;
    float len = float(cols);

    float local_sq_sum = 0.0;
    for (uint j = tiitg; j < cols; j += tptg) {
        float v = data[off + j];
        local_sq_sum += v * v;
    }
    float sq_sum = simd_sum(local_sq_sum);
    float inv_rms = rsqrt(sq_sum / len + eps);

    for (uint j = tiitg; j < cols; j += tptg) {
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
template <bool TRANSB, uint BM = 32, uint BN = 32>
static inline void block_mma_fp16(
    device const float* A,
    device const float* B,
    device float* C,
    uint M, uint N, uint K,
    uint3 tgid, uint sgid, uint lane, uint tpsg,
    threadgroup half (*As)[MMA_BK],
    threadgroup half (*Bs)[MMA_BK],
    threadgroup float (*store_tile)[MMA_F][MMA_F])
{
    constexpr uint BK = 16, WM = 2, WN = 2, F = 8;
    constexpr uint TM = BM / (F * WM);
    constexpr uint TN = BN / (F * WN);
    // The WMxWN simdgroups tile a TMxTN grid of FxF fragments, covering exactly
    // F*WM*TM by F*WN*TN. Require that to equal BMxBN so a tile that is not a
    // whole multiple of F*WM / F*WN fails to build instead of staging only part
    // of the output (the half-MMA-at-64x64 hazard).
    static_assert(F * WM * TM == BM && F * WN * TN == BN,
                  "block_mma_fp16: BM/BN must be whole multiples of F*WM / F*WN");

    const uint sm = sgid / WN;
    const uint sn = sgid % WN;
    const uint block_row = tgid.y * BM;
    const uint block_col = tgid.x * BN;
    const uint tid = sgid * tpsg + lane;

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
                for (uint e = lane; e < F * F; e += tpsg) {
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
    uint  lane             [[thread_index_in_simdgroup]],
    uint  tpsg             [[threads_per_simdgroup]])
{
    threadgroup half As[32][MMA_BK];
    threadgroup half Bs[32][MMA_BK];
    threadgroup float store_tile[2 * 2][MMA_F][MMA_F];
    block_mma_fp16<true>(A, B, C, M, N, K, tgid, sgid, lane, tpsg, As, Bs, store_tile);
}

kernel void batched_matmul_transb_simdgroup_fp16(
    device const float* Q   [[buffer(0)]],
    device const float* Kk  [[buffer(1)]],
    device float*       C   [[buffer(2)]],
    constant uint& seq      [[buffer(3)]],
    constant uint& dim      [[buffer(4)]],
    uint3 tgid              [[threadgroup_position_in_grid]],
    uint  sgid             [[simdgroup_index_in_threadgroup]],
    uint  lane             [[thread_index_in_simdgroup]],
    uint  tpsg             [[threads_per_simdgroup]])
{
    uint h = tgid.z;
    device const float* Ah = Q  + h * seq * dim;
    device const float* Bh = Kk + h * seq * dim;
    device float*       Ch = C  + h * seq * seq;
    threadgroup half As[32][MMA_BK];
    threadgroup half Bs[32][MMA_BK];
    threadgroup float store_tile[2 * 2][MMA_F][MMA_F];
    block_mma_fp16<true>(Ah, Bh, Ch, seq, seq, dim, uint3(tgid.x, tgid.y, 0), sgid, lane, tpsg, As, Bs, store_tile);
}

kernel void batched_matmul_ab_simdgroup_fp16(
    device const float* S   [[buffer(0)]],
    device const float* V   [[buffer(1)]],
    device float*       C   [[buffer(2)]],
    constant uint& seq      [[buffer(3)]],
    constant uint& dim      [[buffer(4)]],
    uint3 tgid              [[threadgroup_position_in_grid]],
    uint  sgid             [[simdgroup_index_in_threadgroup]],
    uint  lane             [[thread_index_in_simdgroup]],
    uint  tpsg             [[threads_per_simdgroup]])
{
    uint h = tgid.z;
    device const float* Ah = S + h * seq * seq;
    device const float* Bh = V + h * seq * dim;
    device float*       Ch = C + h * seq * dim;
    threadgroup half As[32][MMA_BK];
    threadgroup half Bs[32][MMA_BK];
    threadgroup float store_tile[2 * 2][MMA_F][MMA_F];
    block_mma_fp16<false>(Ah, Bh, Ch, seq, dim, seq, uint3(tgid.x, tgid.y, 0), sgid, lane, tpsg, As, Bs, store_tile);
}

// fp16 operands in the wider 64x64 tile (Lever #5 phase 2): composes the half
// stage/issue of block_mma_fp16 with the 64x64 blocking of the proven fp32 wide
// kernel. fp32 accumulate is unchanged. Same 128-thread / 4-simdgroup geometry;
// only the projection GEMM (M/N/K) is composed here — the batched attention
// shapes stay on the 32x32 fp16 path.
kernel void matmul_transb_simdgroup_fp16_wide(
    device const float* A   [[buffer(0)]],
    device const float* B   [[buffer(1)]],
    device float*       C   [[buffer(2)]],
    constant uint& M        [[buffer(3)]],
    constant uint& N        [[buffer(4)]],
    constant uint& K        [[buffer(5)]],
    uint3 tgid              [[threadgroup_position_in_grid]],
    uint  sgid             [[simdgroup_index_in_threadgroup]],
    uint  lane             [[thread_index_in_simdgroup]],
    uint  tpsg             [[threads_per_simdgroup]])
{
    threadgroup half As[64][MMA_BK];
    threadgroup half Bs[64][MMA_BK];
    threadgroup float store_tile[2 * 2][MMA_F][MMA_F];
    // block_mma_fp16<true,64,64> blocks over a 64x64 output, so the A/B stage must
    // hold 64 rows; a 32-row stage would leave half the tile unstaged (the prior
    // half-MMA-at-64x64 parity bug). Couple the stage size to the 64 tile at
    // compile time so the two can never drift apart.
    static_assert(sizeof(As) / sizeof(As[0]) == 64,
                  "fp16 wide: As must stage 64 M-rows for the 64x64 tile");
    static_assert(sizeof(Bs) / sizeof(Bs[0]) == 64,
                  "fp16 wide: Bs must stage 64 N-rows for the 64x64 tile");
    block_mma_fp16<true, 64, 64>(A, B, C, M, N, K, tgid, sgid, lane, tpsg, As, Bs, store_tile);
}
"#;

// ---------------------------------------------------------------------------
// C7 flash-attention — SEPARATE shader library skeleton
// ---------------------------------------------------------------------------
// Kept separate from the baseline Metal shader library for the same reason as
// the fp16 MMA library: an experimental C7 compile/pipeline failure must only
// disable C7, never Metal itself. Adding more C7 shaders later should be a
// small registration change instead of a control-flow change.
const C7_FLASH_ATTENTION_SHADER_SOURCE: &str = r#"
#include <metal_stdlib>
using namespace metal;

// One 32-lane simdgroup per (row, head): fuses QK, scale/mask, online softmax,
// and SV without materializing the O(seq^2) score buffer. The launch is
// conservative/default-off; ALiBi and resident-stack routing remain on the
// baseline path until direct parity clears.
constant uint C7_THREADS = 32;
constant uint C7_MAX_HEAD_DIM = 64;

kernel void c7_flash_attention_batched(
    device const float* q           [[buffer(0)]],
    device const float* k           [[buffer(1)]],
    device const float* v           [[buffer(2)]],
    device float* out               [[buffer(3)]],
    device const uint* mask         [[buffer(4)]],
    constant uint& seq_len          [[buffer(5)]],
    constant uint& head_dim         [[buffer(6)]],
    constant float& scale           [[buffer(7)]],
    constant uint& heads_per_group  [[buffer(8)]],
    uint3 tgid                      [[threadgroup_position_in_grid]],
    uint tid                        [[thread_index_in_threadgroup]]
) {
    uint row = tgid.x;
    uint head = tgid.y;
    if (tid >= C7_THREADS) return;
    if (row >= seq_len || heads_per_group == 0 || head_dim > C7_MAX_HEAD_DIM) return;

    uint group = head / heads_per_group;
    uint head_base = head * seq_len * head_dim;
    uint mask_base = group * seq_len;
    uint q_row = head_base + row * head_dim;

    threadgroup float partials[C7_THREADS][C7_MAX_HEAD_DIM];

    for (uint d = 0; d < C7_MAX_HEAD_DIM; d++) {
        if (d < head_dim) {
            partials[tid][d] = 0.0;
        }
    }

    float max_val = -INFINITY;
    for (uint col = tid; col < seq_len; col += C7_THREADS) {
        if (mask[mask_base + col] == 0) {
            continue;
        }
        float score = 0.0;
        uint k_off = head_base + col * head_dim;
        for (uint inner = 0; inner < head_dim; inner++) {
            score += q[q_row + inner] * k[k_off + inner];
        }
        score *= scale;
        max_val = max(max_val, score);
    }
    max_val = simd_max(max_val);

    float local_sum = 0.0;
    for (uint col = tid; col < seq_len; col += C7_THREADS) {
        if (mask[mask_base + col] == 0) {
            continue;
        }
        float score = 0.0;
        uint k_off = head_base + col * head_dim;
        for (uint inner = 0; inner < head_dim; inner++) {
            score += q[q_row + inner] * k[k_off + inner];
        }
        score *= scale;
        float weight = exp(score - max_val);
        local_sum += weight;
        for (uint d = 0; d < head_dim; d++) {
            partials[tid][d] += weight * v[head_base + col * head_dim + d];
        }
    }

    float denom = simd_sum(local_sum);
    threadgroup_barrier(mem_flags::mem_threadgroup);

    for (uint d = tid; d < head_dim; d += C7_THREADS) {
        float numer = 0.0;
        for (uint lane = 0; lane < C7_THREADS; lane++) {
            numer += partials[lane][d];
        }
        out[q_row + d] = denom > 0.0 ? numer / denom : 0.0;
    }
}
"#;

const C7_FLASH_ATTENTION_KERNEL_NAMES: &[&str] = &["c7_flash_attention_batched"];

// ---------------------------------------------------------------------------
// Bounded in-flight submission
// ---------------------------------------------------------------------------
//
// The naive per-op path commits a command buffer and immediately blocks in
// `wait_until_completed`, so ~145 of these round-trips serialize the host
// against the GPU per forward pass (measured ~69% of wall on M5 Max). The
// bounded submitter instead commits WITHOUT waiting and registers a completion
// handler; a depth counter capped at the resolved in-flight depth keeps at most
// a few command buffers (and their resident intermediates) outstanding. When the
// cap is hit the submitter PARKS on a condvar — it does not busy-spin (the
// unbounded busy-spin pile-up is exactly what hung large cold embeds). This caps
// resident intermediate memory at ~cap× a layer's working set regardless of repo
// size.

/// Default committed-but-incomplete command-buffer depth when nothing raises it.
/// 2–3 is the conservative sweet spot: low enough to bound resident memory, high
/// enough to overlap host encoding with GPU execution.
const DEFAULT_MAX_INFLIGHT: u32 = 3;

/// Resolve the bounded in-flight command-buffer depth for this process.
///
/// Priority:
/// 1. `KIN_INFER_MAX_INFLIGHT` — explicit override for tuning and watchdog
///    ceiling probing (any value ≥ 1).
/// 2. The active resource profile's `max_inflight_command_buffers`, selected by
///    `KIN_RESOURCE_PROFILE` (the same switch kin-db's BatchBudget reads), so the
///    hardware-scaled throughput depth takes effect instead of a fixed constant.
/// 3. [`DEFAULT_MAX_INFLIGHT`].
fn resolve_max_inflight() -> u32 {
    resolve_max_inflight_inner(
        std::env::var("KIN_INFER_MAX_INFLIGHT").ok().as_deref(),
        std::env::var("KIN_RESOURCE_PROFILE").ok().as_deref(),
    )
}

/// Pure core of [`resolve_max_inflight`]: explicit override (≥ 1) wins, else the
/// named profile's accelerator depth, else [`DEFAULT_MAX_INFLIGHT`].
fn resolve_max_inflight_inner(override_raw: Option<&str>, profile_raw: Option<&str>) -> u32 {
    if let Some(n) = override_raw
        .and_then(|raw| raw.trim().parse::<u32>().ok())
        .filter(|n| *n >= 1)
    {
        return n;
    }
    let profile = profile_raw.and_then(|raw| match raw.trim().to_ascii_lowercase().as_str() {
        "proof" => Some(crate::resource::Profile::Proof),
        "interactive" => Some(crate::resource::Profile::Interactive),
        "throughput" => Some(crate::resource::Profile::Throughput),
        "ci" => Some(crate::resource::Profile::Ci),
        _ => None,
    });
    match profile {
        Some(p) => (crate::resource::ResourcePlan::detect(p)
            .accelerator
            .max_inflight_command_buffers as u32)
            .max(1),
        None => DEFAULT_MAX_INFLIGHT,
    }
}

/// Shared in-flight depth counter + condvar. The submitter increments on commit
/// and parks while depth ≥ the in-flight cap; the completion handler decrements and
/// notifies — on BOTH success and Error, so an errored buffer can never deadlock
/// the submitter.
type InflightGate = Arc<(Mutex<u32>, Condvar)>;

/// Shared byte gate for resident stack command buffers. This is deliberately a
/// no-wait gate: stack paths can return `Ok(None)` and let the caller use the
/// proven fallback path instead of parking after allocating large MTLBuffers.
#[derive(Clone)]
struct ResidentStackMemoryGate {
    budget_bytes: usize,
    active_bytes: Arc<Mutex<usize>>,
}

struct ResidentStackReservation {
    active_bytes: Arc<Mutex<usize>>,
    bytes: usize,
}

impl ResidentStackMemoryGate {
    fn new(budget_bytes: usize) -> Self {
        Self {
            budget_bytes,
            active_bytes: Arc::new(Mutex::new(0)),
        }
    }

    fn try_reserve(&self, bytes: usize) -> Option<ResidentStackReservation> {
        if bytes > self.budget_bytes {
            return None;
        }
        let mut active = self.active_bytes.lock();
        let next = active.checked_add(bytes)?;
        if next > self.budget_bytes {
            return None;
        }
        *active = next;
        Some(ResidentStackReservation {
            active_bytes: Arc::clone(&self.active_bytes),
            bytes,
        })
    }
}

impl Drop for ResidentStackReservation {
    fn drop(&mut self) {
        let mut active = self.active_bytes.lock();
        *active = active.saturating_sub(self.bytes);
    }
}

fn resolve_resident_stack_budget(device: &Device) -> usize {
    if let Some(bytes) = std::env::var("KIN_INFER_METAL_RESIDENT_BUDGET_BYTES")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|bytes| *bytes > 0)
    {
        return bytes;
    }

    let recommended = device.recommended_max_working_set_size();
    let system_total = crate::resource::detect_memory().system_total_bytes;
    // Single canonical copy of the formula lives in `resource`, so the runtime
    // budget and the inspect-only `MetalGovernorPlan` can never diverge.
    crate::resource::resident_stack_budget_bytes(recommended, system_total) as usize
}

/// A size-classed free-list of `StorageModeShared` buffers. Recycling a buffer
/// back onto the list avoids the per-op `new_buffer` churn that otherwise mints
/// a fresh MTLBuffer for every activation/output tensor. Buffers only return to
/// the list once the GPU is done with them (recycling is tied to the completion
/// handler that owns the `PooledBuffer`, never to Rust scope exit while the
/// buffer may still be GPU-resident).
///
/// The free-list is trimmed: a buffer is recycled only while doing so keeps the
/// pooled total under `cap_bytes` and the buffer itself is under
/// `per_buffer_cap_bytes`; otherwise it is dropped so Metal frees the unified
/// allocation. Trimming never changes which buffer a computation uses — a dropped
/// buffer is re-allocated on the next acquire of that class — so it preserves the
/// determinism guarantees the acquire path documents.
struct BufferPool {
    device: Device,
    free: Mutex<HashMap<usize, Vec<Buffer>>>,
    /// Total bytes (by size-class) currently held on the free-list. Maintained
    /// under the same lock as `free` so the pair stays consistent.
    pooled_bytes: Mutex<usize>,
    /// Ceiling on `pooled_bytes`; recycling that would exceed it drops instead.
    cap_bytes: usize,
    /// Per-buffer high-water; a size-class above this is never pooled.
    per_buffer_cap_bytes: usize,
}

/// Decide whether a buffer of `class` bytes should be recycled onto the free-list
/// given the bytes already pooled. Pure (no lock, no device) so the trim policy
/// is unit-testable. Drops (returns `false`) when the buffer is larger than the
/// per-buffer high-water, or when adding it would push the pooled total over the
/// cap.
#[inline]
fn buffer_pool_should_recycle(
    class: usize,
    pooled_bytes: usize,
    cap_bytes: usize,
    per_buffer_cap_bytes: usize,
) -> bool {
    if class > per_buffer_cap_bytes {
        return false;
    }
    match pooled_bytes.checked_add(class) {
        Some(next) => next <= cap_bytes,
        None => false,
    }
}

/// Resolve the BufferPool total-bytes cap, honoring `KIN_INFER_METAL_POOL_CAP_BYTES`.
fn resolve_buffer_pool_cap_bytes() -> usize {
    std::env::var("KIN_INFER_METAL_POOL_CAP_BYTES")
        .ok()
        .and_then(|raw| raw.trim().parse::<usize>().ok())
        .filter(|bytes| *bytes > 0)
        .unwrap_or(crate::resource::DEFAULT_BUFFER_POOL_CAP_BYTES as usize)
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

#[inline]
fn estimate_size_class(bytes: usize) -> usize {
    let bytes = bytes.max(1);
    const CHUNK: usize = 64 * 1024;
    if bytes <= CHUNK {
        bytes.checked_next_power_of_two().unwrap_or(usize::MAX)
    } else {
        bytes
            .checked_add(CHUNK - 1)
            .map(|rounded| (rounded / CHUNK) * CHUNK)
            .unwrap_or(usize::MAX)
    }
}

#[inline]
fn estimate_pooled_f32_bytes(count: usize) -> usize {
    estimate_size_class(count.saturating_mul(std::mem::size_of::<f32>()))
}

#[inline]
fn estimate_raw_bytes(count: usize, elem_bytes: usize) -> usize {
    count.saturating_mul(elem_bytes)
}

fn estimate_layer_kv_heads(weights: &LayerTensors<'_>, config: &LayerConfig<'_>) -> usize {
    if let Some(k) = weights.k_weight {
        k.len() / (config.hidden_size * config.head_dim).max(1)
    } else if let Some(qkv) = weights.qkv_weight {
        let total_qkv_dim = qkv.len() / config.hidden_size.max(1);
        let q_dim = config.num_heads * config.head_dim;
        total_qkv_dim.saturating_sub(q_dim) / (2 * config.head_dim).max(1)
    } else {
        config.num_heads
    }
}

fn estimate_embedding_prelude_bytes(
    embedding: Option<&EmbeddingPrelude<'_>>,
    config: &LayerConfig<'_>,
) -> usize {
    let total_rows = config.batch_size.saturating_mul(config.max_len);
    let hidden = total_rows.saturating_mul(config.hidden_size);
    match embedding {
        Some(embedding) if embedding.projection.is_some() => {
            estimate_pooled_f32_bytes(total_rows.saturating_mul(embedding.input_dim))
                .saturating_add(estimate_pooled_f32_bytes(hidden))
        }
        _ => estimate_pooled_f32_bytes(hidden),
    }
}

fn estimate_layer_resident_bytes(weights: &LayerTensors<'_>, config: &LayerConfig<'_>) -> usize {
    let batch_size = config.batch_size;
    let max_len = config.max_len;
    let total_rows = batch_size.saturating_mul(max_len);
    let h = config.hidden_size;
    let heads = config.num_heads;
    let head_dim = config.head_dim;
    let inter = config.inter_size;
    let kv_heads = estimate_layer_kv_heads(weights, config);
    let q_dim = heads.saturating_mul(head_dim);
    let kv_dim = kv_heads.saturating_mul(head_dim);
    let hidden_elems = total_rows.saturating_mul(h);
    let q_elems = total_rows.saturating_mul(q_dim);
    let kv_elems = total_rows.saturating_mul(kv_dim);
    let q_heads = batch_size.saturating_mul(heads);

    let mut bytes = 0usize;
    if config.pre_ln {
        bytes = bytes.saturating_add(estimate_pooled_f32_bytes(hidden_elems));
    }

    bytes = bytes
        .saturating_add(estimate_pooled_f32_bytes(q_elems))
        .saturating_add(estimate_pooled_f32_bytes(kv_elems))
        .saturating_add(estimate_pooled_f32_bytes(kv_elems));

    if weights.qkv_weight.is_some() {
        let total_qkv = q_dim.saturating_add(kv_dim.saturating_mul(2));
        bytes = bytes.saturating_add(estimate_pooled_f32_bytes(
            total_rows.saturating_mul(total_qkv),
        ));
    }

    bytes = bytes
        .saturating_add(estimate_pooled_f32_bytes(q_elems))
        .saturating_add(estimate_pooled_f32_bytes(q_elems))
        .saturating_add(estimate_pooled_f32_bytes(q_elems))
        .saturating_add(estimate_pooled_f32_bytes(
            q_heads.saturating_mul(max_len).saturating_mul(max_len),
        ))
        .saturating_add(estimate_raw_bytes(total_rows, std::mem::size_of::<u32>()))
        .saturating_add(estimate_pooled_f32_bytes(1))
        .saturating_add(estimate_pooled_f32_bytes(q_elems))
        .saturating_add(estimate_pooled_f32_bytes(q_elems))
        .saturating_add(estimate_pooled_f32_bytes(hidden_elems));

    if config.pre_ln {
        bytes = bytes.saturating_add(estimate_pooled_f32_bytes(hidden_elems));
    }

    bytes = bytes.saturating_add(estimate_pooled_f32_bytes(hidden_elems));
    if weights.ffn_gate_weight.is_some() {
        bytes = bytes
            .saturating_add(estimate_pooled_f32_bytes(
                total_rows.saturating_mul(inter).saturating_mul(2),
            ))
            .saturating_add(estimate_pooled_f32_bytes(total_rows.saturating_mul(inter)));
    } else {
        bytes = bytes.saturating_add(estimate_pooled_f32_bytes(total_rows.saturating_mul(inter)));
    }
    bytes
}

fn estimate_resident_segment_bytes(
    layers: &[LayerTensors<'_>],
    config: &LayerConfig<'_>,
    embedding: Option<&EmbeddingPrelude<'_>>,
    include_pooling: bool,
) -> usize {
    let mut bytes = estimate_embedding_prelude_bytes(embedding, config);
    for weights in layers {
        bytes = bytes.saturating_add(estimate_layer_resident_bytes(weights, config));
    }
    if include_pooling {
        bytes = bytes
            .saturating_add(estimate_pooled_f32_bytes(
                config.batch_size.saturating_mul(config.hidden_size),
            ))
            .saturating_add(estimate_raw_bytes(
                config.batch_size.saturating_mul(config.max_len),
                std::mem::size_of::<u32>(),
            ));
    }
    bytes
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
            pooled_bytes: Mutex::new(0),
            cap_bytes: resolve_buffer_pool_cap_bytes(),
            per_buffer_cap_bytes: crate::resource::DEFAULT_BUFFER_POOL_PER_BUFFER_CAP_BYTES
                as usize,
        }
    }

    /// Pop a recycled buffer of `class` off the free-list, decrementing the
    /// pooled-bytes accounting in lockstep. Returns `None` if none is pooled.
    /// Holds both locks (free, then pooled_bytes — the same order `recycle`
    /// uses) so the pop and the byte decrement are atomic with respect to a
    /// concurrent recycle.
    fn take_pooled(&self, class: usize) -> Option<Buffer> {
        let mut free = self.free.lock();
        let mut pooled = self.pooled_bytes.lock();
        let buf = free.get_mut(&class).and_then(|v| v.pop())?;
        *pooled = pooled.saturating_sub(class);
        Some(buf)
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
        let buf = self.take_pooled(class);
        let buf = match buf {
            Some(buf) => buf,
            None => try_new_buffer(&self.device, class as u64).ok_or_else(|| {
                InferError::OutOfMemory(format!("metal buffer alloc failed: {class} bytes"))
            })?,
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
        let buf = self.take_pooled(class);
        let buf = match buf {
            Some(buf) => buf,
            None => try_new_buffer(&self.device, class as u64).ok_or_else(|| {
                InferError::OutOfMemory(format!("metal buffer alloc failed: {class} bytes"))
            })?,
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
        let buf = self.take_pooled(class);
        let buf = match buf {
            Some(buf) => buf,
            None => try_new_buffer(&self.device, class as u64).ok_or_else(|| {
                InferError::OutOfMemory(format!("metal buffer alloc failed: {class} bytes"))
            })?,
        };
        if zero_all_buffers() {
            unsafe {
                std::ptr::write_bytes(buf.contents() as *mut u8, 0, class);
            }
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
        // Hold both locks (free, then pooled_bytes) so the decision and the
        // accounting cannot race a concurrent acquire/recycle. Dropping `buf`
        // here (by not pushing it) lets Metal free the unified allocation.
        let mut free = self.free.lock();
        let mut pooled = self.pooled_bytes.lock();
        if !buffer_pool_should_recycle(class, *pooled, self.cap_bytes, self.per_buffer_cap_bytes) {
            return;
        }
        free.entry(class).or_default().push(buf);
        *pooled = pooled.saturating_add(class);
    }

    #[cfg(test)]
    fn pooled_bytes_for_test(&self) -> usize {
        *self.pooled_bytes.lock()
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
    /// Cache weight buffers on GPU keyed by (data_ptr, len, first_element_bits, last_element_bits).
    /// Weight matrices are the same across all forward passes, so allocating once and
    /// reusing eliminates ~100GB of redundant copies for a typical embedding run.
    weight_cache: Mutex<HashMap<(usize, usize, u32, u32), Buffer>>,
    /// Cache row-concatenated weight buffers (e.g. q|k|v, gate|up) keyed by the
    /// component weights' stable (ptr, len, first_bits, last_bits) tuples, so the
    /// fat GEMM uploads the concatenation once and reuses it across every forward pass.
    #[allow(clippy::type_complexity)]
    concat_cache: Mutex<HashMap<Vec<(usize, usize, u32, u32)>, Buffer>>,
    /// Bounded in-flight depth gate shared with completion handlers.
    inflight: InflightGate,
    /// Maximum committed-but-incomplete command buffers, resolved once at
    /// construction from override/profile (see [`resolve_max_inflight`]).
    max_inflight: u32,
    /// Size-classed activation/output buffer pool.
    pool: Arc<BufferPool>,
    /// Byte budget for resident stack command buffers before they allocate.
    resident_stack_memory: ResidentStackMemoryGate,
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
            "pool_rows",
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
        let mut fp16_wide_mma_available = false;
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
                        let pipeline = fp16_library.get_function(name, None).and_then(|func| {
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
                    // Lever #5 phase 2: the composed fp16 + 64x64 projection GEMM,
                    // registered only if the base fp16 kernels built. A failure here
                    // disables only the composed path, never the proven 32x32 fp16 MMA.
                    if ok {
                        let wide = "matmul_transb_simdgroup_fp16_wide";
                        match fp16_library
                            .get_function(wide, None)
                            .and_then(|func| device.new_compute_pipeline_state_with_function(&func))
                        {
                            Ok(pipeline) => {
                                pipelines.insert(wide, pipeline);
                                fp16_wide_mma_available = true;
                            }
                            Err(err) => {
                                eprintln!(
                                    "kin-infer: Metal fp16+wide MMA kernel {wide} unavailable \
                                     ({err}); fp16+wide disabled (32x32 fp16 stays enabled)"
                                );
                            }
                        }
                    }
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
        WIDE_FP16_MMA_AVAILABLE.store(fp16_wide_mma_available, Ordering::Relaxed);

        // C7 flash-attention — OPTIONAL, compiled as a SEPARATE library only
        // when opt-in enabled. C7 availability remains false if compilation or
        // pipeline creation fails, and runtime attention calls continue through
        // the baseline Metal path unless registration succeeds and the shape
        // gate passes.
        let mut c7_flash_attention_available = false;
        if c7_flash_attention_enabled() {
            match device.new_library_with_source(C7_FLASH_ATTENTION_SHADER_SOURCE, &opts) {
                Ok(c7_library) => {
                    if C7_FLASH_ATTENTION_KERNEL_NAMES.is_empty() {
                        eprintln!(
                            "kin-infer: Metal C7 flash-attention requested, but no C7 \
                             kernels are registered yet; baseline attention stays enabled"
                        );
                    } else {
                        let mut ok = true;
                        for &name in C7_FLASH_ATTENTION_KERNEL_NAMES {
                            let pipeline = c7_library.get_function(name, None).and_then(|func| {
                                device.new_compute_pipeline_state_with_function(&func)
                            });
                            match pipeline {
                                Ok(pipeline) => {
                                    pipelines.insert(name, pipeline);
                                }
                                Err(err) => {
                                    eprintln!(
                                        "kin-infer: Metal C7 flash-attention kernel {name} \
                                         unavailable ({err}); C7 disabled (baseline \
                                         attention stays enabled)"
                                    );
                                    ok = false;
                                    break;
                                }
                            }
                        }
                        c7_flash_attention_available = ok;
                    }
                }
                Err(err) => {
                    eprintln!(
                        "kin-infer: Metal C7 flash-attention shader library failed to \
                         compile ({err}); C7 disabled (baseline attention stays enabled)"
                    );
                }
            }
        }
        C7_FLASH_ATTENTION_AVAILABLE.store(c7_flash_attention_available, Ordering::Relaxed);

        let pool = Arc::new(BufferPool::new(device.clone()));
        let resident_stack_memory =
            ResidentStackMemoryGate::new(resolve_resident_stack_budget(&device));
        let max_inflight = resolve_max_inflight();

        // The hardware-derived governor caps actually in force for this process,
        // logged once so the resolved resident budget, pool ceilings, and
        // in-flight depth are visible in runtime logs (mirrors what
        // `kin resources inspect --json` reports via ResourcePlan).
        tracing::info!(
            target: "kin.resource",
            device = %device_name,
            resident_stack_budget_bytes = resident_stack_memory.budget_bytes,
            buffer_pool_cap_bytes = pool.cap_bytes,
            buffer_pool_per_buffer_cap_bytes = pool.per_buffer_cap_bytes,
            max_inflight_command_buffers = max_inflight,
            "metal resident-stack governor resolved"
        );

        Some(Self {
            device,
            queue,
            pipelines,
            device_name,
            weight_cache: Mutex::new(HashMap::new()),
            concat_cache: Mutex::new(HashMap::new()),
            inflight: Arc::new((Mutex::new(0), Condvar::new())),
            max_inflight,
            pool,
            resident_stack_memory,
        })
    }

    fn try_reserve_resident_segment(
        &self,
        bytes: usize,
        path: &'static str,
    ) -> Option<ResidentStackReservation> {
        let reservation = self.resident_stack_memory.try_reserve(bytes);
        if reservation.is_none() {
            tracing::debug!(
                path,
                bytes,
                budget_bytes = self.resident_stack_memory.budget_bytes,
                "kin_infer.metal.resident_stack: declining resident path before command buffer allocation"
            );
        }
        reservation
    }

    /// Replace the resident-stack memory budget on this live instance. Test-only
    /// (no env races): models the tiny-`KIN_INFER_METAL_RESIDENT_BUDGET_BYTES`
    /// case so the resident segment reservation declines and the caller takes the
    /// bounded per-layer / op-by-op fallback path.
    #[cfg(test)]
    fn set_resident_budget_for_test(&mut self, budget_bytes: usize) {
        self.resident_stack_memory = ResidentStackMemoryGate::new(budget_bytes);
    }

    /// Create a Metal buffer from a slice and copy data in.
    fn buf_from_slice(&self, data: &[f32]) -> Result<Buffer, InferError> {
        let bytes = std::mem::size_of_val(data);
        try_new_buffer_with_bytes(&self.device, data.as_ptr() as *const u8, bytes).ok_or_else(
            || InferError::OutOfMemory(format!("metal buffer alloc failed: {bytes} bytes")),
        )
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

    /// Cache key for a weight buffer: pointer, length, and the first/last element
    /// bit patterns. Folding in the content bits means a reused allocation (same
    /// pointer and length, different contents) no longer collides with a stale
    /// cached buffer, while stable weights still hit on every call after the first.
    fn weight_cache_key(data: &[f32]) -> (usize, usize, u32, u32) {
        let first_bits = data.first().map(|x| x.to_bits()).unwrap_or(0);
        let last_bits = data.last().map(|x| x.to_bits()).unwrap_or(0);
        (data.as_ptr() as usize, data.len(), first_bits, last_bits)
    }

    /// Cache key for a row-concatenated weight buffer: the per-component
    /// [`Self::weight_cache_key`] in order, so any component's content change
    /// changes the key.
    fn concat_cache_key(weights: &[&[f32]]) -> Vec<(usize, usize, u32, u32)> {
        weights.iter().map(|w| Self::weight_cache_key(w)).collect()
    }

    /// Get or create a cached buffer for persistent data (weight matrices).
    /// Keyed by [`Self::weight_cache_key`] — weight Array2 data pointers are stable
    /// across forward passes, so this hits on every call after the first.
    fn buf_cached(&self, data: &[f32]) -> Result<Buffer, InferError> {
        let key = Self::weight_cache_key(data);
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
    /// component (ptr, len, first_bits, last_bits) tuples and reused on every
    /// subsequent call. Used to fold the q/k/v (and gate/up) projections into
    /// one fat GEMM.
    fn buf_cached_concat(&self, weights: &[&[f32]]) -> Result<Buffer, InferError> {
        let key = Self::concat_cache_key(weights);
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
        let bytes = std::mem::size_of_val(data);
        try_new_buffer_with_bytes(&self.device, data.as_ptr() as *const u8, bytes).ok_or_else(
            || InferError::OutOfMemory(format!("metal u32 buffer alloc failed: {bytes} bytes")),
        )
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
        if !Self::metal_nan_check_enabled() {
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

    #[inline]
    fn metal_nan_check_enabled() -> bool {
        std::env::var_os("KIN_INFER_METAL_NAN_CHECK").is_some()
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
    /// The submitter parks (does not spin) when depth reaches the in-flight cap, so
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
            while *depth >= self.max_inflight {
                let timed_out = cvar
                    .wait_for(&mut depth, std::time::Duration::from_secs(30))
                    .timed_out();
                if timed_out && *depth >= self.max_inflight {
                    tracing::warn!(
                        depth = *depth,
                        max_inflight = self.max_inflight,
                        "kin_infer.metal.commit_bounded: in-flight depth has not drained for 30s — a completion handler may have failed to fire"
                    );
                }
            }
            *depth += 1;
            debug_assert!(
                *depth <= self.max_inflight,
                "in-flight depth exceeded the cap"
            );
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
                tracing::warn!(
                    "kin_infer.metal.commit_bounded: command buffer completed in Error state"
                );
            }
            // Count this buffer's on-GPU window toward the in-process util%. The
            // handler fires after completion, so `GPUStartTime`/`GPUEndTime` are
            // valid — this is the ONLY place the deferred-readback path can be
            // attributed (the host never waits on it). Gated inside
            // `record_gpu_busy` so it is a no-op when profiling is off.
            record_gpu_busy(cb);
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
        let blocked_start = profile_enabled().then(std::time::Instant::now);
        if blocked_start.is_some() {
            ROUND_TRIPS.fetch_add(1, Ordering::Relaxed);
        }
        cmd.wait_until_completed();
        if let Some(start) = blocked_start {
            STALL_NANOS.fetch_add(start.elapsed().as_nanos() as u64, Ordering::Relaxed);
            if let Some(phase) = CURRENT_PHASE.with(|p| p.get()) {
                phase
                    .gpu_counter()
                    .fetch_add(cmd_gpu_nanos(cmd), Ordering::Relaxed);
            }
            // NB: the total/windowed GPU-busy for the in-process util% is recorded
            // by the `commit_bounded` completion handler (invoked above), which
            // fires for THIS buffer too — recording it again here would
            // double-count. The per-phase attribution stays here because it needs
            // the committing thread's `time_phase` thread-local.
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
        // Pointwise kernels have no cross-thread dependency, so widening the
        // threadgroup toward the pipeline's occupancy ceiling only changes how many
        // SIMD groups pack per threadgroup, not the result. Off by default: the
        // helper returns the historical one-simdgroup width, so this dispatch is
        // byte-identical unless the occupancy lever is explicitly engaged.
        let tg_threads = crate::resource::occupancy_1d_threadgroup(
            thread_w,
            pipeline.max_total_threads_per_threadgroup() as usize,
            total_threads,
            crate::resource::occupancy_dispatch_enabled(),
        );
        let tg_size = MTLSize::new(tg_threads as u64, 1, 1);
        enc.dispatch_threads(threads, tg_size);
        enc.end_encoding();
    }

    /// Dispatch a kernel that reduces over rows using simdgroups (one threadgroup of size `tw` per row).
    fn encode_rows_simdgroup(
        &self,
        cmd: &CommandBufferRef,
        pipeline_name: &str,
        buffers: &[&Buffer],
        rows: usize,
    ) {
        let pipeline = &self.pipelines[pipeline_name];
        let enc = cmd.new_compute_command_encoder();
        enc.set_compute_pipeline_state(pipeline);
        for (i, buf) in buffers.iter().enumerate() {
            enc.set_buffer(i as u64, Some(buf), 0);
        }
        let tw = pipeline.thread_execution_width() as usize;
        let threads = MTLSize::new((rows * tw) as u64, 1, 1);
        let tg_size = MTLSize::new(tw as u64, 1, 1);
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
            self.commit_wait(cmd);
        });
    }

    /// Dispatch a kernel that reduces over rows using simdgroups (one threadgroup of size `tw` per row).
    fn dispatch_rows_simdgroup(&self, pipeline_name: &str, buffers: &[&Buffer], rows: usize) {
        let _span = tracing::info_span!(
            "kin_infer.metal.dispatch_rows_simdgroup",
            pipeline = pipeline_name,
            buffer_count = buffers.len(),
            rows = rows
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

            let tw = pipeline.thread_execution_width() as usize;
            let threads = MTLSize::new((rows * tw) as u64, 1, 1);
            let tg_size = MTLSize::new(tw as u64, 1, 1);
            enc.dispatch_threads(threads, tg_size);
            enc.end_encoding();
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
        let (pipeline, block) =
            if use_fp16_wide_mma(m, n, k) && base_name == "matmul_transb_simdgroup" {
                // fp16 operands in the 64x64 tile (Lever #5 phase 2), projection GEMM
                // only; fp32 accumulate unchanged. Highest precedence when both flags
                // are set and the shape fills 64x64.
                (
                    &self.pipelines["matmul_transb_simdgroup_fp16_wide"],
                    64usize,
                )
            } else if use_fp16_mma(m, n, k) {
                // fp16 operands, fp32 accumulate (32x32 tile).
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

impl MetalCompute {
    /// Encode optional embedding projection and embedding LayerNorm into the
    /// caller's command buffer, returning the resident hidden buffer consumed by
    /// the transformer stack.
    fn encode_embedding_prelude_into(
        &self,
        cmd: &CommandBufferRef,
        hidden: &[f32],
        embedding: &EmbeddingPrelude<'_>,
        config: &LayerConfig,
        retains: &mut Vec<PooledBuffer>,
    ) -> Result<PooledBuffer, InferError> {
        let total_rows = config.batch_size * config.max_len;
        let h = config.hidden_size;
        let input_dim = embedding.input_dim;
        let expected = total_rows
            .checked_mul(input_dim)
            .ok_or_else(|| InferError::Internal("embedding prelude input shape overflow".into()))?;
        if hidden.len() != expected {
            return Err(InferError::Internal(format!(
                "embedding prelude input not {total_rows}x{input_dim}: len={}",
                hidden.len()
            )));
        }

        let current_hidden = if let Some(projection) = embedding.projection {
            let projection_expected = h.checked_mul(input_dim).ok_or_else(|| {
                InferError::Internal("embedding projection shape overflow".into())
            })?;
            if projection.len() != projection_expected {
                return Err(InferError::Internal(format!(
                    "embedding projection not {h}x{input_dim}: len={}",
                    projection.len()
                )));
            }

            let input = self.buf_slice_pooled(hidden)?;
            let projected = self.pool.acquire_uninit(total_rows * h * 4)?;
            let projection = self.buf_cached(projection)?;
            let buf_rows = self.buf_u32(total_rows as u32)?;
            let buf_h = self.buf_u32(h as u32)?;
            let buf_input_dim = self.buf_u32(input_dim as u32)?;

            if use_mma(total_rows, h, input_dim) {
                self.encode_mma(
                    cmd,
                    "matmul_transb_simdgroup",
                    &[
                        input.buffer(),
                        &projection,
                        projected.buffer(),
                        &buf_rows,
                        &buf_h,
                        &buf_input_dim,
                    ],
                    total_rows,
                    h,
                    input_dim,
                    1,
                );
            } else {
                Self::encode_matmul(
                    cmd,
                    &self.pipelines["matmul_transb"],
                    input.buffer(),
                    &projection,
                    projected.buffer(),
                    &buf_rows,
                    &buf_h,
                    &buf_input_dim,
                    h,
                    total_rows,
                );
            }

            retains.push(input);
            projected
        } else {
            if input_dim != h {
                return Err(InferError::Internal(format!(
                    "embedding prelude missing projection for {input_dim}->{h}"
                )));
            }
            self.buf_slice_pooled(hidden)?
        };

        if let (Some(weight), Some(bias)) = (embedding.norm_weight, embedding.norm_bias) {
            if weight.len() != h || bias.len() != h {
                return Err(InferError::Internal(format!(
                    "embedding norm not hidden-sized: weight={} bias={} hidden={h}",
                    weight.len(),
                    bias.len()
                )));
            }
            let weight = self.buf_cached(weight)?;
            let bias = self.buf_cached(bias)?;
            let buf_h = self.buf_u32(h as u32)?;
            let buf_eps = self.buf_f32(embedding.eps)?;
            self.encode_rows_simdgroup(
                cmd,
                "layer_norm",
                &[current_hidden.buffer(), &weight, &bias, &buf_h, &buf_eps],
                total_rows,
            );
        }

        Ok(current_hidden)
    }

    /// Encode one transformer layer into an existing command buffer against the
    /// resident `current_hidden` residual buffer. Does not upload the input,
    /// commit, or read back: the caller owns the command-buffer boundary and must
    /// retain every pooled transient until that buffer has completed.
    #[allow(clippy::too_many_arguments)]
    fn encode_layer_resident_into<'a>(
        &'a self,
        cmd: &'a CommandBufferRef,
        current_hidden: &PooledBuffer,
        masks: &[u32],
        weights: &LayerTensors,
        config: &LayerConfig,
        rope_cos: &[f32],
        rope_sin: &[f32],
        retains: &mut Vec<PooledBuffer>,
    ) -> Result<&'a CommandBufferRef, InferError> {
        self.encode_layer_resident_into_normal(
            cmd,
            current_hidden,
            masks,
            weights,
            config,
            rope_cos,
            rope_sin,
            retains,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn encode_layer_resident_into_normal<'a>(
        &'a self,
        cmd: &'a CommandBufferRef,
        current_hidden: &PooledBuffer,
        masks: &[u32],
        weights: &LayerTensors,
        config: &LayerConfig,
        rope_cos: &[f32],
        rope_sin: &[f32],
        retains: &mut Vec<PooledBuffer>,
    ) -> Result<&'a CommandBufferRef, InferError> {
        let kv_heads = if let Some(k) = weights.k_weight {
            k.len() / (config.hidden_size * config.head_dim)
        } else if let Some(qkv) = weights.qkv_weight {
            let total_qkv_dim = qkv.len() / config.hidden_size;
            let q_dim = config.num_heads * config.head_dim;
            (total_qkv_dim - q_dim) / (2 * config.head_dim)
        } else {
            config.num_heads
        };

        let _span = tracing::info_span!("kin_infer.metal.encode_layer_resident").entered();

        let batch_size = config.batch_size;
        let max_len = config.max_len;
        let total_rows = batch_size * max_len;
        let h = config.hidden_size;
        let heads = config.num_heads;
        let head_dim = config.head_dim;
        let inter = config.inter_size;
        let q_dim = heads * head_dim;
        let kv_dim = kv_heads * head_dim;

        let buf_rows = self.buf_u32(total_rows as u32)?;
        let buf_h = self.buf_u32(h as u32)?;
        let buf_eps = self.buf_f32(if config.use_rms {
            config.rms_eps
        } else {
            config.eps
        })?;

        let step = |cmd_in: &'a CommandBufferRef,
                    phase: Phase,
                    f: &mut dyn FnMut(&CommandBufferRef) -> Result<(), InferError>|
         -> Result<&'a CommandBufferRef, InferError> {
            if profile_enabled() {
                let mut err = Ok(());
                time_phase(phase, || {
                    err = f(cmd_in);
                    self.commit_wait(cmd_in);
                });
                err?;
                Ok(self.queue.new_command_buffer())
            } else {
                f(cmd_in)?;
                Ok(cmd_in)
            }
        };

        let buf_q = self.pool.acquire_uninit(total_rows * q_dim * 4)?;
        let buf_k = self.pool.acquire_uninit(total_rows * kv_dim * 4)?;
        let buf_v = self.pool.acquire_uninit(total_rows * kv_dim * 4)?;

        let mut buf_normed1 = None;
        let buf_q_dim = self.buf_u32(q_dim as u32)?;
        let buf_kv_dim = self.buf_u32(kv_dim as u32)?;

        // --- STAGE 1: QKV Projection ---
        let mut cmd = step(cmd, Phase::Matmul, &mut |cmd| {
            let mut buf_normed1_local = None;
            let mut qkv_in = current_hidden.buffer();
            if config.pre_ln {
                let buf = self.pool.acquire_uninit(total_rows * h * 4)?;
                {
                    let blit = cmd.new_blit_command_encoder();
                    blit.copy_from_buffer(
                        current_hidden.buffer(),
                        0,
                        buf.buffer(),
                        0,
                        (total_rows * h * 4) as u64,
                    );
                    blit.end_encoding();
                }
                let buf_norm1_w = self.buf_cached(weights.norm1_weight)?;
                if config.use_rms {
                    self.encode_rows_simdgroup(
                        cmd,
                        "rms_norm",
                        &[buf.buffer(), &buf_norm1_w, &buf_h, &buf_eps],
                        total_rows,
                    );
                } else {
                    let buf_norm1_b = self.buf_cached(weights.norm1_bias.unwrap_or(&[]))?;
                    self.encode_rows_simdgroup(
                        cmd,
                        "layer_norm",
                        &[buf.buffer(), &buf_norm1_w, &buf_norm1_b, &buf_h, &buf_eps],
                        total_rows,
                    );
                }
                buf_normed1_local = Some(buf);
                qkv_in = buf_normed1_local.as_ref().unwrap().buffer();
            }

            if let Some(qkv_weight) = weights.qkv_weight {
                let total_qkv = q_dim + 2 * kv_dim;
                let buf_qkv_dim = self.buf_u32(total_qkv as u32)?;
                let buf_qkv = self.pool.acquire_uninit(total_rows * total_qkv * 4)?;
                let buf_qkv_w = self.buf_cached(qkv_weight)?;

                if use_mma(total_rows, total_qkv, h) {
                    self.encode_mma(
                        cmd,
                        "matmul_transb_simdgroup",
                        &[
                            qkv_in,
                            &buf_qkv_w,
                            buf_qkv.buffer(),
                            &buf_rows,
                            &buf_qkv_dim,
                            &buf_h,
                        ],
                        total_rows,
                        total_qkv,
                        h,
                        1,
                    );
                } else {
                    Self::encode_matmul(
                        cmd,
                        &self.pipelines["matmul_transb"],
                        qkv_in,
                        &buf_qkv_w,
                        buf_qkv.buffer(),
                        &buf_rows,
                        &buf_qkv_dim,
                        &buf_h,
                        total_qkv,
                        total_rows,
                    );
                }

                if let Some(qkv_bias) = weights.qkv_bias {
                    let b_bias = self.buf_cached(qkv_bias)?;
                    self.encode_1d(
                        cmd,
                        "elementwise_add_broadcast",
                        &[buf_qkv.buffer(), &b_bias, &buf_qkv_dim],
                        total_rows * total_qkv,
                    );
                }

                let split_p = &self.pipelines["split_qkv_packed"];
                let enc = cmd.new_compute_command_encoder();
                enc.set_compute_pipeline_state(split_p);
                enc.set_buffer(0, Some(buf_qkv.buffer()), 0);
                enc.set_buffer(1, Some(buf_q.buffer()), 0);
                enc.set_buffer(2, Some(buf_k.buffer()), 0);
                enc.set_buffer(3, Some(buf_v.buffer()), 0);
                enc.set_buffer(4, Some(&buf_q_dim), 0);
                enc.set_buffer(5, Some(&buf_kv_dim), 0);
                enc.set_buffer(6, Some(&buf_kv_dim), 0);
                let threads = metal::MTLSize::new(total_qkv as u64, total_rows as u64, 1);
                let tw = split_p.thread_execution_width();
                let tg = metal::MTLSize::new(
                    tw.min(total_qkv as u64).max(1),
                    16.min(total_rows as u64).max(1),
                    1,
                );
                enc.dispatch_threads(threads, tg);
                enc.end_encoding();

                if let Some(q_ln_w) = weights.q_ln_weight {
                    let q_ln_w_buf = self.buf_cached(q_ln_w)?;
                    let q_ln_b_buf = self.buf_cached(weights.q_ln_bias.unwrap_or(&[]))?;
                    self.encode_rows_simdgroup(
                        cmd,
                        "layer_norm",
                        &[
                            buf_q.buffer(),
                            &q_ln_w_buf,
                            &q_ln_b_buf,
                            &buf_q_dim,
                            &buf_eps,
                        ],
                        total_rows,
                    );
                }
                if let Some(k_ln_w) = weights.k_ln_weight {
                    let k_ln_w_buf = self.buf_cached(k_ln_w)?;
                    let k_ln_b_buf = self.buf_cached(weights.k_ln_bias.unwrap_or(&[]))?;
                    self.encode_rows_simdgroup(
                        cmd,
                        "layer_norm",
                        &[
                            buf_k.buffer(),
                            &k_ln_w_buf,
                            &k_ln_b_buf,
                            &buf_kv_dim,
                            &buf_eps,
                        ],
                        total_rows,
                    );
                }
                retains.push(buf_qkv);
            } else {
                let buf_qw = self.buf_cached(weights.q_weight.ok_or_else(|| {
                    InferError::ModelIncompatible("attention requires q_weight".into())
                })?)?;
                let buf_kw = self.buf_cached(weights.k_weight.ok_or_else(|| {
                    InferError::ModelIncompatible("attention requires k_weight".into())
                })?)?;
                let buf_vw = self.buf_cached(weights.v_weight.ok_or_else(|| {
                    InferError::ModelIncompatible("attention requires v_weight".into())
                })?)?;
                if use_mma(total_rows, q_dim, h) {
                    self.encode_mma(
                        cmd,
                        "matmul_transb_simdgroup",
                        &[
                            qkv_in,
                            &buf_qw,
                            buf_q.buffer(),
                            &buf_rows,
                            &buf_q_dim,
                            &buf_h,
                        ],
                        total_rows,
                        q_dim,
                        h,
                        1,
                    );
                } else {
                    Self::encode_matmul(
                        cmd,
                        &self.pipelines["matmul_transb"],
                        qkv_in,
                        &buf_qw,
                        buf_q.buffer(),
                        &buf_rows,
                        &buf_q_dim,
                        &buf_h,
                        q_dim,
                        total_rows,
                    );
                }
                if use_mma(total_rows, kv_dim, h) {
                    self.encode_mma(
                        cmd,
                        "matmul_transb_simdgroup",
                        &[
                            qkv_in,
                            &buf_kw,
                            buf_k.buffer(),
                            &buf_rows,
                            &buf_kv_dim,
                            &buf_h,
                        ],
                        total_rows,
                        kv_dim,
                        h,
                        1,
                    );
                    self.encode_mma(
                        cmd,
                        "matmul_transb_simdgroup",
                        &[
                            qkv_in,
                            &buf_vw,
                            buf_v.buffer(),
                            &buf_rows,
                            &buf_kv_dim,
                            &buf_h,
                        ],
                        total_rows,
                        kv_dim,
                        h,
                        1,
                    );
                } else {
                    Self::encode_matmul(
                        cmd,
                        &self.pipelines["matmul_transb"],
                        qkv_in,
                        &buf_kw,
                        buf_k.buffer(),
                        &buf_rows,
                        &buf_kv_dim,
                        &buf_h,
                        kv_dim,
                        total_rows,
                    );
                    Self::encode_matmul(
                        cmd,
                        &self.pipelines["matmul_transb"],
                        qkv_in,
                        &buf_vw,
                        buf_v.buffer(),
                        &buf_rows,
                        &buf_kv_dim,
                        &buf_h,
                        kv_dim,
                        total_rows,
                    );
                }
                if let Some(q_bias) = weights.q_bias {
                    let b = self.buf_cached(q_bias)?;
                    self.encode_1d(
                        cmd,
                        "elementwise_add_broadcast",
                        &[buf_q.buffer(), &b, &buf_q_dim],
                        total_rows * q_dim,
                    );
                }
                if let Some(k_bias) = weights.k_bias {
                    let b = self.buf_cached(k_bias)?;
                    self.encode_1d(
                        cmd,
                        "elementwise_add_broadcast",
                        &[buf_k.buffer(), &b, &buf_kv_dim],
                        total_rows * kv_dim,
                    );
                }
                if let Some(v_bias) = weights.v_bias {
                    let b = self.buf_cached(v_bias)?;
                    self.encode_1d(
                        cmd,
                        "elementwise_add_broadcast",
                        &[buf_v.buffer(), &b, &buf_kv_dim],
                        total_rows * kv_dim,
                    );
                }
            }
            buf_normed1 = buf_normed1_local;
            Ok(())
        })?;

        // --- STAGE 2: Attention ---
        let buf_q_reshaped = self.pool.acquire_uninit(total_rows * q_dim * 4)?;
        let buf_k_reshaped = self.pool.acquire_uninit(total_rows * q_dim * 4)?;
        let buf_v_reshaped = self.pool.acquire_uninit(total_rows * q_dim * 4)?;
        let buf_heads = self.buf_u32(heads as u32)?;
        let buf_seq = self.buf_u32(max_len as u32)?;
        let buf_head_dim = self.buf_u32(head_dim as u32)?;
        let total_q_heads = batch_size * heads;

        let buf_scores = self
            .pool
            .acquire_uninit(total_q_heads * max_len * max_len * 4)?;
        let buf_scale = self.buf_f32(config.scale)?;
        let buf_masks = self.buf_u32_slice(masks)?;
        let buf_has_alibi = self.buf_u32(0)?;
        let buf_alibi = self.buf_slice_pooled(&[0.0f32])?;
        let buf_out_reshaped = self.pool.acquire_uninit(total_rows * q_dim * 4)?;
        let buf_attn_out = self.pool.acquire_uninit(total_rows * q_dim * 4)?;

        cmd = step(cmd, Phase::Attention, &mut |cmd| {
            if !rope_cos.is_empty() {
                let buf_cos = self.buf_cached(rope_cos)?;
                let buf_sin = self.buf_cached(rope_sin)?;
                let buf_max_len = self.buf_u32(max_len as u32)?;
                let buf_head_dim = self.buf_u32(head_dim as u32)?;
                let buf_actual = self.buf_u32(max_len as u32)?;

                let rope_p = &self.pipelines["rope_apply_batched"];

                // Q RoPE
                {
                    let enc = cmd.new_compute_command_encoder();
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
                    let tg =
                        metal::MTLSize::new(16.min(num_pairs) as u64, 16.min(total_rows) as u64, 1);
                    enc.dispatch_threads(threads, tg);
                    enc.end_encoding();
                }

                // K RoPE
                {
                    let enc = cmd.new_compute_command_encoder();
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
                    let tg =
                        metal::MTLSize::new(16.min(num_pairs) as u64, 16.min(total_rows) as u64, 1);
                    enc.dispatch_threads(threads, tg);
                    enc.end_encoding();
                }
            }

            if kv_heads == heads {
                self.encode_3d(
                    cmd,
                    "reshape_qkv_pos_to_head",
                    &[
                        buf_q.buffer(),
                        buf_k.buffer(),
                        buf_v.buffer(),
                        buf_q_reshaped.buffer(),
                        buf_k_reshaped.buffer(),
                        buf_v_reshaped.buffer(),
                        &buf_heads,
                        &buf_seq,
                        &buf_head_dim,
                    ],
                    head_dim,
                    max_len,
                    total_q_heads,
                );
            } else {
                let buf_kv_heads = self.buf_u32(kv_heads as u32)?;
                let p = &self.pipelines["reshape_qkv_pos_to_head_gqa"];
                let enc = cmd.new_compute_command_encoder();
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

                let threads =
                    metal::MTLSize::new(head_dim as u64, max_len as u64, total_q_heads as u64);
                let tg = metal::MTLSize::new(16.min(head_dim) as u64, 16.min(max_len) as u64, 1);
                enc.dispatch_threads(threads, tg);
                enc.end_encoding();
            }

            let qk_bufs = [
                buf_q_reshaped.buffer(),
                buf_k_reshaped.buffer(),
                buf_scores.buffer(),
                &buf_seq,
                &buf_head_dim,
                &self.buf_u32(1)?,
            ];
            if use_mma(max_len, max_len, head_dim) {
                self.encode_mma(
                    cmd,
                    "batched_matmul_transb_simdgroup",
                    &qk_bufs,
                    max_len,
                    max_len,
                    head_dim,
                    total_q_heads,
                );
            } else {
                self.encode_3d(
                    cmd,
                    "batched_matmul_transb",
                    &qk_bufs,
                    max_len,
                    max_len,
                    total_q_heads,
                );
            }

            self.encode_3d(
                cmd,
                "scale_mask_alibi_grouped",
                &[
                    buf_scores.buffer(),
                    buf_alibi.buffer(),
                    &buf_masks,
                    &buf_scale,
                    &buf_seq,
                    &buf_has_alibi,
                    &buf_heads,
                ],
                max_len,
                max_len,
                total_q_heads,
            );

            self.encode_rows_simdgroup(
                cmd,
                "softmax_rows",
                &[buf_scores.buffer(), &buf_seq],
                total_q_heads * max_len,
            );

            let sv_bufs = [
                buf_scores.buffer(),
                buf_v_reshaped.buffer(),
                buf_out_reshaped.buffer(),
                &buf_seq,
                &buf_head_dim,
                &self.buf_u32(1)?,
            ];
            if use_mma(max_len, head_dim, max_len) {
                self.encode_mma(
                    cmd,
                    "batched_matmul_ab_simdgroup",
                    &sv_bufs,
                    max_len,
                    head_dim,
                    max_len,
                    total_q_heads,
                );
            } else {
                self.encode_3d(
                    cmd,
                    "batched_matmul_ab",
                    &sv_bufs,
                    head_dim,
                    max_len,
                    total_q_heads,
                );
            }

            self.encode_3d(
                cmd,
                "reshape_head_to_pos",
                &[
                    buf_out_reshaped.buffer(),
                    buf_attn_out.buffer(),
                    &buf_heads,
                    &buf_seq,
                    &buf_head_dim,
                ],
                head_dim,
                max_len,
                total_q_heads,
            );

            Ok(())
        })?;

        retains.push(buf_q_reshaped);
        retains.push(buf_k_reshaped);
        retains.push(buf_v_reshaped);
        retains.push(buf_scores);
        retains.push(buf_out_reshaped);
        retains.push(buf_alibi);

        // --- STAGE 3: Attention Out ---
        cmd = step(cmd, Phase::Matmul, &mut |cmd| {
            let buf_proj_out = self.pool.acquire_uninit(total_rows * h * 4)?;
            let buf_out_w = self.buf_cached(weights.attn_out_weight)?;

            if use_mma(total_rows, h, q_dim) {
                self.encode_mma(
                    cmd,
                    "matmul_transb_simdgroup",
                    &[
                        buf_attn_out.buffer(),
                        &buf_out_w,
                        buf_proj_out.buffer(),
                        &buf_rows,
                        &buf_h,
                        &buf_q_dim,
                    ],
                    total_rows,
                    h,
                    q_dim,
                    1,
                );
            } else {
                Self::encode_matmul(
                    cmd,
                    &self.pipelines["matmul_transb"],
                    buf_attn_out.buffer(),
                    &buf_out_w,
                    buf_proj_out.buffer(),
                    &buf_rows,
                    &buf_h,
                    &buf_q_dim,
                    h,
                    total_rows,
                );
            }

            if let Some(attn_out_bias) = weights.attn_out_bias {
                let b = self.buf_cached(attn_out_bias)?;
                self.encode_1d(
                    cmd,
                    "elementwise_add_broadcast",
                    &[buf_proj_out.buffer(), &b, &buf_h],
                    total_rows * h,
                );
            }

            self.encode_1d(
                cmd,
                "elementwise_add",
                &[current_hidden.buffer(), buf_proj_out.buffer()],
                total_rows * h,
            );

            if !config.pre_ln {
                let buf_norm1_w = self.buf_cached(weights.norm1_weight)?;
                if config.use_rms {
                    self.encode_rows_simdgroup(
                        cmd,
                        "rms_norm",
                        &[current_hidden.buffer(), &buf_norm1_w, &buf_h, &buf_eps],
                        total_rows,
                    );
                } else {
                    let buf_norm1_b = self.buf_cached(weights.norm1_bias.unwrap_or(&[]))?;
                    self.encode_rows_simdgroup(
                        cmd,
                        "layer_norm",
                        &[
                            current_hidden.buffer(),
                            &buf_norm1_w,
                            &buf_norm1_b,
                            &buf_h,
                            &buf_eps,
                        ],
                        total_rows,
                    );
                }
            }

            retains.push(buf_proj_out);
            Ok(())
        })?;

        retains.push(buf_attn_out);

        // --- STAGE 4: FFN ---
        let mut buf_normed2 = None;
        let buf_ffn_out = self.pool.acquire_uninit(total_rows * h * 4)?;

        cmd = step(cmd, Phase::Matmul, &mut |cmd| {
            let mut buf_normed2_local = None;
            if config.pre_ln {
                let buf = self.pool.acquire_uninit(total_rows * h * 4)?;
                {
                    let blit = cmd.new_blit_command_encoder();
                    blit.copy_from_buffer(
                        current_hidden.buffer(),
                        0,
                        buf.buffer(),
                        0,
                        (total_rows * h * 4) as u64,
                    );
                    blit.end_encoding();
                }
                let buf_norm2_w = self.buf_cached(weights.norm2_weight)?;
                if config.use_rms {
                    self.encode_rows_simdgroup(
                        cmd,
                        "rms_norm",
                        &[buf.buffer(), &buf_norm2_w, &buf_h, &buf_eps],
                        total_rows,
                    );
                } else {
                    let buf_norm2_b = self.buf_cached(weights.norm2_bias.unwrap_or(&[]))?;
                    self.encode_rows_simdgroup(
                        cmd,
                        "layer_norm",
                        &[buf.buffer(), &buf_norm2_w, &buf_norm2_b, &buf_h, &buf_eps],
                        total_rows,
                    );
                }
                buf_normed2_local = Some(buf);
            }

            let ffn_in = if let Some(ref b) = buf_normed2_local {
                b.buffer()
            } else {
                current_hidden.buffer()
            };
            let buf_inter = self.buf_u32(inter as u32)?;
            let buf_wdown = self.buf_cached(weights.ffn_down_weight)?;

            if let Some(gate_weight) = weights.ffn_gate_weight {
                // SwiGLU FFN
                let up_weight = weights.ffn_up_weight.ok_or_else(|| {
                    InferError::ModelIncompatible("SwiGLU FFN requires ffn_up_weight".into())
                })?;
                let buf_wgateup = self.buf_cached_concat(&[gate_weight, up_weight])?;

                let buf_gateup = self.pool.acquire_uninit(total_rows * 2 * inter * 4)?;
                let buf_act = self.pool.acquire_uninit(total_rows * inter * 4)?;
                let buf_two_inter = self.buf_u32((2 * inter) as u32)?;

                if use_mma(total_rows, inter, h) {
                    self.encode_mma(
                        cmd,
                        "matmul_transb_simdgroup",
                        &[
                            ffn_in,
                            &buf_wgateup,
                            buf_gateup.buffer(),
                            &buf_rows,
                            &buf_two_inter,
                            &buf_h,
                        ],
                        total_rows,
                        2 * inter,
                        h,
                        1,
                    );
                } else {
                    Self::encode_matmul(
                        cmd,
                        &self.pipelines["matmul_transb"],
                        ffn_in,
                        &buf_wgateup,
                        buf_gateup.buffer(),
                        &buf_rows,
                        &buf_two_inter,
                        &buf_h,
                        2 * inter,
                        total_rows,
                    );
                }

                self.encode_1d(
                    cmd,
                    "swiglu_activation_fat",
                    &[buf_gateup.buffer(), buf_act.buffer(), &buf_inter],
                    total_rows * inter,
                );

                if use_mma(total_rows, h, inter) {
                    self.encode_mma(
                        cmd,
                        "matmul_transb_simdgroup",
                        &[
                            buf_act.buffer(),
                            &buf_wdown,
                            buf_ffn_out.buffer(),
                            &buf_rows,
                            &buf_h,
                            &buf_inter,
                        ],
                        total_rows,
                        h,
                        inter,
                        1,
                    );
                } else {
                    Self::encode_matmul(
                        cmd,
                        &self.pipelines["matmul_transb"],
                        buf_act.buffer(),
                        &buf_wdown,
                        buf_ffn_out.buffer(),
                        &buf_rows,
                        &buf_h,
                        &buf_inter,
                        h,
                        total_rows,
                    );
                }

                retains.push(buf_gateup);
                retains.push(buf_act);
            } else {
                // Standard GELU FFN
                let up_weight = weights.ffn_up_weight.ok_or_else(|| {
                    InferError::ModelIncompatible("FFN requires ffn_up_weight".into())
                })?;
                let buf_wup = self.buf_cached(up_weight)?;
                let buf_up = self.pool.acquire_uninit(total_rows * inter * 4)?;

                if use_mma(total_rows, inter, h) {
                    self.encode_mma(
                        cmd,
                        "matmul_transb_simdgroup",
                        &[
                            ffn_in,
                            &buf_wup,
                            buf_up.buffer(),
                            &buf_rows,
                            &buf_inter,
                            &buf_h,
                        ],
                        total_rows,
                        inter,
                        h,
                        1,
                    );
                } else {
                    Self::encode_matmul(
                        cmd,
                        &self.pipelines["matmul_transb"],
                        ffn_in,
                        &buf_wup,
                        buf_up.buffer(),
                        &buf_rows,
                        &buf_inter,
                        &buf_h,
                        inter,
                        total_rows,
                    );
                }

                if let Some(up_bias) = weights.ffn_up_bias {
                    let b = self.buf_cached(up_bias)?;
                    self.encode_1d(
                        cmd,
                        "elementwise_add_broadcast",
                        &[buf_up.buffer(), &b, &buf_inter],
                        total_rows * inter,
                    );
                }

                self.encode_1d(
                    cmd,
                    "gelu_activation",
                    &[buf_up.buffer()],
                    total_rows * inter,
                );

                if use_mma(total_rows, h, inter) {
                    self.encode_mma(
                        cmd,
                        "matmul_transb_simdgroup",
                        &[
                            buf_up.buffer(),
                            &buf_wdown,
                            buf_ffn_out.buffer(),
                            &buf_rows,
                            &buf_h,
                            &buf_inter,
                        ],
                        total_rows,
                        h,
                        inter,
                        1,
                    );
                } else {
                    Self::encode_matmul(
                        cmd,
                        &self.pipelines["matmul_transb"],
                        buf_up.buffer(),
                        &buf_wdown,
                        buf_ffn_out.buffer(),
                        &buf_rows,
                        &buf_h,
                        &buf_inter,
                        h,
                        total_rows,
                    );
                }
                retains.push(buf_up);
            }

            if let Some(down_bias) = weights.ffn_down_bias {
                let b = self.buf_cached(down_bias)?;
                self.encode_1d(
                    cmd,
                    "elementwise_add_broadcast",
                    &[buf_ffn_out.buffer(), &b, &buf_h],
                    total_rows * h,
                );
            }

            self.encode_1d(
                cmd,
                "elementwise_add",
                &[current_hidden.buffer(), buf_ffn_out.buffer()],
                total_rows * h,
            );

            if !config.pre_ln {
                let buf_norm2_w = self.buf_cached(weights.norm2_weight)?;
                if config.use_rms {
                    self.encode_rows_simdgroup(
                        cmd,
                        "rms_norm",
                        &[current_hidden.buffer(), &buf_norm2_w, &buf_h, &buf_eps],
                        total_rows,
                    );
                } else {
                    let buf_norm2_b = self.buf_cached(weights.norm2_bias.unwrap_or(&[]))?;
                    self.encode_rows_simdgroup(
                        cmd,
                        "layer_norm",
                        &[
                            current_hidden.buffer(),
                            &buf_norm2_w,
                            &buf_norm2_b,
                            &buf_h,
                            &buf_eps,
                        ],
                        total_rows,
                    );
                }
            }

            buf_normed2 = buf_normed2_local;
            Ok(())
        })?;

        retains.push(buf_q);
        retains.push(buf_k);
        retains.push(buf_v);

        if let Some(b) = buf_normed1 {
            retains.push(b);
        }
        if let Some(b) = buf_normed2 {
            retains.push(b);
        }
        retains.push(buf_ffn_out);

        Ok(cmd)
    }

    fn encode_pool_rows_into(
        &self,
        cmd: &CommandBufferRef,
        current_hidden: &PooledBuffer,
        masks: &[u32],
        config: &LayerConfig,
        pooling: PoolingMode,
    ) -> Result<PooledBuffer, InferError> {
        let h = config.hidden_size;
        let pooled = self.pool.acquire_uninit(config.batch_size * h * 4)?;
        let mask_buf = self.buf_u32_slice(masks)?;
        let buf_max_len = self.buf_u32(config.max_len as u32)?;
        let buf_h = self.buf_u32(h as u32)?;
        let buf_cls_pooling = self.buf_u32(matches!(pooling, PoolingMode::Cls) as u32)?;

        let pipeline = &self.pipelines["pool_rows"];
        let enc = cmd.new_compute_command_encoder();
        enc.set_compute_pipeline_state(pipeline);
        enc.set_buffer(0, Some(current_hidden.buffer()), 0);
        enc.set_buffer(1, Some(&mask_buf), 0);
        enc.set_buffer(2, Some(pooled.buffer()), 0);
        enc.set_buffer(3, Some(&buf_max_len), 0);
        enc.set_buffer(4, Some(&buf_h), 0);
        enc.set_buffer(5, Some(&buf_cls_pooling), 0);
        let tw = pipeline.thread_execution_width().max(1);
        let threads = MTLSize::new(config.batch_size as u64 * tw, 1, 1);
        let tg = MTLSize::new(tw, 1, 1);
        enc.dispatch_threads(threads, tg);
        enc.end_encoding();
        Ok(pooled)
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
        let total_rows = config.batch_size * config.max_len;
        let h = config.hidden_size;
        let estimated_bytes =
            estimate_resident_segment_bytes(std::slice::from_ref(weights), config, None, false);
        let Some(_resident_reservation) =
            self.try_reserve_resident_segment(estimated_bytes, "forward_layer_batched")
        else {
            return Ok(None);
        };
        let out = autoreleasepool(|_| -> Result<Vec<f32>, InferError> {
            let current_hidden = self.buf_slice_pooled(hidden)?;
            let mut cmd = self.queue.new_command_buffer();
            let mut retains = Vec::new();
            cmd = self.encode_layer_resident_into(
                cmd,
                &current_hidden,
                masks,
                weights,
                config,
                rope_cos,
                rope_sin,
                &mut retains,
            )?;
            self.commit_wait(cmd);
            Ok(Self::read_buf(current_hidden.buffer(), total_rows * h))
        })?;
        Ok(Some(out))
    }

    fn forward_layers_batched(
        &self,
        hidden: &[f32],
        masks: &[u32],
        layers: &[LayerTensors],
        config: &LayerConfig,
        rope_cos: &[f32],
        rope_sin: &[f32],
    ) -> Result<Option<Vec<f32>>, InferError> {
        if layers.is_empty() {
            return Ok(None);
        }
        let _span = tracing::info_span!(
            "kin_infer.metal.forward_layers_batched",
            layers = layers.len()
        )
        .entered();
        let total_rows = config.batch_size * config.max_len;
        let h = config.hidden_size;
        let estimated_bytes = estimate_resident_segment_bytes(layers, config, None, false);
        let Some(_resident_reservation) =
            self.try_reserve_resident_segment(estimated_bytes, "forward_layers_batched")
        else {
            return Ok(None);
        };
        let out = autoreleasepool(|_| -> Result<Vec<f32>, InferError> {
            let current_hidden = self.buf_slice_pooled(hidden)?;
            let mut cmd = self.queue.new_command_buffer();
            let mut retains = Vec::new();
            for weights in layers {
                cmd = self.encode_layer_resident_into(
                    cmd,
                    &current_hidden,
                    masks,
                    weights,
                    config,
                    rope_cos,
                    rope_sin,
                    &mut retains,
                )?;
            }
            self.commit_wait(cmd);
            Ok(Self::read_buf(current_hidden.buffer(), total_rows * h))
        })?;
        Ok(Some(out))
    }

    fn forward_layers_batched_segmented(
        &self,
        hidden: &[f32],
        masks: &[u32],
        layers: &[LayerTensors],
        config: &LayerConfig,
        rope_cos: &[f32],
        rope_sin: &[f32],
        segment_layers: usize,
    ) -> Result<Option<Vec<f32>>, InferError> {
        if layers.is_empty() {
            return Ok(None);
        }
        let segment_layers = segment_layers.max(1);
        let segment_count = layers.len().div_ceil(segment_layers);
        let _span = tracing::info_span!(
            "kin_infer.metal.forward_layers_batched_segmented",
            layers = layers.len(),
            segment_layers = segment_layers,
            segment_count = segment_count,
            batch_size = config.batch_size,
            max_seq = config.max_len,
        )
        .entered();
        let total_rows = config.batch_size * config.max_len;
        let h = config.hidden_size;
        let out = autoreleasepool(|_| -> Result<Option<Vec<f32>>, InferError> {
            let mut current_hidden = None;
            for (segment_index, chunk) in layers.chunks(segment_layers).enumerate() {
                let estimated_bytes = estimate_resident_segment_bytes(chunk, config, None, false);
                let Some(_resident_reservation) = self.try_reserve_resident_segment(
                    estimated_bytes,
                    "forward_layers_batched_segmented",
                ) else {
                    return Ok(None);
                };
                let hidden_buf = if segment_index == 0 {
                    self.buf_slice_pooled(hidden)?
                } else {
                    current_hidden.take().ok_or_else(|| {
                        InferError::Internal(
                            "segmented resident Metal path lost current hidden buffer".into(),
                        )
                    })?
                };
                let mut cmd = self.queue.new_command_buffer();
                let mut retains = Vec::new();
                for weights in chunk {
                    cmd = self.encode_layer_resident_into(
                        cmd,
                        &hidden_buf,
                        masks,
                        weights,
                        config,
                        rope_cos,
                        rope_sin,
                        &mut retains,
                    )?;
                }
                self.commit_wait(cmd);

                let is_last = segment_index + 1 == segment_count;
                if is_last {
                    return Ok(Some(Self::read_buf(hidden_buf.buffer(), total_rows * h)));
                }
                current_hidden = Some(hidden_buf);
            }

            Err(InferError::Internal(
                "segmented resident Metal path completed no segments".into(),
            ))
        })?;
        Ok(out)
    }

    fn forward_layers_batched_pooled(
        &self,
        hidden: &[f32],
        masks: &[u32],
        layers: &[LayerTensors],
        config: &LayerConfig,
        embedding: &EmbeddingPrelude<'_>,
        rope_cos: &[f32],
        rope_sin: &[f32],
        pooling: PoolingMode,
    ) -> Result<Option<Vec<f32>>, InferError> {
        if layers.is_empty() {
            return Ok(None);
        }
        let _span = tracing::info_span!(
            "kin_infer.metal.forward_layers_batched_pooled",
            layers = layers.len()
        )
        .entered();
        let h = config.hidden_size;
        let estimated_bytes =
            estimate_resident_segment_bytes(layers, config, Some(embedding), true);
        let Some(_resident_reservation) =
            self.try_reserve_resident_segment(estimated_bytes, "forward_layers_batched_pooled")
        else {
            return Ok(None);
        };
        let out = autoreleasepool(|_| -> Result<Vec<f32>, InferError> {
            let mut cmd = self.queue.new_command_buffer();
            let mut retains = Vec::new();
            let current_hidden =
                self.encode_embedding_prelude_into(cmd, hidden, embedding, config, &mut retains)?;
            for weights in layers {
                cmd = self.encode_layer_resident_into(
                    cmd,
                    &current_hidden,
                    masks,
                    weights,
                    config,
                    rope_cos,
                    rope_sin,
                    &mut retains,
                )?;
            }

            let pooled =
                self.encode_pool_rows_into(cmd, &current_hidden, masks, config, pooling)?;
            self.commit_wait(cmd);

            Ok(Self::read_buf(pooled.buffer(), config.batch_size * h))
        })?;
        Ok(Some(out))
    }

    fn forward_layers_batched_pooled_segmented(
        &self,
        hidden: &[f32],
        masks: &[u32],
        layers: &[LayerTensors],
        config: &LayerConfig,
        embedding: &EmbeddingPrelude<'_>,
        rope_cos: &[f32],
        rope_sin: &[f32],
        pooling: PoolingMode,
        segment_layers: usize,
    ) -> Result<Option<Vec<f32>>, InferError> {
        if layers.is_empty() {
            return Ok(None);
        }
        let segment_layers = segment_layers.max(1);
        let segment_count = layers.len().div_ceil(segment_layers);
        let _span = tracing::info_span!(
            "kin_infer.metal.forward_layers_batched_pooled_segmented",
            layers = layers.len(),
            segment_layers = segment_layers,
            segment_count = segment_count,
            batch_size = config.batch_size,
            max_seq = config.max_len,
        )
        .entered();
        let h = config.hidden_size;
        let out = autoreleasepool(|_| -> Result<Option<Vec<f32>>, InferError> {
            let mut current_hidden = None;
            for (segment_index, chunk) in layers.chunks(segment_layers).enumerate() {
                let is_last = segment_index + 1 == segment_count;
                let segment_embedding = (segment_index == 0).then_some(embedding);
                let estimated_bytes =
                    estimate_resident_segment_bytes(chunk, config, segment_embedding, is_last);
                let Some(_resident_reservation) = self.try_reserve_resident_segment(
                    estimated_bytes,
                    "forward_layers_batched_pooled_segmented",
                ) else {
                    return Ok(None);
                };
                let mut cmd = self.queue.new_command_buffer();
                let mut retains = Vec::new();
                let hidden_buf = if segment_index == 0 {
                    self.encode_embedding_prelude_into(
                        cmd,
                        hidden,
                        embedding,
                        config,
                        &mut retains,
                    )?
                } else {
                    current_hidden.take().ok_or_else(|| {
                        InferError::Internal(
                            "segmented pooled Metal path lost current hidden buffer".into(),
                        )
                    })?
                };

                for weights in chunk {
                    cmd = self.encode_layer_resident_into(
                        cmd,
                        &hidden_buf,
                        masks,
                        weights,
                        config,
                        rope_cos,
                        rope_sin,
                        &mut retains,
                    )?;
                }

                if is_last {
                    let pooled =
                        self.encode_pool_rows_into(cmd, &hidden_buf, masks, config, pooling)?;
                    self.commit_wait(cmd);
                    return Ok(Some(Self::read_buf(pooled.buffer(), config.batch_size * h)));
                }

                self.commit_wait(cmd);
                current_hidden = Some(hidden_buf);
            }

            Err(InferError::Internal(
                "segmented pooled Metal path completed no segments".into(),
            ))
        })?;
        Ok(out)
    }

    fn matmul(
        &self,
        a: &[f32],
        b: &[f32],
        m: usize,
        n: usize,
        k: usize,
    ) -> Result<Vec<f32>, InferError> {
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

        Ok(Self::read_buf(
            buf_c.buffer(),
            num_heads * seq_len * seq_len,
        ))
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

        Ok(Self::read_buf(
            buf_c.buffer(),
            num_heads * seq_len * head_dim,
        ))
    }

    fn softmax(&self, data: &mut [f32], rows: usize, cols: usize) -> Result<(), InferError> {
        let _span =
            tracing::info_span!("kin_infer.metal.softmax", rows = rows, cols = cols).entered();
        Self::count_nonfinite(&format!("softmax_in rows={rows} cols={cols}"), data);
        let buf = self.buf_slice_pooled(data)?;
        let buf_cols = self.buf_u32(cols as u32)?;
        time_phase(Phase::Norm, || {
            self.dispatch_rows_simdgroup("softmax_rows", &[buf.buffer(), &buf_cols], rows)
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
        let buf_gamma = self.buf_slice_pooled(gamma)?;
        let buf_beta = self.buf_slice_pooled(beta)?;
        let buf_cols = self.buf_u32(cols as u32)?;
        let buf_eps = self.buf_f32(eps)?;
        time_phase(Phase::Norm, || {
            self.dispatch_rows_simdgroup(
                "layer_norm",
                &[
                    buf.buffer(),
                    buf_gamma.buffer(),
                    buf_beta.buffer(),
                    &buf_cols,
                    &buf_eps,
                ],
                rows,
            )
        });
        Self::read_buf_into(buf.buffer(), data);
        Self::count_nonfinite(&format!("layer_norm rows={rows} cols={cols}"), data);
        Ok(())
    }

    fn rms_norm(
        &self,
        data: &mut [f32],
        weight: &[f32],
        rows: usize,
        cols: usize,
        eps: f32,
    ) -> Result<(), InferError> {
        let _span = tracing::info_span!(
            "kin_infer.metal.rms_norm",
            rows = rows,
            cols = cols,
            eps = eps
        )
        .entered();
        let buf = self.buf_slice_pooled(data)?;
        let buf_weight = self.buf_slice_pooled(weight)?;
        let buf_cols = self.buf_u32(cols as u32)?;
        let buf_eps = self.buf_f32(eps)?;
        time_phase(Phase::Norm, || {
            self.dispatch_rows_simdgroup(
                "rms_norm",
                &[buf.buffer(), buf_weight.buffer(), &buf_cols, &buf_eps],
                rows,
            )
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
            self.dispatch_1d(
                "elementwise_mul",
                &[buf_a.buffer(), buf_b.buffer()],
                a.len(),
            )
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
                self.encode_mma(
                    cmd,
                    mm_mma,
                    &[
                        buf_x.buffer(),
                        &buf_wgateup,
                        buf_gateup.buffer(),
                        &buf_rows,
                        &buf_two_inter,
                        &buf_hidden,
                    ],
                    rows,
                    2 * inter,
                    hidden,
                    1,
                );
            } else {
                Self::encode_matmul(
                    cmd,
                    mm,
                    buf_x.buffer(),
                    &buf_wgateup,
                    buf_gateup.buffer(),
                    &buf_rows,
                    &buf_two_inter,
                    &buf_hidden,
                    2 * inter,
                    rows,
                );
            }

            // act = silu(gate) * up -> [rows, inter], reading the interleaved fat buffer
            {
                let enc = cmd.new_compute_command_encoder();
                enc.set_compute_pipeline_state(swi);
                enc.set_buffer(0, Some(buf_gateup.buffer()), 0);
                enc.set_buffer(1, Some(buf_act.buffer()), 0);
                enc.set_buffer(2, Some(&buf_inter), 0);
                let total = (rows * inter) as u64;
                let tw = swi.thread_execution_width();
                enc.dispatch_threads(
                    MTLSize::new(total, 1, 1),
                    MTLSize::new(tw.min(total).max(1), 1, 1),
                );
                enc.end_encoding();
            }

            // out = act @ w_down^T -> [rows, hidden]  (M=rows, N=hidden, K=inter)
            if down_mma {
                self.encode_mma(
                    cmd,
                    mm_mma,
                    &[
                        buf_act.buffer(),
                        &buf_wdown,
                        buf_out.buffer(),
                        &buf_rows,
                        &buf_hidden,
                        &buf_inter,
                    ],
                    rows,
                    hidden,
                    inter,
                    1,
                );
            } else {
                Self::encode_matmul(
                    cmd,
                    mm,
                    buf_act.buffer(),
                    &buf_wdown,
                    buf_out.buffer(),
                    &buf_rows,
                    &buf_hidden,
                    &buf_inter,
                    hidden,
                    rows,
                );
            }

            time_phase(Phase::Matmul, || {
                self.commit_wait(cmd);
            });
            Self::read_buf(buf_out.buffer(), rows * hidden)
        });
        Self::count_nonfinite(
            &format!("fused_ffn_swiglu rows={rows} hidden={hidden} inter={inter}"),
            &out,
        );
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

        // gate/up projection, SwiGLU, down projection, residual add, and LayerNorm
        // each read the previous stage's output, so each runs in its own command
        // buffer and completes before the next reads it. Chaining the stages in one
        // command buffer left each output visible to its dependent read only by
        // timing, which produced nondeterministic bytes for non-tile-aligned rows.
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
            // gateup = x @ [w_gate|w_up]^T -> [rows, 2*inter]
            let cmd = self.queue.new_command_buffer();
            if gateup_mma {
                self.encode_mma(
                    cmd,
                    mm_mma,
                    &[
                        buf_x.buffer(),
                        &buf_wgateup,
                        buf_gateup.buffer(),
                        &buf_rows,
                        &buf_two_inter,
                        &buf_hidden,
                    ],
                    rows,
                    2 * inter,
                    hidden,
                    1,
                );
            } else {
                Self::encode_matmul(
                    cmd,
                    mm,
                    buf_x.buffer(),
                    &buf_wgateup,
                    buf_gateup.buffer(),
                    &buf_rows,
                    &buf_two_inter,
                    &buf_hidden,
                    2 * inter,
                    rows,
                );
            }
            time_phase(Phase::Matmul, || self.commit_wait(cmd));

            // act = silu(gate) * up -> [rows, inter]
            let cmd = self.queue.new_command_buffer();
            {
                let enc = cmd.new_compute_command_encoder();
                enc.set_compute_pipeline_state(swi);
                enc.set_buffer(0, Some(buf_gateup.buffer()), 0);
                enc.set_buffer(1, Some(buf_act.buffer()), 0);
                enc.set_buffer(2, Some(&buf_inter), 0);
                let total = (rows * inter) as u64;
                let tw = swi.thread_execution_width();
                enc.dispatch_threads(
                    MTLSize::new(total, 1, 1),
                    MTLSize::new(tw.min(total).max(1), 1, 1),
                );
                enc.end_encoding();
            }
            time_phase(Phase::Activation, || self.commit_wait(cmd));

            // out = act @ w_down^T -> [rows, hidden]
            let cmd = self.queue.new_command_buffer();
            if down_mma {
                self.encode_mma(
                    cmd,
                    mm_mma,
                    &[
                        buf_act.buffer(),
                        &buf_wdown,
                        buf_out.buffer(),
                        &buf_rows,
                        &buf_hidden,
                        &buf_inter,
                    ],
                    rows,
                    hidden,
                    inter,
                    1,
                );
            } else {
                Self::encode_matmul(
                    cmd,
                    mm,
                    buf_act.buffer(),
                    &buf_wdown,
                    buf_out.buffer(),
                    &buf_rows,
                    &buf_hidden,
                    &buf_inter,
                    hidden,
                    rows,
                );
            }
            time_phase(Phase::Matmul, || self.commit_wait(cmd));

            // out += residual (resident)
            let cmd = self.queue.new_command_buffer();
            {
                let enc = cmd.new_compute_command_encoder();
                enc.set_compute_pipeline_state(add);
                enc.set_buffer(0, Some(buf_out.buffer()), 0);
                enc.set_buffer(1, Some(buf_residual.buffer()), 0);
                let total = (rows * hidden) as u64;
                let tw = add.thread_execution_width();
                enc.dispatch_threads(
                    MTLSize::new(total, 1, 1),
                    MTLSize::new(tw.min(total).max(1), 1, 1),
                );
                enc.end_encoding();
            }
            time_phase(Phase::Activation, || self.commit_wait(cmd));

            // out = layer_norm(out, gamma, beta, eps) (in-place)
            let cmd = self.queue.new_command_buffer();
            {
                let enc = cmd.new_compute_command_encoder();
                enc.set_compute_pipeline_state(ln);
                enc.set_buffer(0, Some(buf_out.buffer()), 0);
                enc.set_buffer(1, Some(&buf_gamma), 0);
                enc.set_buffer(2, Some(&buf_beta), 0);
                enc.set_buffer(3, Some(&buf_hidden), 0);
                enc.set_buffer(4, Some(&buf_eps), 0);
                let tw = ln.thread_execution_width();
                let rows_u = rows as u64;
                enc.dispatch_threads(MTLSize::new(rows_u * tw, 1, 1), MTLSize::new(tw, 1, 1));
                enc.end_encoding();
            }
            time_phase(Phase::Norm, || self.commit_wait(cmd));

            Self::read_buf(buf_out.buffer(), rows * hidden)
        });
        Self::count_nonfinite(
            &format!("fused_ffn_swiglu_add_norm rows={rows} hidden={hidden} inter={inter}"),
            &out,
        );
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

        // x uploaded once; weight/gamma/beta hit the persistent cache. The residual
        // add and LayerNorm read the projection in place, so each stage runs in its
        // own command buffer and completes before the next reads its output. A single
        // command buffer chaining all three left the matmul output visible to the
        // dependent reads only by timing, which produced nondeterministic bytes for
        // non-tile-aligned row counts. The proj buffer is a pooled transient.
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
            // proj = x @ weight^T -> [rows, hidden]  (M=rows, N=hidden, K=cols)
            let cmd = self.queue.new_command_buffer();
            if proj_mma {
                self.encode_mma(
                    cmd,
                    mm_mma,
                    &[
                        buf_x.buffer(),
                        &buf_w,
                        buf_proj.buffer(),
                        &buf_rows,
                        &buf_hidden,
                        &buf_cols,
                    ],
                    rows,
                    hidden,
                    cols,
                    1,
                );
            } else {
                Self::encode_matmul(
                    cmd,
                    mm,
                    buf_x.buffer(),
                    &buf_w,
                    buf_proj.buffer(),
                    &buf_rows,
                    &buf_hidden,
                    &buf_cols,
                    hidden,
                    rows,
                );
            }
            time_phase(Phase::Matmul, || self.commit_wait(cmd));

            // proj += residual (in-place on the resident projection buffer)
            let cmd = self.queue.new_command_buffer();
            {
                let enc = cmd.new_compute_command_encoder();
                enc.set_compute_pipeline_state(add);
                enc.set_buffer(0, Some(buf_proj.buffer()), 0);
                enc.set_buffer(1, Some(buf_residual.buffer()), 0);
                let total = (rows * hidden) as u64;
                let tw = add.thread_execution_width();
                enc.dispatch_threads(
                    MTLSize::new(total, 1, 1),
                    MTLSize::new(tw.min(total).max(1), 1, 1),
                );
                enc.end_encoding();
            }
            time_phase(Phase::Activation, || self.commit_wait(cmd));

            // out = layer_norm(proj, gamma, beta, eps) (in-place)
            let cmd = self.queue.new_command_buffer();
            {
                let enc = cmd.new_compute_command_encoder();
                enc.set_compute_pipeline_state(ln);
                enc.set_buffer(0, Some(buf_proj.buffer()), 0);
                enc.set_buffer(1, Some(&buf_gamma), 0);
                enc.set_buffer(2, Some(&buf_beta), 0);
                enc.set_buffer(3, Some(&buf_hidden), 0);
                enc.set_buffer(4, Some(&buf_eps), 0);
                let tw = ln.thread_execution_width();
                let rows_u = rows as u64;
                enc.dispatch_threads(MTLSize::new(rows_u * tw, 1, 1), MTLSize::new(tw, 1, 1));
                enc.end_encoding();
            }
            time_phase(Phase::Norm, || self.commit_wait(cmd));

            Self::read_buf(buf_proj.buffer(), rows * hidden)
        });
        Self::count_nonfinite(
            &format!("fused_linear_add_norm rows={rows} hidden={hidden}"),
            &out,
        );
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
                let tw = p.thread_execution_width();
                let threads = MTLSize::new((total_rows as u64) * tw, 1, 1);
                let tg = MTLSize::new(tw, 1, 1);
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

            Ok(Self::read_buf(
                buf_out.buffer(),
                num_heads * seq_len * head_dim,
            ))
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
        let buf_out = self.buf_zeros_pooled(total_heads * seq_len * head_dim)?;
        let buf_seq = self.buf_u32(seq_len as u32)?;
        let buf_dim = self.buf_u32(head_dim as u32)?;
        let buf_scale = self.buf_f32(scale)?;
        let has_alibi = !alibi_slopes.is_empty();
        let buf_masks = self.buf_u32_slice(masks)?;
        let buf_heads_per_group = self.buf_u32(heads_per_group as u32)?;

        if let Some(c7_pipeline) = self
            .pipelines
            .get("c7_flash_attention_batched")
            .filter(|pipeline| pipeline.thread_execution_width() == 32)
            .filter(|_| {
                use_c7_flash_attention(
                    num_groups,
                    seq_len,
                    head_dim,
                    heads_per_group,
                    has_alibi,
                    scale,
                    masks,
                )
            })
        {
            let out = autoreleasepool(|_| -> Result<Vec<f32>, InferError> {
                let cmd = self.queue.new_command_buffer();
                {
                    let _op_span = tracing::info_span!(
                        "kin_infer.metal.fused_attention_batched.c7_flash_attention"
                    )
                    .entered();
                    let enc = cmd.new_compute_command_encoder();
                    enc.set_compute_pipeline_state(c7_pipeline);
                    enc.set_buffer(0, Some(buf_q.buffer()), 0);
                    enc.set_buffer(1, Some(buf_k.buffer()), 0);
                    enc.set_buffer(2, Some(buf_v.buffer()), 0);
                    enc.set_buffer(3, Some(buf_out.buffer()), 0);
                    enc.set_buffer(4, Some(&buf_masks), 0);
                    enc.set_buffer(5, Some(&buf_seq), 0);
                    enc.set_buffer(6, Some(&buf_dim), 0);
                    enc.set_buffer(7, Some(&buf_scale), 0);
                    enc.set_buffer(8, Some(&buf_heads_per_group), 0);
                    let groups = MTLSize::new(seq_len as u64, total_heads as u64, 1);
                    let tg = MTLSize::new(32, 1, 1);
                    enc.dispatch_thread_groups(groups, tg);
                    enc.end_encoding();
                }
                {
                    let _commit_span = tracing::info_span!(
                        "kin_infer.metal.fused_attention_batched.c7_commit_wait"
                    )
                    .entered();
                    time_phase(Phase::Attention, || {
                        self.commit_wait(cmd);
                    });
                }
                Ok(Self::read_buf(
                    buf_out.buffer(),
                    total_heads * seq_len * head_dim,
                ))
            })?;
            Self::count_nonfinite(
                &format!("c7_flash_attention_batched seq_len={seq_len} total_heads={total_heads}"),
                &out,
            );
            return Ok(out);
        }

        let alibi_ref = if has_alibi { alibi_slopes } else { &[0.0f32] };
        let pooled_alibi = self.buf_slice_pooled(alibi_ref)?;
        let buf_has_alibi = self.buf_u32(has_alibi as u32)?;
        let buf_scores = self.buf_zeros_pooled(total_heads * seq_len * seq_len)?;

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
                let threads = MTLSize::new((total_rows * tw) as u64, 1, 1);
                let tg = MTLSize::new(tw as u64, 1, 1);
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

            Ok(Self::read_buf(
                buf_out.buffer(),
                total_heads * seq_len * head_dim,
            ))
        })?;
        Self::count_nonfinite(
            &format!("fused_attention_batched seq_len={seq_len} total_heads={total_heads}"),
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
                let threads = MTLSize::new(head_dim as u64, seq_len as u64, total_heads as u64);
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
                let threads = MTLSize::new((total_rows * tw) as u64, 1, 1);
                let tg = MTLSize::new(tw as u64, 1, 1);
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
                let threads = MTLSize::new(head_dim as u64, seq_len as u64, total_heads as u64);
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
    use std::sync::{Mutex as StdMutex, MutexGuard as StdMutexGuard};

    static PROFILE_TEST_LOCK: StdMutex<()> = StdMutex::new(());

    fn profile_test_lock() -> StdMutexGuard<'static, ()> {
        PROFILE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[test]
    fn util_sampler_attributes_busy_span_across_windows() {
        // A busy span that straddles a window boundary is split proportionally
        // into each window it overlaps — the same accounting a fixed-interval
        // sampler would produce. Window 0 is [0, W); the span [W/2, W + W/4)
        // contributes W/2 to window 0 and W/4 to window 1.
        let w = UTIL_WINDOW_NANOS;
        let mut sampler = UtilSampler::new();
        sampler.anchor = Some(std::time::Instant::now());
        sampler.attribute(w / 2, w / 2 + w / 4);
        assert_eq!(sampler.windows.len(), 2);
        assert_eq!(sampler.windows[0], w / 2);
        assert_eq!(sampler.windows[1], w / 4);
    }

    #[test]
    fn util_sampler_no_op_without_anchor() {
        // Before any reset establishes an anchor, attribution records nothing —
        // util% reads as "no timed region" rather than a bogus fraction.
        let mut sampler = UtilSampler::new();
        sampler.attribute(0, UTIL_WINDOW_NANOS);
        assert!(sampler.windows.is_empty());
    }

    #[test]
    fn util_median_counts_trailing_idle_windows_as_zero() {
        // Two fully-busy windows followed by two idle windows must median to a
        // value reflecting the late stall — not stay pinned at 100% — so the
        // median is the honest "sustained saturation" number. Sampling under the
        // process-wide profile lock since the util sampler is global state.
        let _guard = profile_test_lock();
        let w = UTIL_WINDOW_NANOS;
        {
            let mut sampler = util_sampler().lock();
            sampler.windows.clear();
            // Backdate the anchor by ~4 windows so `profile_gpu_util_median_pct`
            // sees four elapsed windows, the last two of which have no GPU work.
            sampler.anchor = std::time::Instant::now()
                .checked_sub(std::time::Duration::from_nanos(4 * w + w / 2));
            sampler.windows = vec![w, w, 0, 0]; // 100%, 100%, 0%, 0%
        }
        let median = profile_gpu_util_median_pct();
        // Median of [100, 100, 0, 0, 0] (>=5 windows incl. the current partial) is
        // 0; of an even count it averages the two middles. Either way the trailing
        // idle drags it well below 100 — the property under test.
        assert!(
            median < 60.0,
            "median util% should reflect trailing idle, got {median}"
        );
        // Leave global state clean for other tests.
        let mut sampler = util_sampler().lock();
        sampler.windows.clear();
        sampler.anchor = None;
    }

    #[test]
    fn resident_stack_memory_gate_reserves_declines_and_releases() {
        let gate = ResidentStackMemoryGate::new(100);

        let first = gate.try_reserve(60).expect("first reservation fits");
        assert!(gate.try_reserve(41).is_none());
        assert!(gate.try_reserve(101).is_none());

        drop(first);
        assert!(gate.try_reserve(100).is_some());
    }

    #[test]
    fn resident_stack_budget_caps_against_hw_memsize_and_absolute_ceiling() {
        use crate::resource::{
            resident_stack_budget_bytes, DEFAULT_RESIDENT_STACK_BUDGET_DIVISOR,
            RESIDENT_STACK_ABS_CEILING_BYTES, RESIDENT_STACK_HW_MEMSIZE_PERCENT,
        };
        const GIB: u64 = 1024 * 1024 * 1024;
        let pct = RESIDENT_STACK_HW_MEMSIZE_PERCENT;
        let ceiling = RESIDENT_STACK_ABS_CEILING_BYTES;

        // Large unified Mac: working-set/2 (48G) and hw% (32G) both exceed the
        // absolute ceiling, so the budget is the ceiling — not the loose ~48G.
        let big = resident_stack_budget_bytes(96 * GIB, Some(128 * GIB));
        assert_eq!(big, ceiling);
        assert!(big < 96 * GIB / DEFAULT_RESIDENT_STACK_BUDGET_DIVISOR);

        // Small Mac where the hw% term is the binding ceiling (below both the
        // working-set term and the absolute ceiling).
        let small = resident_stack_budget_bytes(11 * GIB, Some(16 * GIB));
        let expected_hw = (16 * GIB).saturating_mul(pct) / 100;
        assert_eq!(small, expected_hw);
        assert!(small < ceiling);

        // Working-set unknown (recommended == 0): hw% / absolute ceiling still bound.
        let no_ws = resident_stack_budget_bytes(0, Some(64 * GIB));
        let hw_64 = ((64 * GIB).saturating_mul(pct) / 100).min(RESIDENT_STACK_ABS_CEILING_BYTES);
        assert_eq!(no_ws, hw_64);

        // Physical RAM unknown: working-set term and absolute ceiling still bound.
        let no_hw = resident_stack_budget_bytes(96 * GIB, None);
        assert_eq!(no_hw, ceiling);

        // Both unknown: only the absolute ceiling remains.
        let neither = resident_stack_budget_bytes(0, None);
        assert_eq!(neither, ceiling);
    }

    // The inspect-only MetalGovernorPlan must report exactly what the live Metal
    // backend resolves for the same hardware inputs — no divergence. The backend
    // resident budget goes through `crate::resource::resident_stack_budget_bytes`
    // (via `resolve_resident_stack_budget`) and the BufferPool ceilings come from
    // `crate::resource::DEFAULT_BUFFER_POOL_*`, so these assert the two never drift.
    #[test]
    fn metal_governor_plan_matches_backend_resolution() {
        use crate::resource::MetalGovernorPlan;
        const GIB: u64 = 1024 * 1024 * 1024;

        // Resident budget: the plan's value equals the backend formula's, byte for
        // byte, across the same input regimes the backend can hit at startup.
        for (recommended, system_total) in [
            (96 * GIB, Some(128 * GIB)), // absolute-ceiling regime
            (11 * GIB, Some(16 * GIB)),  // hw% binding regime
            (0, Some(64 * GIB)),         // working-set unknown
            (96 * GIB, None),            // physical RAM unknown
            (0, None),                   // both unknown
        ] {
            let plan = MetalGovernorPlan::derive(recommended, system_total);
            let backend_budget =
                crate::resource::resident_stack_budget_bytes(recommended, system_total);
            assert_eq!(
                plan.resident_stack_budget_bytes, backend_budget,
                "resident budget diverged for ({recommended}, {system_total:?})"
            );
            // `resolve_resident_stack_budget` returns the same value cast to usize.
            assert_eq!(
                plan.resident_stack_budget_bytes as usize,
                backend_budget as usize
            );
        }

        // BufferPool ceilings: the plan reports exactly the constants the live
        // pool is constructed with. Take the profile lock and assert the default
        // (no-override) path so the env-derived cap equals the documented default.
        let _guard = profile_test_lock();
        let plan = MetalGovernorPlan::derive(64 * GIB, Some(128 * GIB));
        if std::env::var_os("KIN_INFER_METAL_POOL_CAP_BYTES").is_none() {
            assert_eq!(
                resolve_buffer_pool_cap_bytes() as u64,
                plan.buffer_pool_cap_bytes
            );
        }
        assert_eq!(
            crate::resource::DEFAULT_BUFFER_POOL_CAP_BYTES,
            plan.buffer_pool_cap_bytes
        );
        assert_eq!(
            crate::resource::DEFAULT_BUFFER_POOL_PER_BUFFER_CAP_BYTES,
            plan.buffer_pool_per_buffer_cap_bytes
        );
    }

    #[test]
    fn buffer_pool_should_recycle_trims_at_caps() {
        let cap = 1_000usize;
        let per_buffer = 400usize;

        // Fits: under per-buffer cap and pooled total stays under the cap.
        assert!(buffer_pool_should_recycle(300, 0, cap, per_buffer));
        assert!(buffer_pool_should_recycle(300, 700, cap, per_buffer));

        // Per-buffer high-water: a single oversized buffer is never pooled, even
        // into an empty list.
        assert!(!buffer_pool_should_recycle(401, 0, cap, per_buffer));

        // Total cap: recycling would push pooled bytes over the cap -> drop.
        assert!(!buffer_pool_should_recycle(300, 800, cap, per_buffer));

        // Exactly at the cap boundary still recycles.
        assert!(buffer_pool_should_recycle(200, 800, cap, per_buffer));

        // Overflow-safe: a class near usize::MAX never panics, just drops.
        assert!(!buffer_pool_should_recycle(usize::MAX, 1, cap, per_buffer));
    }

    #[test]
    fn buffer_pool_free_list_never_exceeds_cap_under_large_recycle_churn() {
        let Some(metal) = get_metal() else {
            eprintln!("skipping: no Metal device");
            return;
        };
        // Small caps so the churn provably exceeds them: 1 MiB total, 256 KiB per
        // buffer. Each acquire of >256 KiB must never be pooled; smaller buffers
        // are pooled only while the running total stays <= 1 MiB.
        let pool = Arc::new(BufferPool {
            device: metal.device.clone(),
            free: Mutex::new(HashMap::new()),
            pooled_bytes: Mutex::new(0),
            cap_bytes: 1024 * 1024,
            per_buffer_cap_bytes: 256 * 1024,
        });

        // Many large acquire/recycle cycles. Each PooledBuffer drops at end of
        // its loop turn (no GPU work committed), exercising the recycle trim.
        for i in 0..256 {
            // Alternate a small class (pools) and a large class (always dropped).
            let small = pool
                .acquire_uninit(64 * 1024 + (i % 4) * 1024)
                .expect("small acquire");
            let large = pool
                .acquire_uninit(512 * 1024 + (i % 8) * 1024)
                .expect("large acquire");
            assert!(
                pool.pooled_bytes_for_test() <= pool.cap_bytes,
                "pooled bytes exceeded cap mid-churn"
            );
            drop(small);
            drop(large);
            assert!(
                pool.pooled_bytes_for_test() <= pool.cap_bytes,
                "pooled bytes exceeded cap after recycle"
            );
        }

        // Final invariant: the free-list never grew past the cap.
        assert!(pool.pooled_bytes_for_test() <= pool.cap_bytes);

        // And the accounting matches the actual buffers held on the free-list.
        let free = pool.free.lock();
        let actual: usize = free.iter().map(|(class, v)| class * v.len()).sum();
        assert_eq!(actual, pool.pooled_bytes_for_test());
        // No oversized class was ever pooled.
        assert!(
            free.keys().all(|&class| class <= pool.per_buffer_cap_bytes),
            "an oversized buffer was pooled"
        );
    }

    #[test]
    fn resident_segment_estimate_scales_with_layers_and_attention_area() {
        let h = 8usize;
        let heads = 2usize;
        let head_dim = 4usize;
        let inter = 16usize;
        let q_dim = heads * head_dim;
        let kv_dim = q_dim;

        let norm1_weight = vec![1.0; h];
        let norm1_bias = vec![0.0; h];
        let qkv_weight = vec![0.0; (q_dim + 2 * kv_dim) * h];
        let attn_out_weight = vec![0.0; h * q_dim];
        let norm2_weight = vec![1.0; h];
        let norm2_bias = vec![0.0; h];
        let ffn_up_weight = vec![0.0; inter * h];
        let ffn_down_weight = vec![0.0; h * inter];
        let weights = LayerTensors {
            norm1_weight: &norm1_weight,
            norm1_bias: Some(&norm1_bias),
            qkv_weight: Some(&qkv_weight),
            attn_out_weight: &attn_out_weight,
            norm2_weight: &norm2_weight,
            norm2_bias: Some(&norm2_bias),
            ffn_up_weight: Some(&ffn_up_weight),
            ffn_down_weight: &ffn_down_weight,
            ..LayerTensors::default()
        };
        let config = LayerConfig {
            batch_size: 2,
            max_len: 8,
            hidden_size: h,
            num_heads: heads,
            head_dim,
            inter_size: inter,
            eps: 1e-5,
            rms_eps: 1e-6,
            use_rms: false,
            pre_ln: true,
            scale: 1.0,
            alibi_slopes: None,
        };

        let one_layer =
            estimate_resident_segment_bytes(std::slice::from_ref(&weights), &config, None, false);
        let two_layers = estimate_resident_segment_bytes(
            &[weights.clone(), weights.clone()],
            &config,
            None,
            false,
        );
        assert!(two_layers > one_layer);

        let longer = LayerConfig {
            max_len: config.max_len * 2,
            ..config
        };
        let longer_layer =
            estimate_resident_segment_bytes(std::slice::from_ref(&weights), &longer, None, false);
        assert!(longer_layer > one_layer);
    }

    fn get_metal() -> Option<MetalCompute> {
        MetalCompute::try_new()
    }

    /// An over-budget resident segment declines (returns `None`, which routes the
    /// lib.rs caller to the bounded per-layer fallback at lib.rs:2426), while the
    /// smaller per-layer path under the same tight budget still succeeds and
    /// produces the SAME finite output as the unconstrained resident path. This is
    /// the safety property the governor relies on: shrinking the budget degrades
    /// gracefully without OOM and without changing numerics.
    #[test]
    fn tiny_resident_budget_forces_per_layer_fallback_with_correct_output() {
        let Some(mut metal) = get_metal() else {
            eprintln!("skipping: no Metal device");
            return;
        };

        let batch_size = 2usize;
        let max_len = 16usize;
        let hidden = 64usize;
        let num_heads = 4usize;
        let head_dim = 16usize;
        let inter = 128usize;
        let total_rows = batch_size * max_len;
        let q_dim = num_heads * head_dim;
        let kv_dim = num_heads * head_dim;

        let mk = |n: usize, salt: f32| -> Vec<f32> {
            (0..n)
                .map(|i| ((i as f32) * 0.7 + salt).sin() * 0.05)
                .collect()
        };

        let norm1_weight = vec![1.0f32; hidden];
        let norm1_bias = vec![0.0f32; hidden];
        let norm2_weight = vec![1.0f32; hidden];
        let norm2_bias = vec![0.0f32; hidden];
        let qkv_weight = mk((q_dim + 2 * kv_dim) * hidden, 1.0);
        let attn_out_weight = mk(hidden * (num_heads * head_dim), 2.0);
        let ffn_up_weight = mk(inter * hidden, 3.0);
        let ffn_down_weight = mk(hidden * inter, 4.0);

        let weights = crate::gpu::LayerTensors {
            norm1_weight: &norm1_weight,
            norm1_bias: Some(&norm1_bias),
            qkv_weight: Some(&qkv_weight),
            attn_out_weight: &attn_out_weight,
            norm2_weight: &norm2_weight,
            norm2_bias: Some(&norm2_bias),
            ffn_up_weight: Some(&ffn_up_weight),
            ffn_down_weight: &ffn_down_weight,
            ..crate::gpu::LayerTensors::default()
        };

        let config = crate::gpu::LayerConfig {
            batch_size,
            max_len,
            hidden_size: hidden,
            num_heads,
            head_dim,
            inter_size: inter,
            eps: 1e-5,
            rms_eps: 1e-6,
            use_rms: false,
            pre_ln: false,
            scale: 1.0 / (head_dim as f32).sqrt(),
            alibi_slopes: None,
        };

        let hidden_in = mk(total_rows * hidden, 0.0);
        let masks = vec![1u32; total_rows];
        let two_layers = [weights.clone(), weights.clone()];

        // Reference: unconstrained resident path over the 2-layer stack.
        let reference = metal
            .forward_layers_batched(&hidden_in, &masks, &two_layers, &config, &[], &[])
            .expect("reference forward_layers_batched errored")
            .expect("reference resident path unexpectedly declined");
        assert_eq!(reference.len(), total_rows * hidden);
        assert!(reference.iter().all(|x| x.is_finite()));

        // Budget that admits ONE layer's transients but not the whole 2-layer
        // segment: the per-layer path fits, the whole-stack segment does not.
        let one_layer_estimate =
            estimate_resident_segment_bytes(std::slice::from_ref(&weights), &config, None, false);
        let two_layer_estimate = estimate_resident_segment_bytes(&two_layers, &config, None, false);
        assert!(two_layer_estimate > one_layer_estimate);
        metal.set_resident_budget_for_test(one_layer_estimate);

        // The whole-stack resident segment now declines (this is the `None` that
        // makes lib.rs fall to the per-layer loop).
        let declined = metal
            .forward_layers_batched(&hidden_in, &masks, &two_layers, &config, &[], &[])
            .expect("forward_layers_batched errored under tight budget");
        assert!(
            declined.is_none(),
            "over-budget resident segment should decline, not allocate unbounded"
        );

        // The per-layer fallback rung still runs under the same tight budget, layer
        // by layer, and reproduces the reference output bit-for-bit (same kernels,
        // same inputs — only the command-buffer granularity changed).
        let mut hidden_state = hidden_in.clone();
        for _ in 0..two_layers.len() {
            hidden_state = metal
                .forward_layer_batched(&hidden_state, &masks, &weights, &config, &[], &[])
                .expect("per-layer fallback errored")
                .expect("per-layer fallback declined under one-layer budget");
        }
        assert_eq!(hidden_state.len(), total_rows * hidden);
        assert!(hidden_state.iter().all(|x| x.is_finite()));
        let max_diff = max_abs_diff(&reference, &hidden_state);
        assert!(
            max_diff == 0.0,
            "per-layer fallback diverged from resident path: max_abs_diff {max_diff}"
        );
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
        assert_eq!(
            tags,
            vec!["matmul", "attention", "norm", "activation", "copy"]
        );
    }

    #[test]
    fn test_profile_round_trip_counter_contract() {
        let _lock = profile_test_lock();
        let Some(metal) = get_metal() else { return };
        reset_profile();
        record_forward_calls(2);
        if profile_enabled() {
            assert_eq!(profile_forward_calls(), 2);
        } else {
            assert_eq!(profile_forward_calls(), 0);
            assert_eq!(profile_round_trips(), 0);
            return;
        }

        let mut data = vec![0.0, 1.0, -1.0];
        metal.gelu(&mut data).unwrap();

        assert_eq!(profile_round_trips(), 1);
        assert_eq!(profile_submissions(), 1);
        assert!(
            profile_host_blocked_nanos() > 0,
            "commit_wait should report host-blocked wait time"
        );
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
            metal
                .rope_pair(&mut qb, &mut kb, &cos, &sin, 0, actual, head_dim, total_dim)
                .unwrap();
            q_ref[base..base + rows].copy_from_slice(&qb);
            k_ref[base..base + rows].copy_from_slice(&kb);
        }

        // Candidate: single-dispatch rope_pair_batched.
        let mut q_bat = q0.clone();
        let mut k_bat = k0.clone();
        metal
            .rope_pair_batched(
                &mut q_bat, &mut k_bat, &cos, &sin, batch_size, max_len, actual, head_dim,
                total_dim,
            )
            .unwrap();

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
        assert!(
            max_q < 1e-4 && max_k < 1e-4,
            "rope_pair_batched diverges from per-block: q={max_q} k={max_k}"
        );
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
        metal
            .layer_norm(&mut data, &gamma, &beta, 1, 4, 1e-5)
            .unwrap();
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

        let scores_metal = metal
            .batched_matmul(&q, &k, num_heads, seq_len, head_dim)
            .unwrap();
        let scores_cpu = cpu
            .batched_matmul(&q, &k, num_heads, seq_len, head_dim)
            .unwrap();

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

        let out_metal = metal
            .batched_attn_values(&scores, &v, num_heads, seq_len, head_dim)
            .unwrap();
        let out_cpu = cpu
            .batched_attn_values(&scores, &v, num_heads, seq_len, head_dim)
            .unwrap();

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

        let out_metal = metal
            .fused_attention_batched(
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
            )
            .unwrap();
        let out_cpu = cpu
            .fused_attention_batched(
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
            )
            .unwrap();

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
    fn test_metal_c7_flash_attention_shape_gate_without_device() {
        let num_groups = 2;
        let heads_per_group = 2;
        let seq_len = 64;
        let head_dim = 64;
        let scale = 1.0 / (head_dim as f32).sqrt();
        let masks = vec![1u32; num_groups * seq_len];

        assert!(c7_flash_attention_shape_supported(
            num_groups,
            seq_len,
            head_dim,
            heads_per_group,
            false,
            scale,
            &masks,
        ));
        assert!(!c7_flash_attention_shape_supported(
            num_groups,
            seq_len,
            head_dim,
            heads_per_group,
            true,
            scale,
            &masks,
        ));
        assert!(!c7_flash_attention_shape_supported(
            num_groups,
            seq_len,
            head_dim,
            heads_per_group,
            false,
            f32::NAN,
            &masks,
        ));
        assert!(!c7_flash_attention_shape_supported(
            num_groups,
            seq_len,
            16,
            heads_per_group,
            false,
            scale,
            &masks,
        ));
        assert!(!c7_flash_attention_shape_supported(
            num_groups,
            32,
            head_dim,
            heads_per_group,
            false,
            scale,
            &masks[..num_groups * 32],
        ));

        let short_masks = &masks[..masks.len() - 1];
        assert!(!c7_flash_attention_shape_supported(
            num_groups,
            seq_len,
            head_dim,
            heads_per_group,
            false,
            scale,
            short_masks,
        ));

        let mut all_zero_group = masks.clone();
        all_zero_group[..seq_len].fill(0);
        assert!(!c7_flash_attention_shape_supported(
            num_groups,
            seq_len,
            head_dim,
            heads_per_group,
            false,
            scale,
            &all_zero_group,
        ));
    }

    #[test]
    fn test_metal_c7_flash_attention_default_off_shape_gate() {
        if c7_flash_attention_enabled() {
            return;
        }
        let seq_len = 64;
        let masks = vec![1u32; seq_len];

        assert!(c7_flash_attention_shape_supported(
            1,
            seq_len,
            64,
            1,
            false,
            1.0 / 8.0,
            &masks,
        ));
        assert!(!use_c7_flash_attention(
            1,
            seq_len,
            64,
            1,
            false,
            1.0 / 8.0,
            &masks,
        ));
    }

    #[test]
    fn test_metal_c7_flash_attention_batched_matches_cpu() {
        if !c7_flash_attention_enabled() {
            return;
        }
        let Some(metal) = get_metal() else { return };
        assert!(
            C7_FLASH_ATTENTION_AVAILABLE.load(Ordering::Relaxed),
            "C7 flash-attention was requested but the optional Metal pipeline did not compile"
        );
        let cpu = crate::gpu::CpuCompute;

        let num_groups = 2;
        let heads_per_group = 2;
        let seq_len = 64;
        let head_dim = 64;
        let total_heads = num_groups * heads_per_group;
        let elems = total_heads * seq_len * head_dim;

        let q: Vec<f32> = (0..elems)
            .map(|i| ((i % 97) as f32 - 48.0) * 0.013)
            .collect();
        let k: Vec<f32> = (0..elems)
            .map(|i| ((i % 83) as f32 - 41.0) * 0.011)
            .collect();
        let v: Vec<f32> = (0..elems)
            .map(|i| ((i % 79) as f32 - 39.0) * 0.007)
            .collect();
        let masks: Vec<u32> = (0..num_groups * seq_len)
            .map(|i| if i % 11 == 0 { 0 } else { 1 })
            .collect();
        let alibi = Vec::new();
        let scale = 1.0 / (head_dim as f32).sqrt();
        assert_eq!(
            metal
                .pipelines
                .get("c7_flash_attention_batched")
                .map(|p| p.thread_execution_width()),
            Some(32),
        );
        assert!(use_c7_flash_attention(
            num_groups,
            seq_len,
            head_dim,
            heads_per_group,
            false,
            scale,
            &masks,
        ));

        let out_metal = metal
            .fused_attention_batched(
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
            )
            .unwrap();
        let out_cpu = cpu
            .fused_attention_batched(
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
            )
            .unwrap();

        assert_eq!(out_metal.len(), elems);
        let max_err = max_abs_diff(&out_metal, &out_cpu);
        assert!(
            max_err < 5e-4,
            "C7 flash_attention_batched max err: {}",
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

        let q: Vec<f32> = (0..elems)
            .map(|i| ((i % 257) as f32 - 128.0) * 0.003)
            .collect();
        let k: Vec<f32> = (0..elems)
            .map(|i| ((i % 251) as f32 - 125.0) * 0.003)
            .collect();
        let v: Vec<f32> = (0..elems)
            .map(|i| ((i % 241) as f32 - 120.0) * 0.003)
            .collect();

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

        let first = metal
            .fused_attention_batched(
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
            )
            .unwrap();
        assert_eq!(first.len(), elems);

        // Determinism: 20 repeats must be bit-identical to the first run.
        for run in 0..20 {
            let out = metal
                .fused_attention_batched(
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
                )
                .unwrap();
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
        let out_cpu = cpu
            .fused_attention_batched(
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
            )
            .unwrap();
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
        let a: Vec<f32> = (0..m * k)
            .map(|i| ((i % 257) as f32 - 128.0) * 0.003)
            .collect();
        let b: Vec<f32> = (0..n * k)
            .map(|i| ((i % 251) as f32 - 125.0) * 0.003)
            .collect();
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
        let a: Vec<f32> = (0..m * k)
            .map(|i| ((i % 257) as f32 - 128.0) * 0.003)
            .collect();
        let w: Vec<f32> = (0..768 * k)
            .map(|i| ((i % 251) as f32 - 125.0) * 0.003)
            .collect();
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
        let x: Vec<f32> = (0..rows * hidden)
            .map(|i| ((i % 257) as f32 - 128.0) * 0.003)
            .collect();
        let wg: Vec<f32> = (0..inter * hidden)
            .map(|i| ((i % 251) as f32 - 125.0) * 0.002)
            .collect();
        let wu: Vec<f32> = (0..inter * hidden)
            .map(|i| ((i % 241) as f32 - 120.0) * 0.002)
            .collect();
        let wd: Vec<f32> = (0..hidden * inter)
            .map(|i| ((i % 239) as f32 - 119.0) * 0.002)
            .collect();
        let first = metal
            .fused_ffn_swiglu(&x, &wg, &wu, &wd, rows, hidden, inter)
            .unwrap();
        assert_eq!(first.len(), rows * hidden);
        for run in 0..20 {
            let out = metal
                .fused_ffn_swiglu(&x, &wg, &wu, &wd, rows, hidden, inter)
                .unwrap();
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
        let base: Vec<f32> = (0..rows * cols)
            .map(|i| ((i % 257) as f32 - 128.0) * 0.01)
            .collect();
        let gamma: Vec<f32> = (0..cols).map(|i| 1.0 + (i % 13) as f32 * 0.01).collect();
        let beta: Vec<f32> = (0..cols).map(|i| (i % 7) as f32 * 0.01).collect();
        let eps = 1e-12f32;
        let mut first = base.clone();
        metal
            .layer_norm(&mut first, &gamma, &beta, rows, cols, eps)
            .unwrap();
        for run in 0..20 {
            let mut out = base.clone();
            metal
                .layer_norm(&mut out, &gamma, &beta, rows, cols, eps)
                .unwrap();
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

        let qh: Vec<f32> = (0..elems)
            .map(|i| ((i % 89) as f32 - 44.0) * 0.01)
            .collect();
        let kh: Vec<f32> = (0..elems)
            .map(|i| ((i % 73) as f32 - 36.0) * 0.01)
            .collect();
        let vh: Vec<f32> = (0..elems)
            .map(|i| ((i % 61) as f32 - 30.0) * 0.01)
            .collect();
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

        let out_pos = metal
            .fused_attention_batched_posmajor(
                &qp,
                &kp,
                &vp,
                num_groups,
                heads_per_group,
                seq_len,
                head_dim,
                scale,
                &alibi,
                &masks,
            )
            .unwrap();
        let out_head = metal
            .fused_attention_batched(
                &qh,
                &kh,
                &vh,
                num_groups,
                heads_per_group,
                seq_len,
                head_dim,
                scale,
                &alibi,
                &masks,
            )
            .unwrap();

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
        let a: Vec<f32> = (0..m * k)
            .map(|i| ((i % 89) as f32 - 44.0) * 0.01)
            .collect();
        let b: Vec<f32> = (0..n * k)
            .map(|i| ((i % 73) as f32 - 36.0) * 0.01)
            .collect();

        let buf_a = metal.buf_slice_pooled(&a).unwrap();
        let buf_b = metal.buf_cached(&b).unwrap();
        let buf_c = metal.buf_zeros_pooled(m * n).unwrap();
        let buf_m = metal.buf_u32(m as u32).unwrap();
        let buf_n = metal.buf_u32(n as u32).unwrap();
        let buf_k = metal.buf_u32(k as u32).unwrap();
        let bufs = [
            buf_a.buffer(),
            &buf_b,
            buf_c.buffer(),
            &buf_m,
            &buf_n,
            &buf_k,
        ];
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
        assert!(
            max_err < 5e-3,
            "wide MMA vs CPU matmul max err: {}",
            max_err
        );
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
        let a: Vec<f32> = (0..m * k)
            .map(|i| ((i % 89) as f32 - 44.0) * 0.01)
            .collect();
        let b: Vec<f32> = (0..n * k)
            .map(|i| ((i % 73) as f32 - 36.0) * 0.01)
            .collect();

        let buf_a = metal.buf_slice_pooled(&a).unwrap();
        let buf_b = metal.buf_cached(&b).unwrap();
        let buf_c = metal.buf_zeros_pooled(m * n).unwrap();
        let buf_m = metal.buf_u32(m as u32).unwrap();
        let buf_n = metal.buf_u32(n as u32).unwrap();
        let buf_k = metal.buf_u32(k as u32).unwrap();
        let bufs = [
            buf_a.buffer(),
            &buf_b,
            buf_c.buffer(),
            &buf_m,
            &buf_n,
            &buf_k,
        ];
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
        assert!(
            max_err < 5e-3,
            "steel MMA vs CPU matmul max err: {}",
            max_err
        );
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
        let a: Vec<f32> = (0..m * k)
            .map(|i| ((i % 89) as f32 - 44.0) * 0.01)
            .collect();
        let b: Vec<f32> = (0..n * k)
            .map(|i| ((i % 73) as f32 - 36.0) * 0.01)
            .collect();

        let buf_a = metal.buf_slice_pooled(&a).unwrap();
        let buf_b = metal.buf_cached(&b).unwrap();
        let buf_c = metal.buf_zeros_pooled(m * n).unwrap();
        let buf_m = metal.buf_u32(m as u32).unwrap();
        let buf_n = metal.buf_u32(n as u32).unwrap();
        let buf_k = metal.buf_u32(k as u32).unwrap();
        let bufs = [
            buf_a.buffer(),
            &buf_b,
            buf_c.buffer(),
            &buf_m,
            &buf_n,
            &buf_k,
        ];
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
        assert!(
            max_err < 5e-2,
            "fp16 MMA vs CPU matmul max err: {}",
            max_err
        );
    }

    #[test]
    fn test_metal_fp16_wide_mma_close_to_cpu() {
        // Lever #5 phase 2: the composed fp16 + 64x64 projection GEMM must compute
        // the right GEMM to within fp16 precision. Direct-dispatch the `*_fp16_wide`
        // kernel on a shape that fills the 64x64 tile with a ragged remainder, and
        // compare to the CPU fp32 reference. Skips unless the composed pipeline
        // built (needs the fp16 library, i.e. KIN_INFER_GEMM_FP16 at construction).
        let Some(metal) = get_metal() else { return };
        if !WIDE_FP16_MMA_AVAILABLE.load(Ordering::Relaxed) {
            return;
        }
        let cpu = crate::gpu::CpuCompute;

        let (m, n, k) = (80usize, 96usize, 64usize);
        let a: Vec<f32> = (0..m * k)
            .map(|i| ((i % 89) as f32 - 44.0) * 0.01)
            .collect();
        let b: Vec<f32> = (0..n * k)
            .map(|i| ((i % 73) as f32 - 36.0) * 0.01)
            .collect();

        let buf_a = metal.buf_slice_pooled(&a).unwrap();
        let buf_b = metal.buf_cached(&b).unwrap();
        let buf_c = metal.buf_zeros_pooled(m * n).unwrap();
        let buf_m = metal.buf_u32(m as u32).unwrap();
        let buf_n = metal.buf_u32(n as u32).unwrap();
        let buf_k = metal.buf_u32(k as u32).unwrap();
        let bufs = [
            buf_a.buffer(),
            &buf_b,
            buf_c.buffer(),
            &buf_m,
            &buf_n,
            &buf_k,
        ];
        autoreleasepool(|_| {
            let cmd = metal.queue.new_command_buffer();
            let pipeline = &metal.pipelines["matmul_transb_simdgroup_fp16_wide"];
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
        let out = MetalCompute::read_buf(buf_c.buffer(), m * n);
        let cpu_out = cpu.matmul(&a, &b, m, n, k).unwrap();

        assert_eq!(out.len(), m * n);
        assert!(
            out.iter().all(|x| x.is_finite()),
            "fp16+wide MMA produced non-finite output"
        );
        // Mixed absolute/relative tolerance: |x-y| <= atol + rtol*max(|x|,|y|).
        // fp16 operands over a K=64 contraction give ~rtol relative error, but
        // sign-cancelling near-zero C entries have a tiny denominator under a pure
        // relative metric and would read as spurious parity failures; the absolute
        // floor (atol) absorbs those. `worst` is the largest amount any element
        // exceeds its bound — <= 0 means every element is within tolerance.
        let atol = 2e-3f32;
        let rtol = 5e-2f32;
        let worst: f32 = out
            .iter()
            .zip(cpu_out.iter())
            .map(|(x, y)| (x - y).abs() - (atol + rtol * x.abs().max(y.abs())))
            .fold(f32::NEG_INFINITY, f32::max);
        assert!(
            worst <= 0.0,
            "fp16+wide MMA vs CPU exceeds mixed abs/rel tol (atol={atol}, rtol={rtol}): worst excess {worst}"
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

        let many = metal
            .matmul_many(&a, &[&b0, &b1, &b2], m, &[n, n, n], k)
            .unwrap();
        let single = [
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

    #[test]
    fn resolve_max_inflight_prefers_override_then_profile_then_default() {
        // Explicit override (≥ 1) wins regardless of profile.
        assert_eq!(resolve_max_inflight_inner(Some("6"), Some("proof")), 6);
        assert_eq!(resolve_max_inflight_inner(Some(" 2 "), None), 2);
        // Invalid/zero override is ignored; no profile -> default.
        assert_eq!(
            resolve_max_inflight_inner(Some("0"), None),
            DEFAULT_MAX_INFLIGHT
        );
        assert_eq!(
            resolve_max_inflight_inner(Some("nope"), None),
            DEFAULT_MAX_INFLIGHT
        );
        assert_eq!(resolve_max_inflight_inner(None, None), DEFAULT_MAX_INFLIGHT);
        assert_eq!(
            resolve_max_inflight_inner(None, Some("bogus")),
            DEFAULT_MAX_INFLIGHT
        );
        // A known profile resolves to its plan depth (machine-dependent but valid).
        assert!(resolve_max_inflight_inner(None, Some("throughput")) >= 1);
        assert!(resolve_max_inflight_inner(None, Some("proof")) >= 1);
    }

    #[test]
    fn test_metal_norm_softmax_cpu_parity_widths() {
        let Some(metal) = get_metal() else { return };
        let cpu = crate::gpu::CpuCompute;

        fn assert_close(metal: &[f32], cpu: &[f32], what: &str) {
            assert_eq!(metal.len(), cpu.len(), "{what}: length mismatch");
            for (i, (m, c)) in metal.iter().zip(cpu.iter()).enumerate() {
                assert!(m.is_finite(), "{what}: metal[{i}] not finite ({m})");
                // GPU and CPU differ only in fp32 accumulation order. Accept when
                // either the absolute or the relative difference is tiny — relative
                // error alone is meaningless near zero.
                let abs = (m - c).abs();
                let rel = abs / m.abs().max(c.abs()).max(f32::MIN_POSITIVE);
                assert!(
                    abs < 1e-4 || rel < 1e-3,
                    "{what}: idx {i} metal={m} cpu={c} abs={abs} rel={rel}"
                );
            }
        }

        // Hidden widths the embedder actually uses (384, 768) plus a deliberate
        // non-multiple-of-32 (100): the simd-reduced kernels stride past the
        // 32-lane simdgroup, so idle lanes must still reduce exactly.
        for &cols in &[384usize, 768, 100] {
            for &rows in &[1usize, 3, 40] {
                let n = rows * cols;
                let data: Vec<f32> = (0..n).map(|i| ((i % 17) as f32 - 8.0) * 0.13).collect();
                let gamma: Vec<f32> = (0..cols).map(|j| 1.0 + (j % 5) as f32 * 0.01).collect();
                let beta: Vec<f32> = (0..cols).map(|j| (j % 3) as f32 * 0.02).collect();

                let (mut m, mut c) = (data.clone(), data.clone());
                metal.softmax(&mut m, rows, cols).unwrap();
                cpu.softmax(&mut c, rows, cols).unwrap();
                assert_close(&m, &c, &format!("softmax rows={rows} cols={cols}"));

                let (mut m, mut c) = (data.clone(), data.clone());
                metal
                    .layer_norm(&mut m, &gamma, &beta, rows, cols, 1e-5)
                    .unwrap();
                cpu.layer_norm(&mut c, &gamma, &beta, rows, cols, 1e-5)
                    .unwrap();
                assert_close(&m, &c, &format!("layer_norm rows={rows} cols={cols}"));

                let (mut m, mut c) = (data.clone(), data.clone());
                metal.rms_norm(&mut m, &gamma, rows, cols, 1e-6).unwrap();
                cpu.rms_norm(&mut c, &gamma, rows, cols, 1e-6).unwrap();
                assert_close(&m, &c, &format!("rms_norm rows={rows} cols={cols}"));
            }
        }
    }

    #[test]
    fn test_metal_forward_layer_bert_is_finite() {
        let Some(metal) = get_metal() else { return };

        // A plain post-LN BERT encoder layer through the fused resident stack.
        // total_rows = 2*5 = 10 is intentionally not a multiple of the 32-lane
        // simdgroup width: the stack's norm kernels must dispatch one simdgroup
        // per row, not one thread per row, or simd_sum folds uninitialized lanes
        // and the embedding goes NaN.
        let batch_size = 2usize;
        let max_len = 5usize;
        let hidden = 64usize;
        let num_heads = 2usize;
        let head_dim = 32usize;
        let inter = 128usize;
        let total_rows = batch_size * max_len;
        let q_dim = num_heads * head_dim;
        let kv_dim = num_heads * head_dim;

        let mk = |n: usize, salt: f32| -> Vec<f32> {
            (0..n)
                .map(|i| ((i as f32) * 0.7 + salt).sin() * 0.05)
                .collect()
        };

        let norm1_weight = vec![1.0f32; hidden];
        let norm1_bias = vec![0.0f32; hidden];
        let norm2_weight = vec![1.0f32; hidden];
        let norm2_bias = vec![0.0f32; hidden];
        let qkv_weight = mk((q_dim + 2 * kv_dim) * hidden, 1.0);
        let attn_out_weight = mk(hidden * (num_heads * head_dim), 2.0);
        let ffn_up_weight = mk(inter * hidden, 3.0);
        let ffn_down_weight = mk(hidden * inter, 4.0);

        let weights = crate::gpu::LayerTensors {
            norm1_weight: &norm1_weight,
            norm1_bias: Some(&norm1_bias),
            qkv_weight: Some(&qkv_weight),
            qkv_bias: None,
            q_weight: None,
            q_bias: None,
            k_weight: None,
            k_bias: None,
            v_weight: None,
            v_bias: None,
            q_ln_weight: None,
            q_ln_bias: None,
            k_ln_weight: None,
            k_ln_bias: None,
            attn_out_weight: &attn_out_weight,
            attn_out_bias: None,
            norm2_weight: &norm2_weight,
            norm2_bias: Some(&norm2_bias),
            ffn_gate_weight: None,
            ffn_up_weight: Some(&ffn_up_weight),
            ffn_up_bias: None,
            ffn_down_weight: &ffn_down_weight,
            ffn_down_bias: None,
            ffn_up_gated_weight: None,
            relative_attention_bias: None,
            rel_pos_embeddings: None,
        };

        let config = crate::gpu::LayerConfig {
            batch_size,
            max_len,
            hidden_size: hidden,
            num_heads,
            head_dim,
            inter_size: inter,
            eps: 1e-5,
            rms_eps: 1e-6,
            use_rms: false,
            pre_ln: false,
            scale: 1.0 / (head_dim as f32).sqrt(),
            alibi_slopes: None,
        };

        let hidden_in = mk(total_rows * hidden, 0.0);
        let masks = vec![1u32; total_rows];

        let out = metal
            .forward_layer_batched(&hidden_in, &masks, &weights, &config, &[], &[])
            .expect("forward_layer_batched errored")
            .expect("metal backend returned None for forward_layer_batched");

        assert_eq!(out.len(), total_rows * hidden);
        let nonfinite = out.iter().filter(|x| !x.is_finite()).count();
        assert_eq!(
            nonfinite,
            0,
            "fused BERT layer produced {nonfinite}/{} non-finite outputs",
            out.len()
        );
    }

    #[test]
    fn test_metal_pooled_stack_uses_single_submission_when_profiled() {
        let _lock = profile_test_lock();
        let Some(metal) = get_metal() else { return };
        reset_profile();
        if !profile_enabled() {
            return;
        }

        let batch_size = 1usize;
        let max_len = 3usize;
        let hidden = 32usize;
        let num_heads = 1usize;
        let head_dim = 32usize;
        let inter = 64usize;
        let total_rows = batch_size * max_len;
        let q_dim = num_heads * head_dim;
        let kv_dim = num_heads * head_dim;

        let mk = |n: usize, salt: f32| -> Vec<f32> {
            (0..n)
                .map(|i| ((i as f32) * 0.17 + salt).sin() * 0.03)
                .collect()
        };

        let norm1_weight = vec![1.0f32; hidden];
        let norm1_bias = vec![0.0f32; hidden];
        let norm2_weight = vec![1.0f32; hidden];
        let norm2_bias = vec![0.0f32; hidden];
        let embed_norm_weight = vec![1.0f32; hidden];
        let embed_norm_bias = vec![0.0f32; hidden];
        let qkv_weight = mk((q_dim + 2 * kv_dim) * hidden, 1.0);
        let attn_out_weight = mk(hidden * q_dim, 2.0);
        let ffn_up_weight = mk(inter * hidden, 3.0);
        let ffn_down_weight = mk(hidden * inter, 4.0);

        let weights = crate::gpu::LayerTensors {
            norm1_weight: &norm1_weight,
            norm1_bias: Some(&norm1_bias),
            qkv_weight: Some(&qkv_weight),
            qkv_bias: None,
            q_weight: None,
            q_bias: None,
            k_weight: None,
            k_bias: None,
            v_weight: None,
            v_bias: None,
            q_ln_weight: None,
            q_ln_bias: None,
            k_ln_weight: None,
            k_ln_bias: None,
            attn_out_weight: &attn_out_weight,
            attn_out_bias: None,
            norm2_weight: &norm2_weight,
            norm2_bias: Some(&norm2_bias),
            ffn_gate_weight: None,
            ffn_up_weight: Some(&ffn_up_weight),
            ffn_up_bias: None,
            ffn_down_weight: &ffn_down_weight,
            ffn_down_bias: None,
            ffn_up_gated_weight: None,
            relative_attention_bias: None,
            rel_pos_embeddings: None,
        };
        let layers = [weights];

        let config = crate::gpu::LayerConfig {
            batch_size,
            max_len,
            hidden_size: hidden,
            num_heads,
            head_dim,
            inter_size: inter,
            eps: 1e-5,
            rms_eps: 1e-6,
            use_rms: false,
            pre_ln: false,
            scale: 1.0 / (head_dim as f32).sqrt(),
            alibi_slopes: None,
        };
        let embedding = crate::gpu::EmbeddingPrelude {
            input_dim: hidden,
            projection: None,
            norm_weight: Some(&embed_norm_weight),
            norm_bias: Some(&embed_norm_bias),
            eps: 1e-5,
        };

        let hidden_in = mk(total_rows * hidden, 0.0);
        let masks = vec![1u32; total_rows];
        let out = metal
            .forward_layers_batched_pooled(
                &hidden_in,
                &masks,
                &layers,
                &config,
                &embedding,
                &[],
                &[],
                crate::gpu::PoolingMode::Mean,
            )
            .expect("forward_layers_batched_pooled errored")
            .expect("metal backend returned None for pooled stack");

        assert_eq!(out.len(), batch_size * hidden);
        assert_eq!(
            profile_submissions(),
            5,
            "pooled resident stack should submit 5 command buffers when profiled"
        );
        assert_eq!(
            profile_round_trips(),
            5,
            "pooled resident stack should wait 5 times when profiled"
        );
    }

    #[test]
    fn test_metal_segmented_pooled_stack_uses_one_submission_per_segment_when_profiled() {
        let _lock = profile_test_lock();
        let Some(metal) = get_metal() else { return };
        reset_profile();
        if !profile_enabled() {
            return;
        }

        let batch_size = 1usize;
        let max_len = 3usize;
        let hidden = 32usize;
        let num_heads = 1usize;
        let head_dim = 32usize;
        let inter = 64usize;
        let total_rows = batch_size * max_len;
        let q_dim = num_heads * head_dim;
        let kv_dim = num_heads * head_dim;

        let mk = |n: usize, salt: f32| -> Vec<f32> {
            (0..n)
                .map(|i| ((i as f32) * 0.17 + salt).sin() * 0.03)
                .collect()
        };

        let norm1_weight = vec![1.0f32; hidden];
        let norm1_bias = vec![0.0f32; hidden];
        let norm2_weight = vec![1.0f32; hidden];
        let norm2_bias = vec![0.0f32; hidden];
        let embed_norm_weight = vec![1.0f32; hidden];
        let embed_norm_bias = vec![0.0f32; hidden];
        let qkv_weight = mk((q_dim + 2 * kv_dim) * hidden, 1.0);
        let attn_out_weight = mk(hidden * q_dim, 2.0);
        let ffn_up_weight = mk(inter * hidden, 3.0);
        let ffn_down_weight = mk(hidden * inter, 4.0);

        let weights = crate::gpu::LayerTensors {
            norm1_weight: &norm1_weight,
            norm1_bias: Some(&norm1_bias),
            qkv_weight: Some(&qkv_weight),
            qkv_bias: None,
            q_weight: None,
            q_bias: None,
            k_weight: None,
            k_bias: None,
            v_weight: None,
            v_bias: None,
            q_ln_weight: None,
            q_ln_bias: None,
            k_ln_weight: None,
            k_ln_bias: None,
            attn_out_weight: &attn_out_weight,
            attn_out_bias: None,
            norm2_weight: &norm2_weight,
            norm2_bias: Some(&norm2_bias),
            ffn_gate_weight: None,
            ffn_up_weight: Some(&ffn_up_weight),
            ffn_up_bias: None,
            ffn_down_weight: &ffn_down_weight,
            ffn_down_bias: None,
            ffn_up_gated_weight: None,
            relative_attention_bias: None,
            rel_pos_embeddings: None,
        };
        let layers = [weights.clone(), weights];

        let config = crate::gpu::LayerConfig {
            batch_size,
            max_len,
            hidden_size: hidden,
            num_heads,
            head_dim,
            inter_size: inter,
            eps: 1e-5,
            rms_eps: 1e-6,
            use_rms: false,
            pre_ln: false,
            scale: 1.0 / (head_dim as f32).sqrt(),
            alibi_slopes: None,
        };
        let embedding = crate::gpu::EmbeddingPrelude {
            input_dim: hidden,
            projection: None,
            norm_weight: Some(&embed_norm_weight),
            norm_bias: Some(&embed_norm_bias),
            eps: 1e-5,
        };

        let hidden_in = mk(total_rows * hidden, 0.0);
        let masks = vec![1u32; total_rows];
        let out = metal
            .forward_layers_batched_pooled_segmented(
                &hidden_in,
                &masks,
                &layers,
                &config,
                &embedding,
                &[],
                &[],
                crate::gpu::PoolingMode::Mean,
                1,
            )
            .expect("forward_layers_batched_pooled_segmented errored")
            .expect("metal backend returned None for segmented pooled stack");

        assert_eq!(out.len(), batch_size * hidden);
        assert_eq!(
            profile_submissions(),
            10,
            "segmented pooled stack should submit 10 command buffers when profiled"
        );
        assert_eq!(
            profile_round_trips(),
            10,
            "segmented pooled stack should wait 10 times when profiled"
        );
    }

    #[test]
    fn test_metal_segmented_resident_stack_uses_one_submission_per_segment_when_profiled() {
        let _lock = profile_test_lock();
        let Some(metal) = get_metal() else { return };
        reset_profile();
        if !profile_enabled() {
            return;
        }

        let batch_size = 1usize;
        let max_len = 3usize;
        let hidden = 32usize;
        let num_heads = 1usize;
        let head_dim = 32usize;
        let inter = 64usize;
        let total_rows = batch_size * max_len;
        let q_dim = num_heads * head_dim;
        let kv_dim = num_heads * head_dim;

        let mk = |n: usize, salt: f32| -> Vec<f32> {
            (0..n)
                .map(|i| ((i as f32) * 0.19 + salt).sin() * 0.03)
                .collect()
        };

        let norm1_weight = vec![1.0f32; hidden];
        let norm1_bias = vec![0.0f32; hidden];
        let norm2_weight = vec![1.0f32; hidden];
        let norm2_bias = vec![0.0f32; hidden];
        let qkv_weight = mk((q_dim + 2 * kv_dim) * hidden, 1.0);
        let attn_out_weight = mk(hidden * q_dim, 2.0);
        let ffn_up_weight = mk(inter * hidden, 3.0);
        let ffn_down_weight = mk(hidden * inter, 4.0);

        let weights = crate::gpu::LayerTensors {
            norm1_weight: &norm1_weight,
            norm1_bias: Some(&norm1_bias),
            qkv_weight: Some(&qkv_weight),
            qkv_bias: None,
            q_weight: None,
            q_bias: None,
            k_weight: None,
            k_bias: None,
            v_weight: None,
            v_bias: None,
            q_ln_weight: None,
            q_ln_bias: None,
            k_ln_weight: None,
            k_ln_bias: None,
            attn_out_weight: &attn_out_weight,
            attn_out_bias: None,
            norm2_weight: &norm2_weight,
            norm2_bias: Some(&norm2_bias),
            ffn_gate_weight: None,
            ffn_up_weight: Some(&ffn_up_weight),
            ffn_up_bias: None,
            ffn_down_weight: &ffn_down_weight,
            ffn_down_bias: None,
            ffn_up_gated_weight: None,
            relative_attention_bias: None,
            rel_pos_embeddings: None,
        };
        let layers = [weights.clone(), weights];

        let config = crate::gpu::LayerConfig {
            batch_size,
            max_len,
            hidden_size: hidden,
            num_heads,
            head_dim,
            inter_size: inter,
            eps: 1e-5,
            rms_eps: 1e-6,
            use_rms: false,
            pre_ln: false,
            scale: 1.0 / (head_dim as f32).sqrt(),
            alibi_slopes: None,
        };

        let hidden_in = mk(total_rows * hidden, 0.0);
        let masks = vec![1u32; total_rows];
        let out = metal
            .forward_layers_batched_segmented(&hidden_in, &masks, &layers, &config, &[], &[], 1)
            .expect("forward_layers_batched_segmented errored")
            .expect("metal backend returned None for segmented resident stack");

        assert_eq!(out.len(), total_rows * hidden);
        assert_eq!(
            profile_submissions(),
            10,
            "segmented resident stack should submit 10 command buffers when profiled"
        );
        assert_eq!(
            profile_round_trips(),
            10,
            "segmented resident stack should wait 10 times when profiled"
        );
    }

    #[test]
    fn test_fused_attention_batched_finite_long_seq() {
        let Some(metal) = get_metal() else { return };
        let heads = 2usize;
        let head_dim = 64usize;
        let scale = 1.0 / (head_dim as f32).sqrt();
        for &seq in &[600usize, 1024, 2048] {
            let n = heads * seq * head_dim;
            let q: Vec<f32> = (0..n).map(|i| ((i % 23) as f32 - 11.0) * 0.02).collect();
            let k = q.clone();
            let v = q.clone();
            // num_groups=heads, heads_per_group=1 -> all-valid mask (no padding),
            // no alibi: isolates the QK GEMM + softmax from any masking effect.
            let masks = vec![1u32; heads * seq];
            let out = metal
                .fused_attention_batched(&q, &k, &v, heads, 1, seq, head_dim, scale, &[], &masks)
                .expect("fused_attention_batched");
            let nonfinite = out.iter().filter(|x| !x.is_finite()).count();
            assert_eq!(
                nonfinite,
                0,
                "seq={seq}: {nonfinite}/{} non-finite attention outputs",
                out.len()
            );
        }
    }
}
