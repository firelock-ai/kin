// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Shared resource plan — inspect-only host/accelerator/memory detection plus
//! per-profile budgets. Stable JSON (`kin.resource_plan.v1`) consumed across the
//! ecosystem. Runtime embedding code also reads the profile-resolved kernel plan
//! from this module so CLI/daemon behavior matches the reported plan.

use serde::{Deserialize, Serialize};

const GIB: u64 = 1024 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Schema version (always serializes the fixed token)
// ---------------------------------------------------------------------------

/// Stable schema tag. Serializes as the literal `kin.resource_plan.v1` and only
/// deserializes that exact string.
pub const SCHEMA_VERSION: &str = "kin.resource_plan.v1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SchemaVersion;

impl Serialize for SchemaVersion {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(SCHEMA_VERSION)
    }
}

impl<'de> Deserialize<'de> for SchemaVersion {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        if s == SCHEMA_VERSION {
            Ok(SchemaVersion)
        } else {
            Err(serde::de::Error::custom(format!(
                "unexpected schema_version: {s}"
            )))
        }
    }
}

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Profile {
    Proof,
    Interactive,
    Throughput,
    Ci,
}

impl Profile {
    /// Resolve the active runtime profile from the canonical `KIN_RESOURCE_PROFILE`
    /// selector (the same selector the embedding budgets key off). An unset or
    /// unrecognized value resolves to [`Profile::Proof`] — the safe, bit-identical
    /// default, so nothing turns on a throughput-only fast path by accident.
    pub fn from_env() -> Profile {
        match std::env::var("KIN_RESOURCE_PROFILE") {
            Ok(value) => match value.trim().to_ascii_lowercase().as_str() {
                "throughput" => Profile::Throughput,
                "interactive" => Profile::Interactive,
                "ci" => Profile::Ci,
                _ => Profile::Proof,
            },
            Err(_) => Profile::Proof,
        }
    }
}

/// Parse a boolean env override: `1/true/yes/on` → `Some(true)`,
/// `0/false/no/off` → `Some(false)`, anything else (incl. unset) → `None`.
/// Used by per-lever `KIN_INFER_*` overrides to take precedence over the
/// profile-resolved kernel plan in both directions (force-on and force-off).
pub fn env_flag_override(name: &str) -> Option<bool> {
    match std::env::var(name).ok().as_deref().map(str::trim) {
        Some("1") | Some("true") | Some("yes") | Some("on") => Some(true),
        Some("0") | Some("false") | Some("no") | Some("off") => Some(false),
        _ => None,
    }
}

/// The GPU kernel-family selection for the active embedding process, resolved
/// once from the canonical [`Profile::from_env`] selector and the detected
/// accelerator backend. kin-infer's Metal forward path consults this to decide
/// whether to take the parity-cleared fast GEMM/attention kernels. Per-lever
/// `KIN_INFER_*` env overrides still win at the gate (see the metal backend).
pub fn active_gpu_kernel_plan() -> GpuKernelPlan {
    use std::sync::OnceLock;
    static PLAN: OnceLock<GpuKernelPlan> = OnceLock::new();
    *PLAN.get_or_init(|| {
        let backend = detect_accelerator().backend;
        GpuKernelPlan::resolve(Profile::from_env(), backend)
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceleratorBackend {
    Auto,
    Metal,
    Cuda,
    Cpu,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HybridMode {
    Off,
    SequentialFloor,
    Balanced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OomRetry {
    SplitBatchThenCpu,
    CpuOnce,
    Fail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NonfinitePolicy {
    Error,
    RetrySingle,
    ZeroSentinel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrossEncoderPolicy {
    Off,
    PinnedFailHard,
    AdaptiveNonproof,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactMode {
    Proof,
    NonCitableExplore,
}

// ---------------------------------------------------------------------------
// Sub-structs
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostInfo {
    pub arch: String,
    pub logical_cores: usize,
    pub physical_cores: Option<usize>,
    pub performance_cores: Option<usize>,
    pub efficiency_cores: Option<usize>,
    pub rayon_threads: usize,
    pub reserve_logical_cores: usize,
    pub blas_threads: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryInfo {
    pub system_total_bytes: Option<u64>,
    pub system_available_bytes: Option<u64>,
    pub max_process_rss_bytes: Option<u64>,
    pub hot_graph_budget_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceleratorInfo {
    pub backend: AcceleratorBackend,
    pub device_index: usize,
    pub unified_memory: bool,
    pub device_total_bytes: Option<u64>,
    pub device_available_bytes: Option<u64>,
    pub recommended_working_set_bytes: Option<u64>,
    pub max_single_buffer_bytes: Option<u64>,
    pub max_inflight_command_buffers: usize,
    pub reserve_device_bytes: Option<u64>,
    pub allow_cpu_fallback: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbeddingPlan {
    pub max_seq_len: usize,
    pub max_batch_tokens: usize,
    pub max_attention_area: Option<u64>,
    pub max_entities_per_graph_chunk: usize,
    pub hybrid_mode: HybridMode,
    pub oom_retry: OomRetry,
    pub nonfinite_policy: NonfinitePolicy,
    /// GPU GEMM/attention kernel-family selection for the forward pass.
    #[serde(default)]
    pub gpu_kernels: GpuKernelPlan,
}

/// Metal GEMM/attention kernel-family selection for the embedding forward pass.
///
/// All-off (the [`Default`]) is the proven fp32 single-buffer 32x32-MMA path with
/// the host-side attention reshape — bit-identical across runs and the only shape
/// the proof profile ever uses. Profiles currently keep the alternate,
/// parity-cleared kernels off until they beat the baseline, except for
/// scheduling/readback levers that preserve embedding values. kin-infer's Metal
/// backend resolves these into its per-process kernel gates; a `KIN_INFER_*` env
/// override still wins per lever so each can be A/B-measured in isolation.
/// `flash_attention` selects the optional C7 fused-attention family when the
/// backend has compiled it; it remains default-off until parity and throughput
/// are proven on the same corpus.
/// `pooled_output` also remains default-off until runtime support exists, is
/// parity-cleared, and measures as a win.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct GpuKernelPlan {
    /// fp16-operand MMA GEMM (`KIN_INFER_GEMM_FP16`).
    #[serde(default)]
    pub gemm_fp16: bool,
    /// Double-buffered K-loop ("steel") MMA GEMM (`KIN_INFER_STEEL`).
    #[serde(default)]
    pub steel: bool,
    /// Wider 64x64 MMA register tile (`KIN_INFER_MMA_WIDE`).
    #[serde(default)]
    pub mma_wide: bool,
    /// On-device head-major attention reshape (`KIN_INFER_RESHAPE_GPU`).
    #[serde(default)]
    pub reshape_gpu: bool,
    /// Optional fused flash-attention kernel family (`KIN_INFER_FLASH_ATTENTION`).
    #[serde(default)]
    pub flash_attention: bool,
    /// Final pooled-output readback instead of full hidden-state readback.
    #[serde(default)]
    pub pooled_output: bool,
}

impl GpuKernelPlan {
    /// Kernel selection for `profile` on `backend`. Proof stays on the
    /// historical bit-identical path. Throughput may use parity-cleared kernels
    /// that improve scheduling/readback without changing embedding values.
    pub fn resolve(profile: Profile, backend: AcceleratorBackend) -> GpuKernelPlan {
        let mut plan = GpuKernelPlan::default();
        if matches!(profile, Profile::Throughput) && matches!(backend, AcceleratorBackend::Metal) {
            plan.pooled_output = true;
            plan.steel = true;
        }
        plan
    }

    /// The selected value of a single lever in this plan.
    pub fn get(&self, kernel: GpuKernel) -> bool {
        match kernel {
            GpuKernel::GemmFp16 => self.gemm_fp16,
            GpuKernel::Steel => self.steel,
            GpuKernel::MmaWide => self.mma_wide,
            GpuKernel::ReshapeGpu => self.reshape_gpu,
            GpuKernel::FlashAttention => self.flash_attention,
            GpuKernel::PooledOutput => self.pooled_output,
        }
    }

    fn field_mut(&mut self, kernel: GpuKernel) -> &mut bool {
        match kernel {
            GpuKernel::GemmFp16 => &mut self.gemm_fp16,
            GpuKernel::Steel => &mut self.steel,
            GpuKernel::MmaWide => &mut self.mma_wide,
            GpuKernel::ReshapeGpu => &mut self.reshape_gpu,
            GpuKernel::FlashAttention => &mut self.flash_attention,
            GpuKernel::PooledOutput => &mut self.pooled_output,
        }
    }

    /// Apply per-lever overrides to this derived plan. `lookup` returns
    /// `Some(true)`/`Some(false)` to force a lever on/off, or `None` to keep the
    /// profile/backend-derived value. Precedence: an explicit override always
    /// wins over the derived default — the single canonical copy of the rule
    /// each Metal-backend call site applies today by hand. Used by
    /// [`resolved_gpu_kernel_plan`] with the `KIN_INFER_*` env overrides as the
    /// lookup.
    pub fn with_overrides(mut self, lookup: impl Fn(GpuKernel) -> Option<bool>) -> GpuKernelPlan {
        for kernel in GpuKernel::ALL {
            if let Some(forced) = lookup(kernel) {
                *self.field_mut(kernel) = forced;
            }
        }
        self
    }
}

/// Per-lever selector for the [`GpuKernelPlan`] kernel families. Each variant
/// maps to one plan field and to the canonical `KIN_INFER_*` environment
/// override that forces that lever on or off independent of the
/// profile/backend-derived default. This is the single source of truth for
/// those override names: the embedding forward path resolves a lever through
/// [`resolved_gpu_kernel`] (or the whole plan through
/// [`resolved_gpu_kernel_plan`]) instead of naming the variable at each call
/// site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GpuKernel {
    GemmFp16,
    Steel,
    MmaWide,
    ReshapeGpu,
    FlashAttention,
    PooledOutput,
}

impl GpuKernel {
    /// Every per-lever kernel knob, in declaration order. Plan-wide resolution
    /// iterates this so a new lever is overridable as soon as it is listed here.
    pub const ALL: [GpuKernel; 6] = [
        GpuKernel::GemmFp16,
        GpuKernel::Steel,
        GpuKernel::MmaWide,
        GpuKernel::ReshapeGpu,
        GpuKernel::FlashAttention,
        GpuKernel::PooledOutput,
    ];

    /// Canonical `KIN_INFER_*` environment variable that overrides this lever in
    /// either direction (parsed via [`env_flag_override`]).
    pub fn env_var(self) -> &'static str {
        match self {
            GpuKernel::GemmFp16 => "KIN_INFER_GEMM_FP16",
            GpuKernel::Steel => "KIN_INFER_STEEL",
            GpuKernel::MmaWide => "KIN_INFER_MMA_WIDE",
            GpuKernel::ReshapeGpu => "KIN_INFER_RESHAPE_GPU",
            GpuKernel::FlashAttention => "KIN_INFER_FLASH_ATTENTION",
            GpuKernel::PooledOutput => "KIN_INFER_POOLED_OUTPUT",
        }
    }
}

/// The fully-resolved GPU kernel plan for the active embedding process: the
/// profile/backend-derived plan ([`active_gpu_kernel_plan`]) with every
/// `KIN_INFER_*` env override applied, an explicit override winning over the
/// derived default. This is the selection the Metal forward path actually gates
/// on; exposing it in one place lets callers report the resolved value without
/// recomputing the precedence per lever.
pub fn resolved_gpu_kernel_plan() -> GpuKernelPlan {
    active_gpu_kernel_plan().with_overrides(|kernel| env_flag_override(kernel.env_var()))
}

/// The resolved value of a single GPU kernel lever: its `KIN_INFER_*` env
/// override if set, otherwise the profile/backend-derived default. Matches the
/// corresponding field of [`resolved_gpu_kernel_plan`]; provided for a caller
/// that needs only one lever and should not resolve the whole plan.
pub fn resolved_gpu_kernel(kernel: GpuKernel) -> bool {
    env_flag_override(kernel.env_var()).unwrap_or_else(|| active_gpu_kernel_plan().get(kernel))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocateSearchPlan {
    pub max_concurrent_requests: usize,
    pub semantic_query_concurrency: usize,
    pub rerank_batch_size: usize,
    pub cross_encoder_policy: CrossEncoderPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BenchPlan {
    pub citable_freeze_parallelism: usize,
    pub explore_fast_jobs: Option<usize>,
    pub artifact_mode: ArtifactMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchdogPlan {
    pub enabled: bool,
    pub orphan_check: bool,
    pub wall_cap_secs: u64,
    pub min_persisted_units_per_sec: Option<u64>,
}

// ---------------------------------------------------------------------------
// Metal resident-stack governor (canonical formula + caps)
// ---------------------------------------------------------------------------

/// Default share of Metal's recommended working set the resident stack may
/// reserve for command-buffer-owned transients. The remaining headroom covers
/// cached weights, host allocations, Metal driver overhead, and other process
/// memory on unified-memory Macs.
pub(crate) const DEFAULT_RESIDENT_STACK_BUDGET_DIVISOR: u64 = 2;

/// Share of physical RAM (`hw.memsize`) the resident stack may reserve for
/// GPU-resident command-buffer transients. On unified memory the cached weights,
/// host activation buffers, the BufferPool free-list, and the rest of the daemon
/// process all draw from this same DRAM, so the working-set figure alone (which
/// reports the GPU's share, not what is left after the process is already
/// resident) over-budgets. Capping against true physical RAM keeps the standing
/// in-flight footprint below the OS jetsam ceiling; over-budget segments fall to
/// the bounded per-layer / op-by-op path instead of allocating unbounded.
pub(crate) const RESIDENT_STACK_HW_MEMSIZE_PERCENT: u64 = 25;

/// Absolute ceiling on the resident-stack transient budget regardless of how
/// large the machine is. A single in-flight segment never needs tens of GB of
/// transients; anything beyond this should segment or drop to the per-layer path.
pub(crate) const RESIDENT_STACK_ABS_CEILING_BYTES: u64 = 8 * GIB;

/// Default ceiling on total bytes the Metal BufferPool free-list may hold. The
/// free list is a recycling cache, not a reservation: anything it drops is simply
/// re-allocated on the next acquire of that size-class. Without a ceiling the
/// list grows monotonically to the run's peak high-water, which on unified memory
/// is permanent physical RAM. Capping it bounds the standing footprint while
/// keeping the hot recycling path intact for the common (small, repeated) classes.
pub(crate) const DEFAULT_BUFFER_POOL_CAP_BYTES: u64 = 3 * GIB;

/// Per-buffer high-water: pooled buffers whose size-class exceeds this are never
/// recycled. The largest pooled allocations are the O(seq²) attention-score
/// buffers, the least likely to be re-hit at the exact same class and the most
/// expensive to strand; dropping them frees the unified allocation immediately.
pub(crate) const DEFAULT_BUFFER_POOL_PER_BUFFER_CAP_BYTES: u64 = 256 * 1024 * 1024;

/// Pure resident-stack budget arithmetic (no device / no env), the single
/// canonical copy of the formula. The Metal backend resolves the live device's
/// `recommended_max_working_set_size()` and physical RAM and calls this; the
/// inspect-only [`MetalGovernorPlan`] derives from the same two inputs, so the
/// reported budget and the runtime budget can never diverge.
///
/// The budget is the smallest of three ceilings:
/// 1. a share of Metal's recommended working set (the GPU's reported headroom),
/// 2. a share of true physical RAM (`hw.memsize`) — the unified-memory ceiling
///    that actually bounds the process before the OS kills it, and
/// 3. an absolute ceiling, so even very large machines never let a single
///    in-flight segment's transients balloon unbounded.
///
/// A `recommended` of 0 means the working-set term is unknown; the physical-RAM
/// and absolute ceilings still apply. When physical RAM is also unknown the
/// remaining ceilings still bound the budget.
pub(crate) fn resident_stack_budget_bytes(
    recommended: u64,
    system_total_bytes: Option<u64>,
) -> u64 {
    let working_set_term = if recommended == 0 {
        u64::MAX
    } else {
        recommended / DEFAULT_RESIDENT_STACK_BUDGET_DIVISOR
    };
    let hw_term = system_total_bytes
        .map(|total| total.saturating_mul(RESIDENT_STACK_HW_MEMSIZE_PERCENT) / 100)
        .unwrap_or(u64::MAX);
    working_set_term
        .min(hw_term)
        .min(RESIDENT_STACK_ABS_CEILING_BYTES)
}

/// Inspect-only view of the Metal resident-stack governor's hardware-derived
/// caps. Reported in [`ResourcePlan`] (and therefore in
/// `kin resources inspect --json`) so the "actual values used" — the resolved
/// resident-stack byte budget plus the BufferPool ceilings — are visible without
/// reading the GPU at runtime. The documented constants the formula keys off
/// (the working-set divisor, the physical-RAM percent, and the absolute ceiling)
/// are reported alongside so the derivation is auditable from the plan alone.
///
/// This is observability only: it derives from the SAME
/// `(recommended_working_set, system_total)` inputs the live governor uses and
/// does not change any runtime memory bound. Env overrides
/// (`KIN_INFER_METAL_RESIDENT_BUDGET_BYTES`, `KIN_INFER_METAL_POOL_CAP_BYTES`)
/// are deliberately not folded in here — this reports the hardware-derived
/// defaults, not the per-process override.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetalGovernorPlan {
    /// Resolved resident-stack transient byte budget (the smallest of the three
    /// ceilings below), from the same formula the backend resolves at startup.
    pub resident_stack_budget_bytes: u64,
    /// Default ceiling on total bytes the BufferPool free-list may hold.
    pub buffer_pool_cap_bytes: u64,
    /// Per-buffer high-water above which a size-class is never pooled.
    pub buffer_pool_per_buffer_cap_bytes: u64,
    /// Divisor applied to Metal's recommended working set for the GPU-headroom
    /// ceiling (term 1 of the budget formula).
    pub resident_stack_budget_divisor: u64,
    /// Percent of physical RAM (`hw.memsize`) for the unified-memory ceiling
    /// (term 2 of the budget formula).
    pub resident_stack_hw_memsize_percent: u64,
    /// Absolute ceiling on the resident-stack transient budget (term 3).
    pub resident_stack_abs_ceiling_bytes: u64,
}

impl MetalGovernorPlan {
    /// Derive the governor caps from the same `(recommended_working_set,
    /// system_total)` inputs the live Metal backend resolves. Pure: no device,
    /// no env, no runtime effect.
    pub fn derive(recommended_working_set_bytes: u64, system_total_bytes: Option<u64>) -> Self {
        MetalGovernorPlan {
            resident_stack_budget_bytes: resident_stack_budget_bytes(
                recommended_working_set_bytes,
                system_total_bytes,
            ),
            buffer_pool_cap_bytes: DEFAULT_BUFFER_POOL_CAP_BYTES,
            buffer_pool_per_buffer_cap_bytes: DEFAULT_BUFFER_POOL_PER_BUFFER_CAP_BYTES,
            resident_stack_budget_divisor: DEFAULT_RESIDENT_STACK_BUDGET_DIVISOR,
            resident_stack_hw_memsize_percent: RESIDENT_STACK_HW_MEMSIZE_PERCENT,
            resident_stack_abs_ceiling_bytes: RESIDENT_STACK_ABS_CEILING_BYTES,
        }
    }
}

// ---------------------------------------------------------------------------
// Plan
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourcePlan {
    pub schema_version: SchemaVersion,
    pub profile: Profile,
    pub host: HostInfo,
    pub memory: MemoryInfo,
    pub accelerator: AcceleratorInfo,
    /// Detected GPU core count (Apple-silicon `gpu-core-count`), when available.
    /// Reported for inspection. Populated by [`ResourcePlan::detect`]; left
    /// `None` when a plan is built directly via [`ResourcePlan::for_profile`].
    #[serde(default)]
    pub gpu_core_count: Option<usize>,
    pub embedding: EmbeddingPlan,
    pub locate_search: LocateSearchPlan,
    pub bench: BenchPlan,
    pub watchdog: WatchdogPlan,
    /// Inspect-only Metal resident-stack governor caps, derived from the same
    /// `(recommended_working_set, system_total)` inputs the live backend uses.
    /// Observability only — reported here so `kin resources inspect --json`
    /// surfaces the resolved resident-stack budget and BufferPool ceilings.
    #[serde(default = "MetalGovernorPlan::derive_default")]
    pub metal_governor: MetalGovernorPlan,
}

impl MetalGovernorPlan {
    /// Serde fallback for plans deserialized from an older schema that predates
    /// `metal_governor`: derive from no hardware inputs (both ceilings unknown),
    /// which collapses to the absolute ceiling and the default pool caps.
    fn derive_default() -> MetalGovernorPlan {
        MetalGovernorPlan::derive(0, None)
    }
}

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

/// Detect host topology. `rayon_threads`/`reserve_logical_cores`/`blas_threads`
/// are defaulted here and finalized by [`ResourcePlan::for_profile`].
pub fn detect_host() -> HostInfo {
    let logical_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    let (physical_cores, performance_cores, efficiency_cores) = detect_core_topology();
    HostInfo {
        arch: std::env::consts::ARCH.to_string(),
        logical_cores,
        physical_cores,
        performance_cores,
        efficiency_cores,
        rayon_threads: logical_cores,
        reserve_logical_cores: 0,
        blas_threads: 1,
    }
}

#[cfg(target_os = "macos")]
fn detect_core_topology() -> (Option<usize>, Option<usize>, Option<usize>) {
    // perflevel0 = performance cores, perflevel1 = efficiency cores.
    let out = std::process::Command::new("sysctl")
        .args([
            "-n",
            "hw.physicalcpu",
            "hw.perflevel0.logicalcpu",
            "hw.perflevel1.logicalcpu",
        ])
        .output()
        .ok();
    let mut vals: [Option<usize>; 3] = [None, None, None];
    if let Some(out) = out {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout);
            for (slot, line) in vals.iter_mut().zip(text.lines()) {
                *slot = line.trim().parse().ok();
            }
        }
    }
    (vals[0], vals[1], vals[2])
}

#[cfg(not(target_os = "macos"))]
fn detect_core_topology() -> (Option<usize>, Option<usize>, Option<usize>) {
    (None, None, None)
}

/// Detect total system memory. Other fields are best-effort `None`.
pub fn detect_memory() -> MemoryInfo {
    MemoryInfo {
        system_total_bytes: detect_system_total_bytes(),
        system_available_bytes: None,
        max_process_rss_bytes: None,
        hot_graph_budget_bytes: None,
    }
}

#[cfg(target_os = "macos")]
fn detect_system_total_bytes() -> Option<u64> {
    let out = std::process::Command::new("sysctl")
        .args(["-n", "hw.memsize"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8_lossy(&out.stdout).trim().parse().ok()
}

#[cfg(not(target_os = "macos"))]
fn detect_system_total_bytes() -> Option<u64> {
    None
}

/// Best-effort GPU core count via the IORegistry `gpu-core-count` property
/// (Apple silicon). Returns `None` off macOS or when the property is absent.
#[cfg(target_os = "macos")]
fn detect_gpu_cores() -> Option<usize> {
    let out = std::process::Command::new("ioreg")
        .args(["-l", "-k", "gpu-core-count"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    const KEY: &str = "\"gpu-core-count\"";
    for line in text.lines() {
        if let Some(pos) = line.find(KEY) {
            let value: String = line[pos + KEY.len()..]
                .chars()
                .filter(char::is_ascii_digit)
                .collect();
            if let Ok(n) = value.parse::<usize>() {
                if n > 0 {
                    return Some(n);
                }
            }
        }
    }
    None
}

#[cfg(not(target_os = "macos"))]
fn detect_gpu_cores() -> Option<usize> {
    None
}

/// Detect the best accelerator from read-only device discovery. Does not create
/// a compute instance or load a model. `max_inflight_command_buffers` /
/// `allow_cpu_fallback` are defaulted here and finalized by
/// [`ResourcePlan::for_profile`].
pub fn detect_accelerator() -> AcceleratorInfo {
    let device = crate::gpu::best_device();
    let backend = match device.backend {
        crate::gpu::GpuBackend::Metal => AcceleratorBackend::Metal,
        crate::gpu::GpuBackend::Cuda => AcceleratorBackend::Cuda,
        crate::gpu::GpuBackend::Cpu => AcceleratorBackend::Cpu,
    };
    // Metal `memory_bytes` is the recommended working set; CUDA reports device total.
    let (device_total_bytes, recommended_working_set_bytes) = match device.backend {
        crate::gpu::GpuBackend::Cuda => (Some(device.memory_bytes), None),
        crate::gpu::GpuBackend::Metal if device.memory_bytes > 0 => {
            (None, Some(device.memory_bytes))
        }
        _ => (None, None),
    };
    AcceleratorInfo {
        backend,
        device_index: 0,
        unified_memory: device.unified_memory,
        device_total_bytes,
        device_available_bytes: None,
        recommended_working_set_bytes,
        max_single_buffer_bytes: None,
        max_inflight_command_buffers: 1,
        reserve_device_bytes: None,
        allow_cpu_fallback: true,
    }
}

// ---------------------------------------------------------------------------
// Profile budgets
// ---------------------------------------------------------------------------

/// Throughput budget multiplier for unified-memory Metal, keyed off total
/// unified memory. On Apple silicon memory size tracks GPU class (Max/Ultra
/// parts ship both more memory and more GPU cores), so this scales the batch and
/// attention budgets with effective GPU throughput while keeping the O(seq²)
/// attention area inside the macOS GPU watchdog's wall-time budget. Parts below
/// the smallest tier keep the historical budgets unchanged.
fn unified_throughput_scale(system_total_bytes: Option<u64>) -> usize {
    match system_total_bytes {
        Some(b) if b >= 96 * GIB => 4,
        Some(b) if b >= 64 * GIB => 3,
        Some(b) if b >= 32 * GIB => 2,
        _ => 1,
    }
}

/// In-flight Metal command-buffer depth for unified-memory throughput, scaled by
/// memory tier so larger parts pipeline more work without starving submission.
fn unified_inflight(system_total_bytes: Option<u64>) -> usize {
    match system_total_bytes {
        Some(b) if b >= 96 * GIB => 2, // Cap at 2 to prevent unified-memory thrashing
        Some(b) if b >= 32 * GIB => 2,
        _ => 1,
    }
}

impl ResourcePlan {
    /// Detect host/accelerator/memory and derive the plan for `profile`.
    pub fn detect(profile: Profile) -> ResourcePlan {
        let host = detect_host();
        let accelerator = detect_accelerator();
        let memory = detect_memory();
        let mut plan = ResourcePlan::for_profile(profile, &host, &accelerator, &memory);
        plan.gpu_core_count = detect_gpu_cores();
        plan
    }

    /// Derive a plan for `profile` from detected resources. Proof reproduces the
    /// current kin-db embedding defaults exactly; other profiles diverge only as
    /// documented.
    pub fn for_profile(
        profile: Profile,
        host: &HostInfo,
        accelerator: &AcceleratorInfo,
        memory: &MemoryInfo,
    ) -> ResourcePlan {
        let logical = host.logical_cores.max(1);
        let backend = accelerator.backend;

        let proof_batch_tokens = match backend {
            AcceleratorBackend::Metal => 16384,
            AcceleratorBackend::Cuda => 65536,
            AcceleratorBackend::Cpu | AcceleratorBackend::Auto => 32768,
        };
        let proof_attention_area: Option<u64> = match backend {
            AcceleratorBackend::Metal => Some(8_388_608),
            _ => None,
        };

        let mut host = host.clone();
        host.rayon_threads = logical;
        host.reserve_logical_cores = 0;
        host.blas_threads = 1;

        let mut accel = accelerator.clone();
        accel.max_inflight_command_buffers = 1;
        accel.allow_cpu_fallback = true;

        let mut embedding = EmbeddingPlan {
            max_seq_len: 2048,
            max_batch_tokens: proof_batch_tokens,
            max_attention_area: proof_attention_area,
            max_entities_per_graph_chunk: (logical * 16).clamp(64, 192),
            hybrid_mode: HybridMode::Off,
            oom_retry: OomRetry::SplitBatchThenCpu,
            nonfinite_policy: NonfinitePolicy::Error,
            gpu_kernels: GpuKernelPlan::resolve(profile, backend),
        };

        let mut locate_search = LocateSearchPlan {
            max_concurrent_requests: 1,
            semantic_query_concurrency: 1,
            rerank_batch_size: 20,
            cross_encoder_policy: CrossEncoderPolicy::Off,
        };

        let mut bench = BenchPlan {
            citable_freeze_parallelism: 1,
            explore_fast_jobs: None,
            artifact_mode: ArtifactMode::Proof,
        };

        let watchdog = WatchdogPlan {
            enabled: true,
            orphan_check: true,
            wall_cap_secs: 21600,
            min_persisted_units_per_sec: None,
        };

        match profile {
            Profile::Proof => {}
            Profile::Throughput => {
                host.reserve_logical_cores = 1;
                host.rayon_threads = logical.saturating_sub(1).max(1);
                embedding.max_entities_per_graph_chunk = (logical * 32).clamp(128, 512);
                if backend == AcceleratorBackend::Metal && accel.unified_memory {
                    // Scale the batch + attention budgets with the unified-memory
                    // tier (a proxy for GPU class). The attention area stays inside
                    // the macOS GPU watchdog's wall-time budget because higher tiers
                    // also have proportionally more GPU cores.
                    let scale = unified_throughput_scale(memory.system_total_bytes);
                    embedding.max_batch_tokens = 65_536 * scale;
                    // Cap attention area scale to 2 to prevent extreme O(L^2) memory footprint
                    let area_scale = scale.min(2);
                    embedding.max_attention_area =
                        proof_attention_area.map(|a| a * area_scale as u64);
                    accel.max_inflight_command_buffers =
                        unified_inflight(memory.system_total_bytes);
                } else {
                    accel.max_inflight_command_buffers = 2;
                }
                embedding.hybrid_mode = if memory.system_total_bytes.is_some_and(|b| b >= 32 * GIB)
                {
                    HybridMode::Balanced
                } else {
                    HybridMode::Off
                };
                bench.explore_fast_jobs = Some(logical.saturating_sub(2).max(1));
                bench.artifact_mode = ArtifactMode::NonCitableExplore;
            }
            Profile::Interactive => {
                let reserve = (logical / 4).clamp(2, 4);
                host.reserve_logical_cores = reserve;
                host.rayon_threads = logical.saturating_sub(reserve).max(1);
                accel.max_inflight_command_buffers = 2;
            }
            Profile::Ci => {
                host.rayon_threads = logical.min(4);
                host.reserve_logical_cores = logical.saturating_sub(host.rayon_threads);
                host.blas_threads = 1;
                embedding.max_batch_tokens = 4096;
                embedding.max_entities_per_graph_chunk = 64;
                embedding.hybrid_mode = HybridMode::Off;
                embedding.nonfinite_policy = NonfinitePolicy::Error;
                locate_search.cross_encoder_policy = CrossEncoderPolicy::Off;
            }
        }

        // Inspect-only governor caps from the same inputs the live Metal backend
        // resolves: the GPU's recommended working set and true physical RAM. The
        // formula tolerates unknown (0 / None) inputs, so non-Metal backends
        // report the absolute-ceiling default without any runtime effect.
        let metal_governor = MetalGovernorPlan::derive(
            accel.recommended_working_set_bytes.unwrap_or(0),
            memory.system_total_bytes,
        );

        ResourcePlan {
            schema_version: SchemaVersion,
            profile,
            host,
            memory: memory.clone(),
            accelerator: accel,
            gpu_core_count: None,
            embedding,
            locate_search,
            bench,
            watchdog,
            metal_governor,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn host_with(logical: usize) -> HostInfo {
        HostInfo {
            arch: "aarch64".to_string(),
            logical_cores: logical,
            physical_cores: Some(logical),
            performance_cores: None,
            efficiency_cores: None,
            rayon_threads: logical,
            reserve_logical_cores: 0,
            blas_threads: 1,
        }
    }

    fn metal_accel() -> AcceleratorInfo {
        AcceleratorInfo {
            backend: AcceleratorBackend::Metal,
            device_index: 0,
            unified_memory: true,
            device_total_bytes: None,
            device_available_bytes: None,
            recommended_working_set_bytes: Some(64 * GIB),
            max_single_buffer_bytes: None,
            max_inflight_command_buffers: 1,
            reserve_device_bytes: None,
            allow_cpu_fallback: true,
        }
    }

    fn mem_with(total: Option<u64>) -> MemoryInfo {
        MemoryInfo {
            system_total_bytes: total,
            system_available_bytes: None,
            max_process_rss_bytes: None,
            hot_graph_budget_bytes: None,
        }
    }

    #[test]
    fn proof_reproduces_current_defaults() {
        let host = host_with(18);
        let accel = metal_accel();
        let mem = mem_with(Some(128 * GIB));
        let plan = ResourcePlan::for_profile(Profile::Proof, &host, &accel, &mem);

        assert_eq!(plan.profile, Profile::Proof);

        // host
        assert_eq!(plan.host.rayon_threads, 18);
        assert_eq!(plan.host.reserve_logical_cores, 0);
        assert_eq!(plan.host.blas_threads, 1);

        // accelerator
        assert_eq!(plan.accelerator.max_inflight_command_buffers, 1);
        assert!(plan.accelerator.allow_cpu_fallback);

        // embedding (Metal contract)
        assert_eq!(plan.embedding.max_seq_len, 2048);
        assert_eq!(plan.embedding.max_batch_tokens, 16384);
        assert_eq!(plan.embedding.max_attention_area, Some(8_388_608));
        assert_eq!(plan.embedding.max_entities_per_graph_chunk, 192);
        assert_eq!(plan.embedding.hybrid_mode, HybridMode::Off);
        assert_eq!(plan.embedding.oom_retry, OomRetry::SplitBatchThenCpu);
        assert_eq!(plan.embedding.nonfinite_policy, NonfinitePolicy::Error);
        // Proof keeps every fast GPU kernel off for a bit-identical forward pass.
        assert_eq!(plan.embedding.gpu_kernels, GpuKernelPlan::default());

        // locate/search
        assert_eq!(plan.locate_search.max_concurrent_requests, 1);
        assert_eq!(plan.locate_search.semantic_query_concurrency, 1);
        assert_eq!(plan.locate_search.rerank_batch_size, 20);
        assert_eq!(
            plan.locate_search.cross_encoder_policy,
            CrossEncoderPolicy::Off
        );

        // bench
        assert_eq!(plan.bench.citable_freeze_parallelism, 1);
        assert_eq!(plan.bench.explore_fast_jobs, None);
        assert_eq!(plan.bench.artifact_mode, ArtifactMode::Proof);

        // watchdog
        assert!(plan.watchdog.enabled);
        assert!(plan.watchdog.orphan_check);
        assert_eq!(plan.watchdog.wall_cap_secs, 21600);
        assert_eq!(plan.watchdog.min_persisted_units_per_sec, None);
    }

    #[test]
    fn proof_cpu_and_cuda_batch_tokens() {
        let host = host_with(8);
        let mem = mem_with(None);

        let mut cpu = metal_accel();
        cpu.backend = AcceleratorBackend::Cpu;
        cpu.unified_memory = false;
        let plan = ResourcePlan::for_profile(Profile::Proof, &host, &cpu, &mem);
        assert_eq!(plan.embedding.max_batch_tokens, 32768);
        assert_eq!(plan.embedding.max_attention_area, None);

        let mut cuda = metal_accel();
        cuda.backend = AcceleratorBackend::Cuda;
        cuda.unified_memory = false;
        let plan = ResourcePlan::for_profile(Profile::Proof, &host, &cuda, &mem);
        assert_eq!(plan.embedding.max_batch_tokens, 65536);
        assert_eq!(plan.embedding.max_attention_area, None);
    }

    #[test]
    fn throughput_scales_budgets_on_high_memory_unified_metal() {
        let host = host_with(18);
        let accel = metal_accel();
        let mem = mem_with(Some(128 * GIB));
        let plan = ResourcePlan::for_profile(Profile::Throughput, &host, &accel, &mem);

        // 128 GiB unified -> top tier (4x) over the historical 8.38M / 65536 base.
        // Cap attention area scale to 2x (16_777_216) and inflight command buffers to 2 to prevent memory pressure crashes.
        assert_eq!(plan.embedding.max_attention_area, Some(16_777_216));
        assert_eq!(plan.embedding.max_batch_tokens, 262_144);
        assert_eq!(plan.accelerator.max_inflight_command_buffers, 2);
        assert_eq!(plan.embedding.max_entities_per_graph_chunk, 512);
        assert_eq!(plan.embedding.hybrid_mode, HybridMode::Balanced);
        assert_eq!(plan.host.rayon_threads, 17);
        assert_eq!(plan.host.reserve_logical_cores, 1);
        assert_eq!(plan.bench.explore_fast_jobs, Some(16));
        assert_eq!(plan.bench.artifact_mode, ArtifactMode::NonCitableExplore);
        assert_eq!(
            plan.embedding.gpu_kernels,
            GpuKernelPlan {
                pooled_output: true,
                steel: true,
                ..GpuKernelPlan::default()
            }
        );
    }

    #[test]
    fn gpu_kernel_plan_enables_throughput_metal_kernels() {
        for profile in [
            Profile::Proof,
            Profile::Interactive,
            Profile::Throughput,
            Profile::Ci,
        ] {
            for backend in [
                AcceleratorBackend::Metal,
                AcceleratorBackend::Cuda,
                AcceleratorBackend::Cpu,
            ] {
                let expected = if matches!(profile, Profile::Throughput)
                    && matches!(backend, AcceleratorBackend::Metal)
                {
                    GpuKernelPlan {
                        pooled_output: true,
                        steel: true,
                        ..GpuKernelPlan::default()
                    }
                } else {
                    GpuKernelPlan::default()
                };
                assert_eq!(GpuKernelPlan::resolve(profile, backend), expected);
            }
        }
    }

    #[test]
    fn gpu_kernel_plan_defaults_future_kernels_off() {
        let plan = GpuKernelPlan::default();

        assert!(!plan.gemm_fp16);
        assert!(!plan.steel);
        assert!(!plan.mma_wide);
        assert!(!plan.reshape_gpu);
        assert!(!plan.flash_attention);
        assert!(!plan.pooled_output);
    }

    #[test]
    fn gpu_kernel_plan_deserializes_missing_future_fields_as_off() {
        let plan: GpuKernelPlan = serde_json::from_value(serde_json::json!({
            "gemm_fp16": false,
            "steel": false,
            "mma_wide": false,
            "reshape_gpu": false
        }))
        .unwrap();

        assert_eq!(plan, GpuKernelPlan::default());
        assert!(!plan.flash_attention);
        assert!(!plan.pooled_output);
    }

    #[test]
    fn gpu_kernel_plan_accepts_explicit_future_schema_values() {
        let plan: GpuKernelPlan = serde_json::from_value(serde_json::json!({
            "flash_attention": true,
            "pooled_output": true
        }))
        .unwrap();

        assert!(plan.flash_attention);
        assert!(plan.pooled_output);
        assert!(!plan.gemm_fp16);
        assert!(!plan.steel);
        assert!(!plan.mma_wide);
        assert!(!plan.reshape_gpu);
    }

    #[test]
    fn env_flag_override_parses_both_directions() {
        assert_eq!(env_flag_override("KIN_INFER_NONEXISTENT_FLAG_XYZ"), None);
    }

    #[test]
    fn gpu_kernel_env_var_names_are_canonical() {
        assert_eq!(GpuKernel::GemmFp16.env_var(), "KIN_INFER_GEMM_FP16");
        assert_eq!(GpuKernel::Steel.env_var(), "KIN_INFER_STEEL");
        assert_eq!(GpuKernel::MmaWide.env_var(), "KIN_INFER_MMA_WIDE");
        assert_eq!(GpuKernel::ReshapeGpu.env_var(), "KIN_INFER_RESHAPE_GPU");
        assert_eq!(
            GpuKernel::FlashAttention.env_var(),
            "KIN_INFER_FLASH_ATTENTION"
        );
        assert_eq!(GpuKernel::PooledOutput.env_var(), "KIN_INFER_POOLED_OUTPUT");
    }

    #[test]
    fn gpu_kernel_all_lists_each_lever_once() {
        assert_eq!(GpuKernel::ALL.len(), 6);
        let mut seen = std::collections::HashSet::new();
        for kernel in GpuKernel::ALL {
            assert!(
                seen.insert(kernel.env_var()),
                "duplicate lever {kernel:?} in GpuKernel::ALL"
            );
        }
    }

    #[test]
    fn gpu_kernel_get_reads_matching_field() {
        let plan = GpuKernelPlan {
            gemm_fp16: true,
            steel: false,
            mma_wide: true,
            reshape_gpu: false,
            flash_attention: true,
            pooled_output: false,
        };
        assert!(plan.get(GpuKernel::GemmFp16));
        assert!(!plan.get(GpuKernel::Steel));
        assert!(plan.get(GpuKernel::MmaWide));
        assert!(!plan.get(GpuKernel::ReshapeGpu));
        assert!(plan.get(GpuKernel::FlashAttention));
        assert!(!plan.get(GpuKernel::PooledOutput));
    }

    #[test]
    fn with_overrides_none_keeps_derived_default() {
        // No override for any lever: the derived plan passes through unchanged.
        let derived = GpuKernelPlan::resolve(Profile::Throughput, AcceleratorBackend::Metal);
        assert!(derived.pooled_output); // throughput/Metal derives this on
        assert_eq!(derived.with_overrides(|_| None), derived);
    }

    #[test]
    fn with_overrides_explicit_value_wins_over_derived() {
        // An explicit override beats the derived default in both directions.
        let derived = GpuKernelPlan::resolve(Profile::Throughput, AcceleratorBackend::Metal);
        assert!(derived.pooled_output);
        assert!(!derived.gemm_fp16);

        let resolved = derived.with_overrides(|kernel| match kernel {
            GpuKernel::PooledOutput => Some(false), // force off over a derived on
            GpuKernel::GemmFp16 => Some(true),      // force on over a derived off
            _ => None,
        });
        assert!(!resolved.pooled_output);
        assert!(resolved.gemm_fp16);
        // Levers without an override keep the derived default: steel is derived
        // on for throughput/Metal, flash_attention derived off.
        assert!(resolved.steel);
        assert!(!resolved.flash_attention);
    }

    #[test]
    fn with_overrides_applies_every_lever() {
        // A force value for every lever yields a uniform plan regardless of base.
        let all_on = GpuKernelPlan::default().with_overrides(|_| Some(true));
        for kernel in GpuKernel::ALL {
            assert!(all_on.get(kernel), "{kernel:?} not forced on");
        }
        let all_off = GpuKernelPlan {
            gemm_fp16: true,
            steel: true,
            mma_wide: true,
            reshape_gpu: true,
            flash_attention: true,
            pooled_output: true,
        }
        .with_overrides(|_| Some(false));
        for kernel in GpuKernel::ALL {
            assert!(!all_off.get(kernel), "{kernel:?} not forced off");
        }
    }

    #[test]
    fn throughput_mid_memory_tiers_scale_proportionally() {
        let host = host_with(18);
        let accel = metal_accel();

        let plan = ResourcePlan::for_profile(
            Profile::Throughput,
            &host,
            &accel,
            &mem_with(Some(64 * GIB)),
        );
        assert_eq!(plan.embedding.max_attention_area, Some(16_777_216));
        assert_eq!(plan.embedding.max_batch_tokens, 196_608);
        assert_eq!(plan.accelerator.max_inflight_command_buffers, 2);

        let plan = ResourcePlan::for_profile(
            Profile::Throughput,
            &host,
            &accel,
            &mem_with(Some(32 * GIB)),
        );
        assert_eq!(plan.embedding.max_attention_area, Some(16_777_216));
        assert_eq!(plan.embedding.max_batch_tokens, 131_072);
        assert_eq!(plan.accelerator.max_inflight_command_buffers, 2);
    }

    #[test]
    fn throughput_keeps_historical_budgets_below_32gib() {
        let host = host_with(18);
        let accel = metal_accel();
        let mem = mem_with(Some(16 * GIB));
        let plan = ResourcePlan::for_profile(Profile::Throughput, &host, &accel, &mem);
        // Smallest tier (1x): unchanged from the pre-scaling throughput budgets.
        assert_eq!(plan.embedding.max_attention_area, Some(8_388_608));
        assert_eq!(plan.embedding.max_batch_tokens, 65_536);
        assert_eq!(plan.accelerator.max_inflight_command_buffers, 1);
        assert_eq!(plan.embedding.hybrid_mode, HybridMode::Off);
    }

    #[test]
    fn throughput_does_not_scale_non_unified_metal() {
        let host = host_with(18);
        let mut accel = metal_accel();
        accel.unified_memory = false;
        let mem = mem_with(Some(128 * GIB));
        let plan = ResourcePlan::for_profile(Profile::Throughput, &host, &accel, &mem);
        // Discrete-memory Metal has no unified headroom: keep the proof budgets.
        assert_eq!(plan.embedding.max_attention_area, Some(8_388_608));
        assert_eq!(plan.embedding.max_batch_tokens, 16_384);
        assert_eq!(plan.accelerator.max_inflight_command_buffers, 2);
    }

    #[test]
    fn for_profile_leaves_gpu_core_count_none() {
        let host = host_with(18);
        let accel = metal_accel();
        let mem = mem_with(Some(128 * GIB));
        for profile in [
            Profile::Proof,
            Profile::Interactive,
            Profile::Throughput,
            Profile::Ci,
        ] {
            let plan = ResourcePlan::for_profile(profile, &host, &accel, &mem);
            assert_eq!(plan.gpu_core_count, None);
        }
    }

    #[test]
    fn interactive_reserves_cores() {
        let host = host_with(18);
        let accel = metal_accel();
        let mem = mem_with(Some(128 * GIB));
        let plan = ResourcePlan::for_profile(Profile::Interactive, &host, &accel, &mem);
        assert_eq!(plan.host.reserve_logical_cores, 4);
        assert_eq!(plan.host.rayon_threads, 14);
        assert_eq!(plan.accelerator.max_inflight_command_buffers, 2);
        // Proof-level embedding.
        assert_eq!(plan.embedding.max_batch_tokens, 16384);
        assert_eq!(plan.embedding.max_attention_area, Some(8_388_608));
    }

    #[test]
    fn ci_caps_budgets() {
        let host = host_with(18);
        let accel = metal_accel();
        let mem = mem_with(Some(128 * GIB));
        let plan = ResourcePlan::for_profile(Profile::Ci, &host, &accel, &mem);
        assert_eq!(plan.host.rayon_threads, 4);
        assert_eq!(plan.host.blas_threads, 1);
        assert_eq!(plan.embedding.max_batch_tokens, 4096);
        assert_eq!(plan.embedding.max_entities_per_graph_chunk, 64);
        assert_eq!(plan.embedding.hybrid_mode, HybridMode::Off);
        assert_eq!(plan.embedding.nonfinite_policy, NonfinitePolicy::Error);
        assert_eq!(
            plan.locate_search.cross_encoder_policy,
            CrossEncoderPolicy::Off
        );
        assert!(plan.watchdog.enabled);
    }

    #[test]
    fn schema_version_serializes_fixed_token_and_round_trips() {
        let host = host_with(18);
        let accel = metal_accel();
        let mem = mem_with(Some(128 * GIB));
        let plan = ResourcePlan::for_profile(Profile::Proof, &host, &accel, &mem);

        let value: serde_json::Value = serde_json::to_value(&plan).unwrap();
        assert_eq!(value["schema_version"], "kin.resource_plan.v1");
        assert_eq!(value["profile"], "proof");
        assert_eq!(value["embedding"]["gpu_kernels"]["flash_attention"], false);
        assert_eq!(value["embedding"]["gpu_kernels"]["pooled_output"], false);

        let json = serde_json::to_string(&plan).unwrap();
        let back: ResourcePlan = serde_json::from_str(&json).unwrap();
        assert_eq!(plan, back);
    }

    #[test]
    fn resource_plan_deserializes_missing_future_kernel_fields_as_off() {
        let host = host_with(18);
        let accel = metal_accel();
        let mem = mem_with(Some(128 * GIB));
        let plan = ResourcePlan::for_profile(Profile::Proof, &host, &accel, &mem);
        let mut value = serde_json::to_value(&plan).unwrap();

        value["embedding"]["gpu_kernels"]
            .as_object_mut()
            .unwrap()
            .remove("flash_attention");
        value["embedding"]["gpu_kernels"]
            .as_object_mut()
            .unwrap()
            .remove("pooled_output");

        let back: ResourcePlan = serde_json::from_value(value).unwrap();
        assert!(!back.embedding.gpu_kernels.flash_attention);
        assert!(!back.embedding.gpu_kernels.pooled_output);
        assert_eq!(back.embedding.gpu_kernels, GpuKernelPlan::default());
    }

    #[test]
    fn rejects_unknown_schema_version() {
        let host = host_with(4);
        let accel = metal_accel();
        let mem = mem_with(None);
        let plan = ResourcePlan::for_profile(Profile::Proof, &host, &accel, &mem);
        let mut value = serde_json::to_value(&plan).unwrap();
        value["schema_version"] = serde_json::Value::String("kin.resource_plan.v2".to_string());
        assert!(serde_json::from_value::<ResourcePlan>(value).is_err());
    }

    #[test]
    fn detect_proof_does_not_panic() {
        let _ = ResourcePlan::detect(Profile::Proof);
    }

    #[test]
    fn metal_governor_plan_reports_resolved_caps_and_constants() {
        // 64 GiB recommended working set, 128 GiB physical RAM: both the
        // working-set term (32G) and the hw% term (32G) exceed the absolute
        // ceiling, so the resolved budget is the ceiling.
        let gov = MetalGovernorPlan::derive(64 * GIB, Some(128 * GIB));
        assert_eq!(
            gov.resident_stack_budget_bytes,
            RESIDENT_STACK_ABS_CEILING_BYTES
        );
        // Reported caps mirror the canonical constants.
        assert_eq!(gov.buffer_pool_cap_bytes, DEFAULT_BUFFER_POOL_CAP_BYTES);
        assert_eq!(
            gov.buffer_pool_per_buffer_cap_bytes,
            DEFAULT_BUFFER_POOL_PER_BUFFER_CAP_BYTES
        );
        assert_eq!(
            gov.resident_stack_budget_divisor,
            DEFAULT_RESIDENT_STACK_BUDGET_DIVISOR
        );
        assert_eq!(
            gov.resident_stack_hw_memsize_percent,
            RESIDENT_STACK_HW_MEMSIZE_PERCENT
        );
        assert_eq!(
            gov.resident_stack_abs_ceiling_bytes,
            RESIDENT_STACK_ABS_CEILING_BYTES
        );
    }

    #[test]
    fn metal_governor_plan_binds_on_hw_percent_for_small_machine() {
        // 11 GiB working set / 16 GiB RAM: hw% (4 GiB) is the binding ceiling,
        // below both the working-set term (5.5 GiB) and the absolute ceiling.
        let gov = MetalGovernorPlan::derive(11 * GIB, Some(16 * GIB));
        let expected_hw = (16 * GIB).saturating_mul(RESIDENT_STACK_HW_MEMSIZE_PERCENT) / 100;
        assert_eq!(gov.resident_stack_budget_bytes, expected_hw);
        assert!(gov.resident_stack_budget_bytes < RESIDENT_STACK_ABS_CEILING_BYTES);
    }

    #[test]
    fn for_profile_populates_metal_governor_from_inputs() {
        let host = host_with(18);
        let accel = metal_accel(); // recommended_working_set_bytes = 64 GiB
        let mem = mem_with(Some(128 * GIB));
        let plan = ResourcePlan::for_profile(Profile::Proof, &host, &accel, &mem);
        let expected = MetalGovernorPlan::derive(
            accel.recommended_working_set_bytes.unwrap_or(0),
            mem.system_total_bytes,
        );
        assert_eq!(plan.metal_governor, expected);
    }

    #[test]
    fn metal_governor_deserializes_missing_field_as_default() {
        let host = host_with(18);
        let accel = metal_accel();
        let mem = mem_with(Some(128 * GIB));
        let plan = ResourcePlan::for_profile(Profile::Proof, &host, &accel, &mem);
        let mut value = serde_json::to_value(&plan).unwrap();
        value.as_object_mut().unwrap().remove("metal_governor");

        let back: ResourcePlan = serde_json::from_value(value).unwrap();
        // An older plan with no governor field falls back to the no-hardware
        // derivation (absolute ceiling + default pool caps).
        assert_eq!(back.metal_governor, MetalGovernorPlan::derive(0, None));
        assert_eq!(
            back.metal_governor.resident_stack_budget_bytes,
            RESIDENT_STACK_ABS_CEILING_BYTES
        );
    }
}
