// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Shared resource plan — inspect-only host/accelerator/memory detection plus
//! per-profile budgets. Stable JSON (`kin.resource_plan.v1`) consumed across the
//! ecosystem. This module describes resources and recommends budgets; it wires
//! nothing and changes no runtime behavior.

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
// Plan
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourcePlan {
    pub schema_version: SchemaVersion,
    pub profile: Profile,
    pub host: HostInfo,
    pub memory: MemoryInfo,
    pub accelerator: AcceleratorInfo,
    pub embedding: EmbeddingPlan,
    pub locate_search: LocateSearchPlan,
    pub bench: BenchPlan,
    pub watchdog: WatchdogPlan,
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

impl ResourcePlan {
    /// Detect host/accelerator/memory and derive the plan for `profile`.
    pub fn detect(profile: Profile) -> ResourcePlan {
        let host = detect_host();
        let accelerator = detect_accelerator();
        let memory = detect_memory();
        ResourcePlan::for_profile(profile, &host, &accelerator, &memory)
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
                // Unified-memory Metal lifts the token budget but keeps the
                // attention area fixed — raising it trips the macOS GPU watchdog.
                if backend == AcceleratorBackend::Metal && accel.unified_memory {
                    embedding.max_batch_tokens = 65536;
                }
                embedding.hybrid_mode = if memory.system_total_bytes.is_some_and(|b| b >= 32 * GIB)
                {
                    HybridMode::Balanced
                } else {
                    HybridMode::Off
                };
                accel.max_inflight_command_buffers = 2;
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

        ResourcePlan {
            schema_version: SchemaVersion,
            profile,
            host,
            memory: memory.clone(),
            accelerator: accel,
            embedding,
            locate_search,
            bench,
            watchdog,
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
    fn throughput_keeps_attention_area_capped() {
        let host = host_with(18);
        let accel = metal_accel();
        let mem = mem_with(Some(128 * GIB));
        let plan = ResourcePlan::for_profile(Profile::Throughput, &host, &accel, &mem);

        // Watchdog guard: token budget rises on unified Metal, attention area does not.
        assert_eq!(plan.embedding.max_attention_area, Some(8_388_608));
        assert_eq!(plan.embedding.max_batch_tokens, 65536);
        assert_eq!(plan.embedding.max_entities_per_graph_chunk, 512);
        assert_eq!(plan.embedding.hybrid_mode, HybridMode::Balanced);
        assert_eq!(plan.host.rayon_threads, 17);
        assert_eq!(plan.host.reserve_logical_cores, 1);
        assert_eq!(plan.accelerator.max_inflight_command_buffers, 2);
        assert_eq!(plan.bench.explore_fast_jobs, Some(16));
        assert_eq!(plan.bench.artifact_mode, ArtifactMode::NonCitableExplore);
    }

    #[test]
    fn throughput_hybrid_off_below_32gib() {
        let host = host_with(18);
        let accel = metal_accel();
        let mem = mem_with(Some(16 * GIB));
        let plan = ResourcePlan::for_profile(Profile::Throughput, &host, &accel, &mem);
        assert_eq!(plan.embedding.hybrid_mode, HybridMode::Off);
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

        let json = serde_json::to_string(&plan).unwrap();
        let back: ResourcePlan = serde_json::from_str(&json).unwrap();
        assert_eq!(plan, back);
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
}
