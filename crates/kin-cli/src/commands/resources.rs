// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_infer::resource::{Profile, ResourcePlan};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CommandResourcesRequest {
    #[serde(default)]
    pub json: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

/// Live daemon embedding state attached to the resource plan so an inspector
/// sees both the recommended budgets and what the running daemon is actually
/// doing. Sourced entirely from daemon-owned state — never recomputed here.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbedRuntimeState {
    /// The background embedding worker has permanently stopped (embed-degraded).
    pub embed_worker_failed: bool,
    /// The embedding work mutex is currently held — an embed pass is in flight.
    pub embedding_work_busy: bool,
    pub embeddings_indexed: usize,
    pub embeddings_pending: usize,
    pub embeddings_total: usize,
    #[serde(default)]
    pub hybrid_metrics: HybridMetricsRuntime,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metal_profile: Option<MetalProfileRuntime>,
    /// Why the daemon did not install the vector index it found on disk when it
    /// opened, when it found one and did not. Without it, a repository that had
    /// full coverage yesterday reports partial coverage today with nothing to
    /// distinguish that from a first run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vector_index_discarded: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridMetricsRuntime {
    pub gpu_entities: u64,
    pub gpu_tokens: u64,
    pub cpu_twin_entities: u64,
    pub cpu_twin_tokens: u64,
    pub hybrid_batches: u64,
    pub single_side_batches: u64,
    pub twin_unavailable_batches: u64,
    pub cpu_parallel_batches: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetalProfileRuntime {
    pub submissions: u64,
    pub round_trips: u64,
    pub forward_calls: u64,
    pub host_blocked_nanos: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_blocked_nanos_per_forward: Option<u64>,
    pub gpu_phase_nanos: Vec<MetalPhaseRuntime>,
    pub gpu_total_nanos: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetalPhaseRuntime {
    pub phase: String,
    pub nanos: u64,
}

/// Actual host resource values observed at runtime, captured in the daemon
/// process so an inspector can compare what is really in use against the plan's
/// recommended (PLANNED) budgets. Capturing these is read-only observation: it
/// never configures a pool, sets an env var, or otherwise changes runtime
/// behavior, and it is sourced from host runtime APIs only (no kin-infer state).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActualResources {
    /// Size of the process-global Rayon thread pool actually in use.
    pub rayon_global_threads: usize,
    /// OS-visible parallelism (`std::thread::available_parallelism`); 0 if it
    /// could not be determined.
    pub available_parallelism: usize,
    /// Active `KIN_RESOURCE_PROFILE` env value, if set and non-empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_profile_env: Option<String>,
    /// Whether that value was selected by the kin binary at startup because the
    /// operator set nothing, rather than being an operator override. Both cases
    /// leave the same env value behind, so without this an inspector cannot
    /// tell a deliberate pin from the shipped default.
    #[serde(default)]
    pub resource_profile_product_selected: bool,
    /// Active `RAYON_NUM_THREADS` override, if set and non-empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rayon_num_threads_env: Option<String>,
    /// Active `TOKENIZERS_PARALLELISM` value, if set and non-empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokenizers_parallelism_env: Option<String>,
}

impl ActualResources {
    /// Capture the actual host resource state from the current process. Must be
    /// called from the daemon/runtime process so `rayon_global_threads` reflects
    /// the pool that actually runs ingest/embed work rather than a transient CLI
    /// process pool.
    pub fn capture() -> Self {
        ActualResources {
            rayon_global_threads: rayon::current_num_threads(),
            available_parallelism: std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(0),
            resource_profile_env: non_empty_env("KIN_RESOURCE_PROFILE"),
            resource_profile_product_selected: crate::resource_profile::product_selected(),
            rayon_num_threads_env: non_empty_env("RAYON_NUM_THREADS"),
            tokenizers_parallelism_env: non_empty_env("TOKENIZERS_PARALLELISM"),
        }
    }
}

/// Read an environment variable, returning `Some(trimmed)` only when it is set
/// and non-empty after trimming.
fn non_empty_env(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResourcesResponse {
    pub plan: ResourcePlan,
    pub embed_runtime: EmbedRuntimeState,
    #[serde(default)]
    pub actual: ActualResources,
    #[serde(default)]
    pub text: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json: Option<String>,
}

/// The `--json` surface: the stable `kin.resource_plan.v1` plan flattened to the
/// top level (so `schema_version` stays where every consumer expects it) with
/// the live daemon embedding state attached alongside.
#[derive(Serialize)]
struct ResourcesJson<'a> {
    #[serde(flatten)]
    plan: &'a ResourcePlan,
    embed_runtime: &'a EmbedRuntimeState,
    actual: &'a ActualResources,
}

/// Parse a CLI/request profile name. Absent input defaults to `Interactive`;
/// an unknown name is rejected rather than silently coerced.
pub fn parse_profile(raw: Option<&str>) -> Result<Profile, String> {
    match raw.map(str::trim) {
        None | Some("") => Ok(Profile::Interactive),
        Some(name) => match name.to_ascii_lowercase().as_str() {
            "proof" => Ok(Profile::Proof),
            "interactive" => Ok(Profile::Interactive),
            "throughput" => Ok(Profile::Throughput),
            "ci" => Ok(Profile::Ci),
            other => Err(format!(
                "unknown resource profile `{other}` (expected proof, interactive, throughput, or ci)"
            )),
        },
    }
}

fn profile_label(profile: Profile) -> &'static str {
    match profile {
        Profile::Proof => "proof",
        Profile::Interactive => "interactive",
        Profile::Throughput => "throughput",
        Profile::Ci => "ci",
    }
}

fn render_lines(
    plan: &ResourcePlan,
    embed: &EmbedRuntimeState,
    actual: &ActualResources,
) -> Vec<String> {
    let accel = format!("{:?}", plan.accelerator.backend).to_ascii_lowercase();
    let mut lines = vec![
        format!("Profile: {}", profile_label(plan.profile)),
        format!(
            "Host: {} ({} logical cores, {} rayon threads, {} reserved)",
            plan.host.arch,
            plan.host.logical_cores,
            plan.host.rayon_threads,
            plan.host.reserve_logical_cores
        ),
        format!(
            "Rayon pool: {} planned, {} actual global threads ({} cores available)",
            plan.host.rayon_threads, actual.rayon_global_threads, actual.available_parallelism
        ),
        format!(
            "Accelerator: {accel} (unified memory: {})",
            plan.accelerator.unified_memory
        ),
        format!(
            "Embedding: max_seq_len {}, max_batch_tokens {}, entities/chunk {}",
            plan.embedding.max_seq_len,
            plan.embedding.max_batch_tokens,
            plan.embedding.max_entities_per_graph_chunk
        ),
        format!(
            "Embed coverage: {}/{} indexed, {} pending",
            embed.embeddings_indexed, embed.embeddings_total, embed.embeddings_pending
        ),
        format!(
            "Embed worker: {}",
            if embed.embed_worker_failed {
                "failed (embed-degraded)"
            } else if embed.embedding_work_busy {
                "busy (pass in flight)"
            } else {
                "idle"
            }
        ),
    ];

    lines.push(profile_selector_line(actual));

    // The profile selector is reported on its own line above, with who chose it.
    // Listing it here too would read as an operator override even when the
    // binary selected it for itself.
    let overrides = [
        ("RAYON_NUM_THREADS", &actual.rayon_num_threads_env),
        ("TOKENIZERS_PARALLELISM", &actual.tokenizers_parallelism_env),
    ]
    .into_iter()
    .filter_map(|(key, value)| value.as_ref().map(|value| format!("{key}={value}")))
    .collect::<Vec<_>>();
    lines.push(format!(
        "Env overrides: {}",
        if overrides.is_empty() {
            "none".to_string()
        } else {
            overrides.join(", ")
        }
    ));

    lines
}

/// How the runtime got its resource profile, as the inspected process saw it.
///
/// The value and its origin are reported together because they answer different
/// questions: what is in effect, and whether anyone asked for it. A binary that
/// selected the default writes the same env value an operator would, so the
/// origin is the only thing that separates a deliberate pin from the ship
/// default.
fn profile_selector_line(actual: &ActualResources) -> String {
    match actual.resource_profile_env.as_deref() {
        Some(value) if actual.resource_profile_product_selected => {
            format!("Profile selector: KIN_RESOURCE_PROFILE={value} (selected by kin; unset in the environment)")
        }
        Some(value) => format!("Profile selector: KIN_RESOURCE_PROFILE={value} (set by operator)"),
        None => "Profile selector: KIN_RESOURCE_PROFILE unset".to_string(),
    }
}

/// Build the inspect response from a detected plan plus live daemon embedding
/// state. Kept free of daemon types so it is unit-testable on its own.
pub fn build_command_resources_response(
    plan: ResourcePlan,
    embed_runtime: EmbedRuntimeState,
    actual: ActualResources,
    json: bool,
) -> Result<CommandResourcesResponse> {
    let text = render_lines(&plan, &embed_runtime, &actual)
        .into_iter()
        .map(|line| format!("{line}\n"))
        .collect::<String>();
    let json = if json {
        Some(serde_json::to_string(&ResourcesJson {
            plan: &plan,
            embed_runtime: &embed_runtime,
            actual: &actual,
        })?)
    } else {
        None
    };
    Ok(CommandResourcesResponse {
        plan,
        embed_runtime,
        actual,
        text,
        json,
    })
}

/// Resolve an embedding batch size. An explicit override always wins; absent
/// one, the batch is `default_batch` unless `KIN_RESOURCE_PROFILE=throughput`,
/// in which case it follows the throughput resource plan (`throughput_batch`).
/// `throughput_batch` is only evaluated when that profile is active, so the
/// default and proof paths never touch resource detection.
pub fn resolve_embed_batch_size(
    explicit: Option<usize>,
    resource_profile: Option<&str>,
    default_batch: usize,
    throughput_batch: impl FnOnce() -> usize,
) -> usize {
    match explicit {
        Some(size) => size,
        None if resource_profile.map(str::trim) == Some("throughput") => throughput_batch(),
        None => default_batch,
    }
}

/// The throughput-profile embedding batch (entities per graph chunk), derived
/// from a freshly detected resource plan.
pub fn throughput_embed_batch_size() -> usize {
    ResourcePlan::detect(Profile::Throughput)
        .embedding
        .max_entities_per_graph_chunk
}

/// Whether the background embed worker should overlap a batch's persist with the
/// next batch's prep + GPU forward. Enabled only under the throughput profile;
/// the proof and default paths stay serial so the persisted vector order is
/// fully deterministic.
pub fn embed_pipeline_overlap_default(resource_profile: Option<&str>) -> bool {
    resource_profile.map(str::trim) == Some("throughput")
}

pub async fn run(json: bool, profile: Option<String>) -> Result<()> {
    let response = run_daemon_resources(&CommandResourcesRequest { json, profile }).await?;
    if json {
        if let Some(json) = response.json {
            println!("{json}");
        }
    } else {
        print!("{}", response.text);
    }
    Ok(())
}

async fn run_daemon_resources(
    request: &CommandResourcesRequest,
) -> Result<CommandResourcesResponse> {
    let layout = crate::commands::require_repository_layout()?;
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(&layout).await?);
    let base_url = daemon_url.ok_or_else(|| {
        anyhow::anyhow!(
            "Kin daemon is required for resource inspection but no daemon endpoint is available"
        )
    })?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    // Resource sizing reflects the daemon worker's captured environment; warn
    // loudly (or fail under KIN_STRICT_BEHAVIOR_ENV) if this command's
    // environment diverges from what that worker started with, so an inspector
    // is not misled about which levers are actually in effect.
    client.warn_on_behavior_env_divergence().await?;
    client
        .command_resources(request)
        .await
        .context("daemon resources failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_infer::resource::{AcceleratorBackend, AcceleratorInfo, HostInfo, MemoryInfo};

    fn sample_plan(profile: Profile) -> ResourcePlan {
        let host = HostInfo {
            arch: "aarch64".to_string(),
            logical_cores: 8,
            physical_cores: Some(8),
            performance_cores: None,
            efficiency_cores: None,
            rayon_threads: 8,
            reserve_logical_cores: 0,
            blas_threads: 1,
        };
        let accel = AcceleratorInfo {
            backend: AcceleratorBackend::Metal,
            device_index: 0,
            unified_memory: true,
            device_total_bytes: None,
            device_available_bytes: None,
            recommended_working_set_bytes: None,
            max_single_buffer_bytes: None,
            max_inflight_command_buffers: 1,
            reserve_device_bytes: None,
            allow_cpu_fallback: true,
        };
        let mem = MemoryInfo {
            system_total_bytes: None,
            system_available_bytes: None,
            max_process_rss_bytes: None,
            hot_graph_budget_bytes: None,
        };
        ResourcePlan::for_profile(profile, &host, &accel, &mem)
    }

    #[test]
    fn json_response_carries_schema_version_and_embed_state() {
        let embed = EmbedRuntimeState {
            embed_worker_failed: true,
            embedding_work_busy: true,
            embeddings_indexed: 3,
            embeddings_pending: 7,
            embeddings_total: 10,
            ..EmbedRuntimeState::default()
        };
        let actual = ActualResources {
            rayon_global_threads: 6,
            available_parallelism: 8,
            resource_profile_env: Some("throughput".to_string()),
            tokenizers_parallelism_env: Some("false".to_string()),
            ..ActualResources::default()
        };
        let response = build_command_resources_response(
            sample_plan(Profile::Interactive),
            embed,
            actual,
            true,
        )
        .unwrap();

        let value: serde_json::Value =
            serde_json::from_str(&response.json.expect("json requested")).unwrap();
        assert_eq!(value["schema_version"], "kin.resource_plan.v1");
        assert_eq!(value["profile"], "interactive");
        assert_eq!(value["embed_runtime"]["embed_worker_failed"], true);
        assert_eq!(value["embed_runtime"]["embedding_work_busy"], true);
        assert_eq!(value["embed_runtime"]["embeddings_indexed"], 3);
        assert_eq!(value["embed_runtime"]["embeddings_pending"], 7);
        assert_eq!(value["embed_runtime"]["embeddings_total"], 10);
        assert_eq!(value["embed_runtime"]["hybrid_metrics"]["gpu_entities"], 0);
        assert_eq!(value["actual"]["rayon_global_threads"], 6);
        assert_eq!(value["actual"]["available_parallelism"], 8);
        assert_eq!(value["actual"]["resource_profile_env"], "throughput");
        assert_eq!(value["actual"]["tokenizers_parallelism_env"], "false");
        // Unset env overrides are omitted from the JSON surface.
        assert!(value["actual"]["rayon_num_threads_env"].is_null());
    }

    #[test]
    fn json_response_carries_hybrid_metrics() {
        let embed = EmbedRuntimeState {
            hybrid_metrics: HybridMetricsRuntime {
                gpu_entities: 40,
                gpu_tokens: 20_000,
                cpu_twin_entities: 12,
                cpu_twin_tokens: 1_200,
                hybrid_batches: 3,
                single_side_batches: 2,
                twin_unavailable_batches: 1,
                cpu_parallel_batches: 4,
            },
            ..EmbedRuntimeState::default()
        };
        let response = build_command_resources_response(
            sample_plan(Profile::Throughput),
            embed,
            ActualResources::default(),
            true,
        )
        .unwrap();

        let value: serde_json::Value =
            serde_json::from_str(&response.json.expect("json requested")).unwrap();
        let metrics = &value["embed_runtime"]["hybrid_metrics"];
        assert_eq!(metrics["gpu_entities"], 40);
        assert_eq!(metrics["gpu_tokens"], 20_000);
        assert_eq!(metrics["cpu_twin_entities"], 12);
        assert_eq!(metrics["cpu_twin_tokens"], 1_200);
        assert_eq!(metrics["hybrid_batches"], 3);
        assert_eq!(metrics["single_side_batches"], 2);
        assert_eq!(metrics["twin_unavailable_batches"], 1);
        assert_eq!(metrics["cpu_parallel_batches"], 4);
    }

    #[test]
    fn json_response_carries_metal_profile_when_present() {
        let embed = EmbedRuntimeState {
            metal_profile: Some(MetalProfileRuntime {
                submissions: 120,
                round_trips: 4,
                forward_calls: 2,
                host_blocked_nanos: 900,
                host_blocked_nanos_per_forward: Some(450),
                gpu_phase_nanos: vec![MetalPhaseRuntime {
                    phase: "matmul".to_string(),
                    nanos: 700,
                }],
                gpu_total_nanos: 700,
            }),
            ..EmbedRuntimeState::default()
        };
        let response = build_command_resources_response(
            sample_plan(Profile::Throughput),
            embed,
            ActualResources::default(),
            true,
        )
        .unwrap();

        let value: serde_json::Value =
            serde_json::from_str(&response.json.expect("json requested")).unwrap();
        let profile = &value["embed_runtime"]["metal_profile"];
        assert_eq!(profile["submissions"], 120);
        assert_eq!(profile["round_trips"], 4);
        assert_eq!(profile["forward_calls"], 2);
        assert_eq!(profile["host_blocked_nanos"], 900);
        assert_eq!(profile["host_blocked_nanos_per_forward"], 450);
        assert_eq!(profile["gpu_total_nanos"], 700);
        assert_eq!(profile["gpu_phase_nanos"][0]["phase"], "matmul");
        assert_eq!(profile["gpu_phase_nanos"][0]["nanos"], 700);
    }

    #[test]
    fn human_text_omitted_json_when_not_requested() {
        let response = build_command_resources_response(
            sample_plan(Profile::Proof),
            EmbedRuntimeState::default(),
            ActualResources::default(),
            false,
        )
        .unwrap();
        assert!(response.json.is_none());
        assert!(response.text.contains("Profile: proof"));
        assert!(response.text.contains("Embed coverage:"));
    }

    #[test]
    fn human_text_reports_planned_vs_actual_and_env_overrides() {
        let actual = ActualResources {
            rayon_global_threads: 6,
            available_parallelism: 8,
            rayon_num_threads_env: Some("6".to_string()),
            tokenizers_parallelism_env: Some("false".to_string()),
            ..ActualResources::default()
        };
        let response = build_command_resources_response(
            sample_plan(Profile::Interactive),
            EmbedRuntimeState::default(),
            actual,
            false,
        )
        .unwrap();
        let planned = response.plan.host.rayon_threads;
        let expected =
            format!("Rayon pool: {planned} planned, 6 actual global threads (8 cores available)");
        assert!(
            response.text.contains(&expected),
            "missing planned-vs-actual line; text was:\n{}",
            response.text
        );
        assert!(response
            .text
            .contains("Env overrides: RAYON_NUM_THREADS=6, TOKENIZERS_PARALLELISM=false"));
    }

    #[test]
    fn human_text_reports_no_env_overrides_when_unset() {
        let response = build_command_resources_response(
            sample_plan(Profile::Interactive),
            EmbedRuntimeState::default(),
            ActualResources::default(),
            false,
        )
        .unwrap();
        assert!(response.text.contains("Env overrides: none"));
    }

    /// The selector line has to separate the two cases that leave the same env
    /// value behind: an operator who pinned a profile, and a binary that chose
    /// one because nobody did.
    #[test]
    fn profile_selector_names_who_chose_it() {
        let operator = ActualResources {
            resource_profile_env: Some("proof".to_string()),
            resource_profile_product_selected: false,
            ..ActualResources::default()
        };
        assert_eq!(
            profile_selector_line(&operator),
            "Profile selector: KIN_RESOURCE_PROFILE=proof (set by operator)"
        );

        let shipped = ActualResources {
            resource_profile_env: Some("interactive".to_string()),
            resource_profile_product_selected: true,
            ..ActualResources::default()
        };
        assert_eq!(
            profile_selector_line(&shipped),
            "Profile selector: KIN_RESOURCE_PROFILE=interactive \
             (selected by kin; unset in the environment)"
        );

        assert_eq!(
            profile_selector_line(&ActualResources::default()),
            "Profile selector: KIN_RESOURCE_PROFILE unset"
        );
    }

    /// A product-selected profile is not an operator override, so it must not
    /// be rendered in the override list — it has its own line.
    #[test]
    fn a_product_selected_profile_is_not_listed_as_an_override() {
        let actual = ActualResources {
            resource_profile_env: Some("interactive".to_string()),
            resource_profile_product_selected: true,
            ..ActualResources::default()
        };
        let response = build_command_resources_response(
            sample_plan(Profile::Interactive),
            EmbedRuntimeState::default(),
            actual,
            false,
        )
        .unwrap();
        assert!(response.text.contains("Env overrides: none"));
        assert!(response
            .text
            .contains("Profile selector: KIN_RESOURCE_PROFILE=interactive (selected by kin"));
    }

    #[test]
    fn parse_profile_defaults_to_interactive() {
        assert_eq!(parse_profile(None), Ok(Profile::Interactive));
        assert_eq!(parse_profile(Some("")), Ok(Profile::Interactive));
        assert_eq!(parse_profile(Some(" Throughput ")), Ok(Profile::Throughput));
        assert_eq!(parse_profile(Some("PROOF")), Ok(Profile::Proof));
        assert_eq!(parse_profile(Some("ci")), Ok(Profile::Ci));
        assert!(parse_profile(Some("nonsense")).is_err());
    }

    #[test]
    fn embed_batch_default_path_is_byte_identical() {
        // Daemon worker default (512) and CLI default (64) are unchanged when no
        // profile is set or the profile is anything other than throughput. The
        // throughput closure must never run on these paths.
        let never = || panic!("throughput batch evaluated off the throughput path");
        assert_eq!(resolve_embed_batch_size(None, None, 512, never), 512);
        assert_eq!(resolve_embed_batch_size(None, None, 64, never), 64);
        assert_eq!(
            resolve_embed_batch_size(None, Some("proof"), 512, never),
            512
        );
        assert_eq!(
            resolve_embed_batch_size(None, Some("interactive"), 64, never),
            64
        );
    }

    #[test]
    fn embed_batch_throughput_uses_plan_value() {
        assert_eq!(
            resolve_embed_batch_size(None, Some("throughput"), 512, || 999),
            999
        );
        assert_eq!(
            resolve_embed_batch_size(None, Some(" throughput "), 64, || 256),
            256
        );
    }

    #[test]
    fn embed_batch_explicit_override_always_wins() {
        let never = || panic!("explicit override must not consult the plan");
        assert_eq!(resolve_embed_batch_size(Some(7), None, 512, never), 7);
        assert_eq!(
            resolve_embed_batch_size(Some(7), Some("throughput"), 512, never),
            7
        );
    }

    #[test]
    fn embed_pipeline_overlap_only_under_throughput() {
        assert!(embed_pipeline_overlap_default(Some("throughput")));
        assert!(embed_pipeline_overlap_default(Some(" throughput ")));
        assert!(!embed_pipeline_overlap_default(None));
        assert!(!embed_pipeline_overlap_default(Some("proof")));
        assert!(!embed_pipeline_overlap_default(Some("interactive")));
        assert!(!embed_pipeline_overlap_default(Some("ci")));
    }
}
