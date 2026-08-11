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
    /// Whether this store's embedding coverage has ever been whole, as recorded
    /// by the daemon where the embedding queue drained. Partial coverage means
    /// something different before this has ever been true than after it.
    #[serde(default)]
    pub embedding_coverage_ever_complete: bool,
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

/// What one background pass the daemon runs on its own initiative is doing.
///
/// A user asking why the fan is on gets the answer from the product rather than
/// from Activity Monitor: which pass is working, how long it has been working,
/// and how long since it last recorded anything durable. Sourced entirely from
/// daemon-owned state and never recomputed here.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackgroundPassReport {
    /// Stable pass name, e.g. `embed` or `reconcile`.
    pub name: String,
    /// `idle`, `working`, `waiting_deferred`, or `stopped`.
    ///
    /// `waiting_deferred` is not idleness. It means the pass has nothing it may
    /// admit this instant because deferred work is waiting out a retry ladder,
    /// and it is reported separately because a ladder that never converges
    /// otherwise reads exactly like a pass with nothing to do.
    pub state: String,
    /// Units of work this pass has durably recorded since the daemon started.
    /// Monotonic, so a delta across two reads is meaningful.
    pub progress: u64,
    /// Seconds since `progress` last advanced; absent when it never has. A
    /// working pass whose progress age keeps climbing is the shape the daemon
    /// stops on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress_age_seconds: Option<u64>,
    /// Seconds this pass has been working without an idle stretch in between;
    /// absent while idle.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub working_seconds: Option<u64>,
    /// Seconds the pass has had deferred work owed to it without that queue
    /// draining; absent when nothing is deferred.
    ///
    /// Ages independently of `working_seconds`, which is the point: a retry
    /// ladder that keeps widening leaves the pass alternating between working
    /// and having nothing admittable, so neither of the other two clocks ever
    /// shows the livelock this one measures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deferred_seconds: Option<u64>,
    /// Why this pass was stopped, once it has been. A value drives
    /// `status: "attention"` on `/health`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stopped_reason: Option<String>,
}

/// What the daemon is spending on work nobody asked for interactively.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DaemonWorkState {
    /// Cumulative CPU seconds this daemon process has consumed. Absent before
    /// the supervisor's first sample, which is not the same as zero.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daemon_cpu_seconds: Option<f64>,
    /// Complete durable-authority loads this daemon has paid for.
    ///
    /// Belongs beside the CPU figure because it is the same kind of fact: what
    /// this process has spent. One load per publication rather than one per
    /// request is the property the authority cache exists to make true, and
    /// until now the only way to check it on a running daemon was
    /// `RUST_LOG=kin_daemon=debug`. A number that climbs with request volume
    /// instead of with publications says the reuse regressed.
    ///
    /// Absent when the daemon predates this field, which is not the same as a
    /// daemon that has loaded nothing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_loads: Option<u64>,
    /// Every background pass this daemon has actually started.
    #[serde(default)]
    pub passes: Vec<BackgroundPassReport>,
    /// What the reconciliation loop dropped, retried, and last failed at.
    #[serde(default)]
    pub reconcile: ReconcileHealth,
}

/// Consecutive complete-admission failures before the daemon stops calling
/// itself healthy.
///
/// Not one. A complete exact-tree admission that fails is deferred and retried
/// by design, and a file rewritten mid-pass fails one attempt and succeeds on
/// the next, so a single failure is the mechanism working. Three consecutive
/// failures is no longer a retry: every attempt since the loop last admitted
/// anything has failed, and whatever is rejecting them is not clearing on its
/// own.
pub const ADMISSION_FAILURE_STREAK_ATTENTION: u64 = 3;

/// How long a retained reconcile backlog may sit before it is called stale.
///
/// The loop drains a backlog in bounded batches and yields between them, so a
/// large burst legitimately takes minutes. Fifteen minutes of continuously
/// retained backlog is not a burst being worked off, it is a backlog that is
/// not draining.
pub const BACKLOG_STALE_SECONDS: u64 = 900;

/// What the filesystem reconciliation loop is actually managing to admit.
///
/// This exists because the loop's failures were invisible to every surface that
/// claimed to report daemon health. Admission can fail on every pass for days
/// while `reconciliation_status` reads `idle`, because `idle` describes whether
/// a pass is running right now and says nothing about whether the last one
/// worked. A degraded daemon reporting no issues is the failure this answers,
/// so each field here is a fault the loop already knew about and did not
/// publish.
///
/// Counters are cumulative for this daemon process and reset on restart. Ages
/// are monotonic and therefore unaffected by a wall-clock adjustment; the
/// paired timestamps are wall clock, for lining an incident up against a log.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconcileHealth {
    /// Reconcile events dropped after erroring. Each one leaves exactly one
    /// path's enrichment at whatever the last accepted pass admitted, and it
    /// stays there until that path changes again, so a non-zero count is stale
    /// graph truth rather than transient noise.
    #[serde(default)]
    pub skipped_events: u64,
    /// The most recent reconcile-event error, verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// Seconds since `last_error` was recorded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error_age_seconds: Option<u64>,
    /// Wall-clock time of `last_error`, RFC 3339.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error_at: Option<String>,
    /// Complete exact-tree admission attempts that have failed since the last
    /// one succeeded. This is the counter that would have named the failure on
    /// a store whose every admission pass had failed for two days.
    #[serde(default)]
    pub admission_failure_streak: u64,
    /// Every complete-admission failure this daemon has seen, streak or not.
    #[serde(default)]
    pub admission_failures: u64,
    /// The most recent complete-admission error, verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_admission_error: Option<String>,
    /// Seconds since a complete exact-tree admission last succeeded. Absent
    /// means none has succeeded in this daemon's life, which is not the same as
    /// zero and is only a fault when paired with failures.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_admission_success_age_seconds: Option<u64>,
    /// Wall-clock time of the last successful admission, RFC 3339.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_admission_success_at: Option<String>,
    /// Seconds the loop has held a non-empty backlog without ever clearing it.
    /// Absent when the backlog is empty.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backlog_age_seconds: Option<u64>,
    /// Host paths the most recent complete scan observed that repository
    /// authority does not track and no observation covered.
    ///
    /// Watching a working copy admits new non-ignored files into the workspace,
    /// so a path that stays untracked is one nothing observed arriving: the
    /// daemon was down when it appeared, or its notification never came. No
    /// later ambient tick picks it up on its own, which is exactly why it is
    /// reported rather than left for a reader to infer from the loop's source.
    #[serde(default)]
    pub untracked_path_count: u64,
    /// A bounded sample of `untracked_path_count`, so the notice names paths a
    /// reader can act on without a large working copy flooding the surface.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub untracked_paths_sample: Vec<String>,
    /// Untracked host entries the effective ignore rules excluded from the most
    /// recent walk.
    ///
    /// A count, never a list. An excluded directory is counted once and never
    /// descended into, so this stays small enough to read, and it is the only
    /// signal that separates "nothing has taken your file yet" from "the rules
    /// exclude it and nothing ever will".
    #[serde(default)]
    pub ignored_path_count: u64,
    /// Untracked host leaves outside Kin's regular-file and symbolic-link tree,
    /// which no admission can represent.
    #[serde(default)]
    pub unsupported_path_count: u64,
}

impl ReconcileHealth {
    /// Every reason this reconcile state is degraded, worst first, empty when
    /// it is not.
    ///
    /// One function so the three surfaces cannot disagree. `/health` turning
    /// `attention` while `kin graph status` prints no issues is the same defect
    /// as neither of them saying anything, and two independently written
    /// verdicts drift into exactly that.
    ///
    /// Each reason states its own threshold. An operator reading "3 consecutive
    /// failures" should not have to find the constant to know whether that is
    /// the limit or merely a number.
    pub fn degraded_reasons(&self) -> Vec<String> {
        let mut reasons = Vec::new();
        if self.admission_failure_streak >= ADMISSION_FAILURE_STREAK_ATTENTION {
            let since = match self.last_admission_success_age_seconds {
                Some(age) => format!("last succeeded {age}s ago"),
                None => "none has ever succeeded in this daemon's life".to_string(),
            };
            let error = self
                .last_admission_error
                .as_deref()
                .unwrap_or("no error recorded");
            reasons.push(format!(
                "complete exact-tree admission has failed {} consecutive times (attention at \
                 {ADMISSION_FAILURE_STREAK_ATTENTION}); {since}; last error: {error}",
                self.admission_failure_streak
            ));
        }
        if self.skipped_events > 0 {
            let error = self.last_error.as_deref().unwrap_or("no error recorded");
            let age = match self.last_error_age_seconds {
                Some(age) => format!("{age}s ago"),
                None => "at an unrecorded time".to_string(),
            };
            reasons.push(format!(
                "{} reconcile event(s) errored and were dropped, leaving those paths' enrichment \
                 stale; most recent {age}: {error}",
                self.skipped_events
            ));
        }
        if let Some(age) = self.backlog_age_seconds {
            if age >= BACKLOG_STALE_SECONDS {
                reasons.push(format!(
                    "the reconcile backlog has been retained for {age}s without clearing \
                     (attention at {BACKLOG_STALE_SECONDS})"
                ));
            }
        }
        reasons
    }

    /// Whether this reconcile state should stop any surface from reporting a
    /// healthy daemon.
    pub fn degraded(&self) -> bool {
        !self.degraded_reasons().is_empty()
    }

    /// What the loop is deliberately not doing, stated so no surface has to
    /// leave it unexplained.
    ///
    /// Separate from [`Self::degraded_reasons`] on purpose. Untracked host
    /// content is the ordinary state of a working copy mid-edit, so calling it a
    /// fault would put every healthy repository into `attention` and teach every
    /// reader to ignore the field. It still has to be said: a path the loop
    /// declines to admit is a path whose entities never appear, and silence
    /// there is what made a deliberate refusal look like a stuck daemon.
    ///
    /// The two notices answer the same reader's question from opposite sides. A
    /// file that is missing because nothing observed it arriving is recoverable
    /// and gets named outright; a file that is missing because the rules exclude
    /// it is not, and the count is what tells the reader to go and read the
    /// rules instead of waiting.
    pub fn notices(&self) -> Vec<String> {
        let mut notices = Vec::new();
        if self.untracked_path_count > 0 {
            let sample = if self.untracked_paths_sample.is_empty() {
                String::new()
            } else {
                let more = self
                    .untracked_path_count
                    .saturating_sub(self.untracked_paths_sample.len() as u64);
                let listed = self.untracked_paths_sample.join(", ");
                if more > 0 {
                    format!(": {listed}, and {more} more")
                } else {
                    format!(": {listed}")
                }
            };
            notices.push(format!(
                "{} host path(s) observed but not tracked{sample}. Watching a working copy admits \
                 new non-ignored files, so nothing observed these arriving and no later tick picks \
                 them up on its own; kin admit takes them now, and the next commit takes them \
                 anyway.",
                self.untracked_path_count
            ));
        }
        if self.ignored_path_count > 0 || self.unsupported_path_count > 0 {
            let mut excluded = Vec::new();
            if self.ignored_path_count > 0 {
                excluded.push(format!(
                    "{} excluded by the ignore rules",
                    self.ignored_path_count
                ));
            }
            if self.unsupported_path_count > 0 {
                excluded.push(format!(
                    "{} outside Kin's file and symbolic-link tree",
                    self.unsupported_path_count
                ));
            }
            notices.push(format!(
                "The last complete walk left host content unobserved: {}. Nothing admits these, so \
                 a file missing from here is missing on purpose; check .kinignore before waiting \
                 on it.",
                excluded.join(", ")
            ));
        }
        notices
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResourcesResponse {
    pub plan: ResourcePlan,
    pub embed_runtime: EmbedRuntimeState,
    #[serde(default)]
    pub actual: ActualResources,
    #[serde(default)]
    pub daemon_work: DaemonWorkState,
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
    daemon_work: &'a DaemonWorkState,
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

/// One line per background pass, plus the daemon's cumulative CPU.
///
/// Rendered even when every pass is healthy. The question this answers — what is
/// this process spending my machine on — is one a user asks while nothing is
/// visibly wrong, so a surface that only appears on a fault does not answer it.
fn render_daemon_work_lines(work: &DaemonWorkState) -> Vec<String> {
    let mut lines = vec![format!(
        "Daemon CPU: {}",
        match work.daemon_cpu_seconds {
            Some(seconds) => format!("{seconds:.1}s cumulative"),
            None => "not sampled yet".to_string(),
        }
    )];
    // Rendered next to CPU because it is the other half of the same question.
    // CPU says how much was spent; this says how much of it was spent opening
    // durable authority, which is the one repeated cost the daemon caches away
    // and the one a regression puts straight back.
    if let Some(loads) = work.authority_loads {
        lines.push(format!(
            "Authority loads: {loads} (climbs with publications, not with requests)"
        ));
    }
    lines.extend(render_reconcile_lines(&work.reconcile));
    if work.passes.is_empty() {
        lines.push("Background passes: none started".to_string());
        return lines;
    }
    for pass in &work.passes {
        let detail = match (&pass.stopped_reason, pass.working_seconds) {
            (Some(reason), _) => format!("stopped — {reason}"),
            (None, Some(working)) => format!("working {working}s"),
            (None, None) => "idle".to_string(),
        };
        let progress_age = match pass.progress_age_seconds {
            Some(age) => format!("last advanced {age}s ago"),
            None => "no progress yet".to_string(),
        };
        lines.push(format!(
            "Background pass {}: {detail}, {} units, {progress_age}",
            pass.name, pass.progress
        ));
    }
    lines
}

/// The reconcile loop's own account of itself.
///
/// Rendered whether or not it is degraded, for the same reason the pass lines
/// are: a counter that only appears once it is non-zero cannot be checked
/// against, and its absence reads identically to a surface that was never
/// wired up.
fn render_reconcile_lines(reconcile: &ReconcileHealth) -> Vec<String> {
    let admission = match reconcile.last_admission_success_age_seconds {
        Some(age) => format!("last admitted {age}s ago"),
        None => "never admitted in this daemon's life".to_string(),
    };
    let backlog = match reconcile.backlog_age_seconds {
        Some(age) => format!("backlog retained {age}s"),
        None => "no backlog".to_string(),
    };
    let mut lines = vec![format!(
        "Reconcile: {admission}, {} consecutive admission failure(s), {} dropped event(s), \
         {backlog}",
        reconcile.admission_failure_streak, reconcile.skipped_events
    )];
    for reason in reconcile.degraded_reasons() {
        lines.push(format!("Reconcile degraded: {reason}"));
    }
    lines
}

fn render_lines(
    plan: &ResourcePlan,
    embed: &EmbedRuntimeState,
    actual: &ActualResources,
    daemon_work: &DaemonWorkState,
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
    lines.extend(render_daemon_work_lines(daemon_work));

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
    daemon_work: DaemonWorkState,
    json: bool,
) -> Result<CommandResourcesResponse> {
    let text = render_lines(&plan, &embed_runtime, &actual, &daemon_work)
        .into_iter()
        .map(|line| format!("{line}\n"))
        .collect::<String>();
    let json = if json {
        Some(serde_json::to_string(&ResourcesJson {
            plan: &plan,
            embed_runtime: &embed_runtime,
            actual: &actual,
            daemon_work: &daemon_work,
        })?)
    } else {
        None
    };
    Ok(CommandResourcesResponse {
        plan,
        embed_runtime,
        actual,
        daemon_work,
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
        crate::daemon_client::daemon_required_error("resource inspection", &layout)
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

    /// The counter is rendered when the daemon reports one and omitted when it
    /// does not, rather than shown as a zero.
    ///
    /// Both directions, because a renderer that always printed the line and one
    /// A store failing every admission pass, planted at the exact shape the
    /// umbrella store carried for two days.
    fn failing_admission() -> ReconcileHealth {
        ReconcileHealth {
            admission_failure_streak: 412,
            admission_failures: 412,
            last_admission_error: Some("scan exceeded its budget".to_string()),
            last_admission_success_age_seconds: Some(172_800),
            last_admission_success_at: Some("2026-08-06T09:00:00+00:00".to_string()),
            ..Default::default()
        }
    }

    /// Untracked host content is announced and is not a fault.
    ///
    /// Both halves matter. Without the notice, a file a reader can see on disk
    /// has no entities and no surface says why, which is the question FIR-2152
    /// arrived as. Without the second assertion, every working copy mid-edit
    /// would report `attention`, and a health signal that is always on is one
    /// nobody reads.
    #[test]
    fn untracked_paths_are_announced_without_degrading_the_daemon() {
        let health = ReconcileHealth {
            untracked_path_count: 7,
            untracked_paths_sample: vec!["src/new.rs".to_string(), "notes.md".to_string()],
            ..Default::default()
        };
        assert!(!health.degraded(), "{:?}", health.degraded_reasons());
        let notices = health.notices();
        assert_eq!(notices.len(), 1, "{notices:?}");
        let notice = &notices[0];
        assert!(notice.contains('7'), "the count is the headline: {notice}");
        assert!(
            notice.contains("src/new.rs") && notice.contains("notes.md"),
            "the sample must name paths a reader can act on: {notice}"
        );
        assert!(
            notice.contains("5 more"),
            "a sample that hid the remainder would understate it: {notice}"
        );

        assert!(
            ReconcileHealth::default().notices().is_empty(),
            "a working copy with nothing untracked says nothing"
        );
    }

    /// Excluded content is announced as a count and never as a list.
    ///
    /// It answers a different question from the untracked notice. A path nothing
    /// observed is recoverable and gets named; a path the rules exclude is not
    /// coming however long anyone waits, and the only useful answer is how much
    /// is being left out and where the decision lives. Listing it instead would
    /// put every derived file in the working copy on a surface whose job is to
    /// name the one file a reader is looking for.
    #[test]
    fn excluded_host_content_is_announced_as_a_count_without_degrading_the_daemon() {
        let health = ReconcileHealth {
            ignored_path_count: 3,
            unsupported_path_count: 1,
            ..Default::default()
        };
        assert!(!health.degraded(), "{:?}", health.degraded_reasons());
        let notices = health.notices();
        assert_eq!(notices.len(), 1, "{notices:?}");
        let notice = &notices[0];
        assert!(
            notice.contains('3') && notice.contains("ignore rules"),
            "the excluded count and its cause must both be named: {notice}"
        );
        assert!(
            notice.contains('1') && notice.contains("symbolic-link"),
            "content Kin cannot represent is a separate cause: {notice}"
        );
        assert!(
            notice.contains(".kinignore"),
            "the reader needs the file that decides this: {notice}"
        );

        // The two notices are independent: a repository can be missing a file
        // for either reason, and a reader gets whichever answer is true.
        let both = ReconcileHealth {
            untracked_path_count: 1,
            untracked_paths_sample: vec!["src/new.rs".to_string()],
            ignored_path_count: 2,
            ..Default::default()
        };
        assert_eq!(both.notices().len(), 2, "{:?}", both.notices());
    }

    #[test]
    fn a_failing_admission_streak_is_a_degraded_reason_that_names_its_threshold() {
        let reasons = failing_admission().degraded_reasons();
        assert_eq!(reasons.len(), 1, "one fault, one reason: {reasons:?}");
        let reason = &reasons[0];
        assert!(reason.contains("412"), "the streak must be named: {reason}");
        assert!(
            reason.contains(&ADMISSION_FAILURE_STREAK_ATTENTION.to_string()),
            "an operator must not have to find the constant: {reason}"
        );
        assert!(
            reason.contains("172800"),
            "how long since anything was admitted is the point: {reason}"
        );
        assert!(
            reason.contains("scan exceeded its budget"),
            "the daemon's own error, not a summary invented here: {reason}"
        );
    }

    /// The falsification. Same shape, one below the threshold, and the verdict
    /// has to flip. A check that fired on any failure at all would pass the test
    /// above while being useless, because a single deferred admission is the
    /// retry mechanism working as designed.
    #[test]
    fn a_streak_below_the_threshold_is_not_degraded() {
        let below = ReconcileHealth {
            admission_failure_streak: ADMISSION_FAILURE_STREAK_ATTENTION - 1,
            admission_failures: ADMISSION_FAILURE_STREAK_ATTENTION - 1,
            last_admission_error: Some("file changed during admission".to_string()),
            last_admission_success_age_seconds: Some(30),
            ..Default::default()
        };
        assert!(
            !below.degraded(),
            "a retry in progress is the mechanism working: {:?}",
            below.degraded_reasons()
        );

        let at_threshold = ReconcileHealth {
            admission_failure_streak: ADMISSION_FAILURE_STREAK_ATTENTION,
            ..below
        };
        assert!(
            at_threshold.degraded(),
            "one more consecutive failure crosses it"
        );
    }

    #[test]
    fn a_dropped_reconcile_event_degrades_and_carries_its_error() {
        let dropped = ReconcileHealth {
            skipped_events: 3,
            last_error: Some("src/lib.rs: parser rejected the transaction".to_string()),
            last_error_age_seconds: Some(45),
            ..Default::default()
        };
        let reasons = dropped.degraded_reasons();
        assert_eq!(reasons.len(), 1, "{reasons:?}");
        assert!(reasons[0].contains("3 reconcile event(s)"), "{reasons:?}");
        assert!(reasons[0].contains("src/lib.rs"), "{reasons:?}");
        assert!(
            reasons[0].contains("stale"),
            "the consequence is what makes the count worth reading: {reasons:?}"
        );
    }

    #[test]
    fn a_backlog_degrades_only_once_it_has_stopped_draining() {
        let draining = ReconcileHealth {
            backlog_age_seconds: Some(BACKLOG_STALE_SECONDS - 1),
            ..Default::default()
        };
        assert!(
            !draining.degraded(),
            "a burst being worked off is not a fault: {:?}",
            draining.degraded_reasons()
        );

        let stuck = ReconcileHealth {
            backlog_age_seconds: Some(BACKLOG_STALE_SECONDS),
            ..Default::default()
        };
        assert!(stuck.degraded());
        assert!(stuck.degraded_reasons()[0].contains(&BACKLOG_STALE_SECONDS.to_string()));
    }

    /// The reconcile line is rendered whether or not anything is wrong. A
    /// counter that appears only on a fault cannot be checked against, and its
    /// absence reads exactly like a surface nobody wired up.
    #[test]
    fn the_reconcile_line_is_rendered_on_a_healthy_daemon_too() {
        let healthy = render_reconcile_lines(&ReconcileHealth {
            last_admission_success_age_seconds: Some(4),
            ..Default::default()
        });
        assert_eq!(
            healthy.len(),
            1,
            "no degradation, no extra lines: {healthy:?}"
        );
        assert!(healthy[0].contains("last admitted 4s ago"), "{healthy:?}");
        assert!(
            healthy[0].contains("0 consecutive admission failure(s)"),
            "{healthy:?}"
        );
        assert!(healthy[0].contains("no backlog"), "{healthy:?}");

        let degraded = render_reconcile_lines(&failing_admission());
        assert!(
            degraded
                .iter()
                .any(|line| line.contains("Reconcile degraded")),
            "the fault has to reach the text surface: {degraded:?}"
        );
    }

    /// A daemon that has never admitted anything says so rather than reporting a
    /// zero-second age. The two are different facts and a fresh daemon is not a
    /// daemon that admitted something a moment ago.
    #[test]
    fn a_daemon_that_has_never_admitted_says_so_rather_than_reporting_zero() {
        let lines = render_reconcile_lines(&ReconcileHealth::default());
        assert!(
            lines[0].contains("never admitted in this daemon's life"),
            "{lines:?}"
        );
        assert!(!lines[0].contains("last admitted 0s ago"), "{lines:?}");
    }

    /// that never did would each pass a single-sided test. Zero is a real
    /// answer here — a daemon that has served everything from cache — and it
    /// has to be distinguishable from a daemon too old to have the field.
    #[test]
    fn authority_loads_render_only_when_the_daemon_reports_them() {
        let present = render_daemon_work_lines(&DaemonWorkState {
            daemon_cpu_seconds: Some(12.0),
            authority_loads: Some(3),
            passes: Vec::new(),
            reconcile: Default::default(),
        });
        assert!(
            present
                .iter()
                .any(|line| line.contains("Authority loads: 3")),
            "a reported count must reach the text surface: {present:?}"
        );

        let zero = render_daemon_work_lines(&DaemonWorkState {
            daemon_cpu_seconds: Some(12.0),
            authority_loads: Some(0),
            passes: Vec::new(),
            reconcile: Default::default(),
        });
        assert!(
            zero.iter().any(|line| line.contains("Authority loads: 0")),
            "zero loads is an answer, not an absence: {zero:?}"
        );

        let absent = render_daemon_work_lines(&DaemonWorkState {
            daemon_cpu_seconds: Some(12.0),
            authority_loads: None,
            passes: Vec::new(),
            reconcile: Default::default(),
        });
        assert!(
            !absent.iter().any(|line| line.contains("Authority loads")),
            "a daemon that reports no count must not have one invented: {absent:?}"
        );
    }

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
            DaemonWorkState::default(),
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
            DaemonWorkState::default(),
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
            DaemonWorkState::default(),
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
            DaemonWorkState::default(),
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
            DaemonWorkState::default(),
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
            DaemonWorkState::default(),
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
            DaemonWorkState::default(),
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
