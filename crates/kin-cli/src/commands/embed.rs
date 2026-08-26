// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Default embed command batch.
///
/// The embedder already groups individual texts by token budget inside each
/// queue pass, but the outer batch controls how many graph objects are drained,
/// formatted, tokenized, and held before progress is persisted. Very large
/// outer batches can look like a hang and delay vector sidecar creation on
/// fresh prepared-state builds. Keep the default conservative; callers can
/// still raise it explicitly for tuned hardware runs.
pub const DEFAULT_BATCH_SIZE: usize = 64;

fn default_cap_batch_size() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbedRequest {
    pub batch_size: usize,
    #[serde(default)]
    pub json: bool,
    #[serde(default)]
    pub max_seconds: Option<u64>,
    /// Drop the existing vector index and rebuild it at the current model's
    /// dimension. Required to migrate a repo whose persisted index was built at
    /// a different embedding dimension (e.g. an older 384-dim model). Defaults
    /// to false so a normal embed pass is unchanged and the field is optional on
    /// the daemon wire protocol.
    #[serde(default)]
    pub rebuild: bool,
    /// Keep user-specified bounded passes conservative: the daemon only checks
    /// `max_seconds` between batches, so a very large batch can overrun the
    /// requested timebox. The CLI's internal drive-to-completion loop already
    /// owns retry/progress semantics and disables this cap so throughput-profile
    /// resource planning is not silently forced back to the default batch size.
    #[serde(default = "default_cap_batch_size")]
    pub cap_batch_size: bool,
}

/// The store's own embedding coverage either side of one embed pass, sampled by
/// the daemon that ran it.
///
/// A pass reports how much IT embedded. That number and the store's coverage
/// are different facts, and a pass that arrives after the queue is already
/// drained holds a zero for the first while the second reads whole. Printed
/// under one heading the two are indistinguishable, which is the state a user
/// runs `kin embed` to tell apart.
///
/// Both samples are taken inside `build_embed_response`, which runs holding
/// `DaemonState::embedding_work`. That mutex serializes explicit `/embed`
/// requests against the background embedding worker, so the worker cannot move
/// coverage between the two reads: `indexed_before` is exactly the state this
/// pass inherited and `indexed_after` is exactly the state it left.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassCoverage {
    /// Retrievable objects already in the vector index when the pass started,
    /// before it propagated, queued or embedded anything.
    pub indexed_before: usize,
    /// Retrievable objects in the vector index when the pass returned.
    pub indexed_after: usize,
    /// Retrievable objects that require an embedding, as the pass last read it.
    pub total: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbedResult {
    pub total_entities: usize,
    pub embedded_entities: usize,
    pub pending_entities: usize,
    pub total_artifacts: usize,
    pub embedded_artifacts: usize,
    pub pending_artifacts: usize,
    pub time_limited: bool,
    pub vector_index_path: String,
    /// The store's coverage either side of this pass, or `None` from a daemon
    /// that does not report it.
    ///
    /// Optional rather than defaulted to zeros on purpose: a daemon that never
    /// measured coverage and a store holding nothing both deserialize to the
    /// same three zeros, and a summary line built from those would state a
    /// measurement nobody took. `None` renders no coverage claim at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coverage: Option<PassCoverage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmbedResponse {
    pub result: EmbedResult,
    #[serde(default)]
    pub lines: Vec<String>,
}

/// The completion line for a run that ended with nothing pending.
///
/// The line this replaces was `Done. Full coverage: {embedded} entities,
/// {embedded} artifacts embedded ...`, which put the run's own pass counter
/// under a heading about the store. On the shipped v0.5.45 bytes a stranger ran
/// it on a store whose coverage went from 3 of 51 to 51 of 51 across the call
/// and read `Done. Full coverage: 0 entities, 0 artifacts embedded`. Both
/// numbers were true and the sentence was unreadable: a run that found an empty
/// queue and a run that silently failed to embed produce the same zero, and
/// those are the two states the command is run to tell apart.
///
/// So the run's own work and the store's coverage are named as two facts, and
/// which sentence a zero gets is decided by `coverage`, which the daemon
/// measured, rather than by an assumption about who filled the store. This
/// process cannot observe that: a store already whole at entry may have been
/// filled by the background worker, by `kin init`, or by an earlier explicit
/// pass, and nothing reaching here distinguishes them. What it can say, and
/// does, is that the work was finished before this pass started.
///
/// `None` coverage comes from a daemon that does not report it. That arm states
/// the run's own work and makes no claim about the store, because a claim built
/// from numbers nobody sampled is the defect this function exists to remove.
fn embed_completion_line(
    embedded_entities: usize,
    embedded_artifacts: usize,
    passes: usize,
    rate: f64,
    coverage: Option<PassCoverage>,
) -> String {
    let embedded = embedded_entities + embedded_artifacts;
    let Some(coverage) = coverage else {
        return format!(
            "Done. This run embedded {embedded_entities} entities and {embedded_artifacts} \
             artifacts across {passes} pass(es) at {rate:.2} ent/s, and the daemon reports \
             nothing pending. This daemon does not report the store's coverage, so no claim \
             about it is made here"
        );
    };
    let PassCoverage {
        indexed_before,
        indexed_after,
        total,
    } = coverage;
    if total == 0 {
        return "Done. This repository has no retrievable graph objects that require an \
                embedding, so there was nothing to embed"
            .to_string();
    }
    if embedded > 0 {
        return format!(
            "Done. This run embedded {embedded_entities} entities and {embedded_artifacts} \
             artifacts across {passes} pass(es) at {rate:.2} ent/s, taking this store from \
             {indexed_before}/{total} to {indexed_after}/{total} indexed"
        );
    }
    if indexed_before >= total {
        return format!(
            "Done. Nothing to embed: this store was already fully covered at {indexed_before}/\
             {total} indexed when this pass started, so the work was finished before it ran"
        );
    }
    if indexed_after > indexed_before {
        // Coverage moved while the pass held the embedding lock and its queue
        // embedded nothing, which is `propagate_revision_vectors` reusing
        // vectors from fingerprint-identical revisions. That IS this pass's
        // work; crediting it to an absent worker would be the same error the
        // old line made, pointed the other way.
        return format!(
            "Done. This run embedded nothing through the queue and still took this store from \
             {indexed_before}/{total} to {indexed_after}/{total} indexed, by reusing vectors \
             from content-identical revisions"
        );
    }
    // Nothing pending, nothing embedded, and coverage below total: the queue
    // and the coverage counters disagree about what is left. Report both rather
    // than picking one, since neither is established here.
    format!(
        "Done. This run embedded nothing and the daemon reports nothing pending, but this store \
         reads {indexed_after}/{total} indexed. Run `kin health` to see why coverage and the \
         queue disagree"
    )
}

/// Decide whether the embed loop should enqueue missing retrievable objects.
///
/// Reopened graphs may have a stale or partially useful queue while the vector
/// sidecar is missing revision/artifact keys. Coverage, not raw queue length,
/// is the authority for whether `kin embed` has backfill work to enqueue.
fn should_queue_missing_embedding_pass(indexed: usize, total: usize) -> bool {
    indexed < total
}

fn effective_batch_size(requested: usize, bounded: bool) -> usize {
    let requested = requested.max(1);
    if bounded {
        requested.min(DEFAULT_BATCH_SIZE)
    } else {
        requested
    }
}

/// Default per-pass time budget (seconds) for the drive-to-completion loop used
/// when `kin embed` runs with no explicit `--max-seconds`. Each pass returns
/// well inside the CLI→daemon HTTP timeout, so a pass never has to be severed
/// mid-flight (a severed pass orphans the server-side work behind the embedding
/// lock and makes retries stack). Overridable via `KIN_EMBED_PASS_SECONDS`.
pub const DEFAULT_PASS_SECONDS: u64 = 300;

/// Safety ceiling on drive-to-completion passes so a pathological daemon cannot
/// loop forever even if it keeps reporting a sliver of progress. At the default
/// pass budget this is far above any real corpus. Overridable via
/// `KIN_EMBED_MAX_PASSES`.
pub const DEFAULT_MAX_PASSES: usize = 1000;

fn pass_budget_seconds() -> u64 {
    std::env::var("KIN_EMBED_PASS_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|s| *s > 0)
        .unwrap_or(DEFAULT_PASS_SECONDS)
}

fn max_passes() -> usize {
    std::env::var("KIN_EMBED_MAX_PASSES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .filter(|n| *n > 0)
        .unwrap_or(DEFAULT_MAX_PASSES)
}

/// Default total wall-clock budget (seconds) for one `kin embed` invocation on
/// a constrained resource profile. Instead of driving to full coverage — which
/// extrapolates to hours on a 2–4 core CPU box — a constrained profile makes
/// progress up to this budget and leaves the remainder pending for the next
/// `kin embed` (each pass persists, so coverage resumes). Overridable via
/// `KIN_EMBED_MAX_TOTAL_SECONDS`; not applied on unconstrained profiles.
pub const DEFAULT_CONSTRAINED_TOTAL_SECONDS: u64 = 600;

/// Total wall-clock budget for the drive-to-completion loop, or `None` to drive
/// to full coverage. A constrained resource profile (`interactive` / `small` —
/// the small-machine selectors) auto-bounds so `kin embed` returns a resumable
/// partial index rather than looping for hours; `KIN_EMBED_MAX_TOTAL_SECONDS`
/// overrides the value explicitly on any profile.
fn constrained_total_budget_seconds() -> Option<u64> {
    let override_secs = std::env::var("KIN_EMBED_MAX_TOTAL_SECONDS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok());
    let profile = std::env::var("KIN_RESOURCE_PROFILE").unwrap_or_default();
    resolve_total_budget(
        override_secs,
        &profile,
        !crate::resource_profile::product_selected(),
    )
}

/// Pure budget resolution: an explicit positive override wins on any profile;
/// otherwise a constrained profile gets the default budget and everything else
/// gets `None` (drive to full coverage).
///
/// `profile_chosen_by_operator` is what keeps the cap meaning what it has always
/// meant. `interactive` is read here as a claim about the HOST — "this is a
/// small machine, bound the pass" — which only an operator can make. The kin
/// binaries now select `interactive` themselves when nothing is set, and that
/// selection says nothing about the machine, so it must not start bounding
/// every embed on every box. An explicit `KIN_EMBED_MAX_TOTAL_SECONDS` still
/// bounds the pass either way.
fn resolve_total_budget(
    override_secs: Option<u64>,
    profile: &str,
    profile_chosen_by_operator: bool,
) -> Option<u64> {
    if let Some(secs) = override_secs.filter(|s| *s > 0) {
        return Some(secs);
    }
    if !profile_chosen_by_operator {
        return None;
    }
    match profile.trim().to_ascii_lowercase().as_str() {
        "interactive" | "small" => Some(DEFAULT_CONSTRAINED_TOTAL_SECONDS),
        _ => None,
    }
}

/// Embedding throughput (objects per second), or `0.0` before any wall time has
/// elapsed. "Objects" counts entities + artifacts, the unit of embedding work.
fn throughput_per_sec(embedded: usize, elapsed_secs: f64) -> f64 {
    if elapsed_secs > 0.0 {
        embedded as f64 / elapsed_secs
    } else {
        0.0
    }
}

/// A `, ETA <human>` suffix for a progress line, or empty when the rate is not
/// yet known (no throughput) or nothing is left to embed.
fn eta_suffix(rate_per_sec: f64, pending: usize) -> String {
    if rate_per_sec <= 0.0 || pending == 0 {
        return String::new();
    }
    let secs = (pending as f64 / rate_per_sec).ceil() as u64;
    format!(", ETA {}", format_duration_secs(secs))
}

/// Compact hours/minutes/seconds formatting for ETA display.
fn format_duration_secs(total: u64) -> String {
    let (h, m, s) = (total / 3600, (total % 3600) / 60, total % 60);
    if h > 0 {
        format!("{h}h{m:02}m")
    } else if m > 0 {
        format!("{m}m{s:02}s")
    } else {
        format!("{s}s")
    }
}

/// The embedding model `kin embed` downloads on first use. Named once, in the
/// module that also owns where the download lands and how far along it is.
const EMBED_MODEL_ID: &str = crate::embed_model::DEFAULT_EMBED_MODEL_ID;

/// What that download costs, as the model host reports it. Carried as the
/// published figure rather than as a byte count, so the number a caller sees is
/// the one they will see again when the download runs.
const EMBED_MODEL_DOWNLOAD: &str = "522 MB";

/// The smallest memory ceiling a vector embed has been measured to complete a
/// real repository under. At 1 GiB a tiny repository finishes exactly at the
/// cap and a 512 MiB cgroup gets the daemon OOM-killed; 2 GiB peaks around
/// 1.5 GiB, which is why that is the number the guidance names.
const RECOMMENDED_EMBED_MEMORY_BYTES: u64 = 2 * 1024 * 1024 * 1024;

/// Phrases an established connection renders with when it breaks partway, as
/// distinct from a refusal the daemon stayed alive to answer with.
///
/// Every entry describes a connection that existed and then broke, which is the
/// only failure shape a process killed mid-request can produce. The HTTP
/// client's generic send-failure wrapper is deliberately not here: it also
/// covers a connection that was refused outright, and a daemon that never
/// accepted the request was not lost during this pass, whatever the machine's
/// memory says. An HTTP status the daemon returned reaches the caller as
/// `kin embed refused (HTTP ...)` and matches nothing here either, and neither
/// does a client-side timeout, so each keeps its own diagnosis.
const LOST_CONNECTION_MARKERS: &[&str] = &[
    "connection closed before message completed",
    "connection reset by peer",
    "connection closed",
    "broken pipe",
    "IncompleteMessage",
    "channel closed",
];

fn lost_the_daemon_mid_request(rendered: &str) -> bool {
    LOST_CONNECTION_MARKERS
        .iter()
        .any(|marker| rendered.contains(marker))
}

fn human_bytes(bytes: u64) -> String {
    const GIB: u64 = 1024 * 1024 * 1024;
    const MIB: u64 = 1024 * 1024;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else {
        format!("{} MiB", bytes / MIB)
    }
}

/// Guidance for an embed that lost the daemon under memory pressure, or `None`
/// when this cannot honestly attribute the failure to memory.
///
/// The failure the ticket describes reaches the caller as a bare transport
/// error: the daemon is OOM-killed mid-pass, the connection drops, and the CLI
/// reports a closed connection while the cgroup records `oom_kill 1`. Nothing
/// in that message names memory, the model that needs it, or the fact that
/// lexical and graph retrieval never did.
///
/// Three grades are produced and they are labelled differently on purpose, in
/// descending order of how much the machine actually proved.
///
/// A kill the cgroup recorded WHILE THIS PASS RAN is the kernel's own statement
/// about this pass and is reported as observed. That window is the fix for
/// FIR-1823: the counter is cumulative for the container's whole life, so the
/// same number also counts a kill from an unrelated run an hour ago, and
/// reading it without a baseline reported those as this embed's cause. The
/// evidence carries the difference between two readings now, so a pass that
/// killed nothing reads zero however violent the container's history was.
///
/// A charge that hit the ceiling during the pass without anything being killed
/// is real pressure and a strong prior, so it is reported as likely. Nothing
/// read this before: kin took only the kill count out of `memory.events` and
/// ignored `max` beside it, so a run that spent its life pinned against the cap
/// and a run that never came near it produced identical diagnoses. The 4 GiB
/// container arm on 2026-08-25 hit its ceiling 6344 times, survived, and had
/// nothing to show for it.
///
/// A ceiling below what an embed needs is a prior about the machine rather than
/// an observation of the run, so it grades last and is also reported as likely.
/// A disconnect with none of the three is left alone: a daemon that died for
/// another reason on a large machine keeps its own error rather than being told
/// it ran out of memory.
fn embed_resource_exhaustion(
    rendered: &str,
    evidence: &crate::capability::MemoryEvidence,
) -> Option<String> {
    if !lost_the_daemon_mid_request(rendered) {
        return None;
    }
    let observed_kills = evidence.cgroup_oom_kills.filter(|count| *count > 0);
    let observed_ceiling_hits = evidence.cgroup_ceiling_hits.filter(|count| *count > 0);
    let under_recommendation = evidence.limit_bytes < RECOMMENDED_EMBED_MEMORY_BYTES;
    let cause = match (observed_kills, observed_ceiling_hits, under_recommendation) {
        (Some(count), _, _) => format!(
            "the daemon was lost during this embed pass and this container's kernel recorded \
             {count} out-of-memory kill(s) while it ran, so the embed ran out of memory"
        ),
        // No byte figure in this sentence, deliberately. The ceiling count and
        // `limit_bytes` are resolved by two separate walks up the cgroup tree,
        // and `limit_bytes` falls back to host RAM whenever no cap below it is
        // tighter, so pairing them would let a host-RAM number be quoted as the
        // ceiling a container hit. The count is what is new here; the ceiling
        // worth aiming at is named in the guidance below.
        (None, Some(hits), _) => format!(
            "the daemon was lost during this embed pass and this container's memory charge was \
             held at its ceiling {hits} time(s) while it ran, so it most likely ran out of memory"
        ),
        (None, None, true) => format!(
            "the daemon was lost during this embed pass and only {} of memory is available to \
             it, so it most likely ran out of memory",
            human_bytes(evidence.limit_bytes)
        ),
        (None, None, false) => return None,
    };
    Some(format!(
        "{cause}.\n\
         `kin embed` loads the {EMBED_MODEL_DOWNLOAD} {EMBED_MODEL_ID} model and a real \
         repository peaks well above that, so give this machine at least {}.\n\
         Coverage already embedded is persisted, so re-running `kin embed` under a higher limit \
         resumes rather than starting over.\n\
         Lexical and graph retrieval need no model: `kin locate` and `kin search` keep answering \
         without vectors.",
        human_bytes(RECOMMENDED_EMBED_MEMORY_BYTES),
    ))
}

/// What to tell a caller before an embed starts on a machine that cannot
/// comfortably hold the model, or `None` when the ceiling is adequate.
///
/// The download and the ceiling are both knowable before any work begins, and
/// a caller who learns them from a failed pass learns them too late.
fn constrained_memory_notice(evidence: &crate::capability::MemoryEvidence) -> Option<String> {
    if evidence.limit_bytes >= RECOMMENDED_EMBED_MEMORY_BYTES {
        return None;
    }
    Some(format!(
        "Note: {} of memory is available here. `kin embed` downloads and loads the \
         {EMBED_MODEL_DOWNLOAD} {EMBED_MODEL_ID} model, and at least {} is recommended; below \
         that the daemon can be killed mid-pass. Lexical and graph retrieval need no model.",
        human_bytes(evidence.limit_bytes),
        human_bytes(RECOMMENDED_EMBED_MEMORY_BYTES),
    ))
}

/// Whether the drive-to-completion loop should issue another embed pass.
///
/// Continue only while retrievable work remains AND the last pass actually
/// embedded something. A pass that persisted nothing while objects are still
/// pending is stalled (e.g. objects that repeatedly fail inference); re-issuing
/// would spin without converging, so stop and report the residual instead.
pub fn embed_pass_should_continue(result: &EmbedResult, made_progress: bool) -> bool {
    let pending = result.pending_entities + result.pending_artifacts;
    pending > 0 && made_progress
}

/// Ask the repo daemon to build embeddings for the current repo's graph.
///
/// With an explicit `--max-seconds` this issues a single bounded pass and
/// returns whatever coverage that timebox buys. With no `--max-seconds` the
/// intent is full coverage, so the CLI transparently re-issues bounded passes
/// until the daemon reports zero pending. Each pass persists its
/// batches, so the next pass resumes where the last left off; coverage is
/// therefore decoupled from any single request's HTTP timeout — a large corpus
/// that cannot finish inside one request still completes across several.
pub async fn run(
    batch_size: Option<usize>,
    json: bool,
    max_seconds: Option<u64>,
    rebuild: bool,
) -> Result<()> {
    let batch_size = crate::commands::resources::resolve_embed_batch_size(
        batch_size,
        std::env::var("KIN_RESOURCE_PROFILE").ok().as_deref(),
        DEFAULT_BATCH_SIZE,
        crate::commands::resources::throughput_embed_batch_size,
    );
    let _span = tracing::info_span!(
        "kin.embed",
        batch_size = batch_size,
        json = json,
        max_seconds = max_seconds,
        rebuild = rebuild
    )
    .entered();
    let layout = crate::commands::require_repository_layout()?;

    // Taken before the first pass, and reused by every pass, because the
    // counters it holds are cumulative for the container's whole life. A
    // reading taken only after a failure cannot say whether the kill it counts
    // happened during this embed or during something else an hour ago, and
    // FIR-1823 is what saying so anyway looked like: an unhedged "the embed ran
    // out of memory" for a daemon that died of something else entirely.
    let memory_baseline = crate::capability::memory_baseline();

    if !json {
        if let Some(notice) = constrained_memory_notice(&crate::capability::memory_evidence()) {
            println!("{notice}");
        }
    }

    if let Some(seconds) = max_seconds {
        let response = run_daemon_embed(
            &layout,
            &EmbedRequest {
                batch_size,
                json,
                max_seconds: Some(seconds),
                rebuild,
                cap_batch_size: true,
            },
            memory_baseline,
        )
        .await?;
        if json {
            println!("{}", serde_json::to_string_pretty(&response.result)?);
        } else {
            for line in response.lines {
                println!("{line}");
            }
        }
        return Ok(());
    }

    let pass_seconds = pass_budget_seconds();
    let max_passes = max_passes();
    // Constrained profiles (2–4 core CPU boxes) bound the total wall time so a
    // single `kin embed` returns a resumable partial index instead of driving to
    // full coverage for hours; unconstrained profiles keep driving to zero
    // pending. Each pass persists, so coverage resumes on the next invocation.
    let total_budget = constrained_total_budget_seconds();
    let embed_started = std::time::Instant::now();
    let mut pass = 0usize;
    let mut embedded_entities = 0usize;
    let mut embedded_artifacts = 0usize;
    let mut budget_stopped = false;
    // The run's coverage span is the FIRST pass's entry reading and the LAST
    // pass's exit reading. Taking both from the final pass would report the
    // span of one pass under a heading about the run, which is the same class
    // of error as reporting a pass counter as the store's coverage.
    let mut first_pass_indexed_before: Option<usize> = None;
    let final_result = loop {
        pass += 1;
        let response = run_daemon_embed(
            &layout,
            &EmbedRequest {
                batch_size,
                json,
                max_seconds: Some(pass_seconds),
                // Only the first pass may rebuild — re-issuing `rebuild` would
                // drop the index every pass and discard the vectors the prior
                // passes just persisted, so the loop could never converge.
                rebuild: rebuild && pass == 1,
                cap_batch_size: false,
            },
            memory_baseline,
        )
        .await?;
        let result = response.result;
        embedded_entities += result.embedded_entities;
        embedded_artifacts += result.embedded_artifacts;
        if first_pass_indexed_before.is_none() {
            first_pass_indexed_before = result.coverage.map(|c| c.indexed_before);
        }
        let made_progress = result.embedded_entities + result.embedded_artifacts > 0;

        let elapsed = embed_started.elapsed().as_secs_f64();
        let pending_now = result.pending_entities + result.pending_artifacts;
        if !json {
            let rate = throughput_per_sec(embedded_entities + embedded_artifacts, elapsed);
            println!(
                "Pass {pass}: +{} entities, +{} artifacts ({} entities, {} artifacts still pending) [{:.2} ent/s{}]",
                result.embedded_entities,
                result.embedded_artifacts,
                result.pending_entities,
                result.pending_artifacts,
                rate,
                eta_suffix(rate, pending_now),
            );
        }

        if !embed_pass_should_continue(&result, made_progress) || pass >= max_passes {
            break result;
        }
        if total_budget.is_some_and(|budget| elapsed >= budget as f64) {
            budget_stopped = true;
            break result;
        }
    };
    let pending = final_result.pending_entities + final_result.pending_artifacts;
    let elapsed = embed_started.elapsed().as_secs_f64();
    let rate = throughput_per_sec(embedded_entities + embedded_artifacts, elapsed);
    // The run's span: where the first pass found this store, where the last one
    // left it. Both halves have to be present, so a daemon that reported
    // coverage on only some passes yields no span rather than a mixed one.
    let run_coverage = match (first_pass_indexed_before, final_result.coverage) {
        (Some(indexed_before), Some(last)) => Some(PassCoverage {
            indexed_before,
            ..last
        }),
        _ => None,
    };
    if json {
        let aggregate = EmbedResult {
            embedded_entities,
            embedded_artifacts,
            time_limited: pending > 0,
            coverage: run_coverage,
            ..final_result
        };
        println!("{}", serde_json::to_string_pretty(&aggregate)?);
    } else if pending == 0 {
        println!(
            "{}, index saved to {}",
            embed_completion_line(
                embedded_entities,
                embedded_artifacts,
                pass,
                rate,
                run_coverage,
            ),
            final_result.vector_index_path
        );
    } else if budget_stopped {
        println!(
            "Time budget reached after {:.0}s ({pass} pass(es), {:.2} ent/s): {} entities + {} artifacts still pending{}. Progress is persisted — re-run `kin embed` to continue.",
            elapsed,
            rate,
            final_result.pending_entities,
            final_result.pending_artifacts,
            eta_suffix(rate, pending),
        );
    } else {
        println!(
            "Stopped with {} entities + {} artifacts still pending after {pass} pass(es) — the daemon made no progress on the last pass. Re-run `kin embed` or inspect the daemon log.",
            final_result.pending_entities, final_result.pending_artifacts
        );
    }
    Ok(())
}

async fn run_daemon_embed(
    layout: &kin_core::KinLayout,
    request: &EmbedRequest,
    memory_baseline: crate::capability::MemoryBaseline,
) -> Result<EmbedResponse> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url =
        daemon_url.ok_or_else(|| crate::daemon_client::daemon_required_error("embed", layout))?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    // Embedding behavior is decided in the long-lived daemon worker; warn loudly
    // (or fail under KIN_STRICT_BEHAVIOR_ENV) if this command's environment
    // diverges from what that worker captured at start.
    client.warn_on_behavior_env_divergence().await?;
    client.embed(request).await.map_err(|e| {
        let rendered = format!("{e:#}");
        // The transport error stays in the message either way. A caller who
        // needs to see what the connection actually did still can, and a
        // failure this cannot attribute to memory is passed through untouched
        // rather than being given a diagnosis nobody proved.
        match embed_resource_exhaustion(
            &rendered,
            &crate::capability::memory_evidence_since(memory_baseline),
        ) {
            Some(guidance) => anyhow::anyhow!("daemon embed failed: {rendered}\n\n{guidance}"),
            None => anyhow::anyhow!("daemon embed failed: {rendered}"),
        }
    })
}

pub fn build_embed_response(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    request: &EmbedRequest,
    mut persist_batch: impl FnMut() -> std::result::Result<(), kin_db::KinDbError>,
    is_cancelled: impl Fn() -> bool,
) -> Result<EmbedResponse> {
    let deadline = request
        .max_seconds
        .filter(|seconds| *seconds > 0)
        .map(|seconds| std::time::Instant::now() + std::time::Duration::from_secs(seconds));

    let total_entities = graph.entity_count();
    let total_artifacts = graph.artifact_count();

    // Fast exit: nothing to embed
    if total_entities == 0 && total_artifacts == 0 {
        return Ok(EmbedResponse {
            result: EmbedResult {
                total_entities: 0,
                embedded_entities: 0,
                pending_entities: 0,
                total_artifacts: 0,
                embedded_artifacts: 0,
                pending_artifacts: 0,
                time_limited: false,
                vector_index_path: String::new(),
                coverage: Some(PassCoverage {
                    indexed_before: 0,
                    indexed_after: 0,
                    total: 0,
                }),
            },
            lines: vec!["No retrievable graph objects found. Run `kin init` first.".to_string()],
        });
    }

    // Sampled here, before this pass propagates, queues or embeds anything, so
    // it reports the store this pass INHERITED. The reading taken further down
    // for the queue decision is already post-propagation, and reusing it would
    // credit this pass's own propagation to whatever ran before it.
    //
    // Nothing else can move coverage between this line and the exit sample: the
    // caller holds `DaemonState::embedding_work`, which serializes explicit
    // passes against the background embedding worker.
    let coverage_before = graph.embedding_status();

    // Propagate vectors from fingerprint-identical previous revisions before
    // queueing, so identical-content revisions skip GPU inference entirely.
    // This can eliminate 30-50% of the total embedding work for historical
    // revisions where the entity content didn't actually change.
    let propagated = graph.propagate_revision_vectors();
    if propagated > 0 {
        tracing::info!(
            propagated = propagated,
            "propagated revision vectors via fingerprint match"
        );
    }

    // Rebuild migration (request.rebuild) is handled by the daemon before this
    // runs: it drops the stale-dimension index and re-queues every object. For
    // normal embeds, always enqueue missing retrievable keys when coverage is
    // incomplete; HashSet queues make this idempotent and prevent stale queue
    // entries from masking real backfill work.
    let status = graph.embedding_status();
    if should_queue_missing_embedding_pass(status.indexed, status.total) {
        #[cfg(feature = "embeddings")]
        graph.queue_missing_for_embedding();
        graph.queue_missing_artifacts_for_embedding();
    }
    let effective_batch_size = effective_batch_size(
        request.batch_size,
        request.cap_batch_size && deadline.is_some(),
    );

    // Embed entities with per-batch progress
    let embed_start = std::time::Instant::now();
    let mut total_embedded_entities = 0usize;
    let mut time_limited = false;
    loop {
        if is_cancelled() {
            tracing::info!("Embedding cancelled due to shutdown");
            break;
        }
        if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
            time_limited = true;
            break;
        }
        let pending = graph.pending_embeddings();
        if pending == 0 {
            break;
        }
        match graph.process_embedding_queue(effective_batch_size) {
            Ok(processed) => {
                if processed == 0 {
                    break;
                }
                total_embedded_entities += processed;
                persist_batch()?;
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }

    // Embed artifacts with per-batch progress
    let mut total_embedded_artifacts = 0usize;
    loop {
        if is_cancelled() {
            tracing::info!("Embedding cancelled due to shutdown");
            break;
        }
        if deadline.is_some_and(|deadline| std::time::Instant::now() >= deadline) {
            time_limited = true;
            break;
        }
        let pending = graph.pending_artifact_embeddings();
        if pending == 0 {
            break;
        }
        match graph.process_artifact_embedding_queue(effective_batch_size) {
            Ok(processed) => {
                if processed == 0 {
                    break;
                }
                total_embedded_artifacts += processed;
                persist_batch()?;
            }
            Err(e) => {
                return Err(e.into());
            }
        }
    }

    let vi_path = crate::backend::vector_index_path(layout);
    let pending_entities = graph.pending_embeddings();
    let pending_artifacts = graph.pending_artifact_embeddings();
    let coverage_after = graph.embedding_status();
    let result = EmbedResult {
        total_entities,
        embedded_entities: total_embedded_entities,
        pending_entities,
        total_artifacts,
        embedded_artifacts: total_embedded_artifacts,
        pending_artifacts,
        time_limited,
        vector_index_path: vi_path.to_string_lossy().to_string(),
        coverage: Some(PassCoverage {
            indexed_before: coverage_before.indexed,
            indexed_after: coverage_after.indexed,
            total: coverage_after.total,
        }),
    };
    let mut lines = Vec::new();
    if time_limited {
        lines.push(
            "Time budget reached; persisting completed vectors and leaving the rest pending."
                .to_string(),
        );
    }
    lines.push(format!(
        "Done: {}/{} entities, {}/{} artifacts ({:.1}s)",
        total_embedded_entities,
        total_entities,
        total_embedded_artifacts,
        total_artifacts,
        embed_start.elapsed().as_secs_f64()
    ));
    lines.push(format!(
        "Done. {} entities embedded, {} artifacts embedded, index saved to {}",
        total_embedded_entities,
        total_embedded_artifacts,
        vi_path.display()
    ));

    Ok(EmbedResponse { result, lines })
}

#[cfg(test)]
mod tests {
    use super::{
        constrained_memory_notice, effective_batch_size, embed_completion_line,
        embed_pass_should_continue, embed_resource_exhaustion, eta_suffix, format_duration_secs,
        lost_the_daemon_mid_request, resolve_total_budget, should_queue_missing_embedding_pass,
        throughput_per_sec, EmbedResult, PassCoverage, DEFAULT_BATCH_SIZE,
        DEFAULT_CONSTRAINED_TOTAL_SECONDS, EMBED_MODEL_DOWNLOAD, EMBED_MODEL_ID,
        RECOMMENDED_EMBED_MEMORY_BYTES,
    };

    fn result_with(pending_entities: usize, pending_artifacts: usize) -> EmbedResult {
        EmbedResult {
            total_entities: 100,
            embedded_entities: 0,
            pending_entities,
            total_artifacts: 0,
            embedded_artifacts: 0,
            pending_artifacts,
            time_limited: false,
            vector_index_path: String::new(),
            coverage: None,
        }
    }

    fn coverage(indexed_before: usize, indexed_after: usize, total: usize) -> Option<PassCoverage> {
        Some(PassCoverage {
            indexed_before,
            indexed_after,
            total,
        })
    }

    /// The defect, driven with the stranger's own numbers.
    ///
    /// On the shipped v0.5.45 bytes a store went from 3 of 51 to 51 of 51 across
    /// one `kin embed`, and the command reported `Done. Full coverage: 0
    /// entities, 0 artifacts embedded`. The pass that printed it inherited a
    /// store already at 51 of 51, so its own zero was correct and its heading
    /// was not. Two properties have to hold at once: the store's coverage is
    /// stated, and the run's zero never renders as the store's.
    #[test]
    fn a_pass_that_inherited_a_covered_store_says_the_work_predated_it() {
        let line = embed_completion_line(0, 0, 1, 0.0, coverage(51, 51, 51));
        assert!(
            line.contains("51/51 indexed"),
            "the store's own coverage has to be stated: {line}"
        );
        assert!(
            line.contains("already fully covered")
                && line.contains("the work was finished before it ran"),
            "a zero has to say which of the two states this is: {line}"
        );
        assert!(
            !line.contains("Full coverage: 0"),
            "the run's own zero must never render as the store's coverage: {line}"
        );
    }

    /// The control that lets the arm above fail: a run that did the work reports
    /// its own count and the span it moved the store across, which is a
    /// different sentence and carries different numbers.
    #[test]
    fn a_pass_that_embedded_reports_its_own_work_and_the_span_it_moved() {
        let line = embed_completion_line(48, 2, 2, 12.5, coverage(3, 53, 53));
        assert!(
            line.contains("embedded 48 entities and 2 artifacts"),
            "this run's own work is named: {line}"
        );
        assert!(
            line.contains("3/53") && line.contains("53/53"),
            "the coverage span it moved is named beside it: {line}"
        );
        assert!(
            !line.contains("already fully covered"),
            "a run that did the work must not report the store as pre-covered: {line}"
        );
    }

    /// Coverage that moved while the queue embedded nothing is this pass's own
    /// propagation of vectors from content-identical revisions, so it is
    /// credited here rather than to whatever ran before. Without this arm the
    /// span would be reported under the pre-covered sentence, which is false.
    #[test]
    fn coverage_that_moved_without_the_queue_is_credited_to_this_run() {
        let line = embed_completion_line(0, 0, 1, 0.0, coverage(10, 51, 51));
        assert!(
            line.contains("10/51") && line.contains("51/51"),
            "both ends of the span are named: {line}"
        );
        assert!(
            line.contains("content-identical revisions"),
            "the reader learns where the coverage came from: {line}"
        );
        assert!(
            !line.contains("already fully covered"),
            "a store that was not covered at entry must not be reported as covered: {line}"
        );
    }

    /// A daemon that reports no coverage gets no coverage sentence. Defaulting
    /// the three counters to zero would make an unmeasured store and an empty
    /// one render identically, which is the defect this change removes wearing
    /// a different costume.
    #[test]
    fn an_unreported_coverage_states_the_runs_work_and_claims_nothing_else() {
        let line = embed_completion_line(7, 0, 1, 3.5, None);
        assert!(
            line.contains("embedded 7 entities"),
            "the run's own work still renders: {line}"
        );
        assert!(
            line.contains("does not report the store's coverage"),
            "the absence of a measurement is stated, not filled in: {line}"
        );
        assert!(
            !line.contains("0/0"),
            "an unmeasured store must never render as a counted one: {line}"
        );
    }

    /// The wiring, not the helper: a real pass has to PUBLISH the coverage the
    /// sentence is built from.
    ///
    /// Every arm above drives `embed_completion_line` directly, and a
    /// `build_embed_response` that never filled `coverage` would satisfy all of
    /// them while every real run rendered the no-measurement sentence. That is
    /// the same defect wearing the fix's clothes, and only a test that runs a
    /// pass can tell the two apart.
    ///
    /// The store here is the one FIR-2556 is about: an explicit pass arriving at
    /// a store somebody else already finished. It needs no embedder, because
    /// with coverage whole there is nothing for either queue loop to process,
    /// which is exactly why this case reaches a user as a zero.
    #[cfg(feature = "vector")]
    #[test]
    fn a_pass_publishes_the_store_coverage_its_summary_is_built_from() {
        use super::EmbedRequest;
        use kin_model::{
            Entity, EntityMetadata, EntityStore, FingerprintAlgorithm, Hash256, LanguageId,
            SemanticFingerprint, Visibility,
        };

        let temp = tempfile::tempdir().unwrap();
        let initialized = kin_core::init(temp.path()).unwrap();
        let graph = kin_db::InMemoryGraph::new();
        for name in ["alpha_transform", "beta_reduce"] {
            graph
                .upsert_entity(&Entity {
                    id: kin_model::EntityId::new(),
                    kind: kin_model::EntityKind::Function,
                    name: name.to_string(),
                    language: LanguageId::Rust,
                    fingerprint: SemanticFingerprint {
                        algorithm: FingerprintAlgorithm::V1TreeSitter,
                        ast_hash: Hash256::from_bytes([1; 32]),
                        signature_hash: Hash256::from_bytes([2; 32]),
                        behavior_hash: Hash256::from_bytes([3; 32]),
                        equivalence_hash: Hash256::from_bytes([0; 32]),
                        stability_score: 1.0,
                    },
                    file_origin: None,
                    span: None,
                    signature: format!("fn {name}()"),
                    visibility: Visibility::Public,
                    role: kin_model::EntityRole::Source,
                    doc_summary: None,
                    metadata: EntityMetadata::default(),
                    lineage_parent: None,
                    created_in: None,
                    superseded_by: None,
                })
                .unwrap();
        }

        // Cover every retrievable key, which is what "somebody else finished
        // this store" leaves behind.
        let index = kin_db::VectorIndex::new(2).unwrap();
        let snapshot = graph.to_snapshot();
        for id in snapshot.entities.keys() {
            index
                .upsert_retrievable(kin_model::RetrievalKey::Entity(*id), &[1.0, 0.0])
                .unwrap();
        }
        for revision in snapshot
            .entity_revisions
            .values()
            .flat_map(|revisions| revisions.iter())
        {
            index
                .upsert_retrievable(
                    kin_model::RetrievalKey::EntityRevision(revision.revision_id),
                    &[1.0, 0.0],
                )
                .unwrap();
        }
        let descriptor = kin_db::IndexDescriptor {
            model_id: Some("embed-wiring-fixture@v1".to_string()),
            graph_root: Some(hex::encode(graph.compute_root_hash())),
        };
        index.set_descriptor(descriptor.clone());
        let sidecar = temp.path().join("wiring.kvec");
        index.save(&sidecar).unwrap();
        assert!(matches!(
            graph.load_vector_index_compatible(&sidecar, &descriptor),
            kin_db::VectorIndexLoad::Loaded(_)
        ));

        // Rebuild the graph from its own snapshot and carry the index across.
        // `upsert_entity` enqueues every entity it admits, and nothing short of
        // a real embedder drains that queue, so a graph built by upserting
        // reads as fully indexed AND fully queued at once. A store a worker
        // actually finished has an empty queue, and reconstructing from the
        // snapshot is how this fixture reaches that state without an embedder.
        let covered = kin_db::InMemoryGraph::from_snapshot(graph.to_snapshot()).unwrap();
        covered.share_vector_index_from(&graph);

        let status = covered.embedding_status();
        assert!(
            status.total > 0 && status.indexed == status.total && status.pending == 0,
            "the fixture must be the already-covered store this case is about: {status:?}"
        );

        let response = super::build_embed_response(
            &initialized.layout,
            &covered,
            &EmbedRequest {
                batch_size: DEFAULT_BATCH_SIZE,
                json: false,
                max_seconds: Some(30),
                rebuild: false,
                cap_batch_size: true,
            },
            || Ok(()),
            || false,
        )
        .unwrap();

        let published = response
            .result
            .coverage
            .expect("a pass must publish the coverage it measured");
        assert_eq!(
            (
                published.indexed_before,
                published.indexed_after,
                published.total
            ),
            (status.indexed, status.indexed, status.total),
            "the published span must be the store's own counters, not a placeholder"
        );
        assert_eq!(
            response.result.embedded_entities + response.result.embedded_artifacts,
            0,
            "this pass embedded nothing, which is the zero the old line printed alone"
        );

        // End to end: what a user of this pass would actually read.
        let line = embed_completion_line(
            response.result.embedded_entities,
            response.result.embedded_artifacts,
            1,
            0.0,
            response.result.coverage,
        );
        assert!(
            line.contains("already fully covered")
                && line.contains(&format!("{}/{} indexed", status.indexed, status.total)),
            "a real pass on a covered store must render the covered sentence: {line}"
        );
    }

    /// The empty repository stays a correct fast no-op and says so in its own
    /// words, rather than borrowing a coverage claim over a population of zero.
    #[test]
    fn an_empty_repository_reports_having_nothing_to_embed() {
        let line = embed_completion_line(0, 0, 1, 0.0, coverage(0, 0, 0));
        assert!(
            line.contains("no retrievable graph objects"),
            "the empty repository names its own case: {line}"
        );
        assert!(
            !line.contains("already fully covered"),
            "nothing was covered, so nothing may be reported as covered: {line}"
        );
    }

    #[test]
    fn drive_loop_continues_while_pending_and_progressing() {
        assert!(embed_pass_should_continue(&result_with(40, 0), true));
        assert!(embed_pass_should_continue(&result_with(0, 5), true));
    }

    #[test]
    fn drive_loop_stops_on_full_coverage() {
        // No pending work left → done regardless of whether the last pass moved.
        assert!(!embed_pass_should_continue(&result_with(0, 0), true));
        assert!(!embed_pass_should_continue(&result_with(0, 0), false));
    }

    #[test]
    fn drive_loop_stops_when_stalled_to_avoid_spin() {
        // Pending work remains but the pass embedded nothing — re-issuing would
        // spin forever, so the loop must stop and surface the residual.
        assert!(!embed_pass_should_continue(&result_with(40, 3), false));
    }

    #[test]
    fn default_batch_size_is_progress_friendly() {
        assert_eq!(DEFAULT_BATCH_SIZE, 64);
    }

    #[test]
    fn effective_batch_size_respects_nonzero_request() {
        assert_eq!(effective_batch_size(512, false), 512);
    }

    #[test]
    fn effective_batch_size_caps_bounded_requests_to_default() {
        assert_eq!(effective_batch_size(512, true), DEFAULT_BATCH_SIZE);
    }

    #[test]
    fn effective_batch_size_honors_uncapped_internal_bounded_requests() {
        assert_eq!(effective_batch_size(512, false), 512);
    }

    #[test]
    fn effective_batch_size_keeps_small_bounded_requests() {
        assert_eq!(effective_batch_size(16, true), 16);
    }

    #[test]
    fn effective_batch_size_clamps_zero_to_one() {
        assert_eq!(effective_batch_size(0, false), 1);
        assert_eq!(effective_batch_size(0, true), 1);
    }

    #[test]
    fn queues_missing_pass_when_index_incomplete() {
        assert!(should_queue_missing_embedding_pass(3, 5));
    }

    #[test]
    fn queues_missing_pass_even_when_stale_queue_may_exist() {
        assert!(should_queue_missing_embedding_pass(3, 5));
    }

    #[test]
    fn skips_full_queue_when_embeddings_are_current() {
        assert!(!should_queue_missing_embedding_pass(5, 5));
    }

    fn evidence(limit_bytes: u64, oom_kills: Option<u64>) -> crate::capability::MemoryEvidence {
        crate::capability::MemoryEvidence {
            limit_bytes,
            limit_source: crate::capability::MemoryLimitSource::HostRam,
            cgroup_oom_kills: oom_kills,
            cgroup_ceiling_hits: None,
        }
    }

    /// The exact failure a 512 MB cgroup produced: the daemon is OOM-killed
    /// mid-pass and the CLI is handed a closed connection.
    const OOM_KILLED_MID_PASS: &str =
        "the kin daemon at http://127.0.0.1:7654 stopped answering while the embed request was in \
         flight: error sending request for url (http://127.0.0.1:7654/embed): connection closed \
         before message completed";

    #[test]
    fn a_recorded_oom_kill_is_reported_as_observed_with_the_limit_and_the_remedy() {
        let guidance =
            embed_resource_exhaustion(OOM_KILLED_MID_PASS, &evidence(512 * 1024 * 1024, Some(1)))
                .expect("a kernel OOM kill during an embed is not an opaque transport failure");

        assert!(
            guidance.contains("out-of-memory kill"),
            "the kernel's own record is what makes this observed: {guidance}"
        );
        assert!(
            guidance.contains("2.0 GiB"),
            "the failure must name the limit that would fix it: {guidance}"
        );
        assert!(
            guidance.contains(EMBED_MODEL_ID) && guidance.contains(EMBED_MODEL_DOWNLOAD),
            "the failure must name what is consuming the memory: {guidance}"
        );
        assert!(
            guidance.contains("kin locate") && guidance.contains("kin search"),
            "a repository without vectors is not a repository without retrieval: {guidance}"
        );
        assert!(
            guidance.contains("persisted"),
            "the caller must know a re-run resumes rather than restarts: {guidance}"
        );
    }

    #[test]
    fn a_ceiling_below_the_recommendation_is_reported_as_likely_not_as_observed() {
        // No cgroup accounting is readable, which is every non-Linux host. The
        // ceiling still says the machine cannot hold the model, and saying so
        // is not the same as claiming the kernel proved it.
        let guidance = embed_resource_exhaustion(OOM_KILLED_MID_PASS, &evidence(1 << 29, None))
            .expect("a lost daemon under the recommendation is a memory diagnosis");
        assert!(
            guidance.contains("most likely"),
            "an inference from the ceiling alone must be labelled as one: {guidance}"
        );
        assert!(
            !guidance.contains("kernel recorded"),
            "nothing may claim a kill this host could not observe: {guidance}"
        );
    }

    /// A container reading, for an arm that has to place a history before the
    /// pass it is judging.
    fn cgroup(
        limit_bytes: u64,
        oom_kills: u64,
        ceiling_hits: u64,
    ) -> kin_daemon_spawn::CgroupMemory {
        kin_daemon_spawn::CgroupMemory {
            limit_bytes: Some(limit_bytes),
            oom_kills: Some(oom_kills),
            ceiling_hits: Some(ceiling_hits),
            ..kin_daemon_spawn::CgroupMemory::default()
        }
    }

    /// The evidence one embed pass produces, from the readings that bracket it.
    fn across_pass(
        start: kin_daemon_spawn::CgroupMemory,
        end: kin_daemon_spawn::CgroupMemory,
    ) -> crate::capability::MemoryEvidence {
        crate::capability::evidence_from(
            64 * 1024 * 1024 * 1024,
            end,
            Some(crate::capability::MemoryBaseline::from_reading(start)),
        )
    }

    /// A ceiling with room to spare, so nothing but the counters can produce a
    /// diagnosis and an arm that stays silent stayed silent for the right
    /// reason.
    const ROOMY: u64 = 8 * 1024 * 1024 * 1024;

    /// FIR-1823, end to end: two passes identical except for when the kill
    /// happened.
    ///
    /// Arm one is a container that was killed three times before this pass ever
    /// started and killed nothing during it. The counter reads three both
    /// times. Before the fix that three was read as this pass's own and the
    /// caller was told, flatly, that the embed ran out of memory.
    ///
    /// Arm two is the control that proves the first arm can fail. Same history,
    /// same everything, one more kill by the end. Without it, code that simply
    /// deleted the branch would pass arm one and nobody would know.
    #[test]
    fn a_kill_from_before_the_pass_is_not_this_passs_kill() {
        assert!(
            lost_the_daemon_mid_request(OOM_KILLED_MID_PASS),
            "both arms below are about a daemon that was lost; if this stops being one, they \
             pass for the wrong reason"
        );

        let unmoved = across_pass(cgroup(ROOMY, 3, 900), cgroup(ROOMY, 3, 900));
        assert_eq!(
            embed_resource_exhaustion(OOM_KILLED_MID_PASS, &unmoved),
            None,
            "a container with three historical kills and none during this pass has no memory \
             diagnosis to offer about this pass"
        );

        let moved = across_pass(cgroup(ROOMY, 3, 900), cgroup(ROOMY, 4, 1_100));
        let guidance = embed_resource_exhaustion(OOM_KILLED_MID_PASS, &moved)
            .expect("a kill during the pass is the kernel's own statement about the pass");
        assert!(
            guidance.contains("recorded 1 out-of-memory kill(s)"),
            "the count reported must be the pass's one, not the container's four: {guidance}"
        );
        assert!(
            guidance.contains("so the embed ran out of memory"),
            "a kill during the pass is reported as observed, not hedged: {guidance}"
        );
    }

    /// The same historical kill must not upgrade the grade on a small machine
    /// either.
    ///
    /// A ceiling under the recommendation already earns a hedged diagnosis on
    /// its own, so the arm above cannot see this: silence there proves nothing
    /// about whether the kill was consulted. Here the diagnosis is present and
    /// the question is which sentence it is.
    #[test]
    fn a_historical_kill_does_not_promote_a_ceiling_inference_to_an_observation() {
        let small = 512 * 1024 * 1024;
        let unmoved = across_pass(cgroup(small, 3, 900), cgroup(small, 3, 900));
        let guidance = embed_resource_exhaustion(OOM_KILLED_MID_PASS, &unmoved)
            .expect("a ceiling under the recommendation is still a memory diagnosis");
        assert!(
            !guidance.contains("kernel recorded"),
            "three kills that predate the pass are not evidence about the pass: {guidance}"
        );
        assert!(
            guidance.contains("most likely"),
            "with nothing observed during the pass, the ceiling is a prior and says so: \
             {guidance}"
        );
    }

    /// The ceiling-hit counter, which nothing in kin read until now.
    ///
    /// A container held against its cap for the whole pass, reclaiming on every
    /// allocation and never killed, used to leave a diagnosis with nothing to
    /// say: `oom_kill` reads zero and the ceiling is generous, so the pass came
    /// back as an unexplained disconnect. The 4 GiB arm on 2026-08-25 recorded
    /// 6344 of these beside a single kill, and no kin surface read one.
    #[test]
    fn a_charge_pinned_at_the_ceiling_during_the_pass_is_reported_as_likely() {
        let pinned = across_pass(cgroup(ROOMY, 2, 900), cgroup(ROOMY, 2, 7_244));
        let guidance = embed_resource_exhaustion(OOM_KILLED_MID_PASS, &pinned)
            .expect("a charge held at the ceiling through the pass is memory pressure");
        assert!(
            guidance.contains("6344 time(s)"),
            "the count reported must be the pass's own advance: {guidance}"
        );
        assert!(
            guidance.contains("ceiling") && guidance.contains("most likely"),
            "reaching the ceiling is pressure the kernel absorbed, not a kill it performed: \
             {guidance}"
        );
        assert!(
            !guidance.contains("kernel recorded"),
            "nothing was killed during this pass and nothing may say one was: {guidance}"
        );

        // The control. Same generous ceiling, same violent history, and a
        // counter that did not move during the pass. Without this, a fix that
        // reported the lifetime total would pass the arm above.
        let untouched = across_pass(cgroup(ROOMY, 2, 6_344), cgroup(ROOMY, 2, 6_344));
        assert_eq!(
            embed_resource_exhaustion(OOM_KILLED_MID_PASS, &untouched),
            None,
            "6344 ceiling hits that all predate the pass say nothing about the pass"
        );
    }

    #[test]
    fn a_non_memory_daemon_disconnect_keeps_its_own_error() {
        // The distinguishability the acceptance asks for. A daemon that died
        // for another reason on a machine with room to spare must not be told
        // it ran out of memory, and a refusal the daemon stayed alive to answer
        // with was never a disconnect at all.
        assert!(
            embed_resource_exhaustion(OOM_KILLED_MID_PASS, &evidence(64 << 30, Some(0))).is_none(),
            "a large host with no recorded kill has no memory diagnosis to offer"
        );
        assert!(
            embed_resource_exhaustion(
                "kin embed refused (HTTP 500): Graph error: kindb foo",
                &evidence(512 * 1024 * 1024, Some(3)),
            )
            .is_none(),
            "an answered HTTP refusal is not a daemon that was killed, whatever the cgroup says"
        );
        assert!(
            embed_resource_exhaustion(
                "the kin daemon at http://127.0.0.1:7654 stopped answering while the embed \
                 request was in flight: operation timed out",
                &evidence(512 * 1024 * 1024, Some(3)),
            )
            .is_none(),
            "a client-side timeout keeps its own diagnosis"
        );
        assert!(
            embed_resource_exhaustion(
                "the kin daemon at http://127.0.0.1:7654 stopped answering while the embed \
                 request was in flight: error sending request for url \
                 (http://127.0.0.1:7654/embed): tcp connect error: Connection refused (os error 61)",
                &evidence(512 * 1024 * 1024, Some(3)),
            )
            .is_none(),
            "a connection that was never accepted is not a daemon lost during this pass, whatever \
             the machine's memory says"
        );
    }

    #[test]
    fn a_constrained_machine_is_told_before_the_work_starts_and_a_roomy_one_is_not() {
        let notice = constrained_memory_notice(&evidence(1 << 30, None))
            .expect("a machine under the recommendation is warned before the download");
        assert!(
            notice.contains(EMBED_MODEL_DOWNLOAD) && notice.contains("2.0 GiB"),
            "{notice}"
        );
        assert!(
            constrained_memory_notice(&evidence(RECOMMENDED_EMBED_MEMORY_BYTES, None)).is_none(),
            "a machine at the recommendation gets no warning it does not need"
        );
    }

    #[test]
    fn embed_error_wrap_preserves_underlying_chain() {
        let inner = anyhow::anyhow!("daemon embed error (HTTP 500): Graph error: kindb foo");
        let wrapped: anyhow::Error =
            anyhow::anyhow!("daemon embed failed: {inner:#}", inner = inner);
        let rendered = format!("{wrapped:#}");
        assert!(
            rendered.contains("daemon embed failed"),
            "missing outer hint: {rendered}"
        );
        assert!(
            rendered.contains("Graph error: kindb foo"),
            "underlying cause was flattened away: {rendered}"
        );
    }

    #[test]
    fn constrained_profiles_get_a_default_total_budget() {
        // interactive / small are the small-machine selectors → auto-bounded.
        assert_eq!(
            resolve_total_budget(None, "interactive", true),
            Some(DEFAULT_CONSTRAINED_TOTAL_SECONDS)
        );
        assert_eq!(
            resolve_total_budget(None, "  SMALL ", true),
            Some(DEFAULT_CONSTRAINED_TOTAL_SECONDS)
        );
    }

    #[test]
    fn unconstrained_profiles_drive_to_full_coverage() {
        // Proof/throughput/ci/unset keep the drive-to-completion behavior.
        for profile in ["", "proof", "throughput", "ci", "unknown"] {
            assert_eq!(
                resolve_total_budget(None, profile, true),
                None,
                "profile={profile}"
            );
        }
    }

    /// The product's own `interactive` selection is not a statement about the
    /// machine, so it must not bound the pass the way an operator's is. Without
    /// this, shipping `interactive` as the default would silently cap every
    /// `kin embed` at ten minutes on every box.
    #[test]
    fn a_product_selected_profile_never_bounds_the_pass() {
        for profile in ["interactive", "small", "proof", "throughput", "ci", ""] {
            assert_eq!(
                resolve_total_budget(None, profile, false),
                None,
                "profile={profile}"
            );
        }
        // An explicit budget still bounds it, whoever chose the profile.
        assert_eq!(
            resolve_total_budget(Some(120), "interactive", false),
            Some(120)
        );
    }

    #[test]
    fn explicit_total_budget_override_wins_on_any_profile() {
        assert_eq!(
            resolve_total_budget(Some(120), "throughput", true),
            Some(120)
        );
        assert_eq!(resolve_total_budget(Some(120), "proof", true), Some(120));
        // A zero override is ignored (falls back to profile default / none).
        assert_eq!(resolve_total_budget(Some(0), "proof", true), None);
        assert_eq!(
            resolve_total_budget(Some(0), "interactive", true),
            Some(DEFAULT_CONSTRAINED_TOTAL_SECONDS)
        );
    }

    #[test]
    fn throughput_is_zero_before_any_elapsed_time() {
        assert_eq!(throughput_per_sec(100, 0.0), 0.0);
        assert!((throughput_per_sec(100, 50.0) - 2.0).abs() < f64::EPSILON);
    }

    #[test]
    fn eta_suffix_is_empty_without_rate_or_work() {
        assert_eq!(eta_suffix(0.0, 100), "");
        assert_eq!(eta_suffix(5.0, 0), "");
        // 100 pending at 2/s = 50s.
        assert_eq!(eta_suffix(2.0, 100), ", ETA 50s");
    }

    #[test]
    fn duration_formats_scale_by_magnitude() {
        assert_eq!(format_duration_secs(45), "45s");
        assert_eq!(format_duration_secs(125), "2m05s");
        assert_eq!(format_duration_secs(3 * 3600 + 4 * 60 + 9), "3h04m");
    }
}
