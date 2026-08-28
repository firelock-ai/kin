// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Daemon delegate for MCP operations.
//!
//! Product-mode MCP is transport-only: graph and mutation tools are forwarded
//! to the repo daemon, and session/intent tools are forwarded to the daemon's
//! session endpoints. In-process handlers are reserved for explicit offline
//! unit tests.

use std::collections::HashMap;
use std::path::Path;
use std::sync::OnceLock;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use kin_model::session::SessionCapabilities;
use tracing::debug;

use crate::types::{ContentBlock, ToolCallResult};

/// Cached daemon HTTP client. We only cache positive connectivity so that a
/// daemon that comes online after MCP startup can still take authority.
static DAEMON_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

/// Runtime override for the daemon base URL.
///
/// Set by the revival path when it restarts the daemon on a (potentially
/// different) port.  Takes precedence over `KIN_DAEMON_URL` so subsequent
/// tool calls are routed at the revived daemon immediately, without requiring
/// a process restart.
static DAEMON_URL_OVERRIDE: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// Drop the revival-path daemon URL override.
///
/// The override outranks `KIN_DAEMON_URL` for every delegate call, so a process
/// that revived a daemon for one repository keeps reaching that daemon even
/// after `KIN_DAEMON_URL` is repointed. The stdio server clears it when the MCP
/// client's workspace roots move it to a different repository; without that, a
/// re-bind would repoint the environment and still forward tool calls to the
/// repository the client left.
pub(crate) fn clear_daemon_url_override() {
    if let Ok(mut guard) = DAEMON_URL_OVERRIDE.lock() {
        *guard = None;
    }
}

/// Serializes daemon revival so concurrent failing calls start one daemon, not
/// one each. See [`revive_mcp_daemon`].
static REVIVAL_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// The revival-path daemon URL currently installed, if any.
fn current_daemon_url_override() -> Option<String> {
    DAEMON_URL_OVERRIDE.lock().ok()?.clone()
}

/// Does a daemon answer `/health` at `base` right now?
///
/// Deliberately does not use the cached delegate client: this runs on the
/// revival path to decide whether a daemon another caller just started is
/// usable, so it wants a short, self-contained probe rather than the delegate's
/// 60 s request budget.
async fn daemon_is_healthy(base: &str) -> bool {
    let Ok(probe) = reqwest::Client::builder()
        .connect_timeout(Duration::from_millis(300))
        .timeout(Duration::from_secs(3))
        .build()
    else {
        return false;
    };
    matches!(probe.get(format!("{base}/health")).send().await, Ok(resp) if resp.status().is_success())
}

/// Base URL for the daemon HTTP API.
///
/// Checks the revival-path override first; falls back to the `KIN_DAEMON_URL`
/// environment variable that `kin mcp start` sets at process startup.
fn daemon_base_url() -> Option<String> {
    if let Ok(guard) = DAEMON_URL_OVERRIDE.lock() {
        if let Some(url) = guard.as_ref() {
            return Some(url.clone());
        }
    }
    std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

// ── On-demand delegate re-resolution ────────────────────────────────────
//
// The delegate endpoint used to be resolved exactly once, by the launcher,
// before the first tool call could arrive. A server started before `kin init`
// created the repository therefore bound nothing, and nothing ever asked
// again: every tool call for the rest of that session reported the daemon
// unavailable while `kin doctor`, run in the same directory at the same
// instant, reported it reachable with every embedding indexed. An agent whose
// only interface is MCP cannot restart its own server, so that state was
// terminal by construction, and no part of the response said what had happened.
//
// Resolution is now a question this process re-asks, through the same probe
// `kin doctor` reports from, and it is bounded twice so a directory that never
// becomes a Kin repository cannot turn every call into a stall:
//
//   1. At most one probe per cooldown window. The window starts at
//      RERESOLVE_MIN_BACKOFF and doubles to RERESOLVE_MAX_BACKOFF, so a session
//      that keeps calling into a repository-less directory costs one loopback
//      probe every 30 s rather than one per call. A success resets it.
//   2. Each probe is capped at RERESOLVE_PROBE_BUDGET, so a call that does
//      probe waits seconds at most, never the delegate's request budget.

/// First cooldown between on-demand probes.
const RERESOLVE_MIN_BACKOFF: Duration = Duration::from_secs(1);

/// Ceiling the cooldown doubles to. Chosen well under a cold `kin init` on a
/// large repository, so a session that starts before one finishes still
/// re-resolves several times while it runs rather than settling into a wait
/// longer than the event it is waiting for.
const RERESOLVE_MAX_BACKOFF: Duration = Duration::from_secs(30);

/// How long one probe may take before it is abandoned for this round.
const RERESOLVE_PROBE_BUDGET: Duration = Duration::from_secs(3);

/// Whether this process has ever held a daemon delegate.
///
/// Distinguishes a server that started before its repository existed (and so
/// has never had one) from a server whose daemon went away after it bound one.
/// The two need different remedies and used to share one message.
static DELEGATE_EVER_RESOLVED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Whether a Kin repository existed when this server started, as reported by
/// the launcher's startup binding.
///
/// Absent means nobody reported, which reads as unknown and never as "no": a
/// process that never ran a startup binding must not have its silence turned
/// into a claim about what the disk looked like before it began.
static STARTUP_REPOSITORY_PRESENT: OnceLock<bool> = OnceLock::new();

/// Record whether a Kin repository existed at this server's launch directory
/// when it started.
///
/// Called by the launcher once its startup binding knows. First report wins:
/// the fact is about a single instant that has already passed.
pub fn note_startup_repository(present: bool) {
    let _ = STARTUP_REPOSITORY_PRESENT.set(present);
}

/// What stands between this process and a daemon delegate.
///
/// Three situations that one string used to cover. Each names a different
/// state of the world and a different action a *caller* can take: an agent
/// cannot restart its own MCP server, so a message that tells it to has told
/// it nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DelegateGap {
    /// Nothing at or above this server's working directory is a Kin
    /// repository.
    NoRepository { working_dir: std::path::PathBuf },
    /// A repository is here and no daemon is serving it.
    DaemonNotRunning {
        repo: std::path::PathBuf,
        retry_in: Duration,
    },
    /// This server started before the repository existed, so it bound no
    /// delegate then and has never held one since; the repository exists now.
    StartupPredatesRepository {
        repo: std::path::PathBuf,
        retry_in: Duration,
    },
}

impl DelegateGap {
    /// The same gap with a different wait until the next probe, for a call
    /// answered from the cooldown rather than from a fresh probe.
    fn with_retry_in(&self, retry_in: Duration) -> Self {
        match self {
            Self::NoRepository { working_dir } => Self::NoRepository {
                working_dir: working_dir.clone(),
            },
            Self::DaemonNotRunning { repo, .. } => Self::DaemonNotRunning {
                repo: repo.clone(),
                retry_in,
            },
            Self::StartupPredatesRepository { repo, .. } => Self::StartupPredatesRepository {
                repo: repo.clone(),
                retry_in,
            },
        }
    }

    /// What a caller is told, and what it can do about it.
    fn message(&self, tool: &str) -> String {
        match self {
            Self::NoRepository { working_dir } => format!(
                "kin-mcp cannot answer '{tool}': {} is not a Kin repository, and neither is any \
                 directory above it, so there is no graph to answer from. Run `kin init .` in the \
                 repository you want served, or point this client's workspace roots at one. This \
                 server re-resolves its repository and daemon on every tool call, so the first \
                 call after `kin init` finishes is answered; you do not need to restart the MCP \
                 server, and a caller could not.",
                working_dir.display()
            ),
            Self::DaemonNotRunning { repo, retry_in } => format!(
                "kin-mcp cannot answer '{tool}': {} is a Kin repository, but no daemon is serving \
                 it right now. That is the same probe `kin doctor` reports its daemon-reachability \
                 verdict from, and it starts nothing. Run any `kin` command in that repository, \
                 `kin status` for instance, to start a daemon. This server re-resolves its \
                 delegate on the next tool call (at most {}s from now), so retry once a daemon is \
                 up; restarting the MCP server is not required.",
                repo.display(),
                retry_in.as_secs()
            ),
            Self::StartupPredatesRepository { repo, retry_in } => format!(
                "kin-mcp cannot answer '{tool}': this server started before {} was a Kin \
                 repository, so it bound no daemon at startup, and no daemon is serving that \
                 repository yet. The binding is not one-shot: this server re-resolves it on the \
                 next tool call (at most {}s from now), so retry once a daemon is up, which any \
                 `kin` command in that repository starts. Do not restart the MCP server; a caller \
                 cannot, and it is not what is wrong.",
                repo.display(),
                retry_in.as_secs()
            ),
        }
    }
}

/// The outcome of asking, right now, whether this process has a delegate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DelegateResolution {
    /// A daemon endpoint this process may forward to.
    Resolved(String),
    /// No endpoint, and why.
    Gap(DelegateGap),
}

/// How the re-resolution path reaches the world.
///
/// A seam rather than free functions so the bound, the backoff, and the three
/// classified gaps are assertable without a repository, a daemon, or a clock
/// on disk. `RealDelegateProbe` is the only production implementation.
pub(crate) trait DelegateProbe: Sync {
    /// The working directory the repository is looked for from.
    fn working_dir(&self) -> std::path::PathBuf;

    /// The `.kin` directory of the repository this server stands in, or `None`
    /// when there is none.
    fn repository(&self) -> Option<std::path::PathBuf>;

    /// The endpoint of a daemon **already** serving `kin_root`. Starts nothing.
    async fn running_route(&self, kin_root: &Path) -> Option<String>;
}

/// Production probe: the same two steps, in the same order, that `kin doctor`
/// answers its daemon-reachability check with.
///
/// Doctor discovers the repository from the working directory with
/// `KinLayout::discover` and then asks for the route of a daemon already
/// serving it. Doing anything else here is what let the two surfaces disagree:
/// MCP was reading a URL resolved once at startup, so it reported the daemon
/// unavailable while doctor, resolving at call time, reported it healthy.
pub(crate) struct RealDelegateProbe;

impl DelegateProbe for RealDelegateProbe {
    fn working_dir(&self) -> std::path::PathBuf {
        std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."))
    }

    fn repository(&self) -> Option<std::path::PathBuf> {
        kin_core::KinLayout::discover(&self.working_dir()).map(|layout| layout.root().to_path_buf())
    }

    async fn running_route(&self, kin_root: &Path) -> Option<String> {
        kin_daemon_spawn::running_daemon_route(kin_root).await
    }
}

/// Cooldown state for on-demand re-resolution.
///
/// The cooldown covers the route probe only, and it is keyed to the repository
/// it was measured for. Which repository this server stands in is answered
/// locally and costs no daemon traffic, so there is nothing to save by
/// remembering a stale answer to it, and a great deal to lose: a cooldown
/// installed while nothing was a Kin repository would otherwise outlive the
/// `kin init` that made one, and the first call after init is exactly the call
/// that must be answered.
#[derive(Debug, Default)]
struct ReresolveGate {
    /// The repository the fields below were measured for.
    repository: Option<std::path::PathBuf>,
    /// Earliest instant another route probe is allowed. `None` before the
    /// first one.
    next_attempt_at: Option<tokio::time::Instant>,
    /// Current cooldown window.
    backoff: Option<Duration>,
    /// What the last route probe concluded, replayed while cooling down.
    last_gap: Option<DelegateGap>,
}

impl ReresolveGate {
    /// Widen the cooldown after a route probe that found no daemon and report
    /// the window installed.
    fn back_off(&mut self, now: tokio::time::Instant) -> Duration {
        let backoff = match self.backoff {
            None => RERESOLVE_MIN_BACKOFF,
            Some(previous) => (previous * 2).min(RERESOLVE_MAX_BACKOFF),
        };
        self.backoff = Some(backoff);
        self.next_attempt_at = Some(now + backoff);
        backoff
    }

    /// Forget the cooldown and record which repository the next one is about.
    /// A delegate that resolved once, and a repository that has just appeared
    /// or changed, must not leave a widened window behind.
    fn reset_for(&mut self, repository: Option<std::path::PathBuf>) {
        self.repository = repository;
        self.next_attempt_at = None;
        self.backoff = None;
        self.last_gap = None;
    }
}

static RERESOLVE_GATE: tokio::sync::Mutex<ReresolveGate> =
    tokio::sync::Mutex::const_new(ReresolveGate {
        repository: None,
        next_attempt_at: None,
        backoff: None,
        last_gap: None,
    });

/// What this process has already been through, which decides which of the two
/// repository-present gaps a missing daemon is.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct DelegateHistory {
    /// Whether this process has ever held a delegate.
    ever_resolved: bool,
    /// Whether a repository existed at launch, or `None` when unreported.
    startup_repository_present: Option<bool>,
}

/// Ask whether this process has a delegate, re-resolving on demand.
///
/// The process-wide effects of an answer live here rather than in the core
/// below: routing later calls at a newly resolved daemon, and remembering that
/// this process has held one. Keeping them out of the core is what lets a test
/// drive resolution without a scripted daemon URL leaking into every other
/// call in the binary.
async fn resolve_delegate() -> DelegateResolution {
    let history = DelegateHistory {
        ever_resolved: DELEGATE_EVER_RESOLVED.load(std::sync::atomic::Ordering::Acquire),
        startup_repository_present: STARTUP_REPOSITORY_PRESENT.get().copied(),
    };
    let outcome = resolve_delegate_within(
        &RealDelegateProbe,
        &RERESOLVE_GATE,
        RERESOLVE_PROBE_BUDGET,
        history,
    )
    .await;
    if let DelegateResolution::Resolved(url) = &outcome {
        DELEGATE_EVER_RESOLVED.store(true, std::sync::atomic::Ordering::Release);
        install_daemon_url_override(url);
        tracing::info!(
            url = %url,
            "kin-mcp: re-resolved the repo daemon delegate on demand"
        );
    }
    outcome
}

/// [`resolve_delegate`] with its probe, gate, budget, and history supplied.
///
/// The gate is held across the probe, which serializes re-resolution the way
/// [`REVIVAL_LOCK`] serializes revival: several tool calls can observe a
/// missing delegate at once, and each running its own probe would multiply the
/// very work the cooldown exists to bound.
async fn resolve_delegate_within(
    probe: &impl DelegateProbe,
    gate: &tokio::sync::Mutex<ReresolveGate>,
    probe_budget: Duration,
    history: DelegateHistory,
) -> DelegateResolution {
    let mut gate = gate.lock().await;
    let now = tokio::time::Instant::now();

    // Which repository this server stands in is asked every time. It is a
    // local lookup, and a repository appearing under a server that started
    // without one is precisely the event the cooldown must not survive.
    let repository = probe.repository();
    if gate.repository != repository {
        gate.reset_for(repository.clone());
    }

    let Some(kin_root) = repository else {
        // No cooldown: this answer cost no daemon traffic to reach, so there
        // is nothing to rate-limit, and the next call re-asks from scratch.
        return DelegateResolution::Gap(DelegateGap::NoRepository {
            working_dir: probe.working_dir(),
        });
    };

    if let (Some(next_attempt_at), Some(last_gap)) = (gate.next_attempt_at, gate.last_gap.as_ref())
    {
        if now < next_attempt_at {
            return DelegateResolution::Gap(
                last_gap.with_retry_in(next_attempt_at.saturating_duration_since(now)),
            );
        }
    }

    // A probe that never answers must not become a stall every caller pays,
    // so it is abandoned for this round rather than awaited.
    let route = tokio::time::timeout(probe_budget, probe.running_route(&kin_root))
        .await
        .ok()
        .flatten();

    match route {
        Some(url) => {
            gate.reset_for(Some(kin_root));
            DelegateResolution::Resolved(url)
        }
        None => {
            let retry_in = gate.back_off(now);
            let repo = kin_root
                .parent()
                .unwrap_or(kin_root.as_path())
                .to_path_buf();
            let gap = classify_daemon_absent(
                repo,
                retry_in,
                history.ever_resolved,
                history.startup_repository_present,
            );
            gate.last_gap = Some(gap.clone());
            DelegateResolution::Gap(gap)
        }
    }
}

/// Which of the two repository-present gaps this is.
///
/// Only a server that has never held a delegate *and* whose launcher reported
/// no repository at startup is the startup-ordering case. An unknown startup
/// report (nobody called [`note_startup_repository`]) reads as the ordinary
/// daemon-absent case, because claiming the stronger diagnosis without the
/// evidence for it would be a guess wearing a fact's clothes.
fn classify_daemon_absent(
    repo: std::path::PathBuf,
    retry_in: Duration,
    ever_resolved: bool,
    startup_repository_present: Option<bool>,
) -> DelegateGap {
    if !ever_resolved && startup_repository_present == Some(false) {
        DelegateGap::StartupPredatesRepository { repo, retry_in }
    } else {
        DelegateGap::DaemonNotRunning { repo, retry_in }
    }
}

/// Route every later delegate call at `url` without waiting for another probe.
fn install_daemon_url_override(url: &str) {
    if let Ok(mut guard) = DAEMON_URL_OVERRIDE.lock() {
        *guard = Some(url.to_string());
    }
}

/// The delegate endpoint for this call, re-resolving when startup left none.
///
/// Every forwarded request goes through this rather than through
/// [`daemon_base_url`] directly, so recovery is a property of the delegate and
/// not of the one code path somebody remembered to add it to.
async fn resolved_daemon_base_url() -> Option<String> {
    if let Some(base) = daemon_base_url() {
        DELEGATE_EVER_RESOLVED.store(true, std::sync::atomic::Ordering::Release);
        return Some(base);
    }
    match resolve_delegate().await {
        DelegateResolution::Resolved(url) => Some(url),
        DelegateResolution::Gap(_) => None,
    }
}

// ── MCP-path idle timeout ───────────────────────────────────────────────

/// Idle timeout injected into daemons started by the MCP revival path.
///
/// Interactive MCP agent loops routinely pause longer than a minute between
/// tool calls.  The CLI default of 60 s is far too short for these sessions;
/// 30 minutes gives ample headroom while still ensuring eventual cleanup when
/// an agent session is truly abandoned.  An explicit
/// `KIN_DAEMON_IDLE_TIMEOUT_SECS` env var always overrides this at runtime.
const MCP_IDLE_TIMEOUT_SECS: &str = kin_daemon_spawn::MCP_IDLE_TIMEOUT_SECS;

/// Idle timeout to inject into a revival-spawned daemon, or `None` to inject
/// nothing.
///
/// A user-set `KIN_DAEMON_IDLE_TIMEOUT_SECS` propagates to the child on its own
/// and must never be overwritten, so this returns `None` in that case. The
/// precedence itself lives in `kin_daemon_spawn` so the CLI autostart path and
/// this one cannot disagree about it.
fn mcp_spawn_idle_timeout(user_env_is_set: bool) -> Option<&'static str> {
    kin_daemon_spawn::resolve_idle_timeout(user_env_is_set, Some(MCP_IDLE_TIMEOUT_SECS))
}

/// The spawn plan the revival path starts a daemon from.
///
/// Split out so the contract this path once diverged from is assertable without
/// spawning anything: no port is chosen here, so there is no port to hardcode.
fn mcp_spawn_plan(
    daemon_bin: std::path::PathBuf,
    working_dir: std::path::PathBuf,
    supervisor_url: Option<String>,
) -> kin_daemon_spawn::DaemonSpawnPlan {
    kin_daemon_spawn::DaemonSpawnPlan {
        daemon_bin,
        working_dir,
        idle_timeout_secs: mcp_spawn_idle_timeout(
            std::env::var_os("KIN_DAEMON_IDLE_TIMEOUT_SECS").is_some(),
        )
        .map(str::to_string),
        supervisor_url,
    }
}

// ── Unrecoverable-daemon error class ────────────────────────────────────

/// Prefix marking the "the repo daemon is gone and could not be brought back"
/// error class.
///
/// Every delegate failure that leaves the session unable to reach a daemon is
/// tagged with this, so an agent (or a wrapping client) can tell an
/// unrecoverable lifecycle failure apart from an ordinary tool error such as a
/// bad argument or an HTTP 4xx from a live daemon. The two are handled
/// completely differently: the first needs an operator restart, the second
/// needs a corrected call.
pub const DAEMON_EXITED_RESTART_REQUIRED: &str = "repo daemon exited; restart required";

/// The prefix for a daemon that stopped answering in the middle of a call.
///
/// It exists for the same reason the one above does: the envelope boundary has only the
/// message to go on, and it has to be able to tell daemon loss from a live daemon refusing
/// a call. The text it replaces opened `daemon <operation> failed:` and then handed the
/// caller a bare transport URL, which named neither the daemon nor the cause.
pub const DAEMON_STOPPED_MID_REQUEST: &str = "repo daemon stopped answering mid-request";

/// Marker inside a revival error meaning the replacement daemon is alive and
/// still loading, rather than dead.
///
/// The two need different remediations and got the same one. A daemon mid-boot
/// answers nothing yet, which reads exactly like a daemon that failed to start,
/// and the caller was told to restart `kin mcp start`. Restarting the MCP
/// server while its child is mid-boot is the one action that makes this worse:
/// the work already done is discarded and the next call starts the same wait
/// again. Waiting was always the fix, and on a store whose daemon takes a
/// minute to open its graph, waiting is the ONLY fix.
pub const DAEMON_STILL_STARTING: &str = "daemon is still starting";

/// Whether a revival error describes a daemon that is booting rather than one
/// that is gone.
pub fn is_still_starting_error(message: &str) -> bool {
    message.contains(DAEMON_STILL_STARTING)
}

/// What this store has recorded about daemons of its own that were killed.
///
/// Read from the store rather than remembered in this process, because the
/// daemon that died may have been started by a different one: an out-of-band
/// `kin` command boots a daemon this MCP server then talks to, and a record
/// only one of them could see would be missing exactly when it is wanted.
pub(crate) fn recorded_daemon_kill() -> Option<kin_daemon_spawn::DaemonKillRecord> {
    let kin_dir = discover_kin_dir()?;
    // A death this store has not settled yet answers first, because settlement
    // happens at the next daemon start and the agent reading this error is
    // being served by a session that may not start one. The tally alone would
    // have said nothing at exactly the moment a daemon had just been killed.
    kin_daemon_spawn::peek_unwatched_daemon_death(&kin_dir)
        .or_else(|| kin_daemon_spawn::read_daemon_kill_record(&kin_dir))
}

/// Whether this store's enrichment sweeps are currently suspended.
///
/// Read from the store on every call rather than remembered, for the same
/// reason the kill record is and one more: the tally clears when a sweep
/// completes, and a server that cached this would keep telling agents the
/// producer was off after it had come back on.
pub(crate) fn suspended_sweep() -> Option<kin_daemon_spawn::SuspendedSweep> {
    kin_daemon_spawn::SuspendedSweep::read(&discover_kin_dir()?)
}

/// What this store recorded when its daemon held heavy work back for want of
/// memory, oldest to newest.
///
/// Durable refusals record past decisions and cannot qualify a response until
/// either [`outstanding_memory_pressure_refusal`] reconciles the embedding
/// backlog or the typed graph-status report supplies its own exact coverage.
/// Reading the whole set is load-bearing: a completed embed refusal must not
/// hide an outstanding LSP or future-work refusal stored beside it.
pub(crate) fn recorded_memory_pressure_refusals() -> Vec<kin_core::memory_pressure::PressureRefusal>
{
    discover_kin_dir()
        .map(|kin_root| kin_core::memory_pressure::PressureRefusal::read_all(&kin_root))
        .unwrap_or_default()
}

/// Keep a durable pressure refusal only while it still describes outstanding
/// work for the exact embedding observation a daemon returned.
///
/// A missing observation preserves the record. It can mean the daemon is old,
/// unavailable, or returned a shape this MCP build cannot read, and none of
/// those is evidence that refused work finished. The canonical predicate also
/// keeps every non-embedding refusal visible regardless of the embedding count.
pub(crate) fn pressure_refusal_for_coverage(
    refusal: kin_core::memory_pressure::PressureRefusal,
    coverage: Option<kin_core::memory_pressure::EmbeddingCoverage>,
) -> Option<kin_core::memory_pressure::PressureRefusal> {
    coverage
        .map(|coverage| refusal.describes_outstanding_work(coverage))
        .unwrap_or(true)
        .then_some(refusal)
}

/// Qualify durable pressure state against the graph-status report that will be
/// returned to the caller.
///
/// The typed report is the selected-graph authority, so graph status must not
/// substitute a second `/commands/resources` sample that can be older, newer,
/// unavailable, or scoped differently. Non-embedding work remains visible.
/// An embedding refusal published in the same wall-clock second as the report
/// observation stays visible for this response because second-resolution
/// timestamps cannot prove that the report observed that exact work cycle.
pub(crate) fn pressure_refusal_for_selected_graph(
    refusals: &[kin_core::memory_pressure::PressureRefusal],
    coverage: kin_core::memory_pressure::EmbeddingCoverage,
    observation_started_at_unix: u64,
) -> Option<kin_core::memory_pressure::PressureRefusal> {
    let embed_work = kin_core::memory_pressure::HeavyWork::EmbedBatch.id();
    if let Some(refusal) = refusals
        .iter()
        .rev()
        .find(|refusal| refusal.work != embed_work)
    {
        return Some(refusal.clone());
    }
    let refusal = refusals
        .iter()
        .rev()
        .find(|refusal| refusal.work == embed_work)?
        .clone();
    if refusal.at_unix >= observation_started_at_unix {
        return Some(refusal);
    }
    pressure_refusal_for_coverage(refusal, Some(coverage))
}

/// The wall-clock second at which an external daemon observation starts.
///
/// [`PressureRefusal`] records seconds rather than a per-write nonce. Passing
/// this value into the race guard below keeps the clock itself outside the
/// policy seam, so equal-record ambiguity is deterministic in tests.
pub(crate) fn current_unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or_default()
}

/// Apply an exact whole-coverage observation only to the one pressure record it
/// can settle.
///
/// LSP and future work ids have independent backlogs, so they must not pay for
/// a graph-wide embedding-status request and must not be cleared by its result.
async fn outstanding_pressure_refusal_with<F, Fut, R>(
    refusals: Vec<kin_core::memory_pressure::PressureRefusal>,
    observation_started_at_unix: u64,
    observe_embedding_coverage: F,
    read_current_refusal: R,
) -> Option<kin_core::memory_pressure::PressureRefusal>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Option<kin_core::memory_pressure::EmbeddingCoverage>>,
    R: FnOnce() -> Vec<kin_core::memory_pressure::PressureRefusal>,
{
    let embed_work = kin_core::memory_pressure::HeavyWork::EmbedBatch.id();
    if let Some(refusal) = refusals
        .iter()
        .rev()
        .find(|refusal| refusal.work != embed_work)
    {
        return Some(refusal.clone());
    }
    let refusal = refusals
        .into_iter()
        .rev()
        .find(|refusal| refusal.work == embed_work)?;
    let coverage = observe_embedding_coverage().await;

    // The record is last-writer-wins. A new LSP, unknown-work, or embedding
    // refusal can replace the one above while the bounded HTTP observation is
    // in flight, and suppressing that newer fact with the older record's
    // completion would be the least conservative possible race. A changed record is
    // returned without applying an observation that was not made for it.
    // Equality alone is not enough: the record timestamp has one-second
    // precision, so a clear followed by an identical refusal in the same
    // second can compare equal to the record whose backlog was observed. An
    // equal record stamped at or after observation start stays visible for
    // this response; a later call can settle it after the clock advances.
    // `None` remains conservative too because a clear followed by a new
    // publication can interleave with this cross-process read. A true clear is
    // observed at the start of the next call.
    let current_refusals = read_current_refusal();
    if let Some(refusal) = current_refusals
        .iter()
        .rev()
        .find(|refusal| refusal.work != embed_work)
    {
        return Some(refusal.clone());
    }
    let current_refusal = current_refusals
        .into_iter()
        .rev()
        .find(|refusal| refusal.work == embed_work);
    match current_refusal {
        Some(current) if current == refusal && refusal.at_unix < observation_started_at_unix => {
            pressure_refusal_for_coverage(refusal, coverage)
        }
        Some(current) => Some(current),
        None => Some(refusal),
    }
}

/// Read only the exact coverage tuple needed to decide whether a completed
/// embedding refusal still qualifies this response. Missing and malformed fields remain
/// unknown rather than being coerced to zero for compatibility with older
/// daemons.
fn embedding_coverage_from_resources(
    value: &serde_json::Value,
) -> Option<kin_core::memory_pressure::EmbeddingCoverage> {
    let runtime = value.get("embed_runtime")?;
    let as_usize = |field: &str| {
        runtime
            .get(field)?
            .as_u64()
            .and_then(|value| usize::try_from(value).ok())
    };
    let coverage = kin_core::memory_pressure::EmbeddingCoverage {
        pending: as_usize("embeddings_pending")?,
        indexed: as_usize("embeddings_indexed")?,
        total: as_usize("embeddings_total")?,
    };
    (coverage.indexed <= coverage.total).then_some(coverage)
}

/// Best-effort, bounded observation of the selected graph's embedding backlog.
///
/// This endpoint can inspect the retrievable key set, so it is intentionally
/// not part of the ordinary envelope path. It is called only when an
/// `embed-batch` refusal record already exists. The caller's session header is
/// retained so the observation qualifies the same selected graph as the tool
/// answer.
async fn fetch_embedding_coverage_from_resources_at(
    client: &reqwest::Client,
    base: &str,
    arguments: &HashMap<String, serde_json::Value>,
) -> Option<kin_core::memory_pressure::EmbeddingCoverage> {
    let request = with_session_header(
        with_auth(client.post(format!("{base}/commands/resources"))),
        arguments,
    )
    .timeout(Duration::from_secs(3))
    .json(&serde_json::json!({ "json": false }));
    let response = request.send().await.ok()?;
    if !response.status().is_success() {
        return None;
    }
    let value = response.json::<serde_json::Value>().await.ok()?;
    embedding_coverage_from_resources(&value)
}

async fn fetch_embedding_coverage_from_resources(
    arguments: &HashMap<String, serde_json::Value>,
) -> Option<kin_core::memory_pressure::EmbeddingCoverage> {
    let client = daemon_client().await?;
    let base = daemon_base_url()?;
    fetch_embedding_coverage_from_resources_at(&client, &base, arguments).await
}

/// What this store currently refuses for memory, filtered by exact daemon
/// state when and only when the record is for embedding work.
///
/// The record is read first, so normal calls and non-embedding refusals perform
/// no extra request. A failed or legacy observation preserves the refusal.
pub(crate) async fn outstanding_memory_pressure_refusal(
    arguments: &HashMap<String, serde_json::Value>,
) -> Option<kin_core::memory_pressure::PressureRefusal> {
    let refusals = recorded_memory_pressure_refusals();
    let observation_started_at_unix = current_unix_seconds();
    outstanding_pressure_refusal_with(
        refusals,
        observation_started_at_unix,
        || fetch_embedding_coverage_from_resources(arguments),
        recorded_memory_pressure_refusals,
    )
    .await
}

/// What this store records about being below its own relation census.
pub(crate) fn relation_census_hold() -> Option<kin_core::relation_census::CensusHold> {
    kin_core::relation_census::CensusHold::read(&discover_kin_dir()?)
}

/// What this store's last enrichment sweep could not publish.
///
/// Read fresh on every call for the reason the others are: the record is
/// retired by the next sweep that comes out clean, and a server that cached it
/// would keep telling agents the graph was short of edges after a later pass
/// had filled them.
pub(crate) fn enrichment_shortfall() -> Option<kin_daemon_spawn::RefusedEnrichment> {
    kin_daemon_spawn::RefusedEnrichment::read(&discover_kin_dir()?)
}

/// The recorded cause and a remediation the caller can perform, ready to append
/// to an error about a daemon that stopped answering.
///
/// Empty when the store has recorded nothing, which leaves every message on a
/// host that has never lost a daemon byte for byte what it was. A record says
/// what has happened to this store's daemons; it is not a claim about the cause
/// of the request that just failed, and the wording keeps those apart.
fn recorded_kill_detail(record: Option<&kin_daemon_spawn::DaemonKillRecord>) -> String {
    match record {
        Some(record) => format!(" {}", record.summary()),
        None => String::new(),
    }
}

/// The advice that closes an error about a daemon that could not be brought
/// back.
///
/// "Restart `kin mcp start` to recover" is addressed to whoever owns the MCP
/// server process, and inside an MCP session nobody does: the agent reading it
/// is being served by that very process, and the stranger who met this error
/// had to leave the tool surface entirely to act on it. When the store has
/// recorded why its daemons keep dying, the record's own remediation replaces
/// that advice, because every action in it is one the caller can take.
fn daemon_gone_advice(record: Option<&kin_daemon_spawn::DaemonKillRecord>) -> String {
    match record {
        Some(record) => record.summary(),
        None => "Restart `kin mcp start` to recover.".to_string(),
    }
}

/// The message for a daemon that stopped answering and could not be replaced.
pub(crate) fn revival_failed_message(
    operation: &str,
    daemon_url: &str,
    first_err: &str,
    revive_err: &str,
    record: Option<&kin_daemon_spawn::DaemonKillRecord>,
) -> String {
    format!(
        "{DAEMON_EXITED_RESTART_REQUIRED}: {operation}: daemon at {daemon_url} is not \
         responding ({first_err}); revival failed: {revive_err}. {}",
        daemon_gone_advice(record)
    )
}

/// The message for a replacement daemon that started and still could not answer.
pub(crate) fn revived_retry_failed_message(
    operation: &str,
    new_url: &str,
    detail: &str,
    record: Option<&kin_daemon_spawn::DaemonKillRecord>,
) -> String {
    format!(
        "{DAEMON_EXITED_RESTART_REQUIRED}: {operation}: daemon was revived at {new_url} but the \
         retry still failed: {detail}. Check `kin daemon status`.{}",
        recorded_kill_detail(record)
    )
}

/// The message for a connection that broke while it was carrying a request.
pub(crate) fn transport_dropped_message(
    operation: &str,
    error: &str,
    record: Option<&kin_daemon_spawn::DaemonKillRecord>,
) -> String {
    format!(
        "{DAEMON_STOPPED_MID_REQUEST}: {operation}: {error}{}",
        recorded_kill_detail(record)
    )
}

/// Does this delegate error mean the repo daemon is gone rather than that the
/// call itself was rejected?
///
/// Callers that retry, degrade, or prompt for an operator restart need the two
/// apart: only this class is fixed by restarting a daemon, and restarting one
/// over an ordinary tool error is wasted work.
pub fn is_daemon_exited_error(message: &str) -> bool {
    message.starts_with(DAEMON_EXITED_RESTART_REQUIRED)
}

/// Did this delegate error mean the daemon stopped answering, by any of the routes?
///
/// [`is_daemon_exited_error`] answers a narrower question, the one a caller deciding
/// whether to restart wants: the revival was attempted and is spent. The envelope wants
/// the wider one, because `daemon_unreachable` absent reads to a client as a live daemon,
/// and a connection that broke while it was carrying the request is not a live daemon. It
/// is what a daemon killed mid-answer looks like from here, it is the first error a caller
/// meets when the kernel takes the daemon out, and keying the flag on the narrow predicate
/// sent exactly that shape out looking healthy.
pub fn is_daemon_loss_error(message: &str) -> bool {
    is_daemon_exited_error(message) || message.starts_with(DAEMON_STOPPED_MID_REQUEST)
}

/// Bearer token the daemon expects on non-public routes.
///
/// Resolution mirrors the daemon and CLI client exactly so all three agree in
/// every case: an explicit `KIN_DAEMON_AUTH_TOKEN` env override wins, otherwise
/// the auto-provisioned per-install loopback token at `.kin/daemon.token`
/// (which the daemon writes via `ensure_loopback_token`). When neither is
/// present we send no header — harmless while enforcement is flag-gated, and
/// correct once it is enabled.
fn daemon_auth_token() -> Option<String> {
    resolve_daemon_auth_token(
        std::env::var("KIN_DAEMON_AUTH_TOKEN").ok(),
        discover_kin_dir().as_deref(),
    )
}

/// Pure resolution of the daemon bearer token, factored out of
/// [`daemon_auth_token`] so the precedence is unit-testable without mutating
/// process env or cwd.
///
/// Precedence mirrors the daemon's `resolve_serve_auth_token` and the CLI's
/// `resolve_daemon_auth_token` exactly so all three agree in every case: an
/// explicit `KIN_DAEMON_AUTH_TOKEN` override wins, otherwise the
/// auto-provisioned per-install loopback token at `<kin_dir>/daemon.token`
/// (which the daemon writes via `ensure_loopback_token`). Empty/whitespace
/// values — env or file — are treated as absent so a blank file never shadows
/// the env override and never produces a `Bearer ` header with no secret.
fn resolve_daemon_auth_token(env_token: Option<String>, kin_dir: Option<&Path>) -> Option<String> {
    if let Some(env_token) = env_token {
        let env_token = env_token.trim().to_string();
        if !env_token.is_empty() {
            return Some(env_token);
        }
    }
    let token_path = kin_dir?.join("daemon.token");
    let contents = std::fs::read_to_string(token_path).ok()?;
    let token = contents.trim().to_string();
    (!token.is_empty()).then_some(token)
}

/// Walk up from the working directory to the repo's `.kin` directory.
///
/// This intentionally does not use `KinLayout::discover`, whose `KIN_DAEMON_URL`
/// short-circuit assumes the cwd is the repo root; the token file lives in the
/// repo `.kin` even when an agent runs from a subdirectory, so we walk up to
/// find it.
fn discover_kin_dir() -> Option<std::path::PathBuf> {
    let mut current = std::env::current_dir().ok()?;
    loop {
        let candidate = current.join(".kin");
        if candidate.is_dir() {
            return Some(candidate);
        }
        if !current.pop() {
            return None;
        }
    }
}

/// Attach the daemon bearer token to a request when auth is configured.
///
/// `pub(crate)`: also used by `handlers::common`'s spine federation client,
/// which talks to the daemon's `/spine/*` routes directly rather than
/// through this module's own forwarding helpers.
pub(crate) fn with_auth(request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    match daemon_auth_token() {
        Some(token) => request.bearer_auth(token),
        None => request,
    }
}

/// Attach the session header (from explicit args or `KIN_SESSION_ID`) to a
/// forwarded request so the daemon resolves the caller's session graph.
fn with_session_header(
    request: reqwest::RequestBuilder,
    arguments: &HashMap<String, serde_json::Value>,
) -> reqwest::RequestBuilder {
    if let Some(session_id) = optional_string(arguments, "session_id") {
        return request.header("X-Kin-Session", session_id);
    }
    if let Ok(session_id) = std::env::var("KIN_SESSION_ID") {
        if !session_id.trim().is_empty() {
            return request.header("X-Kin-Session", session_id);
        }
    }
    request
}

fn text_result_from_value(value: serde_json::Value) -> Result<ToolCallResult, String> {
    let json = serde_json::to_string_pretty(&value)
        .map_err(|e| format!("daemon response serialization failed: {e}"))?;
    Ok(ToolCallResult::text(json))
}

fn required_string(args: &HashMap<String, serde_json::Value>, key: &str) -> Result<String, String> {
    args.get(key)
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .ok_or_else(|| format!("missing required parameter: {key}"))
}

fn optional_string<'a>(args: &'a HashMap<String, serde_json::Value>, key: &str) -> Option<&'a str> {
    args.get(key).and_then(|value| value.as_str())
}

fn optional_u32(args: &HashMap<String, serde_json::Value>, key: &str) -> Option<u32> {
    args.get(key)
        .and_then(|value| value.as_u64())
        .map(|value| value as u32)
}

// ── get_entity_source failure memo ──────────────────────────────────────
//
// `get_entity_source` / `get_entity_body` are pure functions of (entity_id,
// graph generation): for a given graph, an ID either resolves to a body or it
// does not. The observed agent-loop failure mode is calling the tool on a
// hallucinated, invented, or stale ID, getting a failure, and then retrying the
// same ID (or probing adjacent ones), which burns tool-call budget. Memoizing
// the failure lets an identical repeated call short-circuit locally instead of
// paying another daemon round-trip.
//
// The memo is bounded and keyed by (session, entity_id), and is dropped whenever
// the graph generation marker advances — a re-index can resurrect a previously
// absent ID, so a stale negative must not outlive the graph it described.

/// Maximum number of remembered failures across all sessions. Bounds memory for
/// long-lived agent sessions; eviction is oldest-first.
const ENTITY_SOURCE_MEMO_CAP: usize = 512;

/// Bounded per-session memo of `get_entity_source` failures, valid for a single
/// graph generation.
struct EntitySourceFailureMemo {
    generation: u64,
    entries: HashMap<(String, String), String>,
    order: std::collections::VecDeque<(String, String)>,
}

impl EntitySourceFailureMemo {
    fn new(generation: u64) -> Self {
        Self {
            generation,
            entries: HashMap::new(),
            order: std::collections::VecDeque::new(),
        }
    }

    /// Drop every entry and rebind to `generation`.
    fn reset(&mut self, generation: u64) {
        self.generation = generation;
        self.entries.clear();
        self.order.clear();
    }

    /// Cached failure message for `key` at `generation`, if any. A generation
    /// change invalidates the whole memo before the lookup.
    fn get(&mut self, generation: u64, key: &(String, String)) -> Option<String> {
        if generation != self.generation {
            self.reset(generation);
            return None;
        }
        self.entries.get(key).cloned()
    }

    /// Remember `message` as the failure for `key` at `generation`. First write
    /// for a key wins; the oldest entry is evicted once the cap is reached.
    fn insert(&mut self, generation: u64, key: (String, String), message: String) {
        if generation != self.generation {
            self.reset(generation);
        }
        if self.entries.contains_key(&key) {
            return;
        }
        if self.entries.len() >= ENTITY_SOURCE_MEMO_CAP {
            if let Some(evicted) = self.order.pop_front() {
                self.entries.remove(&evicted);
            }
        }
        self.order.push_back(key.clone());
        self.entries.insert(key, message);
    }
}

static ENTITY_SOURCE_MEMO: OnceLock<std::sync::Mutex<EntitySourceFailureMemo>> = OnceLock::new();

fn entity_source_memo() -> &'static std::sync::Mutex<EntitySourceFailureMemo> {
    ENTITY_SOURCE_MEMO.get_or_init(|| std::sync::Mutex::new(EntitySourceFailureMemo::new(0)))
}

/// Session identity for the memo key. Mirrors [`with_session_header`]: an
/// explicit `session_id` argument wins, else `KIN_SESSION_ID`, else a shared
/// process-global bucket (the common single-session MCP process case).
fn session_key(arguments: &HashMap<String, serde_json::Value>) -> String {
    if let Some(session_id) = optional_string(arguments, "session_id") {
        return session_id.to_string();
    }
    if let Ok(session_id) = std::env::var("KIN_SESSION_ID") {
        let trimmed = session_id.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    String::new()
}

/// Current graph generation from the local marker the daemon maintains at
/// `<kin_dir>/kindb/head-generation`. Read directly off disk (no daemon round-trip);
/// a missing or unreadable marker reads as generation 0, which still gives a
/// stable within-session memo, just without cross-generation invalidation.
fn current_graph_generation() -> u64 {
    let Some(kin_dir) = discover_kin_dir() else {
        return 0;
    };
    std::fs::read_to_string(kin_core::KinLayout::new(kin_dir).kindb_head_generation_path())
        .ok()
        .and_then(|contents| contents.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

/// Extract a cacheable failure message from a forwarded tool result. Only
/// error results are cacheable — a success or a non-result is never memoized.
fn cacheable_failure_message(result: Option<&ToolCallResult>) -> Option<String> {
    let result = result?;
    if result.is_error != Some(true) {
        return None;
    }
    result.content.first().map(|block| match block {
        ContentBlock::Text { text } => text.clone(),
    })
}

/// Forward `get_entity_source` / `get_entity_body` through the failure memo.
///
/// On a cache hit the remembered failure is returned without contacting the
/// daemon; otherwise the call is forwarded and a resulting failure is recorded
/// for the current graph generation. Calls without a concrete `entity_id` are
/// forwarded unmemoized (there is nothing stable to key on).
async fn forward_entity_source_memoized(
    name: &str,
    arguments: &HashMap<String, serde_json::Value>,
) -> Result<Option<ToolCallResult>, String> {
    let Some(entity_id) = optional_string(arguments, "entity_id").map(str::to_string) else {
        return forward_mcp_tool_call(name, arguments).await;
    };
    let key = (session_key(arguments), entity_id);
    let generation = current_graph_generation();

    if let Ok(mut memo) = entity_source_memo().lock() {
        if let Some(cached) = memo.get(generation, &key) {
            debug!(tool = name, "get_entity_source failure served from memo");
            return Ok(Some(ToolCallResult::error(cached)));
        }
    }

    let result = forward_mcp_tool_call(name, arguments).await?;

    if let Some(message) = cacheable_failure_message(result.as_ref()) {
        if let Ok(mut memo) = entity_source_memo().lock() {
            memo.insert(generation, key, message);
        }
    }
    Ok(result)
}

/// Read the capabilities a client declared for itself, or `None` when it
/// declared none. See the sibling in `handlers::common` for why the two must
/// not collapse into one.
fn parse_capabilities(args: &HashMap<String, serde_json::Value>) -> Option<SessionCapabilities> {
    let obj = args
        .get("capabilities")
        .and_then(|value| value.as_object())?;
    Some(SessionCapabilities {
        can_read: obj
            .get("can_read")
            .and_then(|value| value.as_bool())
            .unwrap_or(true),
        can_write: obj
            .get("can_write")
            .and_then(|value| value.as_bool())
            .unwrap_or(false),
        can_execute: obj
            .get("can_execute")
            .and_then(|value| value.as_bool())
            .unwrap_or(false),
        can_branch: obj
            .get("can_branch")
            .and_then(|value| value.as_bool())
            .unwrap_or(false),
        can_commit: obj
            .get("can_commit")
            .and_then(|value| value.as_bool())
            .unwrap_or(false),
        max_concurrent_intents: obj
            .get("max_concurrent_intents")
            .and_then(|value| value.as_u64())
            .map(|value| value as usize)
            .unwrap_or(1),
    })
}

fn scope_to_string(value: &serde_json::Value) -> Result<String, String> {
    if let Some(scope) = value.as_str() {
        return Ok(scope.to_string());
    }
    let Some(obj) = value.as_object() else {
        return Err(
            "invalid scope: expected string, {\"Entity\":\"uuid\"}, {\"Contract\":\"uuid\"}, or {\"Artifact\":\"path\"}"
                .to_string(),
        );
    };
    if let Some(entity) = obj.get("Entity").and_then(|value| value.as_str()) {
        return Ok(format!("entity:{entity}"));
    }
    if let Some(contract) = obj.get("Contract").and_then(|value| value.as_str()) {
        return Ok(format!("contract:{contract}"));
    }
    if let Some(artifact) = obj.get("Artifact").and_then(|value| value.as_str()) {
        return Ok(format!("file:{artifact}"));
    }
    Err(
        "invalid scope: expected string, {\"Entity\":\"uuid\"}, {\"Contract\":\"uuid\"}, or {\"Artifact\":\"path\"}"
            .to_string(),
    )
}

fn scope_strings(args: &HashMap<String, serde_json::Value>) -> Result<Vec<String>, String> {
    let scopes = args
        .get("scopes")
        .and_then(|value| value.as_array())
        .ok_or_else(|| "missing required parameter: scopes".to_string())?;
    scopes.iter().map(scope_to_string).collect()
}

// ── Daemon revival seam ─────────────────────────────────────────────────

/// Error returned by [`DaemonCallSeam::call_tool`].
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum DaemonCallError {
    /// Transport-level failure that reached no listener (connection refused,
    /// TCP reset, connect timeout) — the daemon may have exited. The revival
    /// path will attempt exactly one restart before surfacing an error, and
    /// only when nothing proves the recorded daemon is still alive.
    ConnectionLost(String),
    /// The request was sent and no answer arrived inside this attempt's budget.
    ///
    /// Kept apart from [`Self::ConnectionLost`] on purpose. A deadline measures
    /// this caller's patience, not the daemon's health: the connection was
    /// established, so something is listening, and a large graph load or a long
    /// enrichment pass is the ordinary reason an answer is late. Folding it into
    /// connection loss is what turned slow daemons into dead ones.
    Timeout(String),
    /// The daemon answered that it is still opening its state.
    ///
    /// Positive evidence of life, and the strongest kind: the daemon described
    /// its own condition. Never a reason to revive — the process that would be
    /// replaced is the one holding the repository lock the replacement needs.
    Warming(String),
    /// HTTP-level or protocol failure — the daemon responded but signalled an
    /// error.  Revival is not attempted; the error is surfaced immediately.
    DaemonError(String),
}

/// Classify a `reqwest` send failure.
///
/// The order matters. reqwest reports a connect timeout as both `is_connect`
/// and `is_timeout`, so connect-class is tested first: failing to establish a
/// loopback connection at all is evidence about the *endpoint*, while a
/// request-class timeout on an established connection is evidence only about
/// how long this caller waited. Everything else is a protocol-level failure
/// from a daemon that did respond.
fn classify_send_error(operation: &str, error: reqwest::Error) -> DaemonCallError {
    if error.is_connect() {
        DaemonCallError::ConnectionLost(error.to_string())
    } else if error.is_timeout() {
        DaemonCallError::Timeout(error.to_string())
    } else {
        // A send that was neither refused nor timed out is a connection that
        // broke while it was carrying this request, which is what a daemon
        // killed mid-answer looks like from here. It reached the caller as a
        // bare URL and nothing else; the recorded cause is appended so the
        // fourth failure shape names memory too.
        DaemonCallError::DaemonError(transport_dropped_message(
            operation,
            &error.to_string(),
            recorded_daemon_kill().as_ref(),
        ))
    }
}

/// Ability to restart a dead repo daemon and report its new base URL.
///
/// Split from [`DaemonCallSeam`] so every forwarded request — session, intent,
/// traffic, status, and MCP tool calls alike — shares one revival policy
/// through [`attempt_with_revival`], rather than revival being a property of
/// the tool-call path only.
pub(crate) trait DaemonReviver: Sync {
    /// Attempt to revive a dead daemon and return its new base URL.
    async fn revive(&self) -> Result<String, String>;

    /// Positive evidence that the daemon at `base` is alive, consulted before
    /// [`Self::revive`] is allowed to run.
    ///
    /// Part of the revival policy rather than a free function so the veto is
    /// reachable in tests: proving that a live daemon is spared needs a witness
    /// that reports life, and no single loopback port can both refuse
    /// connections and answer a probe.
    async fn is_provably_alive(&self, base: &str) -> bool {
        daemon_is_provably_alive(base).await
    }
}

/// Abstraction over daemon communication and revival used by
/// [`forward_mcp_with_seam`].
///
/// The production implementation ([`RealDaemonSeam`]) makes real HTTP requests
/// and can spawn a new daemon process via `std::process::Command`.  Tests
/// inject a controlled stub to exercise the revival state machine without
/// touching the network or spawning any processes.
pub(crate) trait DaemonCallSeam: DaemonReviver {
    /// Attempt a single MCP tool call against the daemon at `base`, waiting at
    /// most `patience` for an answer.
    ///
    /// The budget is per attempt rather than per client so the ladder can widen
    /// it once liveness is established, instead of one flat deadline deciding
    /// both how long a healthy call may take and when a daemon is presumed
    /// dead.
    ///
    /// Returns:
    /// - `Ok(Some(result))` on success.
    /// - `Ok(None)` when no HTTP client can be built at all (graceful no-op).
    /// - `Err(ConnectionLost(_))` for transport failures — warrants revival.
    /// - `Err(Timeout(_))` when the budget ran out — warrants patience.
    /// - `Err(Warming(_))` when the daemon is still opening — warrants waiting.
    /// - `Err(DaemonError(_))` for HTTP/protocol failures — no revival.
    async fn call_tool(
        &self,
        base: &str,
        name: &str,
        args: &HashMap<String, serde_json::Value>,
        patience: Duration,
    ) -> Result<Option<ToolCallResult>, DaemonCallError>;
}

/// Production implementation of [`DaemonCallSeam`].
pub(crate) struct RealDaemonSeam;

impl DaemonReviver for RealDaemonSeam {
    async fn revive(&self) -> Result<String, String> {
        revive_mcp_daemon().await
    }
}

impl DaemonCallSeam for RealDaemonSeam {
    async fn call_tool(
        &self,
        base: &str,
        name: &str,
        args: &HashMap<String, serde_json::Value>,
        patience: Duration,
    ) -> Result<Option<ToolCallResult>, DaemonCallError> {
        let Some(client) = daemon_client().await else {
            return Ok(None);
        };
        let request = client
            .post(format!("{}/mcp/tools/call", base))
            .timeout(patience)
            .json(&serde_json::json!({ "name": name, "arguments": args }));
        let request = with_session_header(with_auth(request), args);
        let resp = request
            .send()
            .await
            .map_err(|e| classify_send_error("MCP tool call", e))?;
        if !resp.status().is_success() {
            return Err(daemon_http_error("MCP tool call", resp).await);
        }
        let result = resp.json::<ToolCallResult>().await.map_err(|e| {
            DaemonCallError::DaemonError(format!("daemon MCP tool call response parse failed: {e}"))
        })?;
        Ok(Some(result))
    }
}

// ── Revival helpers ─────────────────────────────────────────────────────

/// Locate the `kin-daemon` binary for the revival path.
///
/// Resolution order mirrors `lifecycle.rs::find_daemon_binary` so the MCP
/// revival path finds the same binary without a `kin-daemon` crate dep
/// (which would be circular: `kin-daemon` already depends on `kin-mcp`).
fn find_mcp_daemon_binary() -> Option<std::path::PathBuf> {
    let explicit = std::env::var_os("KIN_DAEMON_BIN");
    let executable = std::env::current_exe().ok();
    let search_path = std::env::var_os("PATH");
    find_mcp_daemon_binary_from(
        explicit.as_deref(),
        executable.as_deref(),
        search_path.as_deref(),
    )
}

#[cfg(windows)]
const MCP_DAEMON_BINARY_FILE_NAME: &str = "kin-daemon.exe";
#[cfg(not(windows))]
const MCP_DAEMON_BINARY_FILE_NAME: &str = "kin-daemon";

fn find_mcp_daemon_binary_from(
    explicit: Option<&std::ffi::OsStr>,
    executable: Option<&std::path::Path>,
    search_path: Option<&std::ffi::OsStr>,
) -> Option<std::path::PathBuf> {
    if let Some(explicit) = explicit {
        let path = std::path::PathBuf::from(explicit);
        if path.exists() {
            return Some(path);
        }
    }
    if let Some(exe) = executable {
        let sibling = exe.with_file_name(MCP_DAEMON_BINARY_FILE_NAME);
        if sibling.exists() {
            return Some(sibling);
        }
        // Dev/test layout: .../target/<profile>/deps/ → .../target/<profile>/
        if exe
            .parent()
            .and_then(|p| p.file_name())
            .is_some_and(|name| name == "deps")
        {
            if let Some(target_dir) = exe.parent().and_then(|p| p.parent()) {
                let target_sibling = target_dir.join(MCP_DAEMON_BINARY_FILE_NAME);
                if target_sibling.exists() {
                    return Some(target_sibling);
                }
            }
        }
    }
    // Walk PATH manually (avoids `which` crate dep).
    let path_var = search_path?;
    for dir in std::env::split_paths(&path_var) {
        let candidate = dir.join(MCP_DAEMON_BINARY_FILE_NAME);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

fn configured_managed_install_root() -> Option<std::path::PathBuf> {
    for key in ["KIN_HOME", "KIN_DIR"] {
        if let Some(value) = std::env::var_os(key).filter(|value| !value.is_empty()) {
            return Some(std::path::PathBuf::from(value));
        }
    }
    kin_core::layout::global_home_kin_dir()
}

/// Whether `KIN_NO_DAEMON` forbids this process from starting daemon processes.
///
/// Same accepted spellings as the CLI's transient-bool reader, so the one
/// contract ("this process spawns no daemon") cannot mean different things on
/// the two sides of the transport. The revival path consults it because
/// revival is a spawn: a scheduled probe that sets `KIN_NO_DAEMON` and then
/// issues a `tools/call` against a dead daemon's recorded route would
/// otherwise start a full daemon from inside the "no daemon" session, which
/// is exactly the boot-time spawn storm of the 2026-08-15 incident
/// (FIR-2341).
fn no_daemon_spawns_requested() -> bool {
    std::env::var("KIN_NO_DAEMON")
        .ok()
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

/// Spawn a fresh daemon and wait for it to pass `/health`.
///
/// Uses the MCP-path idle timeout (30 min) unless the user has set
/// `KIN_DAEMON_IDLE_TIMEOUT_SECS` explicitly.  On success, writes the new
/// base URL into [`DAEMON_URL_OVERRIDE`] so all subsequent delegate calls
/// are routed to the revived daemon automatically.
///
/// Every decision about *how* the daemon is started belongs to
/// [`kin_daemon_spawn`], which the CLI autostart path uses too. This path once
/// carried its own copy and drifted from it twice: it reserved a port and
/// passed the number (reopening the reserve-release-rebind race the port file
/// exists to close), fell back to a hardcoded port when reservation failed,
/// never cleared a stale port record, and never registered the daemon it
/// started with the supervisor.
async fn revive_mcp_daemon() -> Result<String, String> {
    // The no-spawn contract is checked before any revival work, including the
    // lock: a probe session must be able to observe "the daemon is dead" as an
    // honest answer without this path quietly replacing the daemon it was
    // asked about. Nothing is spawned, nothing is cleared, nothing is
    // registered.
    if no_daemon_spawns_requested() {
        return Err(
            "KIN_NO_DAEMON is set, so this session reports the dead daemon instead of \
             starting a replacement; unset KIN_NO_DAEMON (or drop --no-spawn) and re-run \
             to let kin start one"
                .to_string(),
        );
    }
    // Serialize revival across concurrent tool calls. Every forwarded request
    // now reaches this path, so a dead daemon can be observed by several calls
    // at once; without this each would spawn its own daemon and all but one
    // would lose the race for the repo lock and exit, turning one recoverable
    // outage into a burst of doomed processes.
    let _revival_guard = REVIVAL_LOCK.lock().await;
    // A concurrent caller may have already revived the daemon while we waited
    // for the guard. Reuse a healthy one rather than starting a second.
    if let Some(existing) = current_daemon_url_override() {
        if daemon_is_healthy(&existing).await {
            tracing::debug!(url = %existing, "MCP revival: reusing daemon revived concurrently");
            return Ok(existing);
        }
    }

    let kin_dir =
        discover_kin_dir().ok_or_else(|| "MCP revival: cannot find .kin directory".to_string())?;
    let working_dir = kin_dir
        .parent()
        .ok_or_else(|| "MCP revival: invalid .kin layout (no parent directory)".to_string())?
        .to_path_buf();
    let daemon_bin = find_mcp_daemon_binary().ok_or_else(|| {
        "MCP revival: kin-daemon binary not found (not in PATH or next to kin binary)".to_string()
    })?;
    let _install_spawn_fence = configured_managed_install_root()
        .map(|root| kin_daemon_spawn::ManagedInstallSpawnFence::acquire(&daemon_bin, &root))
        .transpose()
        .map_err(|error| format!("MCP revival: managed install spawn admission failed: {error}"))?
        .flatten();

    // A port record with no PID owner beside it belongs to a daemon that is
    // already gone. Left in place, the port we are about to read back would be
    // its port, not the new daemon's.
    kin_daemon_spawn::clear_orphaned_port_record(&kin_dir);

    let supervisor_url = kin_daemon_spawn::supervisor_url_for_spawn().await;
    let plan = mcp_spawn_plan(daemon_bin, working_dir.clone(), supervisor_url);

    tracing::info!(
        binary = %plan.daemon_bin.display(),
        repo = %working_dir.display(),
        "MCP revival: starting fresh daemon (daemon-assigned port)"
    );

    let mut cmd = plan.command();
    cmd.stdout(std::process::Stdio::null());
    cmd.stderr(std::process::Stdio::null());
    // Opened before the spawn, because attributing a kill to memory needs the
    // kernel's counter from before this daemon existed. A reading taken only
    // after it died counts kills that may belong to anything else on the box.
    let watch = kin_daemon_spawn::DaemonWatch::begin(&kin_dir);
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("MCP revival: spawn kin-daemon failed: {e}"))?;

    let revived = await_revived_daemon(&kin_dir, &mut child).await;
    // This process is an MCP server: it runs for the whole agent session and
    // reaches this path on every tool call that finds a dead daemon. `setsid`
    // does not change the parent pid, so a daemon started here stays this
    // process's child, and dropping the handle would leave it `<defunct>` from
    // the moment it dies until the session ends. Adopt it on every outcome —
    // the startup failures below leave a daemon running on purpose too.
    kin_daemon_spawn::adopt_watched_daemon_child(child, watch);
    revived
}

/// Wait for a just-started MCP daemon to report its port and serve health.
///
/// Split from the spawn so the child handle outlives every exit this can take
/// and reaches the reaper once, rather than being dropped down one of five
/// returns.
async fn await_revived_daemon(
    kin_dir: &std::path::Path,
    child: &mut std::process::Child,
) -> Result<String, String> {
    // The daemon binds :0 and publishes the port it actually got. There is no
    // fallback: a revival that cannot learn the real port has no daemon to
    // talk to, and addressing a default port would reach whatever else is
    // listening there.
    // A deadline is patience, not a health check: `startup_disposition` inside
    // `await_reported_port` detects a dead child immediately and independently
    // of this number. Fifteen seconds was hardcoded here while the CLI's own
    // wait on the same daemon resolved to 300 and said in its doc comment why.
    // The observed cost of the store this fired on was 48.9 s to 71.1 s, so the
    // MCP path gave up four times too early on every single boot and then told
    // the caller to restart. It prices off the same record the CLI's idle window
    // reads, the one the daemon writes when it finishes opening a store, so the
    // two paths cannot disagree about what this store costs.
    let patience = kin_daemon_spawn::daemon_startup_patience(
        kin_daemon_spawn::read_boot_cost(kin_dir).map(|cost| cost.total_ms),
        kin_daemon_spawn::daemon_startup_patience_override(),
    );
    let port_deadline = tokio::time::Instant::now() + patience;
    let port = kin_daemon_spawn::await_reported_port(kin_dir, child, port_deadline)
        .await
        .map_err(|e| format!("MCP revival: {e}"))?;

    // Poll /health until the daemon is ready, under the same patience.
    let new_base = format!("http://127.0.0.1:{port}");
    let probe = reqwest::Client::builder()
        .connect_timeout(Duration::from_millis(300))
        .timeout(Duration::from_secs(3))
        .build()
        .map_err(|e| format!("MCP revival: build probe client: {e}"))?;
    let deadline = tokio::time::Instant::now() + patience;
    loop {
        if let Ok(resp) = probe.get(format!("{new_base}/health")).send().await {
            if resp.status().is_success() {
                // A daemon the supervisor does not know about is unroutable to
                // every other client, so registration is part of starting one.
                if let Err(error) =
                    kin_daemon_spawn::register_started_daemon(kin_dir, &new_base).await
                {
                    tracing::warn!(
                        url = %new_base,
                        %error,
                        "MCP revival: daemon is healthy but supervisor registration failed"
                    );
                }
                // Route all subsequent delegate calls at the revived daemon.
                if let Ok(mut guard) = DAEMON_URL_OVERRIDE.lock() {
                    *guard = Some(new_base.clone());
                }
                tracing::info!(url = %new_base, "MCP revival: daemon is healthy");
                return Ok(new_base);
            }
        }

        // The child reporting a port then failing to serve is still a startup
        // in progress; only its death is evidence against it.
        if let Ok(disposition) = kin_daemon_spawn::startup_disposition(child) {
            if let kin_daemon_spawn::StartupDisposition::Exited(status) = disposition {
                return Err(format!(
                    "MCP revival: daemon exited during startup with status {status} (port {port})"
                ));
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(still_starting_message(port, patience));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// What a revival reports when the daemon it started is alive, has published a
/// port, and has not finished opening its store inside this caller's patience.
///
/// The number is derived from the patience actually waited rather than written
/// into the sentence. It was written before: the wait beside it was raised to
/// [`kin_daemon_spawn::daemon_startup_patience`], which floors at 300 s and
/// shares its override with the CLI, while this message went on saying `15s`.
/// A stranger run read the sentence, believed the bound, and reported the wait
/// as the defect that made MCP recovery impossible; the wait had already been
/// fixed and only the sentence still said fifteen. A number that comes from the
/// deadline it describes cannot drift from it again, and the test beside this
/// asserts two different patiences to prove the number is derived rather than
/// merely correct once.
///
/// Worded as a still-starting state rather than a failure, matching
/// [`kin_daemon_spawn::PortWaitError::StillStarting`] on the port half of the
/// same revival: the child is alive and was left running, so retrying is the
/// remedy and killing it is not.
fn still_starting_message(port: u16, patience: Duration) -> String {
    format!(
        "MCP revival: daemon on port {port} is still starting after {}s and was left running \
         rather than killed. Retry this call, or raise {} to wait longer",
        patience.as_secs(),
        kin_daemon_spawn::DAEMON_STARTUP_PATIENCE_ENV
    )
}

// ── Seam-based MCP tool dispatch ────────────────────────────────────────

/// How long one attempt waits before the ladder asks whether the daemon is
/// alive. Override with `KIN_MCP_DAEMON_TIMEOUT_SECS`.
///
/// This is the budget every call used to run under as a flat client-wide
/// deadline, kept at the same default so nothing that answers today starts
/// costing a second attempt. What changed is what happens when it runs out:
/// exhausting it is now a question, not a verdict.
fn fast_path_patience() -> Duration {
    env_secs("KIN_MCP_DAEMON_TIMEOUT_SECS", 60)
}

/// Total patience for one forwarded call once the daemon has shown it is alive.
/// Override with `KIN_MCP_DAEMON_PATIENCE_SECS`.
///
/// Matches the CLI's `KIN_DAEMON_READY_TIMEOUT_SECS` default deliberately: both
/// bound how long a caller waits on a *live* daemon still doing startup work,
/// and a repository large enough to need five minutes over one transport needs
/// it over the other.
fn escalated_patience() -> Duration {
    env_secs("KIN_MCP_DAEMON_PATIENCE_SECS", 300)
}

fn env_secs(key: &str, default: u64) -> Duration {
    Duration::from_secs(
        std::env::var(key)
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(default),
    )
}

/// Gap between polls while the daemon reports it is still opening its state.
const WARMING_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Run one attempt, absorbing a warming refusal by waiting for the daemon to
/// finish opening rather than treating its own report of life as a failure.
///
/// A warming answer costs nothing to produce and nothing to poll — the daemon
/// refuses immediately — so this loops on the wall-clock deadline rather than
/// on an attempt count. It never revives: replacing the process that is holding
/// the repository lock is precisely the move that cannot succeed.
async fn attempt_through_warmup<T, A, Fut>(
    attempt: &A,
    url: &str,
    budget: Duration,
    deadline: tokio::time::Instant,
) -> Result<T, DaemonCallError>
where
    A: Fn(String, Duration) -> Fut,
    Fut: std::future::Future<Output = Result<T, DaemonCallError>>,
{
    let mut warming_detail: Option<String> = None;
    loop {
        let budget = match warming_detail {
            None => budget,
            // Later passes inherit whatever is left, so a daemon that warms for
            // longer than one budget is still answered inside one call.
            Some(_) => budget.min(remaining_until(deadline)),
        };
        match attempt(url.to_string(), budget).await {
            Err(DaemonCallError::Warming(detail)) => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(DaemonCallError::Timeout(format!(
                        "daemon is still opening its state ({detail})"
                    )));
                }
                warming_detail = Some(detail);
                tokio::time::sleep(WARMING_POLL_INTERVAL).await;
            }
            other => return other,
        }
    }
}

fn remaining_until(deadline: tokio::time::Instant) -> Duration {
    deadline.saturating_duration_since(tokio::time::Instant::now())
}

/// Positive evidence that a daemon at `base` is alive, gathered without
/// spawning or killing anything.
///
/// Two independent witnesses, either of which is enough:
///
/// - The endpoint answers HTTP at all. Any status counts, including a refusal:
///   a process that writes a response line is running. This mirrors the CLI's
///   rule that a non-2xx `/health` is silence about *identity*, never a report
///   of death.
/// - The daemon's own PID record, but only when the recorded port is the port
///   being called, so the record provably describes this endpoint rather than
///   some other repository's daemon.
///
/// One-directional by construction. `false` means no proof of life was found,
/// never proof of death, and callers only ever use `true` to withhold revival.
async fn daemon_is_provably_alive(base: &str) -> bool {
    if let Some(kin_root) = discover_kin_dir() {
        if kin_daemon_spawn::read_reported_port(&kin_root)
            .map(|port| format!(":{port}"))
            .is_some_and(|suffix| base.ends_with(&suffix))
            && kin_daemon_spawn::recorded_owner_is_alive(&kin_root)
        {
            return true;
        }
    }
    let Ok(probe) = reqwest::Client::builder()
        .connect_timeout(Duration::from_millis(300))
        .timeout(Duration::from_secs(3))
        .build()
    else {
        return false;
    };
    probe.get(format!("{base}/health")).send().await.is_ok()
}

/// Run one daemon request with escalating patience and one-shot revival, shared
/// by every forwarded call.
///
/// The question every attempt ends on is the one the CLI transport already
/// answers correctly: is this daemon slow, or is it dead? Each failure class
/// answers it differently, and only one of them authorizes a restart.
///
/// - **Warming.** The daemon says it is still opening its state. Waited out,
///   never revived, and never charged against the attempt budget.
/// - **Timeout.** The deadline measures this caller's patience, not the
///   daemon's health — the connection was established, so something is
///   listening. Costs exactly one escalated re-attempt on the remaining
///   patience, and never a revival. Killing on a deadline is the mistake
///   `daemon_client.rs` recorded a post-mortem for: a daemon still loading a
///   large graph was destroyed for being slow, and its replacement started from
///   cold and hit the same deadline.
/// - **Connection loss.** Retried once against the **same** URL first: a
///   transport error is just as often a stale kept-alive socket or a request
///   landing inside the daemon's post-boot stall as it is a dead daemon. Only
///   when that retry also fails, and nothing proves the daemon is still alive,
///   is `revive` called **exactly once**.
/// - **Daemon error.** Surfaced immediately; retry and revival are bypassed.
///
/// `attempt` receives the base URL and the budget for that attempt, so the
/// post-revival retry addresses the new daemon rather than the dead one and
/// each rung can widen its own deadline.
///
/// Invariants:
/// - `revive` is called at most once per invocation.
/// - `revive` is never called while [`daemon_is_provably_alive`] holds.
/// - A timeout never reaches `revive`.
/// - Non-connection errors are never silently discarded.
/// - Every failure that ends with no reachable daemon is tagged
///   [`DAEMON_EXITED_RESTART_REQUIRED`]; a failure that ends with a daemon
///   proven alive deliberately is not.
async fn attempt_with_revival<T, A, Fut>(
    operation: &str,
    daemon_url: &str,
    reviver: &impl DaemonReviver,
    attempt: A,
) -> Result<T, String>
where
    A: Fn(String, Duration) -> Fut,
    Fut: std::future::Future<Output = Result<T, DaemonCallError>>,
{
    attempt_with_revival_within(
        operation,
        daemon_url,
        reviver,
        attempt,
        fast_path_patience(),
        escalated_patience(),
    )
    .await
}

/// [`attempt_with_revival`] with both budgets supplied rather than resolved from
/// the environment.
///
/// Split so tests drive the ladder at whatever scale makes the behavior
/// observable, the way `daemon_client.rs` splits `wait_for_existing_daemon` from
/// `wait_for_existing_daemon_within`. Production resolves the budgets once, in
/// the wrapper.
async fn attempt_with_revival_within<T, A, Fut>(
    operation: &str,
    daemon_url: &str,
    reviver: &impl DaemonReviver,
    attempt: A,
    fast: Duration,
    patience: Duration,
) -> Result<T, String>
where
    A: Fn(String, Duration) -> Fut,
    Fut: std::future::Future<Output = Result<T, DaemonCallError>>,
{
    let deadline = tokio::time::Instant::now() + patience;

    let first_err = match attempt_through_warmup(&attempt, daemon_url, fast, deadline).await {
        Ok(result) => return Ok(result),
        Err(DaemonCallError::DaemonError(e)) => return Err(e),
        // `attempt_through_warmup` resolves every warming answer, so this arm
        // exists to make the class impossible to lose rather than because it is
        // reachable today: a warming report is evidence of life, and grouping
        // it with the timeout keeps it on the patience path if some future
        // attempt path ever surfaces one directly.
        Err(DaemonCallError::Timeout(e)) | Err(DaemonCallError::Warming(e)) => {
            return escalate_after_timeout(operation, daemon_url, &attempt, deadline, patience, e)
                .await;
        }
        Err(DaemonCallError::ConnectionLost(e)) => e,
    };
    tokio::time::sleep(Duration::from_millis(250)).await;
    let retry_err = match attempt_through_warmup(&attempt, daemon_url, fast, deadline).await {
        Ok(result) => return Ok(result),
        Err(DaemonCallError::DaemonError(e)) => return Err(e),
        // The endpoint went from refusing connections to accepting one and
        // taking its time: it is coming up, not going down.
        Err(DaemonCallError::Timeout(e)) | Err(DaemonCallError::Warming(e)) => {
            return escalate_after_timeout(operation, daemon_url, &attempt, deadline, patience, e)
                .await;
        }
        Err(DaemonCallError::ConnectionLost(e)) => e,
    };

    // Two transport failures in a row on fresh connections. That is evidence
    // about the endpoint, but not yet a verdict: if the recorded daemon is
    // demonstrably running, a replacement would only lose the race for the
    // repository lock this one already holds, and the caller would be told a
    // live daemon had exited.
    let first_err = format!("{first_err}; retry: {retry_err}");
    if reviver.is_provably_alive(daemon_url).await {
        return Err(format!(
            "{operation}: daemon at {daemon_url} is alive but did not answer this request \
             ({first_err}); it was left running rather than restarted. Retry, or inspect it \
             with `kin daemon status`."
        ));
    }
    match reviver.revive().await {
        Err(revive_err) if is_still_starting_error(&revive_err) => Err(format!(
            "{operation}: daemon at {daemon_url} is not responding ({first_err}); a replacement \
             was started and is still loading this repository's graph ({revive_err}). It was \
             left running. Retry this tool in a moment; do not restart `kin mcp start`, which \
             discards the startup already in progress."
        )),
        Err(revive_err) => Err(revival_failed_message(
            operation,
            daemon_url,
            &first_err,
            &revive_err,
            recorded_daemon_kill().as_ref(),
        )),
        Ok(new_url) => {
            // Retry exactly once on the post-revival URL. A daemon this call
            // just started is the likeliest of all to answer warming, so the
            // retry goes through the same warm-up wait.
            match attempt_through_warmup(&attempt, &new_url, fast, deadline).await {
                Ok(result) => Ok(result),
                Err(e) => {
                    let detail = match e {
                        DaemonCallError::ConnectionLost(s)
                        | DaemonCallError::Timeout(s)
                        | DaemonCallError::Warming(s)
                        | DaemonCallError::DaemonError(s) => s,
                    };
                    Err(revived_retry_failed_message(
                        operation,
                        &new_url,
                        &detail,
                        recorded_daemon_kill().as_ref(),
                    ))
                }
            }
        }
    }
}

/// Spend the rest of this call's patience on a daemon that answered late.
///
/// Exactly one further attempt, on whatever budget remains, and no revival on
/// any outcome. A request-class timeout means the connection was established
/// and the answer was slow; the endpoint is serving somebody, and restarting it
/// would throw away the warm-up work that is the reason the answer is slow.
async fn escalate_after_timeout<T, A, Fut>(
    operation: &str,
    daemon_url: &str,
    attempt: &A,
    deadline: tokio::time::Instant,
    patience: Duration,
    first_err: String,
) -> Result<T, String>
where
    A: Fn(String, Duration) -> Fut,
    Fut: std::future::Future<Output = Result<T, DaemonCallError>>,
{
    let remaining = remaining_until(deadline);
    if !remaining.is_zero() {
        match attempt_through_warmup(attempt, daemon_url, remaining, deadline).await {
            Ok(result) => return Ok(result),
            Err(DaemonCallError::DaemonError(e)) => return Err(e),
            Err(_) => {}
        }
    }
    Err(format!(
        "{operation}: daemon at {daemon_url} did not answer within {}s ({first_err}); it was \
         left running rather than restarted for being slow. Wait for it, raise \
         KIN_MCP_DAEMON_PATIENCE_SECS, or stop it with `kin daemon stop`.",
        patience.as_secs()
    ))
}

/// Core MCP-tool-call dispatch, layered on [`attempt_with_revival`].
async fn forward_mcp_with_seam(
    name: &str,
    args: &HashMap<String, serde_json::Value>,
    seam: &impl DaemonCallSeam,
    daemon_url: &str,
) -> Result<Option<ToolCallResult>, String> {
    attempt_with_revival(
        &format!("tool {name}"),
        daemon_url,
        seam,
        |base, patience| async move { seam.call_tool(&base, name, args, patience).await },
    )
    .await
}

async fn forward_mcp_tool_call(
    name: &str,
    arguments: &HashMap<String, serde_json::Value>,
) -> Result<Option<ToolCallResult>, String> {
    let Some(base) = resolved_daemon_base_url().await else {
        return Ok(None);
    };
    forward_mcp_with_seam(name, arguments, &RealDaemonSeam, &base).await
}

/// Issue a JSON daemon request under the shared retry/revive policy.
///
/// `build` is invoked once per attempt with the base URL for **that** attempt,
/// so the post-revival retry addresses the revived daemon rather than the dead
/// one. This is the single entry point for the session, intent, traffic, and
/// status forwards: before it existed each of them issued a bare one-shot
/// request, so an idle-shutdown between two tool calls took every one of them
/// down permanently while `/mcp/tools/call` recovered.
///
/// An empty response body (the daemon answers some mutations with `204 No
/// Content`) parses as `Value::Null` rather than failing.
async fn daemon_json_request<B>(
    operation: &str,
    base: &str,
    build: B,
) -> Result<serde_json::Value, String>
where
    B: Fn(&reqwest::Client, &str) -> reqwest::RequestBuilder,
{
    attempt_with_revival(operation, base, &RealDaemonSeam, |url, patience| {
        let build = &build;
        async move {
            let Some(client) = daemon_client().await else {
                return Err(DaemonCallError::DaemonError(format!(
                    "daemon {operation} failed: could not build an HTTP client"
                )));
            };
            send_daemon_json(operation, build(&client, &url).timeout(patience)).await
        }
    })
    .await
}

/// Maximum daemon error-body bytes preserved in an MCP-facing error.
///
/// The daemon is a loopback peer, but an accidental HTML/proxy response or a
/// pathological route body must not turn one rejected tool call into an
/// unbounded MCP response.
const MAX_DAEMON_ERROR_BODY_BYTES: usize = 8 * 1024;

/// Preserve an actionable, bounded response body from a daemon HTTP error.
///
/// Reading by chunks enforces the bound while the response is in flight rather
/// than collecting an arbitrarily large body and truncating only afterward.
async fn daemon_http_error(operation: &str, mut response: reqwest::Response) -> DaemonCallError {
    let status = response.status();
    let mut body = Vec::with_capacity(MAX_DAEMON_ERROR_BODY_BYTES);
    let mut truncated = false;

    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                let remaining = MAX_DAEMON_ERROR_BODY_BYTES.saturating_sub(body.len());
                if chunk.len() > remaining {
                    body.extend_from_slice(&chunk[..remaining]);
                    truncated = true;
                    break;
                }
                body.extend_from_slice(&chunk);
                if body.len() == MAX_DAEMON_ERROR_BODY_BYTES {
                    match response.chunk().await {
                        Ok(Some(_)) => truncated = true,
                        Ok(None) => {}
                        Err(error) => {
                            return DaemonCallError::DaemonError(format!(
                                "daemon {operation} failed: HTTP {status}; error response read \
                                 failed after {} bytes: {error}",
                                body.len()
                            ));
                        }
                    }
                    break;
                }
            }
            Ok(None) => break,
            Err(error) => {
                return DaemonCallError::DaemonError(format!(
                    "daemon {operation} failed: HTTP {status}; error response read failed: {error}"
                ));
            }
        }
    }

    let detail = String::from_utf8_lossy(&body);
    let detail = detail.trim();
    let truncation = if truncated { " … [truncated]" } else { "" };
    if is_warming_refusal(status, detail) {
        return DaemonCallError::Warming(format!("HTTP {status}: {detail}{truncation}"));
    }
    if detail.is_empty() {
        DaemonCallError::DaemonError(format!("daemon {operation} failed: HTTP {status}"))
    } else {
        DaemonCallError::DaemonError(format!(
            "daemon {operation} failed: HTTP {status}: {detail}{truncation}"
        ))
    }
}

/// Whether a refusal is the daemon reporting that it is still opening its
/// state, rather than a failure.
///
/// The daemon answers every route with `503` while it opens, carrying
/// `{"error":"daemon_opening","ready":false,"warming":true}`. Both markers are
/// required alongside the status so an ordinary `503` — a real dependency
/// outage, a proxy in front of the loopback port — keeps reading as the error
/// it is. Recognising it is what lets a client attach to a daemon that has
/// published its endpoint before it can serve, which is the whole point of
/// binding the socket early.
fn is_warming_refusal(status: reqwest::StatusCode, body: &str) -> bool {
    status == reqwest::StatusCode::SERVICE_UNAVAILABLE
        && serde_json::from_str::<serde_json::Value>(body).is_ok_and(|value| {
            value.get("warming").and_then(serde_json::Value::as_bool) == Some(true)
                || value.get("error").and_then(serde_json::Value::as_str) == Some("daemon_opening")
        })
}

/// Send one already-built daemon request and read its JSON body.
///
/// Split out of [`daemon_json_request`] so the response handling is testable
/// without the revival wrapper: a test that drove the wrapper would, on any
/// hiccup against its stub, reach the real revival path and spawn an actual
/// `kin-daemon` against whatever repository the test process is sitting in.
///
/// An empty body is `Value::Null`, not an error. Some daemon mutations answer
/// `204 No Content`, and the callers that expect it (intent release) synthesize
/// their own result.
async fn send_daemon_json(
    operation: &str,
    request: reqwest::RequestBuilder,
) -> Result<serde_json::Value, DaemonCallError> {
    let resp = request
        .send()
        .await
        .map_err(|e| classify_send_error(operation, e))?;
    if !resp.status().is_success() {
        return Err(daemon_http_error(operation, resp).await);
    }
    let body = resp.text().await.map_err(|e| {
        DaemonCallError::DaemonError(format!("daemon {operation} response read failed: {e}"))
    })?;
    if body.trim().is_empty() {
        return Ok(serde_json::Value::Null);
    }
    serde_json::from_str(&body).map_err(|e| {
        DaemonCallError::DaemonError(format!("daemon {operation} response parse failed: {e}"))
    })
}

/// Forward any product-mode MCP tool call to the daemon-owned implementation.
pub async fn forward_tool_call(
    name: &str,
    arguments: &HashMap<String, serde_json::Value>,
) -> Result<Option<ToolCallResult>, String> {
    match name {
        "register_session" => {
            let assistant_name = required_string(arguments, "assistant_name")?;
            let cwd = std::env::current_dir()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|_| ".".to_string());
            forward_session_start(&assistant_name, &assistant_name, "mcp", None, &cwd, None)
                .await?
                .map(text_result_from_value)
                .transpose()
        }
        "kin_session_start" => {
            let vendor = required_string(arguments, "vendor")?;
            let client_name = required_string(arguments, "client_name")?;
            let cwd = required_string(arguments, "cwd")?;
            let transport = optional_string(arguments, "transport").unwrap_or("mcp");
            let pid = optional_u32(arguments, "pid");
            let capabilities = parse_capabilities(arguments);
            forward_session_start(
                &vendor,
                &client_name,
                transport,
                pid,
                &cwd,
                capabilities.as_ref(),
            )
            .await?
            .map(text_result_from_value)
            .transpose()
        }
        "kin_session_heartbeat" => {
            let session_id = required_string(arguments, "session_id")?;
            forward_session_heartbeat(&session_id)
                .await?
                .map(text_result_from_value)
                .transpose()
        }
        "kin_session_end" => {
            let session_id = required_string(arguments, "session_id")?;
            forward_session_end(&session_id)
                .await?
                .map(text_result_from_value)
                .transpose()
        }
        "kin_register_intent" => {
            let session_id = required_string(arguments, "session_id")?;
            let task_description = required_string(arguments, "task_description")?;
            let lock_type = optional_string(arguments, "lock_type").unwrap_or("soft");
            let expires_at = optional_string(arguments, "expires_at");
            let scopes = scope_strings(arguments)?;
            forward_register_intent(
                &session_id,
                &scopes,
                lock_type,
                &task_description,
                expires_at,
            )
            .await?
            .map(text_result_from_value)
            .transpose()
        }
        "kin_release_intent" => {
            let session_id = required_string(arguments, "session_id")?;
            let intent_id = required_string(arguments, "intent_id")?;
            forward_release_intent(&session_id, &intent_id)
                .await?
                .map(text_result_from_value)
                .transpose()
        }
        "kin_check_traffic" => {
            let scopes = scope_strings(arguments)?;
            forward_check_traffic(&scopes)
                .await?
                .map(text_result_from_value)
                .transpose()
        }
        // Coverage exposure: the structured graph-status response binds entity,
        // relation, and embedding counts to one daemon-selected query graph.
        // Durable repository-authority status is a different contract and must
        // never be relabeled as MCP query readiness.
        "kin_graph_status" => forward_graph_status(arguments).await,
        // Stage-time validation in product mode: reject intrinsically-malformed
        // staged operations locally before the daemon round-trip, so the agent
        // gets the same fast, actionable failure it gets in-process. The daemon
        // still owns graph-dependent validation and the actual staging.
        "kin_transaction_stage" => match validate_stage_arguments(arguments) {
            Ok(()) => forward_mcp_tool_call(name, arguments).await,
            Err(message) => Ok(Some(ToolCallResult::error(message))),
        },
        // Short-circuit repeated failures for an identical entity ID within a
        // session so a hallucinated/stale ID does not burn a daemon round-trip
        // on every retry.
        "get_entity_source" | "get_entity_body" => {
            forward_entity_source_memoized(name, arguments).await
        }
        _ => forward_mcp_tool_call(name, arguments).await,
    }
}

/// Run the intrinsic stage-time validation over a `kin_transaction_stage`
/// argument map. A missing `operations` field is left for the daemon to report
/// (so the missing-parameter message stays authoritative); a malformed array or
/// a payload that would be silently dropped at commit fails loud here.
///
/// Decoding goes through [`crate::session::parse_staged_operations`] rather
/// than serde directly. Product mode reaches this function and the in-process
/// handler reaches that one, so decoding here by hand gave the two modes
/// different refusals for the identical input: in-process named the whole
/// operation schema and product mode answered with whichever single field
/// serde stopped on. A caller improvising the shape against a real daemon
/// learned one field per attempt and never saw the contract.
fn validate_stage_arguments(arguments: &HashMap<String, serde_json::Value>) -> Result<(), String> {
    let Some(operations_val) = arguments.get("operations") else {
        return Ok(());
    };
    let operations = crate::session::parse_staged_operations(operations_val)?;
    crate::session::validate_staged_operations(&operations)
}

/// Forward graph status over the same `/mcp/tools/call` route every other
/// graph-backed MCP client uses, then validate the successful payload before it
/// crosses the stdio boundary.
///
/// This catches an old or drifted daemon even though the outer
/// [`ToolCallResult`] envelope still deserializes. Daemon errors remain errors
/// verbatim; only a successful status body must satisfy the exact v1 contract.
async fn forward_graph_status(
    arguments: &HashMap<String, serde_json::Value>,
) -> Result<Option<ToolCallResult>, String> {
    forward_mcp_tool_call("kin_graph_status", arguments)
        .await?
        .map(validate_graph_status_result)
        .transpose()
}

fn validate_graph_status_result(result: ToolCallResult) -> Result<ToolCallResult, String> {
    parse_graph_status_report(&result)?;
    Ok(result)
}

pub(crate) fn parse_graph_status_report(
    result: &ToolCallResult,
) -> Result<Option<crate::handlers::entities::GraphStatusReport>, String> {
    if result.is_error == Some(true) {
        return Ok(None);
    }
    let [ContentBlock::Text { text }] = result.content.as_slice() else {
        return Err(format!(
            "daemon kin_graph_status returned {} content blocks; expected exactly one text block",
            result.content.len()
        ));
    };
    serde_json::from_str(text)
        .map(Some)
        .map_err(|error| format!("daemon kin_graph_status contract validation failed: {error}"))
}

/// The answer a `tools/call` gets when this process has no daemon delegate.
///
/// Asks the resolver rather than inspecting the filesystem itself, so the
/// message describes the state the forwarding attempt actually found, and
/// names which of the three gaps it is. Within one tool call this costs no
/// second probe: the forwarding attempt already ran one, and the resolver's
/// cooldown replays that verdict.
pub async fn daemon_unavailable_tool_result(name: &str) -> ToolCallResult {
    match resolve_delegate().await {
        DelegateResolution::Gap(gap) => ToolCallResult::error(gap.message(name)),
        // A delegate resolved between the forwarding attempt and this message,
        // or the attempt failed for a reason that is not endpoint resolution
        // (no HTTP client could be built at all). Neither is something the
        // caller can act on, and neither is any of the three gaps, so it is
        // reported as itself rather than dressed as one of them.
        DelegateResolution::Resolved(url) => ToolCallResult::error(format!(
            "kin-mcp could not issue '{name}' to the repo daemon at {url}, though the delegate \
             resolves there now. Retry the call; if it keeps failing, capture `kin doctor` output, \
             which probes that same endpoint."
        )),
    }
}

/// Best-effort fetch of the daemon `/health` body for response-envelope
/// enrichment.
///
/// Returns the parsed JSON on success and `None` whenever the daemon is
/// unreachable, the request fails, or the body does not parse. The envelope
/// folds the honest degraded/freshness fields from this body
/// (`embed_worker_failed`, `mass_deletion_blocked`, reconciliation state); a
/// `None` here simply leaves those envelope fields unknown rather than blocking
/// or failing the tool call. `/health` is liveness-only and never lazy-loads a
/// repo graph, so this is a cheap localhost probe.
pub async fn fetch_health_snapshot() -> Option<serde_json::Value> {
    let client = daemon_client().await?;
    let base = daemon_base_url()?;
    // Its own deadline, not the client backstop: this is an envelope-decorating
    // probe whose answer is optional, so it must never inherit the patience a
    // forwarded tool call is entitled to.
    let resp = client
        .get(format!("{}/health", base))
        .timeout(Duration::from_secs(3))
        .send()
        .await
        .ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json::<serde_json::Value>().await.ok()
}

/// Get or initialize the daemon HTTP client. Returns `None` only when a client
/// cannot be constructed at all.
///
/// This deliberately does **not** probe the daemon for liveness. It used to:
/// a `/health` probe gated every call and a failed probe returned `None`, which
/// callers read as "no daemon configured" and turned into a graceful no-op.
/// That silently swallowed the exact signal the revival path exists to act on,
/// so a daemon that idled out was never restarted and the whole MCP session
/// stayed dead. Liveness now belongs to the request itself: a transport failure
/// classifies as [`DaemonCallError::ConnectionLost`] and drives retry and
/// revival, while "no daemon configured" is a `None` from [`daemon_base_url`]
/// alone. The probe was also a wasted round-trip in front of every call.
pub async fn daemon_client() -> Option<reqwest::Client> {
    if let Some(client) = DAEMON_CLIENT.get() {
        return Some(client.clone());
    }

    let client = reqwest::Client::builder()
        // Slow is not dead. A daemon fresh off a clone spends its first minute
        // on enrichment and spine work, and a legitimate tool call inside that
        // window can take well over five seconds; a 5 s total-request timeout
        // converted every such call into a transport error, which dispatch
        // must read as daemon-down, which triggered revival that cannot
        // succeed while the live daemon holds the repo lock. Dead daemons are
        // still detected fast by the connect timeout below; busy ones get to
        // finish. The MCP client above this has its own per-tool deadline and
        // remains the effective ceiling.
        //
        // This is only the backstop for a request that sets no deadline of its
        // own. Every call that runs through [`attempt_with_revival`] overrides
        // it per attempt, because one flat client-wide deadline cannot both
        // bound a healthy call and decide when a daemon is presumed dead.
        .timeout(escalated_patience())
        .connect_timeout(Duration::from_millis(500))
        // No pooled keepalive sockets. This client is cached for the process
        // lifetime while agent loops pause arbitrarily long between calls, and
        // the daemon closes idle connections on its own schedule. A POST that
        // reuses a connection the daemon already closed surfaces as a
        // transport error ("error sending request"), which the dispatch layer
        // must treat as daemon-down, so one stale pooled socket misdiagnoses a
        // healthy daemon and triggers doomed revival against its repo lock.
        // Every call paying a fresh loopback connect costs microseconds;
        // misdiagnosing the daemon costs the whole session.
        .pool_max_idle_per_host(0)
        .build()
        .ok()?;

    let _ = DAEMON_CLIENT.set(client.clone());
    Some(client)
}

/// Forward a session start to the daemon.
///
/// POST /session with JSON body. Returns the response JSON on success.
pub async fn forward_session_start(
    vendor: &str,
    client_name: &str,
    transport: &str,
    pid: Option<u32>,
    cwd: &str,
    capabilities: Option<&SessionCapabilities>,
) -> Result<Option<serde_json::Value>, String> {
    let Some(base) = resolved_daemon_base_url().await else {
        return Ok(None);
    };
    let mut body = serde_json::json!({
        "vendor": vendor,
        "client_name": client_name,
        "transport": transport,
        "cwd": cwd,
    });
    // Omitted rather than defaulted, so the daemon can tell a client that
    // declared nothing from one that declared itself read-only.
    if let Some(capabilities) = capabilities {
        body["capabilities"] = serde_json::json!(capabilities);
    }
    if let Some(p) = pid {
        body["pid"] = serde_json::json!(p);
    }
    let value = daemon_json_request("session start", &base, |client, base| {
        with_auth(client.post(format!("{base}/session")).json(&body))
    })
    .await?;
    Ok(Some(value))
}

/// Forward a session heartbeat to the daemon.
pub async fn forward_session_heartbeat(
    session_id: &str,
) -> Result<Option<serde_json::Value>, String> {
    let Some(base) = resolved_daemon_base_url().await else {
        return Ok(None);
    };
    session_heartbeat_request(&base, session_id).await.map(Some)
}

async fn session_heartbeat_request(
    base: &str,
    session_id: &str,
) -> Result<serde_json::Value, String> {
    let value = daemon_json_request("heartbeat", base, |client, base| {
        with_auth(client.post(format!("{base}/session/{session_id}/heartbeat")))
    })
    .await?;
    Ok(value)
}

/// Forward a session end to the daemon.
pub async fn forward_session_end(session_id: &str) -> Result<Option<serde_json::Value>, String> {
    let Some(base) = resolved_daemon_base_url().await else {
        return Ok(None);
    };
    let value = daemon_json_request("session end", &base, |client, base| {
        with_auth(client.delete(format!("{base}/session/{session_id}")))
    })
    .await?;
    Ok(Some(value))
}

/// Forward an intent registration to the daemon.
pub async fn forward_register_intent(
    session_id: &str,
    scopes: &[String],
    lock_type: &str,
    task_description: &str,
    expires_at: Option<&str>,
) -> Result<Option<serde_json::Value>, String> {
    let Some(base) = resolved_daemon_base_url().await else {
        return Ok(None);
    };
    let body = serde_json::json!({
        "session_id": session_id,
        "scopes": scopes,
        "lock_type": lock_type,
        "task_description": task_description,
    });
    let body = if let Some(expires_at) = expires_at {
        let mut body = body;
        body["expires_at"] = serde_json::json!(expires_at);
        body
    } else {
        body
    };
    let value = daemon_json_request("intent register", &base, |client, base| {
        with_auth(client.post(format!("{base}/intent/register")).json(&body))
    })
    .await?;
    Ok(Some(value))
}

/// Forward an intent release to the daemon.
///
/// DELETE /intent/{intent_id}. The daemon returns 204 No Content on success,
/// so we synthesize a JSON response for the MCP handler.
pub async fn forward_release_intent(
    session_id: &str,
    intent_id: &str,
) -> Result<Option<serde_json::Value>, String> {
    let Some(base) = resolved_daemon_base_url().await else {
        return Ok(None);
    };
    // The 204 body is empty, so the shared request helper yields `Null` here.
    daemon_json_request("release intent", &base, |client, base| {
        with_auth(client.delete(format!("{base}/intent/{intent_id}")))
    })
    .await?;
    // Daemon returns 204 No Content; synthesize a result for the MCP handler.
    Ok(Some(serde_json::json!({
        "intent_id": intent_id,
        "session_id": session_id,
        "status": "released",
    })))
}

/// Forward a traffic check to the daemon.
///
/// The daemon exposes GET /traffic/{scope} for a single scope, so we issue
/// one request per scope and collect the results.
pub async fn forward_check_traffic(
    scope_strings: &[String],
) -> Result<Option<serde_json::Value>, String> {
    if resolved_daemon_base_url().await.is_none() {
        return Ok(None);
    }
    let mut reports = Vec::new();
    for scope in scope_strings {
        // Re-resolve per scope: if an earlier scope revived the daemon, the
        // remaining ones must address the new URL directly instead of each
        // rediscovering the dead one through the whole retry-then-revive path.
        let Some(base) = resolved_daemon_base_url().await else {
            return Ok(None);
        };
        let encoded = scope.replace(':', "%3A");
        let value = daemon_json_request("check traffic", &base, |client, base| {
            with_auth(client.get(format!("{base}/traffic/{encoded}")))
        })
        .await?;
        reports.push(value);
    }
    Ok(Some(serde_json::json!({
        "reports": reports,
        "scope_count": scope_strings.len(),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two patiences, because one reading cannot tell a derived number from a
    /// literal that happens to match it.
    ///
    /// The stale sentence said `15s` while the wait resolved to 300 or more, so
    /// asserting only the real bound would pass a message that had simply been
    /// re-typed with a different constant. Each patience must name its own
    /// seconds and must not name the other's.
    #[test]
    fn the_still_starting_report_names_the_bound_it_actually_waited() {
        let short = still_starting_message(40713, Duration::from_secs(15));
        let real = still_starting_message(40713, Duration::from_secs(300));
        assert!(
            short.contains("after 15s"),
            "a 15 s wait must report 15 s: {short}"
        );
        assert!(
            real.contains("after 300s"),
            "a 300 s wait must report 300 s, not the literal the sentence used to carry: {real}"
        );
        assert!(
            !real.contains("after 15s"),
            "the 300 s report still carries the stale 15 s literal: {real}"
        );
        assert!(
            !short.contains("after 300s"),
            "the 15 s report names a bound it did not wait: {short}"
        );
    }

    /// A live daemon that has not finished opening is a retry, not a failure.
    ///
    /// The port half of this same revival already reports it that way
    /// (`PortWaitError::StillStarting`), and the stranger who hit the health
    /// half was told to restart instead. The message has to say the child was
    /// left running, offer the retry, and name the lever that widens the wait,
    /// or the caller has no move but the one that loses the daemon.
    #[test]
    fn the_still_starting_report_offers_a_retry_and_the_lever_that_widens_the_wait() {
        let message = still_starting_message(40713, Duration::from_secs(300));
        assert!(message.contains("still starting"), "{message}");
        assert!(message.contains("left running"), "{message}");
        assert!(message.contains("Retry this call"), "{message}");
        assert!(
            message.contains(kin_daemon_spawn::DAEMON_STARTUP_PATIENCE_ENV),
            "the report names no way to wait longer: {message}"
        );
        assert!(
            message.contains("40713"),
            "the report names no port: {message}"
        );
    }

    fn pressure_refusal(work: &str) -> kin_core::memory_pressure::PressureRefusal {
        kin_core::memory_pressure::PressureRefusal {
            work: work.to_string(),
            level: "constrained".to_string(),
            reason: format!("{work} was refused"),
            at_unix: 1,
        }
    }

    fn coverage(
        pending: usize,
        indexed: usize,
        total: usize,
    ) -> kin_core::memory_pressure::EmbeddingCoverage {
        kin_core::memory_pressure::EmbeddingCoverage {
            pending,
            indexed,
            total,
        }
    }

    #[test]
    fn resources_coverage_extraction_requires_three_exact_nonnegative_integers() {
        assert_eq!(
            embedding_coverage_from_resources(&serde_json::json!({
                "embed_runtime": {
                    "embeddings_pending": 0,
                    "embeddings_indexed": 4,
                    "embeddings_total": 4
                }
            })),
            Some(coverage(0, 4, 4))
        );
        assert_eq!(
            embedding_coverage_from_resources(&serde_json::json!({
                "embed_runtime": {
                    "embeddings_pending": 0,
                    "embeddings_indexed": 4,
                    "embeddings_total": 5
                }
            })),
            Some(coverage(0, 4, 5)),
            "an empty queue with short coverage is an exact outstanding-work observation"
        );

        for value in [
            serde_json::json!({}),
            serde_json::json!({ "embed_runtime": {} }),
            serde_json::json!({ "embed_runtime": {
                "embeddings_pending": 0,
                "embeddings_indexed": 4
            } }),
            serde_json::json!({ "embed_runtime": {
                "embeddings_pending": null,
                "embeddings_indexed": 4,
                "embeddings_total": 4
            } }),
            serde_json::json!({ "embed_runtime": {
                "embeddings_pending": "0",
                "embeddings_indexed": 4,
                "embeddings_total": 4
            } }),
            serde_json::json!({ "embed_runtime": {
                "embeddings_pending": 0,
                "embeddings_indexed": -1,
                "embeddings_total": 4
            } }),
            serde_json::json!({ "embed_runtime": {
                "embeddings_pending": 0,
                "embeddings_indexed": 5,
                "embeddings_total": 4
            } }),
        ] {
            assert_eq!(
                embedding_coverage_from_resources(&value),
                None,
                "an older or malformed resources response stays unobserved: {value}"
            );
        }
    }

    #[test]
    fn graph_status_pressure_uses_its_own_selected_coverage_and_race_boundary() {
        let embed = pressure_refusal("embed-batch");
        assert!(
            pressure_refusal_for_selected_graph(
                std::slice::from_ref(&embed),
                coverage(0, 4, 4),
                2,
            )
            .is_none(),
            "an old embed refusal is settled by the exact complete report being returned"
        );
        for selected in [coverage(0, 3, 4), coverage(1, 4, 4), coverage(0, 5, 4)] {
            assert_eq!(
                pressure_refusal_for_selected_graph(std::slice::from_ref(&embed), selected, 2,),
                Some(embed.clone()),
                "short, live, and impossible selected coverage remain degraded"
            );
        }

        for other_work in ["lsp-sweep", "future-heavy-work"] {
            let other = pressure_refusal(other_work);
            for refusals in [
                vec![other.clone(), embed.clone()],
                vec![embed.clone(), other.clone()],
            ] {
                assert_eq!(
                    pressure_refusal_for_selected_graph(&refusals, coverage(0, 4, 4), 2),
                    Some(other.clone()),
                    "embedding completion cannot hide {other_work} in either publication order"
                );
            }
        }

        let mut same_second = embed.clone();
        same_second.at_unix = 2;
        assert_eq!(
            pressure_refusal_for_selected_graph(
                std::slice::from_ref(&same_second),
                coverage(0, 4, 4),
                2,
            ),
            Some(same_second),
            "a report that may predate a same-second refusal cannot settle it"
        );
    }

    #[tokio::test]
    async fn only_embed_refusals_pay_for_the_pending_observation() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        for work in ["lsp-sweep", "future-heavy-work"] {
            let calls = AtomicUsize::new(0);
            let refusal = pressure_refusal(work);
            let current = refusal.clone();
            let kept = outstanding_pressure_refusal_with(
                vec![refusal],
                2,
                || {
                    calls.fetch_add(1, Ordering::SeqCst);
                    std::future::ready(Some(coverage(0, 4, 4)))
                },
                || vec![current],
            )
            .await;
            assert!(kept.is_some(), "{work} has an independent backlog");
            assert_eq!(
                calls.load(Ordering::SeqCst),
                0,
                "{work} must not trigger a graph-wide embedding observation"
            );
        }

        let calls = AtomicUsize::new(0);
        let refusal = pressure_refusal("embed-batch");
        let current = refusal.clone();
        let cleared = outstanding_pressure_refusal_with(
            vec![refusal],
            2,
            || {
                calls.fetch_add(1, Ordering::SeqCst);
                std::future::ready(Some(coverage(0, 4, 4)))
            },
            || vec![current],
        )
        .await;
        assert!(cleared.is_none(), "completed embed work no longer degrades");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn completed_embed_work_never_hides_an_independent_refusal() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        for other_work in ["lsp-sweep", "future-heavy-work"] {
            for refusals in [
                vec![
                    pressure_refusal(other_work),
                    pressure_refusal("embed-batch"),
                ],
                vec![
                    pressure_refusal("embed-batch"),
                    pressure_refusal(other_work),
                ],
            ] {
                let calls = AtomicUsize::new(0);
                let kept = outstanding_pressure_refusal_with(
                    refusals.clone(),
                    2,
                    || {
                        calls.fetch_add(1, Ordering::SeqCst);
                        std::future::ready(Some(coverage(0, 4, 4)))
                    },
                    || refusals,
                )
                .await
                .expect("independent work remains outstanding");
                assert_eq!(kept.work, other_work);
                assert_eq!(
                    calls.load(Ordering::SeqCst),
                    0,
                    "an independent refusal already requires degraded truth"
                );
            }

            let initial_embed = pressure_refusal("embed-batch");
            let replacement_embed = initial_embed.clone();
            let replacement_other = pressure_refusal(other_work);
            let kept = outstanding_pressure_refusal_with(
                vec![initial_embed],
                2,
                || std::future::ready(Some(coverage(0, 4, 4))),
                || vec![replacement_embed, replacement_other.clone()],
            )
            .await;
            assert_eq!(
                kept,
                Some(replacement_other),
                "work published during the observation outranks the old embed count"
            );
        }
    }

    #[tokio::test]
    async fn a_refusal_changed_during_observation_is_never_muted_by_the_old_count() {
        let initial = pressure_refusal("embed-batch");
        for replacement in [
            pressure_refusal("embed-batch"),
            pressure_refusal("lsp-sweep"),
            pressure_refusal("future-heavy-work"),
        ] {
            let mut replacement = replacement;
            replacement.at_unix = 2;
            let expected = replacement.clone();
            let kept = outstanding_pressure_refusal_with(
                vec![initial.clone()],
                2,
                || std::future::ready(Some(coverage(0, 4, 4))),
                || vec![replacement],
            )
            .await;
            assert_eq!(
                kept,
                Some(expected),
                "the exact zero described the old record, not its replacement"
            );
        }

        let unreadable_or_cleared = outstanding_pressure_refusal_with(
            vec![initial],
            2,
            || std::future::ready(Some(coverage(0, 4, 4))),
            Vec::new,
        )
        .await;
        assert!(
            unreadable_or_cleared.is_some(),
            "a clear and replacement can interleave with the reread, so this response stays \
             conservative and the next call observes a true clear"
        );
    }

    #[tokio::test]
    async fn an_equal_same_second_refusal_is_not_settled_by_the_old_observation() {
        let initial = pressure_refusal("embed-batch");
        let replacement = initial.clone();

        let kept = outstanding_pressure_refusal_with(
            vec![initial],
            1,
            || std::future::ready(Some(coverage(0, 4, 4))),
            || vec![replacement.clone()],
        )
        .await;

        assert_eq!(
            kept,
            Some(replacement),
            "second-resolution equality cannot prove that a same-second refusal is the one whose \
             backlog was observed"
        );
    }

    #[test]
    fn coverage_filter_preserves_short_queued_and_unobserved_refusals() {
        assert!(pressure_refusal_for_coverage(
            pressure_refusal("embed-batch"),
            Some(coverage(0, 4, 4)),
        )
        .is_none());
        assert!(
            pressure_refusal_for_coverage(
                pressure_refusal("embed-batch"),
                Some(coverage(0, 4, 5)),
            )
            .is_some(),
            "zero queued cannot hide a refused missing-coverage backfill"
        );
        assert!(pressure_refusal_for_coverage(
            pressure_refusal("embed-batch"),
            Some(coverage(1, 4, 4)),
        )
        .is_some());
        assert!(
            pressure_refusal_for_coverage(
                pressure_refusal("embed-batch"),
                Some(coverage(0, 5, 4)),
            )
            .is_some(),
            "an impossible over-indexed response cannot authorize suppression"
        );
        assert!(pressure_refusal_for_coverage(pressure_refusal("embed-batch"), None).is_some());
        assert!(pressure_refusal_for_coverage(
            pressure_refusal("lsp-sweep"),
            Some(coverage(0, 4, 4)),
        )
        .is_some());
        assert!(pressure_refusal_for_coverage(
            pressure_refusal("future-heavy-work"),
            Some(coverage(0, 4, 4)),
        )
        .is_some());
    }

    #[test]
    fn windows_daemon_discovery_finds_platform_sibling_without_path() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory
            .path()
            .join(if cfg!(windows) { "kin.exe" } else { "kin" });
        let daemon = directory.path().join(MCP_DAEMON_BINARY_FILE_NAME);
        std::fs::write(&executable, b"kin fixture").unwrap();
        std::fs::write(&daemon, b"daemon fixture").unwrap();

        assert_eq!(
            find_mcp_daemon_binary_from(None, Some(&executable), None),
            Some(daemon)
        );
    }

    /// The no-spawn contract, at the one place in this crate that can start a
    /// process. With `KIN_NO_DAEMON` set, revival must refuse before doing any
    /// work (the refusal happens ahead of binary discovery, record clearing,
    /// and the spawn itself), and the refusal must name the variable so the
    /// honest "daemon is dead" answer teaches the remedy. This is the guard
    /// FIR-2341 demanded: a probe session that may not spawn cannot have its
    /// own tools/call revive the daemon it is probing.
    #[tokio::test]
    async fn revival_refuses_to_spawn_under_kin_no_daemon() {
        let _guard = kin_core::test_env::EnvVarGuard::set("KIN_NO_DAEMON", "1");
        let refusal = revive_mcp_daemon()
            .await
            .expect_err("revival must refuse under KIN_NO_DAEMON");
        assert!(
            refusal.contains("KIN_NO_DAEMON"),
            "the refusal must name the contract that produced it: {refusal}"
        );
        assert!(
            refusal.contains("no-spawn") || refusal.contains("unset"),
            "the refusal must name the remedy: {refusal}"
        );
    }

    // ── Revival state machine ──────────────────────────────────────────────
    //
    // Tests exercise `forward_mcp_with_seam` via a controlled stub seam.
    // No real daemon is started; no network calls beyond loopback are made.

    struct FakeSeam {
        /// Results to return on successive `call_tool` invocations (FIFO).
        calls: std::sync::Mutex<
            std::collections::VecDeque<Result<Option<ToolCallResult>, DaemonCallError>>,
        >,
        /// Value that `revive` returns.
        revive_result: Result<String, String>,
        /// Number of `call_tool` invocations.
        call_count: std::sync::atomic::AtomicUsize,
        /// Number of `revive` invocations.
        revive_count: std::sync::atomic::AtomicUsize,
    }

    impl FakeSeam {
        fn new(
            call_sequence: Vec<Result<Option<ToolCallResult>, DaemonCallError>>,
            revive_result: Result<String, String>,
        ) -> Self {
            Self {
                calls: std::sync::Mutex::new(call_sequence.into()),
                revive_result,
                call_count: std::sync::atomic::AtomicUsize::new(0),
                revive_count: std::sync::atomic::AtomicUsize::new(0),
            }
        }

        fn calls_made(&self) -> usize {
            self.call_count.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn revives_attempted(&self) -> usize {
            self.revive_count.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl DaemonCallSeam for FakeSeam {
        async fn call_tool(
            &self,
            _base: &str,
            _name: &str,
            _args: &HashMap<String, serde_json::Value>,
            _patience: Duration,
        ) -> Result<Option<ToolCallResult>, DaemonCallError> {
            self.call_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.calls
                .lock()
                .unwrap()
                .pop_front()
                .expect("FakeSeam: unexpected extra call_tool invocation")
        }
    }

    impl DaemonReviver for FakeSeam {
        async fn revive(&self) -> Result<String, String> {
            self.revive_count
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.revive_result.clone()
        }
    }

    /// Reviver-only stub for the non-tool-call forwards, which drive
    /// [`attempt_with_revival`] directly.
    struct FakeReviver {
        result: Result<String, String>,
        count: std::sync::atomic::AtomicUsize,
        /// Stands in for the liveness witness the ladder consults before it is
        /// allowed to revive. `None` means "no proof either way", which is what
        /// a closed loopback port really offers.
        alive: Option<bool>,
    }

    impl FakeReviver {
        fn new(result: Result<String, String>) -> Self {
            Self {
                result,
                count: std::sync::atomic::AtomicUsize::new(0),
                alive: None,
            }
        }

        /// A reviver whose daemon is demonstrably still running.
        fn with_a_live_daemon(result: Result<String, String>) -> Self {
            Self {
                alive: Some(true),
                ..Self::new(result)
            }
        }

        fn revives(&self) -> usize {
            self.count.load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl DaemonReviver for FakeReviver {
        async fn revive(&self) -> Result<String, String> {
            self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.result.clone()
        }

        async fn is_provably_alive(&self, base: &str) -> bool {
            match self.alive {
                Some(alive) => alive,
                None => daemon_is_provably_alive(base).await,
            }
        }
    }

    // ── Session-path revival over real sockets ─────────────────────────────
    //
    // The regression: only `/mcp/tools/call` had a revival path, so a repo
    // daemon that idled out between two tool calls left every
    // session/intent/traffic/status forward failing forever. These drive the
    // shared state machine those forwards now use, against real loopback
    // sockets, so reqwest's own error classification is exercised rather than
    // assumed. No daemon process is ever spawned.

    /// A loopback URL whose port is closed: what an exited daemon leaves behind.
    async fn exited_daemon_url() -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        format!("http://127.0.0.1:{port}")
    }

    /// Minimal HTTP responder answering every request with `200 OK` and `body`.
    /// Abort the returned handle to take it down.
    async fn stub_daemon(body: &'static str) -> (String, tokio::task::JoinHandle<()>) {
        stub_daemon_raw(200, "OK", body).await
    }

    /// As [`stub_daemon`], with an explicit status line. `content-length` always
    /// matches `body`, so a `204` carries a genuinely empty body.
    async fn stub_daemon_raw(
        status: u16,
        reason: &'static str,
        body: &'static str,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = [0u8; 8192];
                    let _ = socket.read(&mut buf).await;
                    let response = format!(
                        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\n\
                         content-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        (format!("http://127.0.0.1:{port}"), handle)
    }

    /// One-shot responder that also returns the exact HTTP request it received.
    async fn capturing_resources_daemon(
        body: &'static str,
    ) -> (
        String,
        tokio::sync::oneshot::Receiver<String>,
        tokio::task::JoinHandle<()>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (request_tx, request_rx) = tokio::sync::oneshot::channel();
        let handle = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                let mut chunk = [0u8; 2048];
                let read = socket.read(&mut chunk).await.unwrap();
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
                let Some(header_end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n")
                else {
                    continue;
                };
                let headers = String::from_utf8_lossy(&request[..header_end]);
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                if request.len() >= header_end + 4 + content_length {
                    break;
                }
            }
            let _ = request_tx.send(String::from_utf8_lossy(&request).into_owned());
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
                 connection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
            let _ = socket.shutdown().await;
        });
        (format!("http://127.0.0.1:{port}"), request_rx, handle)
    }

    #[tokio::test]
    async fn resources_observation_preserves_refusal_on_legacy_and_error_shapes() {
        let client = probe_client();
        let arguments = HashMap::new();

        let (exact, exact_handle) = stub_daemon(
            r#"{"embed_runtime":{"embeddings_pending":0,"embeddings_indexed":4,"embeddings_total":4}}"#,
        )
        .await;
        assert_eq!(
            fetch_embedding_coverage_from_resources_at(&client, &exact, &arguments).await,
            Some(coverage(0, 4, 4))
        );
        exact_handle.abort();

        let (legacy, legacy_handle) =
            stub_daemon(r#"{"embed_runtime":{"embeddings_indexed":4}}"#).await;
        assert_eq!(
            fetch_embedding_coverage_from_resources_at(&client, &legacy, &arguments).await,
            None,
            "an older daemon that omits exact coverage is not proof of completion"
        );
        legacy_handle.abort();

        let (malformed, malformed_handle) = stub_daemon("not json").await;
        assert_eq!(
            fetch_embedding_coverage_from_resources_at(&client, &malformed, &arguments).await,
            None
        );
        malformed_handle.abort();

        let (failed, failed_handle) =
            stub_daemon_raw(500, "Internal Server Error", r#"{"error":"old daemon"}"#).await;
        assert_eq!(
            fetch_embedding_coverage_from_resources_at(&client, &failed, &arguments).await,
            None
        );
        failed_handle.abort();
    }

    #[tokio::test]
    async fn resources_observation_posts_the_default_request_for_the_callers_session() {
        let client = probe_client();
        let mut arguments = HashMap::new();
        arguments.insert(
            "session_id".to_string(),
            serde_json::json!("session-selected-graph"),
        );
        let (base, request_rx, handle) = capturing_resources_daemon(
            r#"{"embed_runtime":{"embeddings_pending":0,"embeddings_indexed":4,"embeddings_total":4}}"#,
        )
        .await;

        assert_eq!(
            fetch_embedding_coverage_from_resources_at(&client, &base, &arguments).await,
            Some(coverage(0, 4, 4))
        );
        let request = request_rx.await.expect("captured resources request");
        let request_lower = request.to_ascii_lowercase();
        assert!(
            request.starts_with("POST /commands/resources HTTP/1.1"),
            "the observation must use the inspect-only resources route: {request}"
        );
        assert!(
            request_lower.contains("x-kin-session: session-selected-graph"),
            "the count must describe the same selected graph as the tool answer: {request}"
        );
        assert!(
            request.contains(r#"{"json":false}"#),
            "the observation uses the endpoint's default request shape: {request}"
        );
        handle.abort();
    }

    /// The intent-release forward reads its response through the shared JSON
    /// helper, but the daemon answers `DELETE /intent/{id}` with `204 No
    /// Content`. An empty body must read as `Null`, not as a parse failure that
    /// would report a successful release as an error.
    #[tokio::test]
    async fn empty_204_body_reads_as_null_rather_than_a_parse_failure() {
        let (base, handle) = stub_daemon_raw(204, "No Content", "").await;
        let client = probe_client();
        let value = send_daemon_json(
            "release intent",
            client.delete(format!("{base}/intent/intent-1")),
        )
        .await
        .expect("204 No Content must not be an error");
        assert!(value.is_null(), "empty body must read as Null: {value:?}");
        handle.abort();
    }

    /// A non-empty body that is not JSON is still a loud failure: the empty-body
    /// allowance must not become a general "ignore the body" path.
    #[tokio::test]
    async fn non_json_body_is_still_an_error() {
        let (base, handle) = stub_daemon_raw(200, "OK", "not json at all").await;
        let client = probe_client();
        let err = send_daemon_json("session start", client.get(format!("{base}/session")))
            .await
            .expect_err("a non-JSON body must fail");
        assert!(
            matches!(err, DaemonCallError::DaemonError(ref m) if m.contains("parse failed")),
            "expected a parse failure, got: {err:?}"
        );
        handle.abort();
    }

    fn valid_graph_status_result() -> ToolCallResult {
        ToolCallResult::text(
            serde_json::json!({
                "schema": "kin.graph-status.v1",
                "view": "daemon_selected_graph",
                "scope": "head",
                "authority": "repo-daemon",
                "sampling": "point_in_time_selected_graph",
                "authority_epoch": 42,
                "entity_count": 42,
                "relation_count": 17,
                "embedding_source": "selected_graph",
                "embeddings_indexed": 7,
                "embeddings_pending": 3,
                "embeddings_total": 10,
                "completion_attested": false
            })
            .to_string(),
        )
    }

    #[test]
    fn graph_status_accepts_the_exact_daemon_contract() {
        let result = valid_graph_status_result();
        let ContentBlock::Text { text: expected } = &result.content[0];
        let expected = expected.clone();
        let validated = validate_graph_status_result(result).unwrap();
        let ContentBlock::Text { text: actual } = &validated.content[0];
        assert_eq!(actual, &expected);
    }

    #[test]
    fn graph_status_rejects_a_durable_status_body() {
        let result = ToolCallResult::text(
            serde_json::json!({
                "report": {
                    "schema": "kin.status.v3",
                    "semantic_enrichment": { "entity_count": 42 }
                }
            })
            .to_string(),
        );
        let error = validate_graph_status_result(result)
            .expect_err("durable repository status cannot masquerade as MCP query-graph status");
        assert!(error.contains("unknown field `report`"), "{error}");
    }

    #[test]
    fn graph_status_rejects_wrong_schema_scope_and_additive_drift() {
        for (field, value, expected) in [
            (
                "schema",
                serde_json::json!("kin.graph-status.v0"),
                "unsupported graph status schema",
            ),
            (
                "scope",
                serde_json::json!("workspace"),
                "unknown variant `workspace`",
            ),
            (
                "authority",
                serde_json::json!("repository-v6"),
                "unknown variant `repository-v6`",
            ),
            (
                "completion_attested",
                serde_json::json!(true),
                "does not carry an enrichment-completion attestation",
            ),
            (
                "unexpected",
                serde_json::json!(true),
                "unknown field `unexpected`",
            ),
        ] {
            let ContentBlock::Text { text } = &valid_graph_status_result().content[0];
            let mut body: serde_json::Value = serde_json::from_str(text).unwrap();
            body[field] = value;
            let error = validate_graph_status_result(ToolCallResult::text(body.to_string()))
                .expect_err("contract drift must fail before the result reaches stdio");
            assert!(error.contains(expected), "{field}: {error}");
        }
    }

    #[test]
    fn graph_status_rejects_impossible_embedding_coverage() {
        for (indexed, pending, total, expected) in [
            (
                11,
                0,
                10,
                "embeddings_indexed (11) exceeds embeddings_total (10)",
            ),
            (
                7,
                2,
                10,
                "embeddings_pending (2) is below the uncovered embedding count (3)",
            ),
        ] {
            let ContentBlock::Text { text } = &valid_graph_status_result().content[0];
            let mut body: serde_json::Value = serde_json::from_str(text).unwrap();
            body["embeddings_indexed"] = serde_json::json!(indexed);
            body["embeddings_pending"] = serde_json::json!(pending);
            body["embeddings_total"] = serde_json::json!(total);
            let error = validate_graph_status_result(ToolCallResult::text(body.to_string()))
                .expect_err("impossible coverage must fail before the result reaches stdio");
            assert!(error.contains(expected), "{error}");
        }
    }

    #[test]
    fn graph_status_preserves_daemon_errors_without_parsing_their_text() {
        let result = ToolCallResult::error("daemon graph unavailable");
        let ContentBlock::Text { text: expected } = &result.content[0];
        let expected = expected.clone();
        let validated = validate_graph_status_result(result).unwrap();
        assert_eq!(validated.is_error, Some(true));
        let ContentBlock::Text { text: actual } = &validated.content[0];
        assert_eq!(actual, &expected);
    }

    /// An HTTP error from a live daemon must classify as `DaemonError`, never
    /// `ConnectionLost`: only the latter triggers revival, and restarting a
    /// daemon that just answered is wasted work.
    #[tokio::test]
    async fn http_error_from_a_live_daemon_is_not_a_connection_loss() {
        let (base, handle) = stub_daemon_raw(500, "Internal Server Error", "{}").await;
        let client = probe_client();
        let err = send_daemon_json("session start", client.get(format!("{base}/session")))
            .await
            .expect_err("HTTP 500 must fail");
        assert!(
            matches!(err, DaemonCallError::DaemonError(ref m) if m.contains("HTTP 500")),
            "expected a DaemonError naming the status, got: {err:?}"
        );
        handle.abort();
    }

    #[tokio::test]
    async fn daemon_error_body_is_preserved_but_bounded() {
        let oversized: &'static str = Box::leak(
            "actionable "
                .repeat(MAX_DAEMON_ERROR_BODY_BYTES)
                .into_boxed_str(),
        );
        let (base, handle) = stub_daemon_raw(400, "Bad Request", oversized).await;
        let client = probe_client();
        let error = send_daemon_json("transaction", client.post(format!("{base}/transaction")))
            .await
            .expect_err("HTTP 400 must fail");
        let DaemonCallError::DaemonError(message) = error else {
            panic!("an HTTP response must not be classified as a connection loss");
        };

        assert!(
            message.contains("actionable"),
            "the daemon's diagnostic body must survive: {message}"
        );
        assert!(
            message.contains("[truncated]"),
            "an oversized diagnostic must say it was truncated: {message}"
        );
        assert!(
            message.len() <= MAX_DAEMON_ERROR_BODY_BYTES + 128,
            "bounded error body grew to {} bytes",
            message.len()
        );
        handle.abort();
    }

    /// Drive the real heartbeat delegate response reader and the same final
    /// ToolCallResult adapter used by the product handler. This is the boundary
    /// the direct Axum route test cannot cover.
    #[tokio::test]
    async fn expired_session_404_reaches_the_final_mcp_tool_result() {
        let body = "session not found: dead-session. It expired after its idle timeout. \
                    Call kin_session_start for a new session id.";
        let (base, handle) = stub_daemon_raw(404, "Not Found", body).await;

        let forwarded = session_heartbeat_request(&base, "dead-session")
            .await
            .map(Some);
        let result = crate::handlers::sessions::delegated_session_heartbeat_result(
            forwarded,
            crate::server::SessionAuthorityMode::DaemonRequired,
        )
        .expect("delegate adaptation must succeed")
        .expect("daemon-required mode must produce a result");

        assert_eq!(result.is_error, Some(true));
        let ContentBlock::Text { text } = result
            .content
            .first()
            .expect("error ToolCallResult must carry text");
        assert!(
            text.contains("expired") && text.contains("kin_session_start"),
            "final MCP error lost the daemon recovery diagnosis: {text}"
        );
        handle.abort();
    }

    fn probe_client() -> reqwest::Client {
        reqwest::Client::builder()
            .connect_timeout(Duration::from_millis(300))
            .timeout(Duration::from_secs(3))
            .pool_max_idle_per_host(0)
            .build()
            .unwrap()
    }

    /// One `POST {base}/session` attempt, classified and budgeted the way the
    /// real session forward classifies and budgets it.
    async fn post_session(
        client: &reqwest::Client,
        base: &str,
        patience: Duration,
    ) -> Result<serde_json::Value, DaemonCallError> {
        let resp = client
            .post(format!("{base}/session"))
            .timeout(patience)
            .json(&serde_json::json!({ "vendor": "test" }))
            .send()
            .await
            .map_err(|e| classify_send_error("session start", e))?;
        if !resp.status().is_success() {
            return Err(daemon_http_error("session start", resp).await);
        }
        resp.json().await.map_err(|e| {
            DaemonCallError::DaemonError(format!("daemon session start response parse failed: {e}"))
        })
    }

    /// (a) The daemon exits between calls; the next session forward transparently
    /// respawns and succeeds. Before this change the same call returned a hard
    /// error and every later one did too, for the life of the agent process.
    #[tokio::test]
    async fn session_forward_survives_daemon_exit_by_reviving() {
        let dead = exited_daemon_url().await;
        let (revived, revived_handle) = stub_daemon(r#"{"session_id":"s-1"}"#).await;
        let reviver = FakeReviver::new(Ok(revived.clone()));
        let client = probe_client();

        let value: serde_json::Value =
            attempt_with_revival("session start", &dead, &reviver, |base, patience| {
                let client = client.clone();
                async move { post_session(&client, &base, patience).await }
            })
            .await
            .expect("session start must recover through revival");

        assert_eq!(
            value["session_id"], "s-1",
            "the response must come from the revived daemon"
        );
        assert_eq!(reviver.revives(), 1, "revive runs exactly once");
        revived_handle.abort();
    }

    /// A live daemon is never disturbed: no retry, no revival, one request.
    #[tokio::test]
    async fn healthy_daemon_never_triggers_revival() {
        let (live, live_handle) = stub_daemon(r#"{"session_id":"s-live"}"#).await;
        let reviver = FakeReviver::new(Err("revival must not run".to_string()));
        let client = probe_client();

        let value: serde_json::Value =
            attempt_with_revival("session start", &live, &reviver, |base, patience| {
                let client = client.clone();
                async move { post_session(&client, &base, patience).await }
            })
            .await
            .expect("healthy daemon must answer directly");

        assert_eq!(value["session_id"], "s-live");
        assert_eq!(reviver.revives(), 0);
        live_handle.abort();
    }

    /// (b) When respawn cannot succeed, the caller gets the distinguishable
    /// "daemon exited" class rather than a generic delegate failure.
    #[tokio::test]
    async fn unrecoverable_respawn_surfaces_the_daemon_exited_class() {
        let dead = exited_daemon_url().await;
        let reviver = FakeReviver::new(Err("kin-daemon binary not found".to_string()));
        let client = probe_client();

        let err = attempt_with_revival("session start", &dead, &reviver, |base, patience| {
            let client = client.clone();
            async move { post_session(&client, &base, patience).await }
        })
        .await
        .expect_err("a dead daemon that cannot be revived must fail");

        assert!(
            is_daemon_exited_error(&err),
            "must carry the unrecoverable-daemon class: {err}"
        );
        assert!(
            err.contains("kin-daemon binary not found"),
            "must preserve why revival failed: {err}"
        );
        assert!(
            err.contains("kin mcp start"),
            "must state the recovery action: {err}"
        );
    }

    /// An error from a *live* daemon must not be mistaken for the daemon being
    /// gone: an agent that restarts its MCP server over a bad argument has
    /// misread the failure.
    #[tokio::test]
    async fn live_daemon_errors_are_not_the_daemon_exited_class() {
        let seam = FakeSeam::new(
            vec![Err(daemon_err())],
            Ok("http://127.0.0.1:9".to_string()),
        );
        let err = forward_mcp_with_seam("tool", &HashMap::new(), &seam, "http://127.0.0.1:4219")
            .await
            .unwrap_err();
        assert!(
            !is_daemon_exited_error(&err),
            "an HTTP 500 from a live daemon is not a lifecycle failure: {err}"
        );
    }

    /// A revived daemon that still fails is equally unrecoverable, and says so
    /// in the same class.
    #[tokio::test]
    async fn failure_after_revival_is_also_the_daemon_exited_class() {
        let seam = FakeSeam::new(
            vec![Err(conn_lost()), Err(conn_lost()), Err(conn_lost())],
            Ok("http://127.0.0.1:9999".to_string()),
        );
        let err = forward_mcp_with_seam("tool", &HashMap::new(), &seam, "http://127.0.0.1:4219")
            .await
            .unwrap_err();
        assert!(is_daemon_exited_error(&err), "{err}");
    }

    // ── Idle-timeout injection ─────────────────────────────────────────────

    /// (c) `KIN_DAEMON_IDLE_TIMEOUT_SECS` override behaviour: a user value
    /// propagates to the child on its own and must never be overwritten;
    /// otherwise the revival path injects the 30-minute MCP window.
    #[test]
    fn revival_spawn_injects_mcp_idle_timeout_unless_user_set_one() {
        assert_eq!(
            mcp_spawn_idle_timeout(false),
            Some(MCP_IDLE_TIMEOUT_SECS),
            "with no user override the revived daemon gets the MCP window"
        );
        assert_eq!(
            mcp_spawn_idle_timeout(true),
            None,
            "a user-set KIN_DAEMON_IDLE_TIMEOUT_SECS must never be overwritten"
        );
    }

    // ── Revival spawn contract ─────────────────────────────────────────────
    //
    // This path used to reserve a port itself, pass the number, and fall back
    // to a hardcoded 4219 when reservation failed. Both are gone: the daemon
    // binds and reports, and the port comes back off the port file.

    #[test]
    fn revival_lets_the_daemon_choose_its_port() {
        let plan = mcp_spawn_plan(
            std::path::PathBuf::from("/usr/bin/kin-daemon"),
            std::path::PathBuf::from("/repo"),
            None,
        );
        let cmd = plan.command();
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().to_string())
            .collect();

        assert_eq!(
            args,
            vec!["--repo", "/repo", "--port", "0"],
            "revival must pass --port 0, not a port it reserved and released"
        );
        assert!(
            !args.contains(&"4219".to_string()),
            "no hardcoded fallback port may reach the daemon: {args:?}"
        );
    }

    #[test]
    fn revival_carries_the_operator_background_embed_opt_out() {
        // A daemon revived under an agent session is still the operator's
        // machine. The opt-out decides whether opening a store starts a bulk
        // accelerator pass, and this path spawns without a human watching, so
        // the value has to travel with the spawn rather than be inherited from
        // whatever the shim's environment happened to be.
        let _env = kin_core::test_env::EnvVarGuard::set("KIN_DAEMON_AUTO_EMBED", "0");
        let plan = mcp_spawn_plan(
            std::path::PathBuf::from("/usr/bin/kin-daemon"),
            std::path::PathBuf::from("/repo"),
            None,
        );
        let carried = plan.command().get_envs().any(|(key, value)| {
            key == "KIN_DAEMON_AUTO_EMBED"
                && value.map(|value| value.to_string_lossy().into_owned()) == Some("0".to_string())
        });
        assert!(
            carried,
            "the MCP revival spawn dropped the operator's background-embedding opt-out"
        );
    }

    #[test]
    fn revival_states_no_background_embed_choice_the_operator_did_not_make() {
        let _env = kin_core::test_env::EnvVarGuard::unset("KIN_DAEMON_AUTO_EMBED");
        let plan = mcp_spawn_plan(
            std::path::PathBuf::from("/usr/bin/kin-daemon"),
            std::path::PathBuf::from("/repo"),
            None,
        );
        assert!(
            !plan
                .command()
                .get_envs()
                .any(|(key, _)| key == "KIN_DAEMON_AUTO_EMBED"),
            "the MCP revival spawn invented a background-embedding setting"
        );
    }

    #[test]
    fn revival_reads_the_port_the_daemon_reported() {
        let dir = tempfile::tempdir().unwrap();
        // The port file is the handshake; nothing else names the port.
        assert_eq!(kin_daemon_spawn::read_reported_port(dir.path()), None);
        std::fs::write(dir.path().join(kin_daemon_spawn::PORT_FILE_NAME), "51234\n").unwrap();
        assert_eq!(
            kin_daemon_spawn::read_reported_port(dir.path()),
            Some(51234)
        );
    }

    #[test]
    fn revival_passes_a_supervisor_url_through_to_the_daemon() {
        let plan = mcp_spawn_plan(
            std::path::PathBuf::from("/usr/bin/kin-daemon"),
            std::path::PathBuf::from("/repo"),
            Some("http://127.0.0.1:9100".to_string()),
        );
        let cmd = plan.command();
        let has_supervisor = cmd.get_envs().any(|(k, v)| {
            k == "KIN_SUPERVISOR_URL"
                && v.map(|v| v.to_string_lossy().to_string())
                    == Some("http://127.0.0.1:9100".to_string())
        });
        assert!(
            has_supervisor,
            "a revived daemon must be told where its supervisor is"
        );
    }

    // ── Revival single-flight ──────────────────────────────────────────────

    /// Every forward now reaches revival, so a dead daemon can be observed by
    /// several calls at once. The first caller's daemon must be reused rather
    /// than each caller starting its own and losing the repo-lock race.
    #[tokio::test]
    async fn revival_reuses_a_daemon_another_caller_already_started() {
        let (already_revived, handle) = stub_daemon(r#"{"status":"ok"}"#).await;
        if let Ok(mut guard) = DAEMON_URL_OVERRIDE.lock() {
            *guard = Some(already_revived.clone());
        }

        // No .kin discovery, no binary lookup, no spawn: the healthy override
        // short-circuits before any of that.
        let revived = revive_mcp_daemon()
            .await
            .expect("must reuse the live daemon");
        assert_eq!(revived, already_revived);

        clear_daemon_url_override();
        handle.abort();
    }

    /// The delegate client must not gate calls on a liveness probe. Returning
    /// `None` for an unreachable daemon is what made the delegate swallow the
    /// signal revival exists to act on.
    #[tokio::test]
    async fn daemon_client_is_available_without_a_reachable_daemon() {
        assert!(
            daemon_client().await.is_some(),
            "client construction must not depend on a live daemon"
        );
    }

    fn conn_lost() -> DaemonCallError {
        DaemonCallError::ConnectionLost("connection refused".into())
    }

    fn daemon_err() -> DaemonCallError {
        DaemonCallError::DaemonError("HTTP 500 Internal Server Error".into())
    }

    fn ok_tool_result() -> Result<Option<ToolCallResult>, DaemonCallError> {
        Ok(Some(ToolCallResult::text("ok".to_string())))
    }

    #[tokio::test]
    async fn revival_triggered_exactly_once_on_connection_error() {
        // Attempt and same-URL retry both fail, revival succeeds, post-revival
        // retry succeeds: three calls, one revival.
        let seam = FakeSeam::new(
            vec![Err(conn_lost()), Err(conn_lost()), ok_tool_result()],
            Ok("http://127.0.0.1:9999".to_string()),
        );
        let result =
            forward_mcp_with_seam("tool", &HashMap::new(), &seam, "http://127.0.0.1:4219").await;
        assert!(result.is_ok(), "should succeed after revival: {result:?}");
        assert_eq!(
            seam.calls_made(),
            3,
            "attempt, same-URL retry, post-revival retry"
        );
        assert_eq!(seam.revives_attempted(), 1, "revive must run exactly once");
    }

    /// The regression that motivated the same-URL retry: a stale kept-alive
    /// socket (or a request landing in the daemon's post-boot stall) produces
    /// one transport error against a perfectly healthy daemon. Revival against
    /// a healthy daemon cannot succeed, because the live daemon holds the repo
    /// lock, so treating the first transport error as daemon-down turned one
    /// stale socket into a failed tool call. The retry must heal it with no
    /// revival at all.
    #[tokio::test]
    async fn stale_socket_heals_on_same_url_retry_without_revival() {
        let seam = FakeSeam::new(
            vec![Err(conn_lost()), ok_tool_result()],
            Err("revival must not run".to_string()),
        );
        let result =
            forward_mcp_with_seam("tool", &HashMap::new(), &seam, "http://127.0.0.1:4219").await;
        assert!(result.is_ok(), "retry should heal the call: {result:?}");
        assert_eq!(seam.calls_made(), 2, "attempt plus same-URL retry");
        assert_eq!(
            seam.revives_attempted(),
            0,
            "a single transport error must not trigger revival"
        );
    }

    #[tokio::test]
    async fn non_connection_error_bypasses_revival() {
        let seam = FakeSeam::new(
            vec![Err(daemon_err())],
            Ok("http://127.0.0.1:9999".to_string()),
        );
        let result =
            forward_mcp_with_seam("tool", &HashMap::new(), &seam, "http://127.0.0.1:4219").await;
        let err = result.unwrap_err();
        assert!(err.contains("HTTP 500"), "original error preserved: {err}");
        assert_eq!(
            seam.revives_attempted(),
            0,
            "revive must NOT run for HTTP errors"
        );
        assert_eq!(
            seam.calls_made(),
            1,
            "only one call_tool attempt for HTTP errors"
        );
    }

    #[tokio::test]
    async fn revival_failure_yields_actionable_error() {
        let seam = FakeSeam::new(
            vec![Err(conn_lost()), Err(conn_lost())],
            Err("binary not found".to_string()),
        );
        let err = forward_mcp_with_seam("tool", &HashMap::new(), &seam, "http://127.0.0.1:4219")
            .await
            .unwrap_err();
        assert!(
            err.contains("revival failed"),
            "must mention revival failure: {err}"
        );
        assert!(
            err.contains("kin mcp start"),
            "must suggest recovery action: {err}"
        );
    }

    #[tokio::test]
    async fn second_failure_after_revival_surfaces_clear_error() {
        let seam = FakeSeam::new(
            vec![Err(conn_lost()), Err(conn_lost()), Err(conn_lost())],
            Ok("http://127.0.0.1:9999".to_string()),
        );
        let err = forward_mcp_with_seam("tool", &HashMap::new(), &seam, "http://127.0.0.1:4219")
            .await
            .unwrap_err();
        assert!(
            err.contains("retry still failed"),
            "must indicate retry failure: {err}"
        );
        assert!(
            err.contains("kin daemon status"),
            "must suggest diagnostic: {err}"
        );
        assert_eq!(
            seam.revives_attempted(),
            1,
            "revival attempted at most once even when retry fails"
        );
    }

    #[test]
    fn mcp_idle_timeout_constant_is_1800() {
        assert_eq!(
            MCP_IDLE_TIMEOUT_SECS, "1800",
            "MCP path must use 30-min timeout"
        );
    }

    /// Verify that `reqwest::Error` from a connection-refused qualifies as a
    /// transport error.  Uses a loopback port that is expected to be closed.
    /// No real daemon is spawned.
    #[tokio::test]
    async fn connection_refused_is_a_transport_error() {
        // Bind then immediately drop to guarantee the port is closed.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_millis(300))
            .build()
            .unwrap();
        let err = client
            .get(format!("http://127.0.0.1:{port}/health"))
            .send()
            .await
            .unwrap_err();
        // The real seam classifies is_connect() as ConnectionLost.
        assert!(
            err.is_connect() || err.is_timeout(),
            "connection refused must be a connect error: {err:?}"
        );
    }

    // ── Existing tests below ───────────────────────────────────────────────

    /// Write a `daemon.token` containing `contents` into a fresh temp `.kin`
    /// dir and return (tempdir, kin_dir). The tempdir must outlive the call.
    fn kin_dir_with_token(contents: &str) -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).expect("mkdir .kin");
        std::fs::write(kin_dir.join("daemon.token"), contents).expect("write token");
        (dir, kin_dir)
    }

    // ── Auth token resolution (the R0 loopback-token contract seam) ──────────
    //
    // These lock the MCP client's precedence to the daemon's
    // `resolve_serve_auth_token` / `ensure_loopback_token` and the CLI's
    // `resolve_daemon_auth_token`: env override wins, else `<.kin>/daemon.token`,
    // with empty/whitespace treated as absent. A regression here silently breaks
    // every authenticated MCP→daemon forward once enforcement is enabled.

    #[test]
    fn auth_token_env_override_wins_over_file() {
        let (_guard, kin_dir) = kin_dir_with_token("file-token");
        let resolved = resolve_daemon_auth_token(Some("  env-token  ".to_string()), Some(&kin_dir));
        assert_eq!(resolved.as_deref(), Some("env-token"));
    }

    #[test]
    fn auth_token_falls_back_to_loopback_file() {
        let (_guard, kin_dir) = kin_dir_with_token("loopback-secret\n");
        let resolved = resolve_daemon_auth_token(None, Some(&kin_dir));
        // Trailing newline (as written by the daemon) is trimmed.
        assert_eq!(resolved.as_deref(), Some("loopback-secret"));
    }

    #[test]
    fn auth_token_empty_env_does_not_shadow_file() {
        let (_guard, kin_dir) = kin_dir_with_token("loopback-secret");
        let resolved = resolve_daemon_auth_token(Some("   ".to_string()), Some(&kin_dir));
        assert_eq!(resolved.as_deref(), Some("loopback-secret"));
    }

    #[test]
    fn auth_token_blank_file_is_absent() {
        // A blank token file must never produce a bare `Bearer ` header.
        let (_guard, kin_dir) = kin_dir_with_token("   \n");
        assert!(resolve_daemon_auth_token(None, Some(&kin_dir)).is_none());
    }

    #[test]
    fn auth_token_absent_when_no_env_and_no_kin_dir() {
        assert!(resolve_daemon_auth_token(None, None).is_none());
    }

    #[test]
    fn auth_token_absent_when_file_missing() {
        let dir = tempfile::tempdir().expect("tempdir");
        // .kin exists but has no daemon.token.
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).expect("mkdir .kin");
        assert!(resolve_daemon_auth_token(None, Some(&kin_dir)).is_none());
    }

    // ── Scope request-building (forwarded session/intent tools) ──────────────

    #[test]
    fn scope_to_string_accepts_bare_string() {
        let value = serde_json::json!("file:src/main.rs");
        assert_eq!(scope_to_string(&value).unwrap(), "file:src/main.rs");
    }

    #[test]
    fn scope_to_string_maps_tagged_variants() {
        assert_eq!(
            scope_to_string(&serde_json::json!({ "Entity": "abc" })).unwrap(),
            "entity:abc"
        );
        assert_eq!(
            scope_to_string(&serde_json::json!({ "Contract": "c1" })).unwrap(),
            "contract:c1"
        );
        assert_eq!(
            scope_to_string(&serde_json::json!({ "Artifact": "src/lib.rs" })).unwrap(),
            "file:src/lib.rs"
        );
    }

    #[test]
    fn scope_to_string_rejects_unknown_shape() {
        assert!(scope_to_string(&serde_json::json!(42)).is_err());
        assert!(scope_to_string(&serde_json::json!({ "Bogus": "x" })).is_err());
    }

    // ── Stage-time rejection parity on the daemon-forward path ───────────────
    //
    // `kin_transaction_stage` runs the same intrinsic validation before the
    // daemon round-trip as the in-process handler does, so an operation the
    // commit path would silently drop fails loud at stage time in product
    // (daemon) mode too — not only in offline/in-process mode.

    fn stage_args(
        operations: Vec<crate::session::McpMutationOperation>,
    ) -> HashMap<String, serde_json::Value> {
        let mut args = HashMap::new();
        args.insert("transaction_id".into(), serde_json::json!("tx-1"));
        args.insert(
            "operations".into(),
            serde_json::to_value(operations).expect("serialize operations"),
        );
        args
    }

    fn stage_op(
        verb: &str,
        payload: Option<crate::session::McpMutationPayload>,
    ) -> crate::session::McpMutationOperation {
        crate::session::McpMutationOperation {
            verb: verb.into(),
            target: String::new(),
            payload,
            body: None,
            destination: None,
            description: String::new(),
        }
    }

    fn stage_relation() -> crate::session::McpMutationPayload {
        crate::session::McpMutationPayload::Relation {
            from: kin_model::ids::EntityId::new(),
            to: kin_model::ids::EntityId::new(),
            kind: kin_model::relation::RelationKind::Calls,
        }
    }

    /// Product mode must teach the whole operation schema on a decode failure,
    /// exactly as the in-process handler does. This path used to decode by hand
    /// and answer with whichever single field serde stopped on, so a caller
    /// improvising the shape against a real daemon learned one field per
    /// attempt and never saw the contract it was failing.
    #[test]
    fn delegate_stage_decode_failure_names_the_whole_operation_schema() {
        let mut args = HashMap::new();
        args.insert("transaction_id".into(), serde_json::json!("tx-1"));
        args.insert(
            "operations".into(),
            serde_json::json!([{ "target": "Foo::bar", "content": "new source" }]),
        );
        let err = validate_stage_arguments(&args).unwrap_err();
        for expected in [
            "each element of `operations` is one of",
            "an entity source edit",
            "`verb` (string, REQUIRED)",
            "`target` (string, REQUIRED)",
            "`description` (string, REQUIRED)",
            "`body` (string, optional)",
            "`payload` (object, optional)",
            "`destination` (string, optional)",
            "a rewritten source file",
            "create/add/upsert/insert, update/modify, replace/overwrite, delete/remove, or \
             rename/move",
        ] {
            assert!(err.contains(expected), "refusal omits {expected:?}: {err}");
        }
    }

    /// The key a caller reaches for before it reaches for `body` is named in
    /// the refusal rather than dropped, because silently discarding it commits
    /// nothing while reporting success.
    #[test]
    fn delegate_stage_names_an_unknown_source_field_rather_than_dropping_it() {
        let mut args = HashMap::new();
        args.insert("transaction_id".into(), serde_json::json!("tx-1"));
        args.insert(
            "operations".into(),
            serde_json::json!([{
                "verb": "update",
                "target": "Foo::bar",
                "description": "why",
                "new_body": "new source",
            }]),
        );
        let err = validate_stage_arguments(&args).unwrap_err();
        assert!(err.contains("'new_body'"), "{err}");
        assert!(err.contains("New source text goes in `body`"), "{err}");
    }

    #[test]
    fn delegate_stage_rejects_relation_modify() {
        let args = stage_args(vec![stage_op("modify", Some(stage_relation()))]);
        let err = validate_stage_arguments(&args).unwrap_err();
        assert!(
            err.contains("not committable for relation payloads"),
            "{err}"
        );
    }

    #[test]
    fn delegate_stage_rejects_blob_payload() {
        let args = stage_args(vec![stage_op(
            "create",
            Some(crate::session::McpMutationPayload::Blob(vec![1, 2, 3])),
        )]);
        let err = validate_stage_arguments(&args).unwrap_err();
        assert!(
            err.contains("blob payloads are not yet committable"),
            "{err}"
        );
    }

    #[test]
    fn delegate_stage_accepts_committable_relation() {
        let args = stage_args(vec![stage_op("add", Some(stage_relation()))]);
        assert!(validate_stage_arguments(&args).is_ok());
    }

    #[test]
    fn delegate_stage_missing_operations_defers_to_daemon() {
        // No `operations` key => stage validation is a no-op so the daemon's
        // authoritative missing-parameter message stays the one the agent sees.
        let mut args = HashMap::new();
        args.insert("transaction_id".into(), serde_json::json!("tx-1"));
        assert!(validate_stage_arguments(&args).is_ok());
    }

    #[test]
    fn entity_source_failure_memo_hit_then_generation_invalidates() {
        let mut memo = EntitySourceFailureMemo::new(1);
        let key = ("session-a".to_string(), "entity-1".to_string());

        // Cold: nothing remembered yet.
        assert!(memo.get(1, &key).is_none());

        // Record a failure, then the identical (session, id) lookup is a HIT.
        memo.insert(
            1,
            key.clone(),
            "no entity exists with ID 'entity-1'".to_string(),
        );
        assert_eq!(
            memo.get(1, &key).as_deref(),
            Some("no entity exists with ID 'entity-1'"),
        );

        // A different id in the same session is unaffected.
        let other = ("session-a".to_string(), "entity-2".to_string());
        assert!(memo.get(1, &other).is_none());

        // A graph-generation bump drops the negative — a re-index may resurrect
        // the id, so the stale failure must not be served.
        assert!(memo.get(2, &key).is_none());
    }

    #[test]
    fn entity_source_memo_first_write_wins() {
        let mut memo = EntitySourceFailureMemo::new(0);
        let key = ("s".to_string(), "id".to_string());
        memo.insert(0, key.clone(), "first".to_string());
        memo.insert(0, key.clone(), "second".to_string());
        assert_eq!(memo.get(0, &key).as_deref(), Some("first"));
    }

    #[test]
    fn entity_source_memo_is_bounded_with_oldest_first_eviction() {
        let mut memo = EntitySourceFailureMemo::new(0);
        for i in 0..(ENTITY_SOURCE_MEMO_CAP + 5) {
            memo.insert(0, ("s".to_string(), format!("id-{i}")), format!("fail-{i}"));
        }
        assert_eq!(memo.entries.len(), ENTITY_SOURCE_MEMO_CAP);
        // The five oldest were evicted; the newest survive.
        for i in 0..5 {
            assert!(memo.get(0, &("s".to_string(), format!("id-{i}"))).is_none());
        }
        let newest = ENTITY_SOURCE_MEMO_CAP + 4;
        assert_eq!(
            memo.get(0, &("s".to_string(), format!("id-{newest}")))
                .as_deref(),
            Some(format!("fail-{newest}").as_str()),
        );
    }

    #[test]
    fn only_error_results_are_cacheable() {
        let err = ToolCallResult::error("boom".to_string());
        assert_eq!(
            cacheable_failure_message(Some(&err)).as_deref(),
            Some("boom")
        );

        let ok = ToolCallResult::text("{}".to_string());
        assert!(cacheable_failure_message(Some(&ok)).is_none());

        assert!(cacheable_failure_message(None).is_none());
    }

    #[test]
    fn session_key_prefers_explicit_argument() {
        let mut args = HashMap::new();
        args.insert(
            "session_id".to_string(),
            serde_json::json!("explicit-session"),
        );
        assert_eq!(session_key(&args), "explicit-session");
    }

    // ── On-demand delegate re-resolution ──────────────────────────────────
    //
    // The reported failure: an MCP server started before `kin init` created the
    // repository resolved no delegate, never asked again, and answered every
    // tool call for the rest of the session with one degraded string, while
    // `kin doctor` in the same directory at the same instant reported the
    // daemon reachable with every embedding indexed. These pin the three parts
    // of that: the recovery happens, it is bounded, and each of the three
    // situations the one string covered now says which it is and what a caller
    // can do about it.

    /// A scripted stand-in for the repository and the daemon route, counting
    /// every probe so the bound is assertable. Nothing here touches a
    /// filesystem, a daemon, or the wall clock.
    struct ScriptedProbe {
        working_dir: std::path::PathBuf,
        repository: std::sync::Mutex<Option<std::path::PathBuf>>,
        route: std::sync::Mutex<Option<String>>,
        route_probes: std::sync::atomic::AtomicUsize,
        repository_probes: std::sync::atomic::AtomicUsize,
        /// How long `running_route` takes to answer, for the probe-budget case.
        route_delay: Duration,
    }

    impl ScriptedProbe {
        fn empty_directory() -> Self {
            Self {
                working_dir: std::path::PathBuf::from("/work/express"),
                repository: std::sync::Mutex::new(None),
                route: std::sync::Mutex::new(None),
                route_probes: std::sync::atomic::AtomicUsize::new(0),
                repository_probes: std::sync::atomic::AtomicUsize::new(0),
                route_delay: Duration::ZERO,
            }
        }

        fn repository_without_daemon() -> Self {
            let probe = Self::empty_directory();
            probe.kin_init();
            probe
        }

        /// What `kin init` does to the world this probe reports.
        fn kin_init(&self) {
            *self.repository.lock().unwrap() = Some(std::path::PathBuf::from("/work/express/.kin"));
        }

        /// What starting a daemon does to it.
        fn daemon_starts(&self, url: &str) {
            *self.route.lock().unwrap() = Some(url.to_string());
        }

        fn route_probes(&self) -> usize {
            self.route_probes.load(std::sync::atomic::Ordering::Acquire)
        }

        fn repository_probes(&self) -> usize {
            self.repository_probes
                .load(std::sync::atomic::Ordering::Acquire)
        }
    }

    impl DelegateProbe for ScriptedProbe {
        fn working_dir(&self) -> std::path::PathBuf {
            self.working_dir.clone()
        }

        fn repository(&self) -> Option<std::path::PathBuf> {
            self.repository_probes
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            self.repository.lock().unwrap().clone()
        }

        async fn running_route(&self, _kin_root: &Path) -> Option<String> {
            self.route_probes
                .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
            if !self.route_delay.is_zero() {
                tokio::time::sleep(self.route_delay).await;
            }
            self.route.lock().unwrap().clone()
        }
    }

    fn fresh_gate() -> tokio::sync::Mutex<ReresolveGate> {
        tokio::sync::Mutex::new(ReresolveGate::default())
    }

    /// The whole reported failure, end to end at the resolver: a server that
    /// started with no repository under it answers the next call after `kin
    /// init` and a daemon, with no restart anywhere in between.
    #[tokio::test(start_paused = true)]
    async fn a_server_started_before_kin_init_resolves_once_the_repository_and_daemon_exist() {
        let probe = ScriptedProbe::empty_directory();
        let gate = fresh_gate();

        let first = resolve_delegate_within(
            &probe,
            &gate,
            RERESOLVE_PROBE_BUDGET,
            DelegateHistory::default(),
        )
        .await;
        assert!(
            matches!(
                first,
                DelegateResolution::Gap(DelegateGap::NoRepository { .. })
            ),
            "a directory with no repository must report exactly that: {first:?}"
        );

        probe.kin_init();
        probe.daemon_starts("http://127.0.0.1:37589");
        // No restart, no new process, and no waiting out a cooldown either:
        // the repository appearing is the world changing under the verdict, so
        // the very next call re-asks. The clock deliberately does not move.

        let second = resolve_delegate_within(
            &probe,
            &gate,
            RERESOLVE_PROBE_BUDGET,
            DelegateHistory::default(),
        )
        .await;
        assert_eq!(
            second,
            DelegateResolution::Resolved("http://127.0.0.1:37589".to_string()),
            "once the repository and its daemon exist the next call must resolve"
        );
    }

    /// The bound: a genuinely absent daemon must not turn every tool call into
    /// a probe, and must never turn one into a stall.
    #[tokio::test(start_paused = true)]
    async fn re_resolution_probes_once_per_cooldown_rather_than_once_per_call() {
        let probe = ScriptedProbe::repository_without_daemon();
        let gate = fresh_gate();

        for _ in 0..50 {
            let outcome = resolve_delegate_within(
                &probe,
                &gate,
                RERESOLVE_PROBE_BUDGET,
                DelegateHistory::default(),
            )
            .await;
            assert!(
                matches!(outcome, DelegateResolution::Gap(_)),
                "no daemon exists in this fixture, so nothing may resolve: {outcome:?}"
            );
        }
        assert_eq!(
            probe.route_probes(),
            1,
            "fifty calls inside one cooldown window must cost one probe, not fifty"
        );

        // Each elapsed window buys exactly one more probe, and the window
        // widens rather than staying at its first value.
        tokio::time::advance(RERESOLVE_MIN_BACKOFF).await;
        let _ = resolve_delegate_within(
            &probe,
            &gate,
            RERESOLVE_PROBE_BUDGET,
            DelegateHistory::default(),
        )
        .await;
        assert_eq!(probe.route_probes(), 2, "the elapsed window allows a probe");
        let _ = resolve_delegate_within(
            &probe,
            &gate,
            RERESOLVE_PROBE_BUDGET,
            DelegateHistory::default(),
        )
        .await;
        assert_eq!(
            probe.route_probes(),
            2,
            "the widened window must hold the next call off"
        );
        tokio::time::advance(RERESOLVE_MIN_BACKOFF * 2).await;
        let _ = resolve_delegate_within(
            &probe,
            &gate,
            RERESOLVE_PROBE_BUDGET,
            DelegateHistory::default(),
        )
        .await;
        assert_eq!(probe.route_probes(), 3, "the widened window elapses too");
    }

    /// The cooldown ceiling holds however long the daemon stays absent, so a
    /// long session never stops re-resolving and never starts spinning.
    #[tokio::test(start_paused = true)]
    async fn the_cooldown_widens_to_a_ceiling_and_stops_there() {
        let probe = ScriptedProbe::repository_without_daemon();
        let gate = fresh_gate();

        for _ in 0..12 {
            let _ = resolve_delegate_within(
                &probe,
                &gate,
                RERESOLVE_PROBE_BUDGET,
                DelegateHistory::default(),
            )
            .await;
            tokio::time::advance(RERESOLVE_MAX_BACKOFF).await;
        }
        assert_eq!(
            gate.lock().await.backoff,
            Some(RERESOLVE_MAX_BACKOFF),
            "the window must stop widening at its ceiling rather than growing without bound"
        );
    }

    /// A probe that never answers is abandoned for the round. The alternative
    /// is the failure this whole change exists to remove: a tool call that
    /// waits on daemon resolution instead of answering.
    #[tokio::test(start_paused = true)]
    async fn a_probe_that_hangs_is_abandoned_rather_than_awaited() {
        let mut probe = ScriptedProbe::repository_without_daemon();
        probe.route_delay = Duration::from_secs(600);
        let gate = fresh_gate();

        let began = tokio::time::Instant::now();
        let outcome = resolve_delegate_within(
            &probe,
            &gate,
            Duration::from_secs(3),
            DelegateHistory::default(),
        )
        .await;
        assert!(
            matches!(outcome, DelegateResolution::Gap(_)),
            "an abandoned probe resolves nothing: {outcome:?}"
        );
        assert!(
            began.elapsed() < Duration::from_secs(4),
            "the call must not wait out a probe that never answers: {:?}",
            began.elapsed()
        );
        assert_eq!(
            probe.repository_probes(),
            1,
            "the abandoned round still counts as this window's attempt"
        );
    }

    /// A resolution clears the cooldown, so the next outage starts from the
    /// short window rather than from whatever the last one widened to.
    #[tokio::test(start_paused = true)]
    async fn resolving_resets_the_cooldown() {
        let probe = ScriptedProbe::repository_without_daemon();
        let gate = fresh_gate();

        let _ = resolve_delegate_within(
            &probe,
            &gate,
            RERESOLVE_PROBE_BUDGET,
            DelegateHistory::default(),
        )
        .await;
        tokio::time::advance(RERESOLVE_MAX_BACKOFF).await;
        let _ = resolve_delegate_within(
            &probe,
            &gate,
            RERESOLVE_PROBE_BUDGET,
            DelegateHistory::default(),
        )
        .await;
        assert!(gate.lock().await.backoff.is_some());

        probe.daemon_starts("http://127.0.0.1:41000");
        tokio::time::advance(RERESOLVE_MAX_BACKOFF).await;
        let _ = resolve_delegate_within(
            &probe,
            &gate,
            RERESOLVE_PROBE_BUDGET,
            DelegateHistory::default(),
        )
        .await;

        let gate = gate.lock().await;
        assert_eq!(gate.backoff, None, "a resolution must clear the window");
        assert_eq!(gate.next_attempt_at, None);
        assert_eq!(
            gate.last_gap, None,
            "a stale gap must not outlive its cause"
        );
    }

    /// A cooldown installed while a repository existed must not be replayed
    /// after the client's repository changes underneath it: the verdict it
    /// carries was about a different repository.
    #[tokio::test(start_paused = true)]
    async fn a_changed_repository_clears_a_cooldown_measured_for_another_one() {
        let probe = ScriptedProbe::repository_without_daemon();
        let gate = fresh_gate();

        let _ = resolve_delegate_within(
            &probe,
            &gate,
            RERESOLVE_PROBE_BUDGET,
            DelegateHistory::default(),
        )
        .await;
        assert_eq!(probe.route_probes(), 1);
        let _ = resolve_delegate_within(
            &probe,
            &gate,
            RERESOLVE_PROBE_BUDGET,
            DelegateHistory::default(),
        )
        .await;
        assert_eq!(
            probe.route_probes(),
            1,
            "the cooldown holds within one repo"
        );

        *probe.repository.lock().unwrap() = Some(std::path::PathBuf::from("/work/requests/.kin"));
        let _ = resolve_delegate_within(
            &probe,
            &gate,
            RERESOLVE_PROBE_BUDGET,
            DelegateHistory::default(),
        )
        .await;
        assert_eq!(
            probe.route_probes(),
            2,
            "another repository is another question, so it is asked rather than replayed"
        );
    }

    /// Re-resolution asks a seam and never starts anything. The revival path
    /// is the only place in this module allowed to spawn a daemon, and it is
    /// reached from a failed *request* rather than from a probe; a probe that
    /// could spawn would put a daemon start behind every tool call made in a
    /// directory that has none, which is the boot-time spawn storm the
    /// no-spawn contract exists to prevent.
    #[tokio::test]
    async fn the_production_probe_reports_no_route_rather_than_starting_a_daemon() {
        let route = RealDelegateProbe
            .running_route(Path::new("/nonexistent/repository/.kin"))
            .await;
        assert!(
            route.is_none(),
            "with no route seam installed the probe must answer that it has none: {route:?}"
        );
    }

    // ── The three situations one string used to cover ─────────────────────

    fn gap_text(gap: &DelegateGap) -> String {
        gap.message("semantic_locate")
    }

    #[test]
    fn the_no_repository_message_names_the_path_and_a_caller_action() {
        let text = gap_text(&DelegateGap::NoRepository {
            working_dir: std::path::PathBuf::from("/work/express"),
        });
        assert!(
            text.contains("/work/express") && text.contains("is not a Kin repository"),
            "the message must name the path and what is wrong with it: {text}"
        );
        assert!(
            text.contains("kin init ."),
            "the caller's action is creating the repository: {text}"
        );
        assert!(
            text.contains("do not need to restart"),
            "an agent cannot restart its own MCP server, so the message must not ask it to: {text}"
        );
    }

    #[test]
    fn the_daemon_absent_message_names_the_repository_and_the_shared_probe() {
        let text = gap_text(&DelegateGap::DaemonNotRunning {
            repo: std::path::PathBuf::from("/work/express"),
            retry_in: Duration::from_secs(4),
        });
        assert!(
            text.contains("/work/express") && text.contains("no daemon is serving it"),
            "the message must separate a present repository from an absent daemon: {text}"
        );
        assert!(
            text.contains("kin doctor"),
            "the message must name the probe it shares with doctor, which is why the two cannot \
             disagree: {text}"
        );
        assert!(
            text.contains("at most 4s"),
            "the message must say when the delegate is re-resolved: {text}"
        );
        assert!(
            !text.contains("started before"),
            "a daemon that went away is not a startup-ordering failure: {text}"
        );
    }

    #[test]
    fn the_startup_ordering_message_says_the_server_predates_the_repository() {
        let text = gap_text(&DelegateGap::StartupPredatesRepository {
            repo: std::path::PathBuf::from("/work/express"),
            retry_in: Duration::from_secs(8),
        });
        assert!(
            text.contains("started before /work/express was a Kin repository"),
            "the message must name the ordering that caused this: {text}"
        );
        assert!(
            text.contains("not one-shot") && text.contains("at most 8s"),
            "the message must say the binding is retried and when: {text}"
        );
        assert!(
            text.contains("Do not restart the MCP server"),
            "the recovery a caller cannot perform must be ruled out explicitly: {text}"
        );
    }

    /// The startup-ordering diagnosis is claimed only on the evidence for it.
    #[test]
    fn only_a_never_bound_server_that_launched_without_a_repository_reports_the_ordering_case() {
        let repo = std::path::PathBuf::from("/work/express");
        let retry = Duration::from_secs(1);

        assert!(
            matches!(
                classify_daemon_absent(repo.clone(), retry, false, Some(false)),
                DelegateGap::StartupPredatesRepository { .. }
            ),
            "never bound, and no repository existed at launch: the reported failure"
        );
        assert!(
            matches!(
                classify_daemon_absent(repo.clone(), retry, false, Some(true)),
                DelegateGap::DaemonNotRunning { .. }
            ),
            "a repository that existed at launch makes this an ordinary absent daemon"
        );
        assert!(
            matches!(
                classify_daemon_absent(repo.clone(), retry, true, Some(false)),
                DelegateGap::DaemonNotRunning { .. }
            ),
            "a server that held a delegate once is past the startup-ordering case"
        );
        assert!(
            matches!(
                classify_daemon_absent(repo, retry, false, None),
                DelegateGap::DaemonNotRunning { .. }
            ),
            "an unreported startup must not be read as a claim that no repository existed"
        );
    }

    /// A call answered from the cooldown reports the wait that is actually
    /// left, not the window that was installed when the probe ran.
    #[tokio::test(start_paused = true)]
    async fn a_cooling_down_call_reports_the_remaining_wait() {
        let probe = ScriptedProbe::repository_without_daemon();
        let gate = fresh_gate();

        let _ = resolve_delegate_within(
            &probe,
            &gate,
            RERESOLVE_PROBE_BUDGET,
            DelegateHistory::default(),
        )
        .await;
        tokio::time::advance(RERESOLVE_MIN_BACKOFF / 2).await;
        let DelegateResolution::Gap(gap) = resolve_delegate_within(
            &probe,
            &gate,
            RERESOLVE_PROBE_BUDGET,
            DelegateHistory::default(),
        )
        .await
        else {
            panic!("no daemon exists in this fixture");
        };
        let retry_in = match gap {
            DelegateGap::DaemonNotRunning { retry_in, .. }
            | DelegateGap::StartupPredatesRepository { retry_in, .. } => retry_in,
            DelegateGap::NoRepository { .. } => panic!("the fixture has a repository"),
        };
        assert!(
            retry_in <= RERESOLVE_MIN_BACKOFF / 2 && !retry_in.is_zero(),
            "the wait reported must be what is left of the window: {retry_in:?}"
        );
    }

    // ── Slow is not dead: the escalating-patience ladder ───────────────────
    //
    // The asymmetry these cover: both transports face "is this daemon slow or
    // dead?", and this one used to answer it with a flat deadline. Every test
    // here pins one direction of that question, and the two named
    // `a_proven_dead_daemon_*` / `a_slow_daemon_*` are the paired falsification
    // — a real death must still be recovered, and a slow start must never be.

    /// An attempt closure that replays a fixed sequence, counting calls and the
    /// budget each one was handed. No sockets, no daemon, no wall clock.
    struct ScriptedAttempts {
        script: std::sync::Mutex<std::collections::VecDeque<DaemonCallError>>,
        budgets: std::sync::Mutex<Vec<Duration>>,
    }

    impl ScriptedAttempts {
        /// `errors` are replayed in order; every later call succeeds.
        fn new(errors: Vec<DaemonCallError>) -> Self {
            Self {
                script: std::sync::Mutex::new(errors.into()),
                budgets: std::sync::Mutex::new(Vec::new()),
            }
        }

        async fn attempt(&self, _url: String, budget: Duration) -> Result<u32, DaemonCallError> {
            self.budgets.lock().unwrap().push(budget);
            match self.script.lock().unwrap().pop_front() {
                Some(error) => Err(error),
                None => Ok(7),
            }
        }

        fn budgets(&self) -> Vec<Duration> {
            self.budgets.lock().unwrap().clone()
        }
    }

    fn warming() -> DaemonCallError {
        DaemonCallError::Warming(
            r#"HTTP 503: {"error":"daemon_opening","ready":false,"warming":true}"#.to_string(),
        )
    }

    fn timed_out() -> DaemonCallError {
        DaemonCallError::Timeout("operation timed out".to_string())
    }

    /// FALSIFICATION, "a slow daemon is never destroyed" direction.
    ///
    /// The daemon reports itself warming for well past the 60 s fast-path
    /// budget — 4 minutes of it, at the real production budgets — and then
    /// answers. Revival must never run, and the call must succeed. Time is
    /// paused, so the four simulated minutes cost no wall clock; what is under
    /// test is the ladder's arithmetic, and pausing is the only way to assert
    /// on the real 60/300 constants instead of a scaled-down stand-in.
    ///
    /// Before this change the same daemon was declared `ConnectionLost` at 60 s
    /// and put through a revival that cannot win the repo lock it is holding.
    #[tokio::test(start_paused = true)]
    async fn a_slow_daemon_warming_past_the_fast_path_is_never_revived() {
        // 4 minutes of warming at the 250 ms poll interval.
        let warm_polls = 4 * 60 * 4;
        let attempts = ScriptedAttempts::new((0..warm_polls).map(|_| warming()).collect());
        let reviver = FakeReviver::new(Err("revival must not run".to_string()));
        let started = tokio::time::Instant::now();

        let value = attempt_with_revival_within(
            "tool semantic_locate",
            "http://127.0.0.1:1",
            &reviver,
            |url, budget| attempts.attempt(url, budget),
            Duration::from_secs(60),
            Duration::from_secs(300),
        )
        .await
        .expect("a daemon that finished warming must answer the call that waited for it");

        assert_eq!(value, 7, "the answer must be the warmed daemon's");
        assert_eq!(
            reviver.revives(),
            0,
            "a daemon reporting that it is alive and opening must never be revived"
        );
        let waited = tokio::time::Instant::now() - started;
        assert!(
            waited > Duration::from_secs(60),
            "the wait must have run past the fast-path budget for this to prove anything, \
             waited {waited:?}"
        );
        assert!(
            waited < Duration::from_secs(300),
            "and must stay inside the patience deadline, waited {waited:?}"
        );
    }

    /// A timeout is the caller's patience running out, not a death certificate.
    /// It buys exactly one escalated attempt on the remaining budget, and never
    /// a revival.
    #[tokio::test(start_paused = true)]
    async fn a_timeout_escalates_the_budget_and_never_revives() {
        let attempts = ScriptedAttempts::new(vec![timed_out()]);
        let reviver = FakeReviver::new(Err("revival must not run".to_string()));

        let value = attempt_with_revival_within(
            "tool trace_data_flow",
            "http://127.0.0.1:1",
            &reviver,
            |url, budget| attempts.attempt(url, budget),
            Duration::from_secs(60),
            Duration::from_secs(300),
        )
        .await
        .expect("the escalated attempt must be allowed to answer");

        assert_eq!(value, 7);
        assert_eq!(reviver.revives(), 0, "a timeout must never reach revival");
        let budgets = attempts.budgets();
        assert_eq!(budgets.len(), 2, "exactly one escalation: {budgets:?}");
        assert_eq!(
            budgets[0],
            Duration::from_secs(60),
            "first attempt is the fast path"
        );
        assert!(
            budgets[1] > Duration::from_secs(200),
            "the escalated attempt must inherit the remaining patience, got {:?}",
            budgets[1]
        );
    }

    /// And when the escalated attempt also runs out, the daemon is still left
    /// alone. The message has to say so, because the whole failure mode being
    /// fixed is a user being told a running daemon exited.
    #[tokio::test(start_paused = true)]
    async fn exhausted_patience_reports_a_daemon_left_running() {
        let attempts = ScriptedAttempts::new(vec![timed_out(), timed_out()]);
        let reviver = FakeReviver::new(Err("revival must not run".to_string()));

        let err = attempt_with_revival_within::<u32, _, _>(
            "tool semantic_locate",
            "http://127.0.0.1:1",
            &reviver,
            |url, budget| attempts.attempt(url, budget),
            Duration::from_secs(60),
            Duration::from_secs(300),
        )
        .await
        .expect_err("two exhausted budgets must fail the call");

        assert_eq!(reviver.revives(), 0);
        assert!(
            err.contains("left running rather than restarted for being slow"),
            "the error must say the daemon was spared, got: {err}"
        );
        assert!(
            !err.contains(DAEMON_EXITED_RESTART_REQUIRED),
            "a daemon that never proved dead must not be reported as exited, got: {err}"
        );
    }

    /// FALSIFICATION, "a dead daemon is still recovered" direction.
    ///
    /// A real daemon is killed — its listener is dropped, so the port refuses
    /// connections exactly as an exited daemon's does — and the very next
    /// forward must revive and succeed. Patience must not have cost the client
    /// its recovery.
    #[tokio::test]
    async fn a_proven_dead_daemon_is_still_revived_after_the_patience_change() {
        let (dying, dying_handle) = stub_daemon(r#"{"session_id":"s-doomed"}"#).await;
        let client = probe_client();
        post_session(&client, &dying, Duration::from_secs(3))
            .await
            .expect("the daemon must be genuinely alive before it is killed");
        dying_handle.abort();
        await_refused(&dying).await;

        let (revived, revived_handle) = stub_daemon(r#"{"session_id":"s-revived"}"#).await;
        let reviver = FakeReviver::new(Ok(revived.clone()));

        let value: serde_json::Value = attempt_with_revival_within(
            "session start",
            &dying,
            &reviver,
            |base, patience| {
                let client = client.clone();
                async move { post_session(&client, &base, patience).await }
            },
            Duration::from_secs(3),
            Duration::from_secs(10),
        )
        .await
        .expect("a genuinely dead daemon must still be revived");

        assert_eq!(
            value["session_id"], "s-revived",
            "the answer must come from the revived daemon"
        );
        assert_eq!(reviver.revives(), 1, "revival must run exactly once");
        revived_handle.abort();
    }

    /// Two transport failures are evidence about the endpoint, not a verdict on
    /// the process. A daemon that is demonstrably running keeps the repository
    /// lock a replacement would need, so revival is withheld and the caller is
    /// told what is actually true rather than that the daemon exited.
    #[tokio::test]
    async fn a_daemon_proven_alive_is_never_replaced_by_a_doomed_respawn() {
        let unreachable = exited_daemon_url().await;
        let reviver = FakeReviver::with_a_live_daemon(Ok("http://127.0.0.1:1".to_string()));
        let client = probe_client();

        let err = attempt_with_revival_within::<serde_json::Value, _, _>(
            "session start",
            &unreachable,
            &reviver,
            |base, patience| {
                let client = client.clone();
                async move { post_session(&client, &base, patience).await }
            },
            Duration::from_secs(3),
            Duration::from_secs(10),
        )
        .await
        .expect_err("an unreachable endpoint must still fail the call");

        assert_eq!(
            reviver.revives(),
            0,
            "a daemon proven alive must not be replaced by a respawn that cannot take its lock"
        );
        assert!(
            err.contains("alive but did not answer"),
            "the caller must be told the daemon is alive, got: {err}"
        );
        assert!(
            !err.contains(DAEMON_EXITED_RESTART_REQUIRED),
            "a live daemon must never be reported as exited, got: {err}"
        );
    }

    /// The wire shape, end to end over a real socket: a daemon that publishes
    /// its endpoint before it can serve answers `503 daemon_opening`, and the
    /// delegate must read that as alive-and-warming rather than as a failed
    /// command. This is the client behavior early endpoint publication depends
    /// on.
    #[tokio::test]
    async fn a_warming_503_over_a_real_socket_is_waited_out_not_revived() {
        let (base, handle) = stub_daemon_warming_then_ok(3, r#"{"session_id":"s-warm"}"#).await;
        let reviver = FakeReviver::new(Err("revival must not run".to_string()));
        let client = probe_client();

        let value: serde_json::Value = attempt_with_revival_within(
            "session start",
            &base,
            &reviver,
            |base, patience| {
                let client = client.clone();
                async move { post_session(&client, &base, patience).await }
            },
            Duration::from_secs(3),
            Duration::from_secs(30),
        )
        .await
        .expect("a warming daemon must be waited for, not replaced");

        assert_eq!(value["session_id"], "s-warm");
        assert_eq!(
            reviver.revives(),
            0,
            "a daemon that answered 503 daemon_opening is listening, so it is alive"
        );
        handle.abort();
    }

    /// Block until nothing is listening at `base`, so a test that killed a stub
    /// is asserting against a genuinely closed port rather than racing the
    /// listener's teardown.
    async fn await_refused(base: &str) {
        let port: u16 = base.rsplit(':').next().unwrap().parse().unwrap();
        for _ in 0..200 {
            if tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_err()
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("the killed stub daemon never stopped accepting connections on {base}");
    }

    /// Serves `warming` warming refusals, then `body` with 200, per connection
    /// accepted. The delegate opens a fresh connection per attempt
    /// (`pool_max_idle_per_host(0)`), so the count is a count of attempts.
    async fn stub_daemon_warming_then_ok(
        warming: usize,
        body: &'static str,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = tokio::spawn(async move {
            let mut served = 0usize;
            while let Ok((mut socket, _)) = listener.accept().await {
                let warming_now = served < warming;
                served += 1;
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = [0u8; 8192];
                    let _ = socket.read(&mut buf).await;
                    let (status, reason, payload) = if warming_now {
                        (
                            503,
                            "Service Unavailable",
                            r#"{"error":"daemon_opening","ready":false,"warming":true}"#,
                        )
                    } else {
                        (200, "OK", body)
                    };
                    let response = format!(
                        "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\n\
                         content-length: {}\r\nconnection: close\r\n\r\n{payload}",
                        payload.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                    let _ = socket.shutdown().await;
                });
            }
        });
        (format!("http://127.0.0.1:{port}"), handle)
    }

    /// The warming guard has to be able to say no. A refusal that is not the
    /// daemon reporting its own startup must keep reading as the error it is,
    /// or a real outage would be politely waited out until the patience
    /// deadline.
    #[test]
    fn the_warming_guard_distinguishes_a_startup_from_an_outage() {
        let opening = r#"{"error":"daemon_opening","ready":false,"warming":true}"#;
        assert!(is_warming_refusal(
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            opening
        ));
        assert!(is_warming_refusal(
            reqwest::StatusCode::SERVICE_UNAVAILABLE,
            r#"{"ready":false,"warming":true}"#
        ));

        for (status, body, why) in [
            (
                reqwest::StatusCode::SERVICE_UNAVAILABLE,
                r#"{"error":"embedder_unavailable"}"#,
                "a real dependency outage is not a startup",
            ),
            (
                reqwest::StatusCode::SERVICE_UNAVAILABLE,
                r#"{"warming":false}"#,
                "a daemon that says it is not warming is not warming",
            ),
            (
                reqwest::StatusCode::SERVICE_UNAVAILABLE,
                "<html>502 from a proxy</html>",
                "a non-JSON refusal carries no daemon report at all",
            ),
            (
                reqwest::StatusCode::SERVICE_UNAVAILABLE,
                "",
                "an empty refusal carries no daemon report at all",
            ),
            (
                reqwest::StatusCode::INTERNAL_SERVER_ERROR,
                opening,
                "the status is part of the contract, not decoration",
            ),
            (
                reqwest::StatusCode::OK,
                opening,
                "a 200 is an answer, and must not be waited out",
            ),
        ] {
            assert!(
                !is_warming_refusal(status, body),
                "{why}: HTTP {status} {body}"
            );
        }
    }

    /// A request that is sent and not answered must not classify as the same
    /// thing as a port that refuses connections. Driven over real sockets so
    /// reqwest's own classification is exercised rather than assumed.
    #[tokio::test]
    async fn a_slow_answer_and_a_closed_port_classify_differently() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let silent_port = listener.local_addr().unwrap().port();
        let silent = tokio::spawn(async move {
            // Accept and never answer: the connection succeeds, the reply does
            // not come. Held open, because closing would surface as a reset —
            // the very class this test exists to keep separate.
            let mut held = Vec::new();
            while let Ok((socket, _)) = listener.accept().await {
                held.push(socket);
            }
        });
        let client = probe_client();

        let slow = post_session(
            &client,
            &format!("http://127.0.0.1:{silent_port}"),
            Duration::from_millis(300),
        )
        .await
        .expect_err("a silent daemon must not answer");
        assert!(
            matches!(slow, DaemonCallError::Timeout(_)),
            "an established connection with no reply is a timeout, got {slow:?}"
        );

        let closed = post_session(&client, &exited_daemon_url().await, Duration::from_secs(3))
            .await
            .expect_err("a closed port must not answer");
        assert!(
            matches!(closed, DaemonCallError::ConnectionLost(_)),
            "a refused connection is connection loss, got {closed:?}"
        );
        silent.abort();
    }

    /// Any HTTP answer proves a process is running, including a refusal. This
    /// is the veto that keeps a live daemon from being replaced by one that
    /// cannot take the repository lock it still holds.
    #[tokio::test]
    async fn a_refusing_daemon_still_counts_as_proof_of_life() {
        let (refusing, handle) = stub_daemon_raw(503, "Service Unavailable", r#"{"e":1}"#).await;
        assert!(
            daemon_is_provably_alive(&refusing).await,
            "a process that writes a response line is running"
        );
        handle.abort();

        assert!(
            !daemon_is_provably_alive(&exited_daemon_url().await).await,
            "a closed port offers no proof of life"
        );
    }

    /// A PID record proves life only for the endpoint it actually describes.
    #[test]
    fn the_recorded_owner_proves_life_only_for_its_own_process() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            !kin_daemon_spawn::recorded_owner_is_alive(dir.path()),
            "no record is not proof of life"
        );

        std::fs::write(
            dir.path().join(kin_daemon_spawn::PID_FILE_NAME),
            format!("{}\n", std::process::id()),
        )
        .unwrap();
        assert!(
            kin_daemon_spawn::recorded_owner_is_alive(dir.path()),
            "this test process is unambiguously running"
        );

        std::fs::write(
            dir.path().join(kin_daemon_spawn::PID_FILE_NAME),
            "not-a-pid",
        )
        .unwrap();
        assert!(
            !kin_daemon_spawn::recorded_owner_is_alive(dir.path()),
            "an unreadable record is not proof of life"
        );
    }

    /// The budgets the wrapper resolves are the ones the ladder is documented
    /// against, and the fast path is unchanged from the flat deadline it
    /// replaced, so nothing that answers today starts costing a second attempt.
    #[test]
    fn the_default_budgets_are_the_documented_ones() {
        assert_eq!(fast_path_patience(), Duration::from_secs(60));
        assert_eq!(escalated_patience(), Duration::from_secs(300));
        assert!(escalated_patience() > fast_path_patience());
    }

    // ── What a killed daemon says on the query path ─────────────────────

    fn memory_kill_record(kills: u64) -> kin_daemon_spawn::DaemonKillRecord {
        kin_daemon_spawn::DaemonKillRecord {
            kills,
            memory_kills: kills,
            first_unix: 4_320,
            last_unix: 4_800,
            last_pid: Some(41),
            last_cause: kin_daemon_spawn::DaemonKillCause::MemoryLimit {
                kernel_oom_kills: 1,
            },
            limit_bytes: Some(12 * 1024 * 1024 * 1024),
            last_rss_bytes: None,
        }
    }

    /// The positive control for every message below. A store that has never
    /// lost a daemon must read exactly as it read before any of this existed,
    /// so the expected strings here are the literal pre-change text.
    #[test]
    fn a_store_with_no_kill_record_reads_exactly_as_it_did() {
        assert_eq!(
            revival_failed_message(
                "tool find_references",
                "http://127.0.0.1:32881",
                "error sending request",
                "MCP revival: daemon exited during startup with status signal: 9 (SIGKILL)",
                None,
            ),
            "repo daemon exited; restart required: tool find_references: daemon at \
             http://127.0.0.1:32881 is not responding (error sending request); revival failed: \
             MCP revival: daemon exited during startup with status signal: 9 (SIGKILL). Restart \
             `kin mcp start` to recover."
        );
        assert_eq!(
            revived_retry_failed_message(
                "tool find_references",
                "http://127.0.0.1:34507",
                "timed out",
                None,
            ),
            "repo daemon exited; restart required: tool find_references: daemon was revived at \
             http://127.0.0.1:34507 but the retry still failed: timed out. Check `kin daemon \
             status`."
        );
        assert_eq!(
            transport_dropped_message(
                "MCP tool call",
                "error sending request for url (http://127.0.0.1:42231/mcp/tools/call)",
                None,
            ),
            "repo daemon stopped answering mid-request: MCP tool call: error sending \
             request for url (http://127.0.0.1:42231/mcp/tools/call)"
        );
    }

    /// The remediation a caller can perform replaces the one it cannot. An
    /// agent inside an MCP session does not own the `kin mcp start` process
    /// serving it, so that instruction was addressed to nobody present.
    #[test]
    fn a_recorded_memory_kill_replaces_the_advice_nobody_can_perform() {
        let record = memory_kill_record(4);
        let message = revival_failed_message(
            "tool find_references",
            "http://127.0.0.1:32881",
            "error sending request",
            "MCP revival: daemon exited during startup with status signal: 9 (SIGKILL)",
            Some(&record),
        );
        assert!(
            message.contains("killed by the memory limit 4 time(s) since 01:12Z"),
            "{message}"
        );
        assert!(message.contains("cap 12.0 GiB"), "{message}");
        assert!(
            message.contains("KIN_DAEMON_DISABLE_LSP=1 kin graph status"),
            "{message}"
        );
        assert!(
            !message.contains("Restart `kin mcp start` to recover"),
            "the unperformable remediation must be gone once a performable one exists: {message}"
        );
        assert!(
            message.starts_with(DAEMON_EXITED_RESTART_REQUIRED),
            "the error class a client keys on is unchanged: {message}"
        );
    }

    /// The two shapes that are not an exhausted revival still name the cause:
    /// a daemon revived that could not answer, and a connection that broke
    /// while it was carrying the request.
    #[test]
    fn the_other_two_daemon_loss_shapes_name_the_cause_too() {
        let record = memory_kill_record(4);
        for message in [
            revived_retry_failed_message(
                "tool find_references",
                "http://127.0.0.1:34507",
                "timed out",
                Some(&record),
            ),
            transport_dropped_message(
                "MCP tool call",
                "error sending request for url (http://127.0.0.1:42231/mcp/tools/call)",
                Some(&record),
            ),
        ] {
            assert!(
                message.contains("killed by the memory limit 4 time(s)"),
                "{message}"
            );
            assert!(
                message.contains("KIN_DAEMON_DISABLE_LSP=1 kin graph status"),
                "{message}"
            );
        }
    }

    /// A host that publishes no memory accounting gets the signal and nothing
    /// else. The words "memory limit" appear in a message only where a kernel
    /// counter put them.
    #[test]
    fn an_unattributed_kill_never_reads_as_a_memory_kill() {
        let record = kin_daemon_spawn::DaemonKillRecord {
            kills: 2,
            memory_kills: 0,
            first_unix: 4_320,
            last_unix: 4_800,
            last_pid: Some(41),
            last_cause: kin_daemon_spawn::DaemonKillCause::Unattributed { signal: 9 },
            limit_bytes: None,
            last_rss_bytes: None,
        };
        let message = revival_failed_message(
            "tool find_references",
            "http://127.0.0.1:32881",
            "error sending request",
            "exited with signal: 9 (SIGKILL)",
            Some(&record),
        );
        assert!(
            message.contains("killed by signal 9 2 time(s)"),
            "{message}"
        );
        assert!(
            !message.contains("killed by the memory limit"),
            "no counter said memory, so nothing may say memory: {message}"
        );
        assert!(
            message.contains("no memory accounting"),
            "the reason nothing is attributed belongs in the message: {message}"
        );
    }

    /// The `negative` envelope is attached by message wording: six named tools
    /// whose error text contains "no entity" or "entity not found"
    /// (`crate::negative::is_resolution_miss`). A sentence appended to a
    /// daemon-loss error must therefore not speak that language, or a transport
    /// failure would start carrying a resolution-miss verdict about an entity
    /// nobody asked about.
    #[test]
    fn the_recorded_cause_never_speaks_the_negative_envelope_s_language() {
        let record = memory_kill_record(4);
        let unattributed = kin_daemon_spawn::DaemonKillRecord {
            memory_kills: 0,
            last_cause: kin_daemon_spawn::DaemonKillCause::Unattributed { signal: 9 },
            limit_bytes: None,
            ..memory_kill_record(2)
        };
        for record in [&record, &unattributed] {
            for message in [
                revival_failed_message("tool find_references", "url", "err", "err", Some(record)),
                revived_retry_failed_message("tool find_references", "url", "err", Some(record)),
                transport_dropped_message("MCP tool call", "err", Some(record)),
            ] {
                let lowered = message.to_ascii_lowercase();
                assert!(!lowered.contains("no entity"), "{message}");
                assert!(!lowered.contains("entity not found"), "{message}");
            }
        }
    }
}
