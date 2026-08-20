// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{debug, error, info, warn};

use crate::api;
use crate::error::{DaemonError, Result};
use crate::loop_runner::{self, LoopConfig};
use crate::state::{DaemonState, RECON_IDLE};

/// Configuration for the daemon process.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// Port for the HTTP API server.
    pub api_port: u16,
    /// Reconciliation loop configuration.
    pub loop_config: LoopConfig,
    /// Interval for the orphan session sweeper (default 30s).
    pub sweep_interval: Duration,
    /// Interval for the background embedding worker (default 5s).
    pub embed_interval: Duration,
    /// Batch size for embedding inference (entities per pass).
    pub embed_batch_size: usize,
    /// Whether to enable LSP enrichment (auto-detected if not set).
    pub lsp_enabled: bool,
    /// Optional idle timeout. Intended for CLI-autostarted daemons so command
    /// bursts can reuse warm state without leaving background processes alive
    /// indefinitely.
    pub idle_timeout: Option<Duration>,
    /// Overlap the background embed worker's per-batch persist with the next
    /// batch's prep + GPU forward, so the accelerator is never idle during a
    /// flush. Off by default: the serial path is deterministic and is what the
    /// proof profile relies on. Enabled only under the throughput profile.
    pub embed_pipeline_overlap: bool,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            api_port: 4219,
            loop_config: LoopConfig::default(),
            sweep_interval: Duration::from_secs(30),
            embed_interval: Duration::from_secs(5),
            embed_batch_size: 512,
            lsp_enabled: true,
            idle_timeout: None,
            embed_pipeline_overlap: false,
        }
    }
}

fn should_enable_lsp_enrichment(config_enabled: bool, filesystem_reconcile_disabled: bool) -> bool {
    config_enabled && !filesystem_reconcile_disabled
}

/// Whether the daemon opens its enrichment channel at startup.
///
/// Taken ONCE, during startup, and that is the whole reason a language server
/// installed while a daemon is already running may not reach it. With no server
/// discovered here the channel is never created, so no enrichment message is
/// ever sent for the life of the process and no adapter is ever consulted. That
/// is the state the container behind the v0.5.42 stranger run was in: the Python
/// adapter did not fail to start, it was never reached.
///
/// When discovery DID find a server the channel exists and each language's
/// server is started lazily on first use, so a server installed afterwards is
/// picked up with no restart. Both halves are true, and only the pessimistic one
/// is safe for a surface to print, because a fresh install is exactly the host
/// where discovery finds nothing.
fn enrichment_channel_opens(enrichment_enabled: bool, servers_discovered: usize) -> bool {
    enrichment_enabled && servers_discovered > 0
}

/// Acquire the process-lifetime repository authority before daemon state opens.
pub fn acquire_daemon_authority(
    kin_root: &std::path::Path,
) -> Result<crate::lifecycle::DaemonLock> {
    acquire_daemon_authority_within(kin_root, crate::lifecycle::SINGLETON_LOCK_RETRY_BUDGET)
}

/// Acquire process-lifetime repository authority with one caller-owned budget.
///
/// Exposed so the process entrypoint can acquire before constructing
/// [`DaemonState`], and so deterministic tests can use a short deadline without
/// changing the production retry contract.
pub fn acquire_daemon_authority_within(
    kin_root: &std::path::Path,
    budget: Duration,
) -> Result<crate::lifecycle::DaemonLock> {
    let deadline = Instant::now() + budget;
    let reclaim = match crate::lifecycle::acquire_singleton_lock_within(kin_root, Duration::ZERO) {
        Ok(Some(lock)) => return Ok(lock),
        Ok(None) => {
            // Current automatic recovery deliberately refuses pathname
            // replacement at the mixed-version boundary. It still resolves
            // and reports owner evidence before the bounded retry. Both that
            // resolution and retry share this caller's one deadline.
            crate::lifecycle::reclaim_stale_locks_within(
                kin_root,
                deadline.saturating_duration_since(Instant::now()),
            )
        }
        Err(error) => return Err(DaemonError::Io(error)),
    };

    match crate::lifecycle::acquire_singleton_lock_within(
        kin_root,
        deadline.saturating_duration_since(Instant::now()),
    ) {
        Ok(Some(lock)) => Ok(lock),
        Ok(None) => Err(DaemonError::RepoOwnedByAnotherDaemon(
            singleton_contention_message(kin_root, reclaim),
        )),
        Err(error) => Err(DaemonError::Io(error)),
    }
}

/// Actionable refusal text for a daemon that lost the per-repo singleton lock.
///
/// Reads the holder from disk evidence and renders it. Kept split from
/// [`format_singleton_contention`] so the wording is testable without a repo.
fn singleton_contention_message(
    kin_root: &std::path::Path,
    reclaim: crate::lifecycle::StaleLockReclaim,
) -> String {
    format_singleton_contention(
        &kin_root.display().to_string(),
        crate::lifecycle::singleton_lock_holder(kin_root),
        &reclaim,
    )
}

/// Render the refusal a contended starter reports.
///
/// The old text ("another kin daemon already owns this repo") named nothing an
/// operator could act on, and the process exited 0 so the message never even
/// reached the caller as a failure. Every branch here names the evidence that
/// produced it and what to do next.
fn format_singleton_contention(
    repo: &str,
    holder: Option<crate::lifecycle::SingletonLockHolder>,
    reclaim: &crate::lifecycle::StaleLockReclaim,
) -> String {
    let reclaimed = reclaim.cleared().len();
    let context = match holder {
        Some(holder) if holder.alive => format!(
            "another kin daemon (pid {}) already owns {repo} and is still running",
            holder.pid
        ),
        // An identity-verified stamp can say the owning incarnation is gone
        // without implying anything about whoever holds that PID now.
        Some(holder) if holder.identity_verified => format!(
            "the daemon lock for {repo} is still held after the process that took it (pid {}) \
             exited, so a leaked lock fd is keeping it alive; pid {} no longer identifies that \
             daemon and may since have been reused",
            holder.pid, holder.pid
        ),
        Some(holder) => format!(
            "the daemon lock for {repo} is still held after its recorded owner (pid {}) exited, \
             so a leaked lock fd is keeping it alive",
            holder.pid
        ),
        None => format!(
            "the daemon lock for {repo} is held but names no owner, so the holding process \
             cannot be identified from disk"
        ),
    };
    let remedy = match holder {
        Some(holder) if holder.alive => format!(
            "wait for pid {} to finish starting, or stop it with `kin daemon stop`",
            holder.pid
        ),
        _ => "stop any remaining kin-daemon process for this repo, then retry".to_string(),
    };
    let compatibility_boundary = match reclaim {
        crate::lifecycle::StaleLockReclaim::CoordinationUnavailable(reason) => {
            format!(
                " Automatic lock-file retirement was refused because safe coordination is \
                 unavailable: {reason}. Replacing the inode cannot be proven safe."
            )
        }
        _ => String::new(),
    };
    if reclaimed > 0 {
        format!(
            "refusing to start a second daemon: {context} (reclaimed {reclaimed} stale lock \
             file(s) first, and the lock is still contended).{compatibility_boundary} To proceed, \
             {remedy}."
        )
    } else {
        format!(
            "refusing to start a second daemon: {context}.{compatibility_boundary} To proceed, \
             {remedy}."
        )
    }
}

fn idle_check_interval(idle_timeout: Duration) -> Duration {
    let millis = (idle_timeout.as_millis() / 4).clamp(100, 5_000) as u64;
    Duration::from_millis(millis)
}

/// Next backoff after a persistent embedding-worker error. Doubles the previous
/// backoff (starting from `base` on the first failure) and caps at `max`. Kept
/// pure so the no-tight-spin guarantee is unit-testable.
fn next_embed_error_backoff(current: Option<Duration>, base: Duration, max: Duration) -> Duration {
    current.unwrap_or(base).saturating_mul(2).min(max)
}

#[derive(Debug)]
enum BackgroundEmbeddingBatchOutcome {
    Completed(usize),
    ResetAfterIndexError(kin_db::KinDbError),
    Failed(kin_db::KinDbError),
}

/// Run one background embedding batch and any first-error vector recovery under
/// one `embedding_work` guard.
///
/// The recovery decision belongs inside this critical section. In particular,
/// a foreground `/embed --rebuild` that is already waiting must not acquire the
/// guard, publish a fresh index, and then be wiped by recovery from this stale
/// failed batch.
fn run_background_embedding_batch(
    state: &DaemonState,
    reset_on_index_error: bool,
    process: impl FnOnce(&DaemonState) -> std::result::Result<usize, kin_db::KinDbError>,
) -> BackgroundEmbeddingBatchOutcome {
    let _embedding_guard = match state.embedding_work.lock() {
        Ok(guard) => guard,
        Err(_) => {
            return BackgroundEmbeddingBatchOutcome::Failed(
                kin_db::KinDbError::ConcurrentAccessError(
                    "embedding work lock poisoned".to_string(),
                ),
            );
        }
    };

    match process(state) {
        Ok(count) => BackgroundEmbeddingBatchOutcome::Completed(count),
        Err(error)
            if reset_on_index_error && matches!(&error, kin_db::KinDbError::IndexError(_)) =>
        {
            reset_vector_index_and_requeue_under_guard(state);
            BackgroundEmbeddingBatchOutcome::ResetAfterIndexError(error)
        }
        Err(error) => BackgroundEmbeddingBatchOutcome::Failed(error),
    }
}

/// Detach a stale vector index and rebuild both embedding queues while the
/// caller owns `embedding_work`.
fn reset_vector_index_and_requeue_under_guard(state: &DaemonState) {
    state.graph.reset_vector_index();
    #[cfg(feature = "embeddings")]
    state.graph.queue_missing_for_embedding();
    state.graph.queue_missing_artifacts_for_embedding();
}

/// Deterministically expose reset contention to the status/reset race test.
#[cfg(all(test, feature = "vector"))]
pub(crate) fn reset_vector_index_and_requeue_after_contention_for_test(
    state: &DaemonState,
    on_contention: impl FnOnce(),
) -> std::result::Result<(), kin_db::KinDbError> {
    let _embedding_guard = match state.embedding_work.try_lock() {
        Ok(guard) => guard,
        Err(std::sync::TryLockError::WouldBlock) => {
            on_contention();
            state.embedding_work.lock().map_err(|_| {
                kin_db::KinDbError::ConcurrentAccessError(
                    "embedding work lock poisoned".to_string(),
                )
            })?
        }
        Err(std::sync::TryLockError::Poisoned(_)) => {
            return Err(kin_db::KinDbError::ConcurrentAccessError(
                "embedding work lock poisoned".to_string(),
            ));
        }
    };

    reset_vector_index_and_requeue_under_guard(state);
    Ok(())
}

/// The language server this build starts for `language`, if any.
///
/// One map, read by both the incremental and the sweep enrichment paths below.
/// It used to be two `match` blocks three hundred lines apart, and they agreed
/// only because nobody had added a language since they were written. Adding a
/// language to a single copy is invisible in review and worse at runtime: the
/// sweep would enrich files the incremental path ignored, so the edges would
/// appear only after a full re-ingest and vanish on the next incremental pass.
///
/// This map is also the referent of the claim in
/// `kin_core::reference_coverage::ENRICHABLE_LANGUAGES`, that the daemon wires
/// an adapter for exactly those languages. A test in this module fails when the
/// two disagree, because they already disagreed once: JavaScript and TypeScript
/// were absent here while kin-lsp carried a working adapter for both, so a
/// JavaScript repository was told its reference edges were `unsupported` and
/// cross-file resolution fell back to matching bare names.
///
/// The returned triple is exactly what `LspServer::start` takes: the command,
/// its arguments, and the initialization options for this workspace.
/// Public because it is this build's whole answer to "which server do you start
/// for this language", and two surfaces outside the enrichment loop need that
/// answer to agree with it: the provisioning advice that tells an operator what
/// to install, and the proof that starts a real server against a fixture.
pub fn lsp_adapter_for(
    language: kin_model::LanguageId,
    workspace_root: &std::path::Path,
) -> Option<(String, Vec<String>, Option<serde_json::Value>)> {
    use kin_lsp::adapters::LspAdapter;

    fn describe(
        adapter: &dyn LspAdapter,
        workspace_root: &std::path::Path,
    ) -> (String, Vec<String>, Option<serde_json::Value>) {
        (
            adapter.server_command().to_string(),
            adapter.server_args(),
            adapter.initialization_options(workspace_root),
        )
    }

    match language {
        kin_model::LanguageId::Rust => Some(describe(
            &kin_lsp::adapters::rust_analyzer::RustAnalyzerAdapter,
            workspace_root,
        )),
        kin_model::LanguageId::Python => Some(describe(
            &kin_lsp::adapters::python::PyrightAdapter,
            workspace_root,
        )),
        // One adapter serves both. `typescript-language-server` resolves a
        // CommonJS `require` chain through the same tsserver project model it
        // uses for TypeScript imports, which is why kin-lsp's discovery table
        // maps both language names onto the same binary.
        kin_model::LanguageId::TypeScript | kin_model::LanguageId::JavaScript => Some(describe(
            &kin_lsp::adapters::typescript::TypeScriptAdapter,
            workspace_root,
        )),
        _ => None,
    }
}

/// Every language this build knows about.
///
/// Written as an exhaustive `match` rather than a hand-kept array so a new
/// `LanguageId` variant fails to compile here instead of silently escaping the
/// coverage assertions below. A list that quietly stops enumerating everything
/// is the shape of guard that passes forever.
#[cfg(test)]
fn all_known_languages() -> Vec<kin_model::LanguageId> {
    use kin_model::LanguageId::*;
    let every = [
        TypeScript, JavaScript, Python, Go, Java, Rust, C, Cpp, CSharp, Ruby, Php, Swift, Kotlin,
        Hcl,
    ];
    for language in every {
        // Exhaustive on purpose: adding a variant breaks this arm, which is the
        // point. The body is a no-op; the compiler is the assertion.
        match language {
            TypeScript | JavaScript | Python | Go | Java | Rust | C | Cpp | CSharp | Ruby | Php
            | Swift | Kotlin | Hcl => {}
        }
    }
    every.to_vec()
}

#[cfg(test)]
mod adapter_wiring_tests {
    use super::{all_known_languages, lsp_adapter_for};
    use kin_core::reference_coverage::ENRICHABLE_LANGUAGES;
    use kin_model::LanguageId;
    use std::path::Path;

    /// `ENRICHABLE_LANGUAGES` documents itself as the set the daemon wires an
    /// adapter for. This is that sentence as an assertion, in both directions.
    ///
    /// It failed before this test existed: JavaScript and TypeScript had a
    /// complete adapter in kin-lsp and no arm in the daemon's map, so a
    /// JavaScript repository read `reference_enrichment: "unsupported"` and its
    /// cross-file calls were resolved by matching bare names.
    #[test]
    fn the_adapter_map_and_the_enrichable_set_name_the_same_languages() {
        let root = Path::new("/nonexistent-workspace");
        for language in all_known_languages() {
            let wired = lsp_adapter_for(language, root).is_some();
            let declared = ENRICHABLE_LANGUAGES.contains(&language);
            assert_eq!(
                wired, declared,
                "{language}: daemon wires an adapter = {wired}, ENRICHABLE_LANGUAGES says {declared}"
            );
        }
    }

    /// Both JavaScript and TypeScript resolve to one server binary.
    ///
    /// Pinned because the two are separate `LanguageId` values reaching one
    /// adapter, and a future edit that gives JavaScript its own arm would be
    /// invisible to the set-equality test above while breaking every `.js`
    /// repository that has `typescript-language-server` installed.
    #[test]
    fn javascript_and_typescript_share_one_server_binary() {
        let root = Path::new("/nonexistent-workspace");
        let (js_cmd, js_args, _) =
            lsp_adapter_for(LanguageId::JavaScript, root).expect("JavaScript must be wired");
        let (ts_cmd, ts_args, _) =
            lsp_adapter_for(LanguageId::TypeScript, root).expect("TypeScript must be wired");
        assert_eq!(js_cmd, "typescript-language-server");
        assert_eq!(js_cmd, ts_cmd);
        assert_eq!(js_args, ts_args);
        assert_eq!(js_args, vec!["--stdio".to_string()]);
    }

    /// The commands the map hands `LspServer::start` are the binary names a
    /// host actually installs, so the provisioning advice and the runtime agree.
    #[test]
    fn wired_languages_name_the_binaries_an_operator_installs() {
        let root = Path::new("/nonexistent-workspace");
        for (language, expected) in [
            (LanguageId::Rust, "rust-analyzer"),
            (LanguageId::Python, "pyright-langserver"),
            (LanguageId::TypeScript, "typescript-language-server"),
            (LanguageId::JavaScript, "typescript-language-server"),
        ] {
            let (cmd, _, _) =
                lsp_adapter_for(language, root).unwrap_or_else(|| panic!("{language} not wired"));
            assert_eq!(cmd, expected, "{language} server command");
        }
    }

    /// The startup gate behind the restart advice `kin doctor` prints.
    ///
    /// Asserted rather than reasoned about, because it is a user-facing claim:
    /// a host that had no language server when its daemon started does not gain
    /// enrichment when one is installed, and that is exactly the host doing the
    /// installing. If this predicate ever stops keying on the discovered count,
    /// the advice becomes wrong in the direction that leaves an operator
    /// waiting for edges that will never arrive.
    #[test]
    fn no_server_at_startup_means_no_enrichment_channel_for_this_daemon() {
        use super::enrichment_channel_opens;

        assert!(
            !enrichment_channel_opens(true, 0),
            "with enrichment enabled and no server discovered the channel must stay closed"
        );
        assert!(
            enrichment_channel_opens(true, 1),
            "one discovered server is enough to open the channel"
        );
        assert!(
            !enrichment_channel_opens(false, 3),
            "disabled enrichment must not open a channel however many servers exist"
        );
    }

    /// A language with no adapter stays unwired, so `Unsupported` remains a
    /// truthful state rather than a default nobody maintains.
    #[test]
    fn an_unwired_language_has_no_adapter() {
        let root = Path::new("/nonexistent-workspace");
        for language in [LanguageId::Ruby, LanguageId::Swift, LanguageId::Hcl] {
            assert!(
                lsp_adapter_for(language, root).is_none(),
                "{language} must not be wired without being declared enrichable"
            );
        }
    }
}

/// Poll `workspace/symbol` with an empty query until the LSP server responds
/// or the deadline is reached. Language servers like rust-analyzer and pyright
/// continue background indexing after the `initialize` handshake; this probe
/// detects when they are actually ready to serve symbol queries.
///
/// Falls back to a best-effort fixed delay if the server does not respond to
/// `workspace/symbol` (e.g., server does not declare the capability).
async fn wait_for_lsp_index(server: &kin_lsp::lifecycle::LspServer, max: Duration) {
    const POLL_INTERVAL: Duration = Duration::from_millis(500);
    if !server.has_references() && !server.has_definition() {
        tokio::time::sleep(max.min(Duration::from_secs(5))).await;
        return;
    }
    let deadline = tokio::time::Instant::now() + max;
    loop {
        let probe = server
            .client
            .request("workspace/symbol", serde_json::json!({ "query": "" }))
            .await;
        if probe.is_ok() {
            return;
        }
        if tokio::time::Instant::now() >= deadline {
            return;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Await an in-flight embed-progress flush, logging any persistence or task
/// failure. Awaiting before the next flush is scheduled is what serializes
/// successive flushes: at most one persist runs at a time, so two flushes can
/// never interleave and the persisted generation cursor advances monotonically.
/// Returns once the handle is cleared so callers can use this both to overlap a
/// flush with the next batch's prep and to drain the tail at every loop exit.
///
/// The returned flag says whether a flush actually reached disk, which is what
/// lets a caller credit persisted progress without crediting a failed persist.
/// Nothing in flight is reported as nothing persisted.
async fn drain_pending_flush(pending: &mut Option<tokio::task::JoinHandle<Result<usize>>>) -> bool {
    let Some(handle) = pending.take() else {
        return false;
    };
    match handle.await {
        Ok(Ok(_pending)) => true,
        Ok(Err(e)) => {
            error!(error = %e, "failed to flush embed progress");
            false
        }
        Err(e) => {
            error!(error = %e, "embed progress flush task panicked");
            false
        }
    }
}

/// Drain the in-flight flush and credit what it persisted to the embedding pass.
///
/// Progress is credited here rather than when a batch finishes embedding,
/// because the counter the supervisor judges liveness on has to mean work that
/// survived to disk. A batch whose flush failed produced nothing durable, and
/// crediting it anyway would let a worker that can never persist keep vouching
/// for itself indefinitely — the exact silence this supervisor exists to end.
async fn drain_embed_flush(
    pending: &mut Option<tokio::task::JoinHandle<Result<usize>>>,
    embedded: &mut u64,
    pass: &crate::background_work::BackgroundPass,
) {
    let persisted = drain_pending_flush(pending).await;
    let credited = std::mem::take(embedded);
    if persisted {
        pass.advanced(credited, Instant::now());
    }
}

// Shutdown-latency bound — how long the daemon may take to actually disappear.
// Callers that budget for daemon cleanup (the merge-trust harness attests
// against a 45s window) depend on this being bounded rather than generous, so
// the terms are stated explicitly.
//
// SIGTERM/SIGINT → process gone:
// 1. the signal is observed by the async handler — prompt even mid-hydration,
//    because hydration runs on the blocking pool and leaves the async workers
//    schedulable;
// 2. `drain_handles` joins the daemon's tasks, bounded at 10s. An in-flight
//    hydration is a blocking task rather than a drained handle, but the API
//    server's graceful shutdown waits on in-flight requests, so a hydrating
//    daemon rides this full 10s;
// 3. the final storage flush, the derived-CAS directory barrier, and
//    endpoint-file removal run (all fast on the local backend; the barrier is
//    bounded at one fsync per shard directory touched, so at most 256);
// 4. `runtime.shutdown_timeout(runtime_shutdown_grace())` waits up to 8s for
//    the blocking pool, then abandons whatever is still running;
// 5. the process exits.
//
// That normal path is ~18s. Independently, the escalation watchdog force-exits
// DEFAULT_SHUTDOWN_ESCALATION_GRACE after shutdown is signalled, so the hard
// bound is ~25s. A force-escalated exit skips step 3 entirely: neither the
// barrier nor endpoint retirement runs, which is the deliberate trade of a
// backstop that exists to end a wedged process. Both are recoverable, since
// the derived CAS re-hydrates on open and a stale endpoint is swept by the
// next liveness probe. Owner death costs at most one OWNER_WATCH_CHECK_INTERVAL of
// detection on top of the same bound: ~27s from owner exit to process gone,
// with no signal ever sent.
//
// Both grace periods are configurable — KIN_DAEMON_SHUTDOWN_GRACE_SECS and
// KIN_DAEMON_RUNTIME_SHUTDOWN_GRACE_SECS — so a caller with a tighter cleanup
// budget than 45s can lower the bound rather than resorting to SIGKILL.

/// Default grace the shutdown-escalation watchdog grants — once graceful
/// shutdown is signalled — before force-exiting the process. Generous enough
/// for a legitimate final snapshot flush + task drain to win the race on their
/// own, short enough that a wedged embed batch (blocking GPU compute that cannot
/// observe the cancel signal) can never leave a SIGTERM-immune CPU zombie.
const DEFAULT_SHUTDOWN_ESCALATION_GRACE: Duration = Duration::from_secs(25);

/// Default bound on how long tokio runtime teardown waits for in-flight blocking
/// tasks (e.g. an embedding batch mid GPU-compute) before abandoning them so the
/// process can actually exit.
const DEFAULT_RUNTIME_SHUTDOWN_GRACE: Duration = Duration::from_secs(8);

/// How often the escalation watchdog polls for the shutdown signal.
const SHUTDOWN_WATCH_POLL: Duration = Duration::from_millis(250);

/// Parse a whole-seconds duration, falling back to `default` for absent, empty,
/// or unparseable input. Kept pure so the grace-period config is unit-testable.
fn parse_duration_secs(raw: Option<&str>, default: Duration) -> Duration {
    raw.and_then(|value| value.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(default)
}

fn duration_from_env_secs(name: &str, default: Duration) -> Duration {
    parse_duration_secs(std::env::var(name).ok().as_deref(), default)
}

/// Decide whether the background persistence task should flush dirty state.
///
/// Both clocks are suppressed while a daemon-side embed pass is in flight:
/// - Periodic (`since_save`): bounds how long dirty state may sit unpersisted.
/// - Idle (`since_mutation`): debounces the full-graph serialize to mutation
///   quiet periods.
///
/// During an embed pass the embed handler persists its own progress (pre-pass
/// snapshot, per-batch kvec, post-pass snapshot), and the only graph mutations
/// are re-derivable enrichment (LSP relations). A background FULL-graph flush
/// here is therefore redundant — and on large repos ruinous: it re-serializes
/// the entire graph on every fire. Observed killing the daemon on a ~955MB mui
/// graph (repeated 955MB writes every few seconds starved the embed feed and
/// pressured host memory until the process died — "Connection refused" mid-pass).
/// The post-pass snapshot persists the final state once the pass completes, and
/// a mid-pass crash only loses re-derivable enrichment, never primary truth.
/// O(gaps × graph size) writes on large repos are the failure mode being closed.
fn should_flush_now(
    since_save: Duration,
    since_mutation: Duration,
    embed_pass_active: bool,
    idle_flush: Duration,
    periodic_flush: Duration,
) -> bool {
    if embed_pass_active {
        return false;
    }
    since_save >= periodic_flush || since_mutation >= idle_flush
}

/// Operator opt-out for the background embedding pass the daemon starts on its
/// own after the first reconciliation cycle.
pub(crate) const AUTO_EMBED_ENV: &str = "KIN_DAEMON_AUTO_EMBED";

/// Whether the daemon may queue and drain the embedding backlog without being
/// asked. Default ON: unset, or any value other than the documented falsy set,
/// keeps today's behavior exactly. A falsy value defers the pass until an
/// explicit embed request, which is the opt-out for an operator who does not
/// want a bulk accelerator pass starting because a store was opened.
///
/// The falsy set matches `KIN_DAEMON_REQUIRE_TOKEN`, the sibling boolean knob,
/// so one spelling works across the daemon's env surface.
pub(crate) fn auto_embed_enabled() -> bool {
    kin_daemon_spawn::auto_embed_enabled_from(std::env::var(AUTO_EMBED_ENV).ok().as_deref())
}

/// Build the background embedding backlog and announce it, or defer the whole
/// pass because an operator opted out. Returns whether the backlog was queued.
///
/// Announcing matters because nothing the user ran asks for this work. Opening
/// a store whose index has not caught up is enough to start it, so the pass is
/// a property of the store's state rather than of the command issued, and on an
/// accelerator it is a bulk run writing a sidecar nobody requested. A worker
/// that starts silently leaves an operator inferring it from machine load.
///
/// Deferring pauses rather than disables. The queue is left unbuilt and the
/// worker stood down, so an explicit embed request still runs the pass on
/// demand (`/embed` resumes the worker). Pausing is also what keeps a deferred
/// daemon eligible for idle shutdown: a backlog no worker will drain must not
/// read as work in flight.
fn start_or_defer_background_embed(state: &DaemonState) -> bool {
    if !auto_embed_enabled() {
        state.pause_background_embed();
        warn!(
            trigger = AUTO_EMBED_ENV,
            "background embedding deferred by operator opt-out: no vectors will be generated, and semantic coverage stays as it is until an explicit embed request runs"
        );
        return false;
    }
    // Re-queue every object the persisted index still lacks a vector for, so the
    // worker resumes after a restart drained the in-memory queue (the queue is
    // not persisted; coverage is, via graph-vs-index truth). Idempotent (HashSet
    // queues) — a fresh start that already enqueued via reconcile is unaffected.
    #[cfg(feature = "embeddings")]
    state.graph.queue_missing_for_embedding();
    state.graph.queue_missing_artifacts_for_embedding();
    info!(
        queued_entities = state.graph.pending_embeddings(),
        queued_artifacts = state.graph.pending_artifact_embeddings(),
        opt_out = AUTO_EMBED_ENV,
        "background embedding started: generating vectors for everything the index is missing"
    );
    true
}

/// Grace period the escalation watchdog waits after shutdown is signalled before
/// force-exiting. Configurable via `KIN_DAEMON_SHUTDOWN_GRACE_SECS` (0 escalates
/// immediately once the signal fires — used by tests).
pub fn shutdown_escalation_grace() -> Duration {
    duration_from_env_secs(
        "KIN_DAEMON_SHUTDOWN_GRACE_SECS",
        DEFAULT_SHUTDOWN_ESCALATION_GRACE,
    )
}

/// Bound on how long tokio runtime teardown waits for in-flight blocking tasks
/// before abandoning them. Configurable via
/// `KIN_DAEMON_RUNTIME_SHUTDOWN_GRACE_SECS`.
pub fn runtime_shutdown_grace() -> Duration {
    duration_from_env_secs(
        "KIN_DAEMON_RUNTIME_SHUTDOWN_GRACE_SECS",
        DEFAULT_RUNTIME_SHUTDOWN_GRACE,
    )
}

/// What the on-disk control plane says about this daemon's right to keep
/// serving.
///
/// Endpoint files disappearing is not, on its own, a reason for a healthy
/// daemon to die. The two cases that are — the repository was removed, or
/// another daemon took the repo over — are distinguishable from a third party
/// deleting `daemon.pid`/`daemon.port` out from under a running incumbent, and
/// conflating them is how a refused second start killed the daemon it lost to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlPlane {
    /// `.kin` is present and the published endpoint names this process.
    Ours,
    /// The `.kin` root itself is gone: `kin eject` or doctor removed the repo.
    RootGone,
    /// The endpoint names a different daemon that is still running, so this
    /// process is no longer the one serving the repo.
    Superseded { pid: u32 },
    /// `.kin` is present, but this daemon's endpoint is missing, incomplete, or
    /// attributed to a process that is gone. The daemon still owns the repo
    /// singleton, so the endpoint is repairable rather than fatal.
    EndpointLost,
}

/// How often the control plane is re-examined when no idle timeout paces the
/// monitor. Cheap: three `exists` checks and, at most, one small read.
const CONTROL_PLANE_CHECK_INTERVAL: Duration = Duration::from_secs(5);

/// Whether the `.kin` directory this daemon serves has been removed. The only
/// condition under which a flush must be skipped: there is nowhere to write.
fn repository_root_missing(state: &DaemonState) -> bool {
    !state.layout.root().exists()
}

fn classify_control_plane(state: &DaemonState) -> ControlPlane {
    let root = state.layout.root();
    if !root.exists() {
        return ControlPlane::RootGone;
    }
    // Yielding is gated on proof, not on a PID. This daemon holds the
    // repository singleton for its whole lifetime, so no legitimate successor
    // can exist; a foreign endpoint that cannot prove a live owner is debris,
    // and treating debris as an eviction notice is what killed the incumbent.
    if let Some(pid) = crate::lifecycle::proven_live_other_endpoint_owner(root) {
        return ControlPlane::Superseded { pid };
    }
    match crate::lifecycle::endpoint_ownership(root) {
        crate::lifecycle::EndpointOwnership::CurrentProcess
            if crate::lifecycle::read_port_file(root).is_some() =>
        {
            ControlPlane::Ours
        }
        _ => ControlPlane::EndpointLost,
    }
}

/// Whether outstanding embedding work would be abandoned by a shutdown.
///
/// `embed_pass_active` counts unconditionally: an explicit pass is running
/// right now. A queued backlog counts only while something will actually drain
/// it, which is what `worker_can_drain` reports. A backlog the worker has
/// already stood down from is not work in progress, and treating it as such
/// would make the daemon immortal rather than patient.
fn embed_work_outstanding(embed_pass_active: bool, queued: bool, worker_can_drain: bool) -> bool {
    embed_pass_active || (queued && worker_can_drain)
}

/// What the background embed worker should do when its queue drains.
///
/// The queue is the worker's whole notion of work, so a retrieval key with no
/// vector and no queue entry is work nothing will ever do, announced as
/// `remaining=0`. Coverage is the authority for whether work exists; the queue
/// is only how it gets done, and `kin embed` has always known the difference.
/// Re-queueing the gap is therefore the right answer, and bounding it is what
/// keeps a key that can never be embedded from spinning the worker every
/// interval: the same gap twice running means the previous re-queue changed
/// nothing, so the worker reports it once and stops asking.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CoverageDrainVerdict {
    /// Coverage is whole. The drain really is finished.
    Complete,
    /// Coverage is short and no re-queue has been tried at this gap yet.
    Backfill { missing: usize },
    /// Coverage is short and the last re-queue at this gap produced nothing.
    Stalled { missing: usize },
}

fn coverage_drain_verdict(missing: usize, backfilled_gap: Option<usize>) -> CoverageDrainVerdict {
    if missing == 0 {
        CoverageDrainVerdict::Complete
    } else if backfilled_gap == Some(missing) {
        CoverageDrainVerdict::Stalled { missing }
    } else {
        CoverageDrainVerdict::Backfill { missing }
    }
}

fn embed_work_in_flight(state: &DaemonState) -> bool {
    embed_work_outstanding(
        state.embed_pass_active(),
        state.graph.pending_embeddings() > 0 || state.graph.pending_artifact_embeddings() > 0,
        state.background_embed_worker_can_drain(),
    )
}

/// Work a shutdown would destroy rather than merely interrupt, independent of
/// whether any client can currently reach this daemon.
///
/// The idle clock advances only on API traffic (`begin_request` /
/// `end_request`); no background task touches it. So a daemon still ingesting a
/// repository for the first time, or draining the embedding backlog that first
/// ingest queued, reads as perfectly idle to the monitor, and a CLI autostart,
/// which injects a 60s timeout, kills it mid-pass. None of that work resumes:
/// the next command starts the pass over from the beginning.
fn work_would_be_lost_by_shutdown(state: &DaemonState) -> bool {
    if state.active_request_count() > 0 {
        return true;
    }
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return true;
    }
    if state
        .reconciliation_status
        .load(std::sync::atomic::Ordering::Relaxed)
        != RECON_IDLE
    {
        return true;
    }
    embed_work_in_flight(state)
}

fn ready_for_idle_shutdown(
    state: &DaemonState,
    idle_timeout: Duration,
    control_plane: ControlPlane,
) -> bool {
    if work_would_be_lost_by_shutdown(state) {
        return false;
    }
    if control_plane == ControlPlane::EndpointLost {
        // Rare by construction: the control-plane check earlier in this same
        // tick repairs a lost endpoint, so reaching here means republication
        // itself failed. Kept because that is exactly when it matters: the
        // daemon is unreachable by new clients, so the session and event-
        // subscriber gates below cannot be waiting on anything, and it should be
        // allowed to idle out rather than linger unreachable.
        //
        // Only those client-reachability gates are skipped. The work gates
        // above are not, because an unreachable daemon loses an in-flight first
        // scan or embed drain exactly as a reachable one does, and an endpoint
        // blip is transient where a discarded first ingest is not.
        return state.idle_duration() >= idle_timeout;
    }
    if state.event_tx.receiver_count() > 0 {
        return false;
    }
    if state.has_external_sessions() {
        return false;
    }
    state.idle_duration() >= idle_timeout
}

async fn save_snapshot_blocking(state: Arc<DaemonState>) -> Result<()> {
    tokio::task::spawn_blocking(move || state.save_snapshot())
        .await
        .map_err(|error| DaemonError::Io(std::io::Error::other(error.to_string())))?
}

/// How often the owner-death watchdog checks whether the owning process is
/// still alive. A `kill(pid, 0)` every couple of seconds is a single cheap
/// syscall, so this is set for detection latency rather than to save work.
const OWNER_WATCH_CHECK_INTERVAL: Duration = Duration::from_secs(2);

/// Validate a raw `KIN_DAEMON_WATCH_PID` value into an owner PID this daemon may
/// watch, or `None` to run with no owner-death watchdog at all.
///
/// The rejections here are the safety boundary for the watchdog, so each one is
/// deliberate:
/// - absent / empty / unparseable → no watchdog. This is the default for every
///   daemon; a spawner must opt in explicitly.
/// - `<= 1` → rejects a caller that passed `getppid()` after the daemon already
///   reparented (init is PID 1), and rejects the `kill(0, …)` / `kill(-1, …)`
///   process-group and broadcast selectors, which are not owner PIDs at all.
/// - the daemon's own PID → a self-watch can never observe a death. Treat an
///   obviously misconfigured owner as "no watchdog" instead of as armed.
///
/// Note what is NOT accepted as a source: `getppid()`. Both daemon spawn paths
/// call `setsid()`, so a healthy persistent daemon reparents to init as soon as
/// the CLI that launched it exits. `ppid == 1` is the normal, correct state for
/// a legitimately detached daemon, which is why ownership must be stated
/// explicitly by the spawner rather than inferred from the process tree.
fn parse_owner_watch_pid(raw: Option<&str>, self_pid: u32) -> Option<i32> {
    let pid = raw?.trim().parse::<i32>().ok()?;
    if pid <= 1 {
        return None;
    }
    if i64::from(pid) == i64::from(self_pid) {
        return None;
    }
    Some(pid)
}

/// Shutdown requested through a path that no scheduler can starve.
///
/// Written from a real OS signal handler, so every write must stay
/// async-signal-safe: one relaxed atomic store, no allocation, no locking, no
/// logging.
static SHUTDOWN_REQUESTED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

/// Has shutdown been requested through a runtime-independent path?
pub fn shutdown_requested() -> bool {
    SHUTDOWN_REQUESTED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Arm the runtime-independent shutdown flag from signal delivery itself.
///
/// Registered through `signal_hook_registry`, which chains handlers, so tokio's
/// own SIGTERM/SIGINT registration keeps driving the graceful path unchanged.
/// This handler exists only so the force-exit backstop is armed by the kernel
/// delivering the signal rather than by the runtime's willingness to poll a
/// future.
///
/// A real signal is deliberately the ONLY writer of [`SHUTDOWN_REQUESTED`]. The
/// flag is process-global and never cleared, and the watchdog it arms ends the
/// process with `exit(0)`, so a non-signal writer would let one caller latch the
/// flag and a later, unrelated watchdog inherit it. In a test binary that
/// truncates the run and still reports success. Keeping signal delivery as the
/// sole writer makes the latch mean what it says.
///
/// Registration also replaces SIGTERM's default disposition, because
/// signal-hook-registry skips a `SIG_DFL` previous handler rather than chaining
/// to it. From this call until tokio registers its own listener, a SIGTERM sets
/// only this flag and death comes from the watchdog at grace rather than
/// instantly. Every step between the two is a `tokio::spawn` with no top-level
/// await, so the window is sub-millisecond and stays inside the documented
/// bound, but it is a real window and the watchdog must be spawned right after
/// this call rather than later.
#[cfg(unix)]
pub fn install_shutdown_signal_handler() {
    // `SigId` has no `Drop`, so every call appends another action to the signal
    // slot permanently. Production installs once; the guard keeps the `pub` API
    // from leaking that footgun to any other caller.
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(|| {
        for signal in [libc::SIGTERM, libc::SIGINT] {
            // SAFETY: the handler body performs a single relaxed atomic store
            // and calls nothing that is not async-signal-safe.
            let registered = unsafe {
                signal_hook_registry::register(signal, || {
                    SHUTDOWN_REQUESTED.store(true, std::sync::atomic::Ordering::Relaxed);
                })
            };
            if let Err(error) = registered {
                warn!(
                    signal,
                    error = %error,
                    "failed to arm the runtime-independent shutdown flag; \
                     force-exit escalation falls back to in-runtime arming"
                );
            }
        }
    });
}

#[cfg(not(unix))]
pub fn install_shutdown_signal_handler() {}

/// Has shutdown been signalled by any path?
///
/// Three independent sources, because the force-exit backstop must not depend
/// on the runtime it exists to rescue:
/// - `os_requested`: set by the SIGTERM/SIGINT handler itself, or by the
///   cooperative `/shutdown` endpoint at the moment it accepts the request.
/// - `cancel`: the watch-channel flag every in-runtime shutdown trigger sets.
/// - `is_shutdown`: the state flag the propagation task writes.
///
/// Only `os_requested` survives a saturated runtime. Both other flags are
/// written from inside it: the SIGTERM arm of `select_with_signals` sets
/// `cancel`, but that arm is a future the runtime has to poll, and the
/// propagation task that writes `is_shutdown` is a task the runtime has to
/// schedule. A reconciliation batch occupying every worker thread with
/// synchronous work therefore disarmed the backstop that exists for precisely
/// that case, and the daemon outlived its documented grace with no bound at
/// all — a stop request that never terminated anything.
fn shutdown_signalled(is_shutdown: bool, cancel: bool, os_requested: bool) -> bool {
    is_shutdown || cancel || os_requested
}

/// Spawn the shutdown-escalation watchdog: a plain OS thread — deliberately
/// NOT a tokio task — so it stays runnable even while the async runtime is
/// tearing down or saturated. Once shutdown is signalled it grants a bounded
/// grace period for the drain plus final flush to finish, then force-exits.
///
/// This is the hard backstop against two zombies. A blocking embedding batch
/// mid GPU-compute cannot observe the cancel signal, so runtime teardown can
/// otherwise block forever and leave a headless, SIGTERM-immune CPU zombie that
/// still races kvec writes. A reconciliation batch that occupies every runtime
/// worker with synchronous work is the same failure from the other direction:
/// nothing inside the runtime runs, so nothing inside the runtime can arm this.
///
/// `is_shutdown` is taken as a probe rather than a flag so the production call
/// site keeps reading `DaemonState` while a test can model the runtime whose
/// propagation task never runs at all.
pub fn spawn_shutdown_escalation_watchdog<F>(
    is_shutdown: F,
    cancel: tokio::sync::watch::Receiver<bool>,
    grace: Duration,
) where
    F: Fn() -> bool + Send + 'static,
{
    if let Err(error) = std::thread::Builder::new()
        .name("kin-shutdown-watchdog".to_string())
        .spawn(move || {
            while !shutdown_signalled(is_shutdown(), *cancel.borrow(), shutdown_requested()) {
                std::thread::sleep(SHUTDOWN_WATCH_POLL);
            }
            std::thread::sleep(grace);
            // Still alive after the grace period → the graceful path is wedged
            // (a blocking embed batch the runtime drop is waiting on, or a
            // reconciliation batch holding every worker thread). Force the whole
            // process down so a stop request always results in actual
            // termination — no zombie, and no unbounded stop.
            eprintln!(
                "kin-daemon: graceful shutdown exceeded {}s grace — forcing process exit to prevent a CPU zombie",
                grace.as_secs()
            );
            std::process::exit(0);
        })
    {
        warn!(error = %error, "failed to spawn shutdown-escalation watchdog");
    }
}

/// Is the process with this PID still alive?
///
/// Sends signal 0 — this delivers no signal and only checks for existence. A
/// return of 0 means the process exists. A non-zero return with `ESRCH` (no
/// such process) means it is gone; any other error (e.g. `EPERM`, the process
/// exists but is owned by another user) is treated as still alive so the
/// watchdog never shuts down on a process that is merely out of reach.
#[cfg(unix)]
fn watched_process_is_alive(pid: i32) -> bool {
    if unsafe { libc::kill(pid as libc::pid_t, 0) } == 0 {
        return true;
    }
    !matches!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH)
    )
}

#[cfg(windows)]
fn watched_process_is_alive(pid: i32) -> bool {
    u32::try_from(pid)
        .ok()
        .is_some_and(kin_cli::daemon_client::is_process_alive)
}

#[cfg(not(any(unix, windows)))]
fn watched_process_is_alive(_pid: i32) -> bool {
    // Fail closed on unsupported targets rather than treating an uncheckable
    // owner as dead.
    true
}

/// Watch the control plane for the two states that end this daemon, repairing
/// the one that does not.
///
/// Returns `true` when the daemon must shut down. A lost endpoint is
/// republished instead: this process holds the repository singleton, so it is
/// the only legitimate publisher, and restoring its own record is the exact
/// truth rather than a guess. Republication also makes the failure
/// self-healing, because the clients that lost the endpoint find it again on
/// their next poll.
fn control_plane_demands_shutdown(
    state: &DaemonState,
    bound_port: u16,
    shutting_down: bool,
) -> bool {
    match classify_control_plane(state) {
        ControlPlane::Ours => false,
        ControlPlane::RootGone => {
            warn!(
                root = %state.layout.root().display(),
                "Kin control directory disappeared; shutting down daemon"
            );
            true
        }
        ControlPlane::Superseded { pid } => {
            warn!(
                root = %state.layout.root().display(),
                successor_pid = pid,
                "another daemon now owns this repository endpoint; shutting down"
            );
            true
        }
        ControlPlane::EndpointLost if shutting_down => {
            // Retirement is already running or about to. Republishing now
            // would race it and could land after it, leaving an endpoint
            // advertising a daemon that is about to exit. Task drain is
            // bounded and does not abort this monitor, and publication can
            // block on the coordination lock, so the window is real.
            false
        }
        ControlPlane::EndpointLost => {
            match crate::lifecycle::publish_daemon_endpoint(state.layout.root(), bound_port) {
                Ok(()) => info!(
                    root = %state.layout.root().display(),
                    port = bound_port,
                    "daemon endpoint files were removed by another process; republished them"
                ),
                Err(error) => warn!(
                    root = %state.layout.root().display(),
                    port = bound_port,
                    %error,
                    "daemon endpoint files are missing and could not be republished"
                ),
            }
            false
        }
    }
}

async fn run_idle_monitor(
    state: Arc<DaemonState>,
    idle_timeout: Option<Duration>,
    bound_port: u16,
    cancel_tx: tokio::sync::watch::Sender<bool>,
    mut cancel_rx: tokio::sync::watch::Receiver<bool>,
) {
    let Some(idle_timeout) = idle_timeout else {
        // Endpoint repair is the idle monitor's other job, so it must keep
        // running even for a daemon that never idles out.
        loop {
            tokio::select! {
                _ = tokio::time::sleep(CONTROL_PLANE_CHECK_INTERVAL) => {}
                _ = cancel_rx.changed() => return,
            }
            if *cancel_rx.borrow() {
                return;
            }
            if control_plane_demands_shutdown(&state, bound_port, *cancel_rx.borrow()) {
                let _ = cancel_tx.send(true);
                return;
            }
        }
    };
    // Start the idle window from when monitoring begins, not from process
    // construction. `last_activity_ms` is seeded to 0, so without this the
    // idle clock counts from `started_at` — which includes snapshot load and
    // projection rebuild — and a short timeout can fire before the daemon has
    // ever served a request, racing clients that haven't connected yet.
    state.touch_activity();
    info!(
        idle_timeout_s = idle_timeout.as_secs_f64(),
        "daemon idle shutdown enabled"
    );

    loop {
        // Re-read the window every tick rather than closing over the startup
        // value. An attached client whose session outlasts the window this
        // daemon was spawned with can raise it (see
        // `DaemonState::raise_idle_timeout`), and a monitor holding the old
        // value would shut down underneath the client that just said so.
        let Some(idle_timeout) = state.idle_timeout() else {
            // Only reachable if the window were switched off mid-run, which
            // raising cannot do. Treat it as "never idles out" rather than as
            // "idle out now".
            tokio::select! {
                _ = tokio::time::sleep(CONTROL_PLANE_CHECK_INTERVAL) => {}
                _ = cancel_rx.changed() => return,
            }
            if *cancel_rx.borrow() {
                return;
            }
            if control_plane_demands_shutdown(&state, bound_port, *cancel_rx.borrow()) {
                let _ = cancel_tx.send(true);
                return;
            }
            continue;
        };
        let check_interval = idle_check_interval(idle_timeout);
        tokio::select! {
            _ = tokio::time::sleep(check_interval) => {}
            _ = cancel_rx.changed() => return,
        }

        if *cancel_rx.borrow() {
            return;
        }
        if control_plane_demands_shutdown(&state, bound_port, *cancel_rx.borrow()) {
            let _ = cancel_tx.send(true);
            return;
        }
        // Re-read once more before deciding: a raise that landed during the
        // sleep above must be honoured by this tick, not the next one.
        let idle_timeout = state.idle_timeout().unwrap_or(idle_timeout);
        let control_plane = classify_control_plane(&state);
        if ready_for_idle_shutdown(&state, idle_timeout, control_plane) {
            if state.is_dirty() {
                if repository_root_missing(&state) {
                    warn!(
                        root = %state.layout.root().display(),
                        "skipping dirty graph flush before idle shutdown because Kin control directory is gone"
                    );
                } else {
                    info!("flushing dirty graph before idle shutdown");
                    if let Err(error) = save_snapshot_blocking(Arc::clone(&state)).await {
                        if repository_root_missing(&state) {
                            warn!(
                                error = %error,
                                root = %state.layout.root().display(),
                                "skipping dirty graph flush after Kin control directory disappeared"
                            );
                        } else {
                            warn!(error = %error, "idle shutdown delayed because snapshot flush failed");
                            continue;
                        }
                    } else {
                        state.mark_clean();
                    }
                }
            }
            info!(
                idle_ms = state.idle_duration().as_millis(),
                "daemon idle timeout reached, shutting down"
            );
            let _ = cancel_tx.send(true);
            return;
        }
    }
}

/// Where the sweep records the files it has finished.
///
/// Operational state, beside the pid and port files, not semantic authority: it
/// records what a background pass DID, and nothing answers a query from it.
fn lsp_enriched_marker_path(state: &DaemonState) -> std::path::PathBuf {
    state.layout.root().join("lsp-enriched-files.json")
}

/// Load the marker set, so a daemon that restarts does not re-sweep a graph a
/// previous one already enriched.
///
/// An unreadable or absent marker means "nothing is known to be enriched", which
/// costs a re-sweep and never skips a file wrongly. That asymmetry is deliberate:
/// a wrong skip is silent and loses the answers, a wrong re-sweep only costs
/// time.
///
/// A marker is honored only while the graph it describes still holds
/// language-server relations. A store swept before enrichment became durable
/// carries a complete marker and none of the edges it recorded, and the marker
/// is exactly what makes that loss permanent: every later daemon skips the same
/// files and re-derives nothing, so the store can never repair itself. Dropping
/// such a marker costs one re-sweep and fixes it. A sweep that legitimately
/// produced no relation at all is re-swept too, which is the same asymmetry
/// again and the cheap direction to be wrong in.
///
/// The file is left alone rather than deleted. The judgment is made again from
/// the graph on every load, and the sweep that follows rewrites the marker with
/// what it finished, so removing it would change nothing a later open decides.
///
/// The scan runs only when a marker exists, and costs one snapshot at startup
/// beside a read-index build that already walks the whole graph.
fn load_lsp_enriched_marker(state: &DaemonState) {
    let Ok(bytes) = std::fs::read(lsp_enriched_marker_path(state)) else {
        return;
    };
    let Ok(files) = serde_json::from_slice::<Vec<String>>(&bytes) else {
        return;
    };
    if files.is_empty() {
        return;
    }
    if !graph_holds_language_server_relations(state) {
        warn!(
            marked = files.len(),
            "ignoring the language-server enrichment marker: this graph holds none of the relations it records, so the files it marks are swept again"
        );
        return;
    }
    if let Ok(mut marked) = state.lsp_enriched_files.lock() {
        marked.extend(files);
    }
}

/// Whether this graph still holds any relation a language server produced.
fn graph_holds_language_server_relations(state: &DaemonState) -> bool {
    state
        .graph
        .to_snapshot()
        .relations
        .values()
        .any(|relation| relation.origin == kin_model::RelationOrigin::Lsp)
}

/// Record that the sweep finished this file, and persist the set.
///
/// Written per file rather than once at the end so a killed pass leaves the
/// files it completed marked, which is what makes the next pass resume rather
/// than restart. The write is a small JSON array over the files of one
/// repository; a failure to persist is not fatal, it only costs a re-sweep.
fn mark_file_enriched(state: &DaemonState, file: &str) {
    let snapshot = {
        let Ok(mut marked) = state.lsp_enriched_files.lock() else {
            return;
        };
        marked.insert(file.to_string());
        marked.iter().cloned().collect::<Vec<_>>()
    };
    if let Ok(bytes) = serde_json::to_vec(&snapshot) {
        let _ = std::fs::write(lsp_enriched_marker_path(state), bytes);
    }
}

/// Whether the sweep has already finished this file.
fn file_already_enriched(state: &DaemonState, file: &str) -> bool {
    state
        .lsp_enriched_files
        .lock()
        .map(|marked| marked.contains(file))
        .unwrap_or(false)
}

/// Column an LSP query should be asked at for one entity, given its signature
/// and the column its declaration starts on.
///
/// The cursor has to sit on the name rather than on the declaration's first
/// byte, and for a dotted name it has to sit on the LAST segment. An entity
/// named `app.handle` whose signature reads `app.handle = function handle(`
/// starts at the `app` token, and `signature.find(name)` returns 0 for it, so
/// the query went to the receiver instead of the member.
///
/// That is not a near miss. Asking a language server for references at a
/// receiver returns everything the object touches, so express minted an
/// all-pairs whole-file fan, and every edge in it was stamped `Lsp` and
/// therefore read as `type_resolved` with no evidence behind it. A caller walk
/// then counted fabricated callees as real ones, which is worse than the
/// missing edge it was meant to supply: a wrong answer wearing the label of a
/// resolved one.
///
/// A name with no dot is unaffected. Its segment offset is zero and the result
/// is exactly what it always was.
fn lsp_query_column(signature: &str, name: &str, start_col: u32) -> u32 {
    let segment_offset = name.rfind('.').map_or(0, |dot| dot + 1);
    if let Some(offset) = signature.find(name) {
        return start_col.saturating_add((offset + segment_offset) as u32);
    }
    // The signature does not spell the dotted name out. Ask for the final
    // segment on its own rather than falling back to the declaration start,
    // which is the receiver again whenever the receiver is what opens the line.
    if segment_offset > 0 {
        if let Some(offset) = signature.find(&name[segment_offset..]) {
            return start_col.saturating_add(offset as u32);
        }
    }
    start_col
}

fn install_lsp_relations(state: &DaemonState, relations: &[kin_model::Relation]) -> usize {
    if relations.is_empty() {
        return 0;
    }

    use kin_model::EntityStore;
    let graph_mutation = state.begin_graph_authority_mutation();
    let mut installed = 0usize;
    let mut refused = 0usize;
    for relation in relations {
        match state.graph.upsert_relation(relation) {
            Ok(_) => installed += 1,
            Err(error) => {
                refused += 1;
                // Was `let _ =`. A write the graph refused was indistinguishable
                // from one it took, and the count returned was the number of
                // relations ATTEMPTED, so a pass that installed nothing reported
                // exactly the same number as one that installed everything. That
                // is how a language-server answer proved correct in the trace
                // reached the graph as nothing at all, and every log line about
                // it said the enrichment had worked.
                debug!(
                    kind = ?relation.kind,
                    src = ?relation.src,
                    dst = ?relation.dst,
                    %error,
                    "graph refused an enrichment relation"
                );
            }
        }
    }
    if refused > 0 {
        warn!(
            installed,
            refused, "graph refused enrichment relations; the enriched count reports what it took"
        );
    }
    state.bump_version();
    drop(graph_mutation);
    installed
}

/// Enrich a single entity with all available LSP relation types (calls, overrides,
/// uses-type, references). Each query is capped at 5 seconds. Returns the total
/// number of relations upserted into the graph.
async fn enrich_single_entity(
    server: &kin_lsp::lifecycle::LspServer,
    entity_ref: &kin_lsp::EntityRef,
    index: &kin_lsp::EntityIndex,
    root: &std::path::Path,
    state: &DaemonState,
) -> usize {
    let timeout = std::time::Duration::from_secs(5);
    let mut count = 0;

    // Calls
    match tokio::time::timeout(
        timeout,
        kin_lsp::enrichment::enrich_entity_calls(server, entity_ref, index, root),
    )
    .await
    {
        Ok(Ok(relations)) => {
            count += install_lsp_relations(state, &relations);
        }
        Ok(Err(e)) => {
            debug!(entity = %entity_ref.name, error = %e, "LSP calls enrichment failed");
        }
        Err(_) => {
            debug!(entity = %entity_ref.name, "LSP calls enrichment timed out");
        }
    }

    // Overrides
    if let Ok(Ok(relations)) = tokio::time::timeout(
        timeout,
        kin_lsp::enrichment::enrich_entity_overrides(server, entity_ref, index, root),
    )
    .await
    {
        count += install_lsp_relations(state, &relations);
    }

    // UsesType
    if let Ok(Ok(relations)) = tokio::time::timeout(
        timeout,
        kin_lsp::enrichment::enrich_entity_uses_type(server, entity_ref, index, root),
    )
    .await
    {
        count += install_lsp_relations(state, &relations);
    }

    // References
    if let Ok(Ok(relations)) = tokio::time::timeout(
        timeout,
        kin_lsp::enrichment::enrich_entity_references(server, entity_ref, index, root),
    )
    .await
    {
        count += install_lsp_relations(state, &relations);
    }

    count
}

/// Run the kin daemon. This is the main entry point.
///
/// Starts:
/// 1. The reconciliation loop (file watcher + reconciler)
/// 2. The HTTP API server (for CLI, MCP, and UI)
/// 3. The orphan session sweeper (Phase 7)
///
/// All run concurrently. Any shutting down causes the others to stop.
pub async fn run(state: DaemonState, config: DaemonConfig) -> Result<()> {
    let authority = acquire_daemon_authority(state.layout.root())?;
    run_with_authority(state, config, authority).await
}

/// Run with repository singleton authority already acquired.
///
/// The production process entrypoint uses this form so the lifetime guard is
/// held before `DaemonState::open*` can recover or publish persisted state.
/// [`run`] remains as the source-compatible wrapper for library callers.
pub async fn run_with_authority(
    state: DaemonState,
    config: DaemonConfig,
    daemon_lock: crate::lifecycle::DaemonLock,
) -> Result<()> {
    run_with_authority_on(state, config, daemon_lock, None).await
}

/// The API socket a caller bound and published before opening state.
///
/// Opening state re-verifies the whole durable publication, so a daemon that
/// binds only afterwards refuses every connection for the length of that load.
/// A caller that binds first passes the second handle to its already-bound
/// socket here, along with the signal that retires the readiness surface it has
/// been answering probes on in the meantime.
pub struct PreboundApi {
    /// The serving handle of a socket already bound and already published.
    pub listener: tokio::net::TcpListener,
    pub port: u16,
    /// Set when the full API takes over, which stops the readiness surface.
    pub ready_tx: tokio::sync::watch::Sender<bool>,
}

/// Run with singleton authority held, optionally on an already-bound socket.
pub async fn run_with_authority_on(
    mut state: DaemonState,
    config: DaemonConfig,
    daemon_lock: crate::lifecycle::DaemonLock,
    prebound: Option<PreboundApi>,
) -> Result<()> {
    // A singleton file handle is authority for one canonical repository, not a
    // process-global permission to run any DaemonState. Validate the binding
    // before migration, listener binding, or endpoint publication so a safe
    // public API caller cannot replay repo A's capability against repo B.
    let state_root = state
        .layout
        .root()
        .canonicalize()
        .map_err(DaemonError::Io)?;
    if daemon_lock.canonical_kin_root() != state_root {
        return Err(DaemonError::AuthorityMismatch {
            authority_root: daemon_lock.canonical_kin_root().to_path_buf(),
            state_root,
        });
    }

    // Refuse to serve an incompatible `.kin/` layout. We now hold the singleton
    // lock (sole writer for this repo) but have not bound a port, written
    // endpoint files, or touched graph/kindb state — the safe point to validate
    // and forward-migrate the on-disk layout version. A newer-than-supported or
    // un-upgradable layout fails loudly here instead of being silently
    // mis-served; a current layout is a cheap read with no disk write.
    if let Err(error) = state.layout.migrate() {
        tracing::error!(
            repo = %state.layout.root().display(),
            %error,
            "refusing to start: .kin/ layout is incompatible with this kin build"
        );
        return Err(error.into());
    }

    // Publish which language servers this host has, so every answer this daemon
    // serves reports the same fact the enrichment path acts on. Without it the
    // absence-trust gate cannot tell a language whose program a server resolved
    // from one nothing resolved, and it certified an absence over the latter.
    //
    // A cheap PATH lookup rather than `discover_servers`, which runs `--version`
    // on every server it finds, and published unconditionally: a daemon with
    // enrichment switched off produces no reference edge either, so its answers
    // must not claim otherwise.
    // Load what a previous daemon already enriched, so a restart resumes rather
    // than re-sweeping a converged graph.
    load_lsp_enriched_marker(&state);

    kin_mcp::edge_coverage::publish_installed_language_servers(
        kin_core::reference_coverage::installed_language_servers(),
    );

    // Set up LSP enrichment channel before wrapping state in Arc.
    let enrichment_enabled =
        should_enable_lsp_enrichment(config.lsp_enabled, state.filesystem_reconcile_disabled());
    let lsp_rx = if enrichment_enabled {
        let discovered = kin_lsp::discovery::discover_servers();
        if enrichment_channel_opens(enrichment_enabled, discovered.len()) {
            info!(
                count = discovered.len(),
                languages = ?discovered.iter().map(|s| format!("{}", s.language)).collect::<Vec<_>>(),
                "LSP servers available for enrichment"
            );
            let (tx, rx) = tokio::sync::mpsc::channel::<crate::state::LspEnrichmentMessage>(256);
            state.lsp_enrichment_tx = Some(tx);
            Some(rx)
        } else {
            info!(
                "no LSP servers found, so enrichment is disabled for the life of this daemon; \
                 install one and restart to enable it"
            );
            None
        }
    } else {
        if config.lsp_enabled && state.filesystem_reconcile_disabled() {
            info!(
                "LSP discovery and enrichment disabled; filesystem-derived relations cannot mutate graph-only authority"
            );
        }
        None
    };

    let state = Arc::new(state);

    // Nothing used to trigger a sweep. The enrichment worker started, blocked on
    // a channel, and waited: the incremental path fires only on watcher
    // file-change events, and the only caller of `queue_lsp_sweep` was
    // `POST /lsp/sweep`, which nothing in the product calls. So a freshly
    // converted repository sat with a running server, a wired adapter and zero
    // cross-file reference edges, and the first daemon after `kin init` was
    // signalled 189 ms after its enrichment worker started, taking the intent
    // with it.
    //
    // Queued here, after the channel exists and before the listener binds, so a
    // daemon that comes up for any reason converges the graph it was handed. The
    // sweep skips files that already carry language-server evidence, so this is
    // cheap on a converged repository, resumable after a kill, and safe to queue
    // on every start.
    if enrichment_enabled && state.lsp_enrichment_tx.is_some() {
        info!("queueing an LSP sweep so a graph with unenriched files converges");
        state.queue_lsp_sweep();
    }

    // Bind the API listener so the daemon owns port selection. With
    // config.api_port == 0 the OS assigns a free ephemeral port; we then publish
    // the *actual* bound port via the port file. Binding before the port file is
    // written closes the reserve-release-rebind race (find_free_port TOCTOU)
    // where a launcher picked a port, dropped it, and a sibling process stole it
    // before the daemon bound.
    //
    // Binding HERE is still after `DaemonState::open*`, which reads and
    // re-verifies the whole durable publication. An earlier comment claimed this
    // ran "before the slower graph/LSP startup"; that was true of this function
    // and false of the process, and it read as though first contact during the
    // open window were already handled. It is not, on this path: a client
    // arriving while state opens finds no socket. The process entrypoint passes
    // `prebound` precisely to close that window, and when it does, the socket is
    // already bound, already published, and already answering.
    let (api_listener, bound_port, warming_retired) = match prebound {
        Some(prebound) => (prebound.listener, prebound.port, Some(prebound.ready_tx)),
        None => {
            let (listener, port) = match api::bind_api_listener(&state.layout, config.api_port) {
                Ok(bound) => bound,
                Err(error) => return Err(DaemonError::Io(error)),
            };
            (listener, port, None)
        }
    };

    // Publish PID and the actual bound port as one lifecycle-authorized
    // operation. Endpoint retirement takes the same authority, so no client can
    // delete a successor publication using a verdict about its predecessor.
    //
    // This happens HERE, after state is open, for a prebound caller too. The
    // endpoint is what makes a daemon findable, and a client that finds one
    // sends commands against it — it waits on readiness only when it spawned
    // the daemon itself. Publishing during the open window would therefore turn
    // "not ready yet" into a failed command on the attach path. Binding early
    // costs nothing here because it advertises nothing; only publication does.
    crate::lifecycle::publish_daemon_endpoint(state.layout.root(), bound_port)
        .map_err(DaemonError::Io)?;

    // Retire the readiness surface: the full API serves this socket from here.
    // Both handles accept from one listen queue, so there is no instant at which
    // neither is answering — during the handover a connection is answered by
    // whichever accepts it, and both answers are correct.
    if let Some(ready_tx) = warming_retired {
        let _ = ready_tx.send(true);
    }

    // Shutdown signal: when set to true, all loops exit.
    let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);

    info!(port = bound_port, "starting kin daemon");

    // Publish the startup window into shared state before the monitor reads
    // it, so an attached client can see and grow the window this daemon is
    // actually running with rather than the one its spawner happened to choose.
    state.install_idle_timeout(config.idle_timeout);
    let idle_state = Arc::clone(&state);
    let idle_timeout = config.idle_timeout;
    let idle_cancel_tx = cancel_tx.clone();
    let idle_cancel = cancel_rx.clone();
    let idle_handle = tokio::spawn(async move {
        run_idle_monitor(
            idle_state,
            idle_timeout,
            bound_port,
            idle_cancel_tx,
            idle_cancel,
        )
        .await
    });

    // Opt-in owner-death watchdog. A harness (e.g. the benchmark driver) sets
    // KIN_DAEMON_WATCH_PID to the PID of the process that owns this daemon's
    // work. When that owner dies, nothing will ever consume what this daemon is
    // computing, so it shuts itself down instead of burning cores and holding
    // tens of GB on a result no one will read. An orphaned daemon caught
    // mid-hydration is the motivating case: hydration cost is superlinear, so
    // the longer an abandoned walk runs the more expensive it gets.
    //
    // Deliberately a plain OS thread, NOT a tokio task. The whole point of this
    // watchdog is to work when the daemon is in trouble, and the previous tokio
    // task could only fire if the async runtime was still willing to schedule
    // it. It also sets `is_shutdown` directly rather than relying on the
    // propagation task, so the force-exit backstop is armed even if no tokio
    // task ever runs again.
    //
    // Opt-in only, and never inferred from getppid() — see
    // `parse_owner_watch_pid` for why the process tree cannot answer this
    // question for a daemon that is detached by design.
    if let Some(owner_pid) = parse_owner_watch_pid(
        std::env::var("KIN_DAEMON_WATCH_PID").ok().as_deref(),
        std::process::id(),
    ) {
        info!(owner_pid, "daemon owner-death shutdown enabled");
        let watch_state = Arc::clone(&state);
        let watch_cancel_tx = cancel_tx.clone();
        let watch_cancel_rx = cancel_rx.clone();
        if let Err(error) = std::thread::Builder::new()
            .name("kin-owner-watchdog".to_string())
            .spawn(move || loop {
                std::thread::sleep(OWNER_WATCH_CHECK_INTERVAL);
                if shutdown_signalled(
                    watch_state
                        .is_shutdown
                        .load(std::sync::atomic::Ordering::Relaxed),
                    *watch_cancel_rx.borrow(),
                    shutdown_requested(),
                ) {
                    return;
                }
                if watched_process_is_alive(owner_pid) {
                    continue;
                }
                warn!(
                    owner_pid,
                    "owner process is gone — shutting down orphaned daemon"
                );
                // Arm the force-exit backstop here, not via the propagation
                // task: an orphaned daemon is exactly the case where the async
                // runtime may be unable to make progress.
                watch_state
                    .is_shutdown
                    .store(true, std::sync::atomic::Ordering::Relaxed);
                // Best-effort graceful path; it normally wins the race against
                // the escalation grace and exits cleanly with state flushed.
                let _ = watch_cancel_tx.send(true);
                return;
            })
        {
            warn!(error = %error, "failed to spawn owner-death watchdog");
        }
    }

    // Spawn the reconciliation loop.
    let loop_state = Arc::clone(&state);
    let loop_config = config.loop_config.clone();
    let loop_cancel = cancel_rx.clone();
    let loop_handle =
        tokio::spawn(
            async move { loop_runner::run_loop(loop_state, loop_config, loop_cancel).await },
        );

    // Spawn the API server on the pre-bound listener.
    let api_state = Arc::clone(&state);
    let api_cancel_tx = cancel_tx.clone();
    let api_cancel = cancel_rx.clone();
    let api_handle = tokio::spawn(async move {
        api::serve_bound_with_shutdown(api_state, api_listener, Some(api_cancel_tx), api_cancel)
            .await
    });

    // Register this repo-scoped graph daemon with the lightweight central
    // supervisor when one is available. The supervisor owns process/routing
    // metadata only; this daemon remains graph-authoritative for its repo.
    let supervisor_state = Arc::clone(&state);
    let supervisor_port = bound_port;
    let supervisor_cancel = cancel_rx.clone();
    let supervisor_handle = tokio::spawn(async move {
        crate::supervisor::repo_daemon_registration_loop(
            supervisor_state,
            supervisor_port,
            supervisor_cancel,
        )
        .await
    });

    // Startup watchdog: monitor initialization and warn if it takes too long.
    let watchdog_state = Arc::clone(&state);
    let mut watchdog_cancel = cancel_rx.clone();
    tokio::spawn(async move {
        let init_timeout = Duration::from_secs(120);
        let check = Duration::from_secs(10);
        let start = std::time::Instant::now();
        loop {
            tokio::select! {
                _ = tokio::time::sleep(check) => {}
                _ = watchdog_cancel.changed() => return,
            }
            if watchdog_state
                .is_initialized
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                info!(
                    elapsed_ms = start.elapsed().as_millis(),
                    "daemon initialization complete"
                );
                return;
            }
            let elapsed = start.elapsed();
            if elapsed >= init_timeout {
                error!(
                    elapsed_s = elapsed.as_secs(),
                    "daemon initialization timed out — first reconciliation did not complete within 120s; check snapshot or repo state"
                );
                return;
            }
            info!(
                elapsed_s = elapsed.as_secs(),
                "daemon still initializing (waiting for first reconciliation)"
            );
        }
    });

    // Spawn task to propagate shutdown signals to state.is_shutdown.
    let shutdown_state = Arc::clone(&state);
    let mut shutdown_cancel = cancel_rx.clone();
    tokio::spawn(async move {
        while !*shutdown_cancel.borrow() {
            if shutdown_cancel.changed().await.is_err() {
                break;
            }
        }
        if *shutdown_cancel.borrow() {
            shutdown_state
                .is_shutdown
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
    });

    // Arm the runtime-independent shutdown flag before the reconciliation loop
    // can start occupying worker threads. Neither this flag nor the watchdog
    // below is ever set during normal operation, so neither can fire on a
    // healthy daemon.
    install_shutdown_signal_handler();
    let escalation_state = Arc::clone(&state);
    spawn_shutdown_escalation_watchdog(
        move || {
            escalation_state
                .is_shutdown
                .load(std::sync::atomic::Ordering::Relaxed)
        },
        cancel_rx.clone(),
        shutdown_escalation_grace(),
    );

    // Spawn projection rebuild in background — VFS needs it but locate doesn't.
    // The reconcile loop and API server can start immediately.
    //
    // Registered with the self-limit supervisor as disclose-only. The whole pass
    // is a single `rebuild_projection().await`: there is no loop and so nowhere
    // between start and finish for it to read a halt. Making it stoppable means
    // threading cancellation through `ProjectionState::from_resolved_tree`,
    // which is an API change rather than a registration. Until then the honest
    // thing is to let a user see it working and how long since it advanced, and
    // to never claim it was stopped.
    let projection_state = Arc::clone(&state);
    let projection_pass = state
        .background_work
        .disclosed_pass(crate::background_work::PASS_PROJECTION);
    tokio::spawn(async move {
        projection_pass.working(Instant::now());
        if let Err(error) = projection_state.rebuild_projection().await {
            tracing::error!(error = %error, "failed to rebuild projection state on startup");
        } else {
            projection_pass.advanced(1, Instant::now());
            tracing::info!("projection state rebuilt in background");
        }
        projection_pass.idle();
    });

    // Spawn the orphan session sweeper (Phase 7).
    let sweep_state = Arc::clone(&state);
    let sweep_interval = config.sweep_interval;
    let mut sweep_cancel = cancel_rx.clone();
    let sweep_handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tokio::time::sleep(sweep_interval) => {}
                _ = sweep_cancel.changed() => {
                    info!("session sweeper shutting down");
                    break;
                }
            }
            if *sweep_cancel.borrow() {
                break;
            }
            let _coordination = sweep_state.coordination_gate.lock().await;
            let mode = sweep_state.coordination_mode().as_str().to_string();
            match sweep_state
                .coordinator
                .sweep_stale_sessions_with_reservation(|session, intents| {
                    for intent in intents {
                        sweep_state.record_coordination_event(
                            crate::state::CoordinationEventDraft {
                                event: "intent_release",
                                outcome: "pending:session_reaped".to_string(),
                                session_id: Some(session.session_id.to_string()),
                                intent_id: Some(intent.intent_id.to_string()),
                                intent_ids: vec![intent.intent_id.to_string()],
                                transaction_id: None,
                                scopes: intent
                                    .scopes
                                    .iter()
                                    .map(crate::api::format_scope)
                                    .collect(),
                                enforcement_mode: mode.clone(),
                                blocking_intent_ids: Vec::new(),
                            },
                        )?;
                    }
                    Ok(())
                }) {
                Ok(reaped) => {
                    for (session, intents) in reaped {
                        for intent in intents {
                            let _ = sweep_state.record_coordination_event(
                                crate::state::CoordinationEventDraft {
                                    event: "intent_release",
                                    outcome: "session_reaped".to_string(),
                                    session_id: Some(session.session_id.to_string()),
                                    intent_id: Some(intent.intent_id.to_string()),
                                    intent_ids: vec![intent.intent_id.to_string()],
                                    transaction_id: None,
                                    scopes: intent
                                        .scopes
                                        .iter()
                                        .map(crate::api::format_scope)
                                        .collect(),
                                    enforcement_mode: mode.clone(),
                                    blocking_intent_ids: Vec::new(),
                                },
                            );
                        }
                    }
                }
                Err(e) => {
                    sweep_state.mark_coordination_evidence_incomplete(format!(
                        "stale-session sweep failed after reservation may have been written: {e}"
                    ));
                    error!(error = %e, "session sweeper error");
                }
            }
        }
    });

    // Spawn the background persistence task.
    // Instead of blocking the reconcile loop with synchronous save_graph(),
    // this task periodically flushes dirty state to disk:
    //   - Idle flush: KIN_DAEMON_IDLE_FLUSH_SECS (default 2s) after the last
    //     mutation with no new mutations; suppressed while a daemon-side
    //     embed pass is in flight (see should_flush_now)
    //   - Periodic flush: every KIN_DAEMON_PERIODIC_FLUSH_SECS (default 30s)
    //     of unpersisted dirty state, regardless of activity
    //   - Shutdown flush: handled separately in the graceful shutdown path
    let persist_state = Arc::clone(&state);
    let mut persist_cancel = cancel_rx.clone();
    let persist_handle = tokio::spawn(async move {
        let idle_flush =
            duration_from_env_secs("KIN_DAEMON_IDLE_FLUSH_SECS", Duration::from_secs(2));
        let periodic_flush =
            duration_from_env_secs("KIN_DAEMON_PERIODIC_FLUSH_SECS", Duration::from_secs(30));
        info!(
            idle_flush_s = idle_flush.as_secs(),
            periodic_flush_s = periodic_flush.as_secs(),
            "background persistence intervals"
        );
        let base_interval = Duration::from_millis(500);
        let max_backoff = Duration::from_secs(30);
        const UNHEALTHY_THRESHOLD: u32 = 5;

        let mut consecutive_failures: u32 = 0;
        let mut current_interval = base_interval;

        loop {
            tokio::select! {
                _ = tokio::time::sleep(current_interval) => {}
                _ = persist_cancel.changed() => {
                    if persist_state.is_dirty() {
                        if persist_state.shutdown_flush_would_wipe_graph() {
                            // The in-memory graph collapsed to a small fraction of
                            // the last persisted entity count — almost certainly a
                            // transient wipe (e.g. an empty/bare checkout
                            // reconciled as all-deleted), not a real edit. Skip the
                            // final flush so the larger good snapshot survives; the
                            // daemon reloads it and re-reconciles against the
                            // filesystem on restart. (Graph-keyed, not embed-keyed:
                            // a stale vector index self-heals on load and never
                            // blocks this flush.)
                            warn!(
                                persisted = persist_state.persisted_entity_count.load(std::sync::atomic::Ordering::SeqCst),
                                current = persist_state.graph.entity_count(),
                                "skipping final graph flush on shutdown — in-memory entity count collapsed vs on-disk snapshot; preserving the larger snapshot"
                            );
                        } else {
                            info!("final persistence flush on shutdown");
                            if let Err(e) = save_snapshot_blocking(Arc::clone(&persist_state)).await {
                                error!(error = %e, "shutdown save failed");
                            } else {
                                persist_state.mark_clean();
                            }
                        }
                    }
                    break;
                }
            }
            if *persist_cancel.borrow() {
                break;
            }

            if !persist_state.is_dirty() {
                continue;
            }

            let should_flush = should_flush_now(
                persist_state.time_since_save(),
                persist_state.time_since_mutation(),
                persist_state.embed_pass_active(),
                idle_flush,
                periodic_flush,
            );

            if should_flush {
                let start = std::time::Instant::now();
                match save_snapshot_blocking(Arc::clone(&persist_state)).await {
                    Ok(()) => {
                        persist_state.mark_clean();
                        if consecutive_failures > 0 {
                            info!(
                                prior_failures = consecutive_failures,
                                "persistence recovered"
                            );
                        }
                        consecutive_failures = 0;
                        current_interval = base_interval;
                        info!(
                            elapsed_ms = start.elapsed().as_millis(),
                            "background persistence flush complete"
                        );
                    }
                    Err(e) => {
                        consecutive_failures += 1;
                        let backoff_secs =
                            (1u64 << consecutive_failures.min(5)).min(max_backoff.as_secs());
                        current_interval = Duration::from_secs(backoff_secs);
                        if consecutive_failures >= UNHEALTHY_THRESHOLD {
                            error!(
                                error = %e,
                                consecutive_failures,
                                next_retry_s = backoff_secs,
                                "daemon persistence unhealthy — check disk space and permissions"
                            );
                        } else {
                            tracing::warn!(
                                error = %e,
                                consecutive_failures,
                                next_retry_s = backoff_secs,
                                "background persistence flush failed, backing off"
                            );
                        }
                    }
                }
            }
        }
    });

    // Spawn the background embedding worker.
    // Periodically drains the embedding queue, generating vector embeddings
    // for newly added/modified entities. Non-blocking to the reconcile loop.
    let embed_state = Arc::clone(&state);
    let embed_interval = config.embed_interval;
    let embed_batch_size = config.embed_batch_size;
    let embed_pipeline_overlap = config.embed_pipeline_overlap;
    let mut embed_cancel = cancel_rx.clone();
    let embed_handle = tokio::spawn(async move {
        if !embed_state.can_persist_embed_progress_locally() {
            warn!(
                "background embedding worker disabled: storage-backend graph authority has no durable vector-sidecar persistence contract; graph serving remains available"
            );
            return;
        }
        // Wait for the daemon to finish its first reconciliation cycle
        // before starting embedding work — no point embedding an empty graph.
        while !embed_state
            .is_initialized
            .load(std::sync::atomic::Ordering::Relaxed)
        {
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_millis(500)) => {}
                _ = embed_cancel.changed() => return,
            }
        }
        info!("embedding worker started");
        start_or_defer_background_embed(&embed_state);
        // Register with the self-limit supervisor. Registration is what makes
        // this worker's CPU accountable: from here it declares when it is
        // working, credits what it persists, and is stopped and announced if
        // those two ever come apart.
        let embed_pass = embed_state
            .background_work
            .pass(crate::background_work::PASS_EMBED);
        let embed_retry_budget = crate::background_work::configured_retry_budget();
        let mut consecutive_panics: u32 = 0;
        const MAX_CONSECUTIVE_PANICS: u32 = 3;
        // Recovery + backoff state for vector-index errors (e.g. a stale on-disk
        // index dimension vs the live embedder). We trigger the kin-db
        // reset/re-queue contract exactly ONCE; if the error persists, we back
        // off exponentially so the worker can never busy-spin requeuing a batch
        // that keeps failing — the 100% CPU / 5s requeue-fail loop class.
        let mut index_reset_triggered = false;
        let mut error_backoff: Option<Duration> = None;
        const EMBED_ERROR_BACKOFF_MAX: Duration = Duration::from_secs(60);
        // The coverage gap this worker last re-queued, so a gap it cannot close
        // is reported once instead of re-queued every interval. Cleared by any
        // batch that embeds something, since progress makes the next gap a new
        // question.
        let mut backfilled_gap: Option<usize> = None;
        'wake: loop {
            // Between wakes this worker is genuinely doing nothing, so the
            // working stretch ends here. A wedged drain never reaches this
            // point, which is precisely why the stretch it started keeps
            // accumulating and becomes observable.
            embed_pass.idle();
            // While an embed/index error is being retried, sleep for the current
            // backoff instead of the normal idle interval (no tight-spin).
            let idle = error_backoff.unwrap_or(embed_interval);
            tokio::select! {
                _ = tokio::time::sleep(idle) => {}
                _ = embed_cancel.changed() => {
                    info!("embedding worker shutting down");
                    break;
                }
            }
            if *embed_cancel.borrow() {
                break;
            }
            if embed_pass.halted() {
                break;
            }

            // Drain the pending backlog continuously within this wake rather than
            // one batch per `embed_interval`. A fresh central-graph embed (or an
            // explicit `kin embed --rebuild`) enqueues thousands of entities;
            // trickling a single batch per interval would cap throughput at
            // `embed_batch_size / embed_interval` no
            // matter how fast the GPU runs. We yield between batches so locate,
            // persistence, and cancellation stay responsive, then fall back to the
            // idle sleep once the queue is empty. Incremental trickle (a handful of
            // newly-reconciled entities) drains in a single pass and is unchanged.
            // At most one batch's flush is in flight at a time. Under the
            // throughput profile its flush stays here while the next batch's
            // prep + GPU forward runs, so the accelerator is never idle during a
            // persist; it is drained before the next flush is scheduled and at
            // every loop exit so two flushes never interleave and the tail is
            // always awaited.
            let mut pending_flush: Option<tokio::task::JoinHandle<Result<usize>>> = None;
            // Entities embedded by batches whose flush has not been awaited yet.
            // Credited to the pass only once that flush reports it reached disk.
            let mut embedded_since_flush: u64 = 0;
            loop {
                if *embed_cancel.borrow() {
                    drain_embed_flush(&mut pending_flush, &mut embedded_since_flush, &embed_pass)
                        .await;
                    break 'wake;
                }
                // The supervisor's verdict is enforced here, at the worker's own
                // checkpoint, so an in-flight batch and its flush finish rather
                // than being torn out from under the vector sidecar.
                if embed_pass.halted() {
                    drain_embed_flush(&mut pending_flush, &mut embedded_since_flush, &embed_pass)
                        .await;
                    break 'wake;
                }
                if embed_state.background_embed_paused() {
                    debug!("embedding worker paused after bounded explicit embed");
                    break;
                }
                if embed_state.embed_pass_active() {
                    debug!("embedding worker yielding to explicit embed pass");
                    break;
                }
                let pending = embed_state.graph.pending_embeddings();
                let pending_artifacts = embed_state.graph.pending_artifact_embeddings();
                if pending == 0 && pending_artifacts == 0 {
                    // An empty queue is not the same fact as whole coverage,
                    // and the difference is what let every commit cost a store
                    // part of its memory in silence. A change mints a HEAD
                    // revision key per touched entity, and anything that puts a
                    // retrievable key into truth without queueing it leaves the
                    // worker nothing to do and no reason to say so. Ask coverage
                    // before believing the drain.
                    let status = embed_state.graph.embedding_status();
                    let missing = status.total.saturating_sub(status.indexed);
                    match coverage_drain_verdict(missing, backfilled_gap) {
                        CoverageDrainVerdict::Backfill { missing } => {
                            warn!(
                                missing,
                                indexed = status.indexed,
                                total = status.total,
                                "embedding queue drained while coverage is short; re-queueing the missing keys"
                            );
                            backfilled_gap = Some(missing);
                            #[cfg(feature = "embeddings")]
                            embed_state.graph.queue_missing_for_embedding();
                            embed_state.graph.queue_missing_artifacts_for_embedding();
                            if embed_state.graph.pending_embeddings() > 0
                                || embed_state.graph.pending_artifact_embeddings() > 0
                            {
                                continue;
                            }
                            warn!(
                                missing,
                                "no retrievable key could be queued for the missing coverage"
                            );
                            break;
                        }
                        CoverageDrainVerdict::Stalled { missing } => {
                            debug!(
                                missing,
                                "embedding coverage is short and re-queueing it changed nothing"
                            );
                            break;
                        }
                        CoverageDrainVerdict::Complete => {
                            // Coverage is whole here, so this is where the
                            // has-ever-completed marker is published. Recording
                            // it on the side that did the work keeps the claim
                            // off a reader that only saw a quiet queue.
                            embed_state.record_embedding_coverage_complete();
                            break;
                        }
                    }
                }
                // From here to the next `idle` this worker is spending the
                // machine. Latched, so a drain that never finishes keeps one
                // stretch rather than restarting it every batch.
                embed_pass.working(Instant::now());
                let batch = embed_batch_size;
                let state_for_embed = Arc::clone(&embed_state);
                let is_artifact = pending == 0;
                let reset_on_index_error = !index_reset_triggered;
                let label = if is_artifact {
                    "embedded artifacts"
                } else {
                    "embedded entities"
                };
                let remaining = if is_artifact {
                    pending_artifacts
                } else {
                    pending
                };

                let embed_result = tokio::task::spawn_blocking(move || {
                    run_background_embedding_batch(
                        &state_for_embed,
                        reset_on_index_error,
                        |state| {
                            if is_artifact {
                                state.graph.process_artifact_embedding_queue(batch)
                            } else {
                                state.graph.process_embedding_queue(batch)
                            }
                        },
                    )
                })
                .await;

                match embed_result {
                    Ok(BackgroundEmbeddingBatchOutcome::Completed(count)) if count > 0 => {
                        consecutive_panics = 0;
                        // A successful batch means the index now matches the
                        // embedder — clear any error backoff / reset latch.
                        index_reset_triggered = false;
                        error_backoff = None;
                        // Progress makes the next coverage gap a new question,
                        // so a gap that once looked unclosable gets asked again.
                        backfilled_gap = None;
                        embed_pass.reset_retries();
                        info!(count, remaining = remaining.saturating_sub(count), label);
                        // Serialize successive flushes: the previous batch's
                        // flush — which may still be running concurrently with
                        // this batch's prep + GPU forward under the throughput
                        // profile — must finish before this batch's flush starts.
                        // This guarantees at most one persist runs at a time, so
                        // two flushes never interleave and the persisted
                        // generation cursor advances monotonically.
                        drain_embed_flush(
                            &mut pending_flush,
                            &mut embedded_since_flush,
                            &embed_pass,
                        )
                        .await;
                        embedded_since_flush = count as u64;
                        // Persist the vector index under the shared persist lock so
                        // this kvec write can never interleave with a snapshot save
                        // running in the persistence loop or idle-shutdown flush.
                        // Run inside spawn_blocking so the std persist Mutex is held
                        // only across the synchronous write, never across an await.
                        let state_for_persist = Arc::clone(&embed_state);
                        // Flush this batch incrementally — the vector
                        // sidecar plus any concurrent LSP-enrichment graph delta —
                        // instead of relying on the periodic full-graph save that
                        // re-serializes the whole ~1 GB graph each tick. The method
                        // holds the persist lock and advances the generation cursor
                        // (mirrors save_snapshot), so the two paths never tear.
                        let flush = tokio::task::spawn_blocking(move || {
                            state_for_persist.flush_embed_progress()
                        });
                        pending_flush = Some(flush);
                        // Throughput leaves the flush in flight and loops straight
                        // to the next batch so the GPU is fed while the persist
                        // runs; proof/serial blocks on it now so the persisted
                        // order is fully deterministic.
                        if !embed_pipeline_overlap {
                            drain_embed_flush(
                                &mut pending_flush,
                                &mut embedded_since_flush,
                                &embed_pass,
                            )
                            .await;
                        }
                    }
                    Ok(BackgroundEmbeddingBatchOutcome::Completed(_)) => {
                        // Queue drained out from under us (e.g. an explicit
                        // `/embed` request raced ahead). Stop draining and return
                        // to the idle sleep.
                        consecutive_panics = 0;
                        index_reset_triggered = false;
                        error_backoff = None;
                        embed_pass.reset_retries();
                        break;
                    }
                    Ok(BackgroundEmbeddingBatchOutcome::ResetAfterIndexError(e)) => {
                        warn!(
                            error = %e,
                            "embedding worker hit a vector-index error — reset vector index and re-queued once"
                        );
                        index_reset_triggered = true;
                        error_backoff = None;
                        error!(
                            error = %e,
                            "embedding worker error — reset vector index, retrying next interval"
                        );
                        break;
                    }
                    Ok(BackgroundEmbeddingBatchOutcome::Failed(e)) => {
                        // Distinguish a persistent vector-index error (a stale
                        // loaded index dimension vs the live embedder) from a
                        // transient one. The first IndexError was recovered
                        // inside the failed batch's critical section above. If
                        // it persists (reset already attempted) or it is some
                        // other error, back off exponentially so the worker
                        // never busy-spins. A stale vector index is NOT a reason
                        // to block the graph snapshot flush — it self-heals on
                        // load — so shutdown persistence is left untouched
                        // here; the graph anti-wipe guard is keyed on
                        // entity-count collapse, not on embed errors.
                        let next = next_embed_error_backoff(
                            error_backoff,
                            embed_interval,
                            EMBED_ERROR_BACKOFF_MAX,
                        );
                        error_backoff = Some(next);
                        error!(
                            error = %e,
                            backoff_s = next.as_secs(),
                            "embedding worker error — backing off"
                        );
                        // Backoff bounds how fast this ladder retries and not how
                        // long it retries for, so a failure that never clears
                        // retries at the ceiling until the process dies. Charging
                        // each delay against a cumulative budget puts an end on
                        // it: the work parks with a reason a user can read
                        // instead of retrying out of sight forever.
                        if !embed_pass.charge_retry(
                            next,
                            embed_retry_budget,
                            "the background embedding worker",
                        ) {
                            error!(
                                budget_s = embed_retry_budget.as_secs(),
                                "embedding worker parked — cumulative retry budget exhausted (see /health background_passes)"
                            );
                        }
                        break;
                    }
                    Err(e) => {
                        consecutive_panics += 1;
                        if consecutive_panics >= MAX_CONSECUTIVE_PANICS {
                            // Mark the derived-index worker as permanently failed
                            // so /health surfaces the degraded state LOUDLY. The
                            // daemon keeps serving graph/locate/reconcile — the
                            // worker exiting must NOT take the whole process down
                            // (that was the exit(0) "silent death", #11).
                            embed_state
                                .embed_worker_failed
                                .store(true, std::sync::atomic::Ordering::Relaxed);
                            // Say it on the pass surface too. A reader looking at
                            // background passes must not see this worker sitting
                            // at `idle` when it is never coming back.
                            embed_pass.halt(format!(
                                "the embedding worker panicked {consecutive_panics} times in a row \
                                 and stopped; the vector index will not advance until the daemon \
                                 restarts and the daemon keeps serving graph, locate and reconcile"
                            ));
                            error!(
                                error = %e,
                                consecutive_panics,
                                "embedding worker permanently failed — vector index will not update until daemon restart; daemon continues in embed-degraded mode (see /health embed_worker_failed)"
                            );
                            drain_embed_flush(
                                &mut pending_flush,
                                &mut embedded_since_flush,
                                &embed_pass,
                            )
                            .await;
                            break 'wake;
                        }
                        error!(
                            error = %e,
                            consecutive_panics,
                            "embedding task panicked, respawning after 1s"
                        );
                        tokio::time::sleep(Duration::from_secs(1)).await;
                        break;
                    }
                }

                // Cooperative cancellation: a shutdown signalled mid-drain must
                // not linger in the pacing sleep or loop back for another batch.
                // Break promptly the moment cancel is observed so only the single
                // in-flight blocking batch (which cannot itself observe the
                // signal) is left for the bounded teardown to handle.
                if *embed_cancel.borrow() {
                    info!("embedding worker stopping mid-drain on shutdown");
                    drain_embed_flush(&mut pending_flush, &mut embedded_since_flush, &embed_pass)
                        .await;
                    break 'wake;
                }

                // Cooperative pause: let locate, persistence, and explicit
                // `/embed` requests acquire the embedding lock between background
                // batches during a long drain. A plain yield can let this worker
                // immediately reacquire and starve foreground benchmark backfill.
                tokio::task::yield_now().await;
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            // Drain the tail flush at every drain-loop exit (pause, queue empty,
            // transient error, or panic respawn) so a persist started under the
            // throughput profile is always awaited before the worker idles or
            // re-enters the next wake — no flush outlives the loop unobserved.
            drain_embed_flush(&mut pending_flush, &mut embedded_since_flush, &embed_pass).await;
        }
        embed_pass.idle();
    });

    // Spawn the background-work supervisor.
    //
    // The daemon is the only Kin process on a user's machine, so no watchdog
    // outside it will ever notice a pass that has wedged. This one keys on the
    // persisted-progress delta rather than on CPU utilization — a busy-spin pegs
    // a core while achieving nothing, so utilization cannot tell working from
    // stuck — and stops a pass that spends the machine without advancing,
    // announcing the stop through `/health` and `kin resources` rather than
    // leaving a warm fan as the only evidence.
    let supervisor_work = Arc::clone(&state.background_work);
    let supervisor_work_cancel = cancel_rx.clone();
    tokio::spawn(crate::background_work::run_background_work_supervisor(
        supervisor_work,
        supervisor_work_cancel,
    ));

    // Spawn the LSP enrichment worker (channel was set up before Arc::new).
    if let Some(mut lsp_rx) = lsp_rx {
        let mut lsp_cancel = cancel_rx.clone();
        let lsp_state = Arc::clone(&state);
        // Canonicalize to resolve symlinks (macOS /tmp → /private/tmp).
        // RA needs rootUri and file URIs to match.
        let lsp_root = state
            .layout
            .working_dir()
            .canonicalize()
            .unwrap_or_else(|_| state.layout.working_dir().to_path_buf());
        // Registered with the self-limit supervisor. Unlike the projection
        // rebuild this pass is a real loop, so it has a checkpoint to read a
        // halt at and can be stopped rather than only disclosed.
        let lsp_pass = state.background_work.pass(crate::background_work::PASS_LSP);
        let _lsp_handle = tokio::spawn(async move {
            info!("LSP enrichment worker started");
            let source_view = match lsp_state.graph_owned_source_view() {
                Ok(view) => view,
                Err(error) => {
                    error!(
                        error = %error,
                        "LSP enrichment worker cannot open graph-owned source authority"
                    );
                    return;
                }
            };

            // Lazily start LSP servers on first use per language.
            let mut servers: std::collections::HashMap<
                kin_model::LanguageId,
                kin_lsp::lifecycle::LspServer,
            > = std::collections::HashMap::new();
            // Buffer for requests that arrive during server startup.
            let mut pending_buffer: Vec<crate::state::LspEnrichmentRequest> = Vec::new();
            // Track which languages have had their first didOpen processed.
            let mut first_open_done: std::collections::HashSet<kin_model::LanguageId> =
                std::collections::HashSet::new();

            loop {
                use crate::state::LspEnrichmentMessage;

                // The supervisor's verdict is read here, at the worker's own
                // checkpoint, so an enrichment in flight finishes rather than
                // being torn out from under the LSP server it is talking to.
                if lsp_pass.halted() {
                    for (lang, server) in servers {
                        info!(language = %lang, "shutting down LSP server");
                        let _ = server.shutdown().await;
                    }
                    info!("LSP enrichment worker stopped by the background-work supervisor");
                    break;
                }

                // Process buffered requests first (always incremental), then wait for new messages.
                let message = if let Some(buffered) = pending_buffer.pop() {
                    LspEnrichmentMessage::Incremental(buffered)
                } else {
                    // Blocked on the channel is genuinely doing nothing, so the
                    // working stretch ends here. A wedged enrichment never
                    // reaches this point, which is exactly why the stretch it
                    // started keeps accumulating and becomes observable.
                    lsp_pass.idle();
                    tokio::select! {
                        Some(msg) = lsp_rx.recv() => msg,
                        _ = lsp_cancel.changed() => {
                            for (lang, server) in servers {
                                info!(language = %lang, "shutting down LSP server");
                                let _ = server.shutdown().await;
                            }
                            info!("LSP enrichment worker shutting down");
                            break;
                        }
                    }
                };
                lsp_pass.working(Instant::now());

                match message {
                    LspEnrichmentMessage::Incremental(request) => {
                        // The URI is a compatibility projection of the
                        // graph-owned repository path. didOpen content is
                        // loaded separately from repository authority below.
                        let path = lsp_root.join(&request.file_id.0);
                        let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
                        let language = match ext {
                            "rs" => Some(kin_model::LanguageId::Rust),
                            "py" | "pyi" => Some(kin_model::LanguageId::Python),
                            "ts" | "tsx" => Some(kin_model::LanguageId::TypeScript),
                            "js" | "jsx" => Some(kin_model::LanguageId::JavaScript),
                            "go" => Some(kin_model::LanguageId::Go),
                            "java" => Some(kin_model::LanguageId::Java),
                            "c" | "h" | "cpp" | "hpp" | "cc" | "cxx" => {
                                Some(kin_model::LanguageId::C)
                            }
                            _ => None,
                        };

                        let Some(lang) = language else {
                            continue;
                        };

                        // Lazily start LSP server for this language.
                        if !servers.contains_key(&lang) {
                            if let Some((cmd, args, init_opts)) = lsp_adapter_for(lang, &lsp_root) {
                                let args_refs: Vec<&str> =
                                    args.iter().map(|s| s.as_str()).collect();
                                match kin_lsp::lifecycle::LspServer::start(
                                    &cmd, &args_refs, &lsp_root, init_opts,
                                )
                                .await
                                {
                                    Ok(server) => {
                                        info!(language = %lang, "LSP server started, polling for readiness...");
                                        wait_for_lsp_index(&server, Duration::from_secs(60)).await;
                                        info!(language = %lang, "LSP server ready");
                                        servers.insert(lang, server);

                                        // Buffer the current request + drain any that arrived during startup.
                                        pending_buffer.push(request);
                                        while let Ok(queued) = lsp_rx.try_recv() {
                                            if let LspEnrichmentMessage::Incremental(req) = queued {
                                                pending_buffer.push(req);
                                            }
                                            // Sweep messages are not buffered — they'll be re-sent if needed.
                                        }
                                        info!(
                                            buffered = pending_buffer.len(),
                                            "replaying requests after server startup"
                                        );
                                        continue; // Re-enter loop to process from buffer
                                    }
                                    Err(e) => {
                                        debug!(language = %lang, error = %e, "failed to start LSP server");
                                        continue;
                                    }
                                }
                            }
                        }

                        // Build entity index from graph for matching LSP locations.
                        let Some(server) = servers.get(&lang) else {
                            continue;
                        };
                        use kin_model::EntityStore;
                        let entities = match lsp_state.graph.list_all_entities() {
                            Ok(e) => e,
                            Err(_) => continue,
                        };
                        let entity_refs: Vec<kin_lsp::EntityRef> = entities
                            .iter()
                            .filter_map(|e| {
                                let fo = e.file_origin.as_ref()?;
                                let span = e.span.as_ref()?;
                                // Compute name position by finding name in signature.
                                // LSP needs cursor on name, not declaration start.
                                let name_col =
                                    lsp_query_column(&e.signature, &e.name, span.start_col as u32);
                                Some(kin_lsp::EntityRef {
                                    id: e.id,
                                    name: e.name.clone(),
                                    file_path: fo.0.clone(),
                                    start_line: span.start_line as u32,
                                    start_col: span.start_col as u32,
                                    end_line: span.end_line as u32,
                                    name_line: span.start_line as u32,
                                    name_col,
                                })
                            })
                            .collect();
                        let index = kin_lsp::EntityIndex::new(entity_refs);

                        // Open exact graph/CAS bytes in the LSP server. A
                        // missing body or authority mismatch fails this
                        // enrichment request loudly; the working tree is never
                        // allowed to repair or answer it.
                        let file_content = match source_view.load_text(&request.file_id) {
                            Ok(content) => content,
                            Err(error) => {
                                warn!(
                                    file = %request.file_id,
                                    error = %error,
                                    "LSP enrichment skipped because graph-owned source could not be loaded"
                                );
                                continue;
                            }
                        };
                        let file_uri = kin_lsp::protocol::path_to_uri(&path);
                        let lang_str = match lang {
                            kin_model::LanguageId::Rust => "rust",
                            kin_model::LanguageId::Python => "python",
                            kin_model::LanguageId::TypeScript => "typescript",
                            kin_model::LanguageId::JavaScript => "javascript",
                            kin_model::LanguageId::Go => "go",
                            kin_model::LanguageId::Java => "java",
                            kin_model::LanguageId::C | kin_model::LanguageId::Cpp => "c",
                            _ => "plaintext",
                        };
                        let _ = server
                            .client
                            .notify(
                                "textDocument/didOpen",
                                serde_json::json!({
                                    "textDocument": {
                                        "uri": file_uri,
                                        "languageId": lang_str,
                                        "version": 1,
                                        "text": file_content,
                                    }
                                }),
                            )
                            .await;

                        // On first file per language, wait for RA to process the didOpen.
                        // Subsequent files don't need this — RA is already indexed.
                        if first_open_done.insert(lang) {
                            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                        }

                        let rel_path = request.file_id.0.clone();

                        // Cap: if too many entities changed, it's a full re-parse — skip
                        // this batch to avoid flooding the LSP server. Incremental changes
                        // (1-10 entities) get enriched; bulk changes wait for next edit.
                        const MAX_ENTITIES_PER_REQUEST: usize = 20;
                        if request.changed_entity_ids.len() > MAX_ENTITIES_PER_REQUEST {
                            debug!(
                                path = %rel_path,
                                count = request.changed_entity_ids.len(),
                                max = MAX_ENTITIES_PER_REQUEST,
                                "skipping LSP enrichment — too many changed entities (likely full re-parse)"
                            );
                            continue;
                        }

                        info!(
                            path = %rel_path,
                            entities = request.changed_entity_ids.len(),
                            "enriching changed entities via LSP"
                        );

                        // Only enrich the entities that actually changed.
                        let file_entities: Vec<kin_lsp::EntityRef> = request
                            .changed_entity_ids
                            .iter()
                            .filter_map(|id| {
                                let entity = entities.iter().find(|e| e.id == *id)?;
                                let fo = entity.file_origin.as_ref()?;
                                let span = entity.span.as_ref()?;
                                let name_col = lsp_query_column(
                                    &entity.signature,
                                    &entity.name,
                                    span.start_col as u32,
                                );
                                Some(kin_lsp::EntityRef {
                                    id: entity.id,
                                    name: entity.name.clone(),
                                    file_path: fo.0.clone(),
                                    start_line: span.start_line as u32,
                                    start_col: span.start_col as u32,
                                    end_line: span.end_line as u32,
                                    name_line: span.start_line as u32,
                                    name_col,
                                })
                            })
                            .collect();

                        let mut total_relations = 0usize;
                        for entity_ref in &file_entities {
                            info!(entity = %entity_ref.name, "querying LSP for entity");
                            total_relations += enrich_single_entity(
                                server, entity_ref, &index, &lsp_root, &lsp_state,
                            )
                            .await;
                        }

                        if total_relations > 0 {
                            info!(
                                path = %rel_path,
                                relations = total_relations,
                                "LSP enrichment added relations"
                            );
                            lsp_state.mark_dirty();
                            // Relations reaching the graph is this pass's unit of
                            // durable work, so it is what the supervisor is told
                            // about. Querying an LSP server and finding nothing is
                            // not progress, and crediting it would let a worker
                            // that answers "no relations" forever look healthy.
                            lsp_pass.advanced(total_relations as u64, Instant::now());
                        } else {
                            info!(
                                path = %rel_path,
                                entities_queried = file_entities.len(),
                                "LSP enrichment completed — no new relations found"
                            );
                        }
                    } // end Incremental

                    LspEnrichmentMessage::Sweep => {
                        info!("LSP cold sweep started, enriching all entities");
                        lsp_state
                            .lsp_sweep_running
                            .store(true, std::sync::atomic::Ordering::SeqCst);
                        lsp_state
                            .lsp_sweep_files_done
                            .store(0, std::sync::atomic::Ordering::SeqCst);

                        // Get all entities from the graph.
                        use kin_model::EntityStore;
                        let entities = match lsp_state.graph.list_all_entities() {
                            Ok(e) => e,
                            Err(_) => continue,
                        };

                        // Group entities by file.
                        let mut by_file: std::collections::HashMap<
                            kin_model::FilePathId,
                            Vec<&kin_model::Entity>,
                        > = std::collections::HashMap::new();
                        for entity in &entities {
                            if let Some(ref fo) = entity.file_origin {
                                by_file.entry(fo.clone()).or_default().push(entity);
                            }
                        }

                        let total_files = by_file.len();
                        lsp_state
                            .lsp_sweep_files_total
                            .store(total_files as u64, std::sync::atomic::Ordering::SeqCst);
                        let mut files_processed = 0usize;
                        let mut total_relations = 0usize;

                        // Build entity index for the whole graph (used for target matching).
                        let entity_refs: Vec<kin_lsp::EntityRef> = entities
                            .iter()
                            .filter_map(|e| {
                                let fo = e.file_origin.as_ref()?;
                                let span = e.span.as_ref()?;
                                let name_col =
                                    lsp_query_column(&e.signature, &e.name, span.start_col as u32);
                                Some(kin_lsp::EntityRef {
                                    id: e.id,
                                    name: e.name.clone(),
                                    file_path: fo.0.clone(),
                                    start_line: span.start_line as u32,
                                    start_col: span.start_col as u32,
                                    end_line: span.end_line as u32,
                                    name_line: span.start_line as u32,
                                    name_col,
                                })
                            })
                            .collect();
                        let index = kin_lsp::EntityIndex::new(entity_refs);

                        for (file_id, file_entities) in &by_file {
                            let abs_path = lsp_root.join(&file_id.0);

                            // Determine language from file extension.
                            let ext = abs_path.extension().and_then(|e| e.to_str()).unwrap_or("");
                            let language = match ext {
                                "rs" => Some(kin_model::LanguageId::Rust),
                                "py" | "pyi" => Some(kin_model::LanguageId::Python),
                                "ts" | "tsx" => Some(kin_model::LanguageId::TypeScript),
                                "js" | "jsx" => Some(kin_model::LanguageId::JavaScript),
                                "go" => Some(kin_model::LanguageId::Go),
                                "java" => Some(kin_model::LanguageId::Java),
                                "c" | "h" | "cpp" | "hpp" | "cc" | "cxx" => {
                                    Some(kin_model::LanguageId::C)
                                }
                                _ => None,
                            };
                            let Some(lang) = language else { continue };

                            // Skip a file this graph already holds language-server
                            // evidence for. This is what makes the sweep idempotent
                            // and resumable: a pass killed halfway leaves the files
                            // it finished carrying Lsp-origin edges, so the next
                            // pass starts where the last one stopped instead of
                            // re-querying the server for every entity again. On the
                            // requests corpus a full pass is about three minutes,
                            // so re-running one from scratch on every daemon start
                            // is not a cost anyone would accept, and a sweep nobody
                            // dares run is a sweep that never runs.
                            if file_already_enriched(&lsp_state, &file_id.0) {
                                files_processed += 1;
                                // Info, not debug. A skip and a zero are different
                                // facts and both are findings, and a skip nobody can
                                // see is how a predicate that dropped the three files
                                // this ticket is about survived a run that reported
                                // 37 of 37 complete.
                                info!(
                                    file = %file_id.0,
                                    progress = %format!("{files_processed}/{total_files}"),
                                    "sweep skipped an already-enriched file"
                                );
                                continue;
                            }

                            // Lazily start LSP server for this language (same as incremental).
                            if !servers.contains_key(&lang) {
                                if let Some((cmd, args, init_opts)) =
                                    lsp_adapter_for(lang, &lsp_root)
                                {
                                    let args_refs: Vec<&str> =
                                        args.iter().map(|s| s.as_str()).collect();
                                    match kin_lsp::lifecycle::LspServer::start(
                                        &cmd, &args_refs, &lsp_root, init_opts,
                                    )
                                    .await
                                    {
                                        Ok(server) => {
                                            info!(language = %lang, "LSP server started for sweep, polling for readiness...");
                                            wait_for_lsp_index(&server, Duration::from_secs(60))
                                                .await;
                                            info!(language = %lang, "LSP server ready");
                                            servers.insert(lang, server);
                                        }
                                        Err(e) => {
                                            debug!(language = %lang, error = %e, "failed to start LSP server for sweep");
                                            continue;
                                        }
                                    }
                                }
                            }

                            let Some(server) = servers.get(&lang) else {
                                continue;
                            };

                            // didOpen exact graph/CAS content. The compatibility
                            // path may not exist on the host; that must not
                            // affect graph-owned semantic enrichment.
                            let file_content = match source_view.load_text(file_id) {
                                Ok(content) => content,
                                Err(error) => {
                                    warn!(
                                        file = %file_id,
                                        error = %error,
                                        "LSP sweep skipped graph source that could not be loaded from authority"
                                    );
                                    continue;
                                }
                            };
                            let uri = kin_lsp::protocol::path_to_uri(&abs_path);
                            let lang_str = match lang {
                                kin_model::LanguageId::Rust => "rust",
                                kin_model::LanguageId::Python => "python",
                                kin_model::LanguageId::TypeScript => "typescript",
                                kin_model::LanguageId::JavaScript => "javascript",
                                kin_model::LanguageId::Go => "go",
                                kin_model::LanguageId::Java => "java",
                                kin_model::LanguageId::C | kin_model::LanguageId::Cpp => "c",
                                _ => "plaintext",
                            };
                            let _ = server.client.notify("textDocument/didOpen", serde_json::json!({
                            "textDocument": { "uri": uri, "languageId": lang_str, "version": 1, "text": file_content }
                        })).await;

                            // First file per language gets a processing delay.
                            if first_open_done.insert(lang) {
                                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                            }

                            // Enrich each entity in this file.
                            let file_entity_refs: Vec<kin_lsp::EntityRef> = file_entities
                                .iter()
                                .filter_map(|e| {
                                    let span = e.span.as_ref()?;
                                    let name_col = lsp_query_column(
                                        &e.signature,
                                        &e.name,
                                        span.start_col as u32,
                                    );
                                    Some(kin_lsp::EntityRef {
                                        id: e.id,
                                        name: e.name.clone(),
                                        file_path: file_id.0.clone(),
                                        start_line: span.start_line as u32,
                                        start_col: span.start_col as u32,
                                        end_line: span.end_line as u32,
                                        name_line: span.start_line as u32,
                                        name_col,
                                    })
                                })
                                .collect();

                            // File-level enrichment: query definition at every identifier
                            // to capture ALL relationships (40-50x more than per-entity).
                            let file_result = kin_lsp::file_enrichment::enrich_file_definitions(
                                server,
                                &abs_path,
                                &file_content,
                                &index,
                                &lsp_root,
                            )
                            .await
                            .unwrap_or_default();

                            let mut file_relations =
                                install_lsp_relations(&lsp_state, &file_result.relations);

                            // Also run per-entity call hierarchy for Calls relations
                            // (definition approach gives References, call hierarchy gives Calls).
                            for entity_ref in &file_entity_refs {
                                file_relations += enrich_single_entity(
                                    server, entity_ref, &index, &lsp_root, &lsp_state,
                                )
                                .await;
                            }

                            // didClose to free LSP server memory.
                            let _ = server
                                .client
                                .notify(
                                    "textDocument/didClose",
                                    serde_json::json!({
                                        "textDocument": { "uri": uri }
                                    }),
                                )
                                .await;

                            files_processed += 1;
                            mark_file_enriched(&lsp_state, &file_id.0);
                            lsp_state
                                .lsp_sweep_files_done
                                .store(files_processed as u64, std::sync::atomic::Ordering::SeqCst);
                            total_relations += file_relations;
                            // Credited per file rather than once at the end. A
                            // cold sweep walks the whole graph, and a pass that
                            // reported nothing until it finished would look
                            // stalled for the entire run and be stopped part
                            // way through exactly the work a user asked for.
                            if file_relations > 0 {
                                lsp_pass.advanced(file_relations as u64, Instant::now());
                            }

                            if file_relations > 0 {
                                info!(
                                    file = %file_id,
                                    relations = file_relations,
                                    progress = format!("{}/{}", files_processed, total_files),
                                    "sweep enriched file"
                                );
                            } else {
                                // A file the sweep visited and got nothing from is a
                                // finding, not a non-event. Only enriched files used
                                // to be logged, so a pass could report itself complete
                                // over 37 files while the three that carried the
                                // answers produced nothing, and the log said only that
                                // the other 34 went fine. On the requests corpus that
                                // is exactly what happened: sessions.py, auth.py and
                                // adapters.py each yielded zero while a test file
                                // yielded a thousand.
                                info!(
                                    file = %file_id,
                                    entities = file_entity_refs.len(),
                                    progress = format!("{}/{}", files_processed, total_files),
                                    "sweep enriched NOTHING for this file"
                                );
                            }

                            // Check for shutdown between files.
                            if *lsp_cancel.borrow() {
                                break;
                            }
                            // Same checkpoint, for the supervisor's verdict. A
                            // sweep that is burning the CPU without enriching
                            // anything stops here, between files, rather than
                            // mid-request to a language server.
                            if lsp_pass.halted() {
                                info!("LSP cold sweep stopped by the background-work supervisor");
                                break;
                            }
                        }

                        if total_relations > 0 {
                            lsp_state.mark_dirty();
                        }
                        // Marked complete even when the loop broke early on
                        // shutdown or a supervisor halt. A waiter blocked on a
                        // counter that only advances on a clean finish would
                        // wait out its whole budget on a sweep that already
                        // stopped, and report a timeout for a pass that ended
                        // seconds in. What was enriched is durable either way,
                        // and the next sweep resumes from it.
                        lsp_state
                            .lsp_sweep_running
                            .store(false, std::sync::atomic::Ordering::SeqCst);
                        lsp_state
                            .lsp_sweeps_completed
                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        info!(
                            files = files_processed,
                            total_files,
                            relations = total_relations,
                            "LSP cold sweep complete"
                        );
                    } // end Sweep
                } // end match
            }
        });
    }

    // Persistent daemons stay alive until SIGTERM/SIGINT, `kin eject`, or
    // `kin setup doctor`. CLI-autostarted daemons opt into idle shutdown via
    // KIN_DAEMON_IDLE_TIMEOUT_SECS.

    // Wait for either task to finish (or fail), or a shutdown signal.
    // When one exits, signal the others to shut down.
    //
    // SIGTERM handling is Unix-only (used in Docker containers).
    // On Windows we rely solely on ctrl_c() (Ctrl+C / CTRL_C_EVENT).
    let result = select_with_signals(
        loop_handle,
        api_handle,
        sweep_handle,
        embed_handle,
        idle_handle,
        persist_handle,
        supervisor_handle,
        cancel_tx,
    )
    .await;

    // The derived ingestion CAS defers its directory barriers and commits them
    // on an explicit sync, on drop, or on a self-drain. This process ends in
    // `process::exit`, which runs no destructor, so the barrier has to be
    // issued here or the only one that ever fires is the self-drain.
    sync_blob_store_blocking(Arc::clone(&state)).await;

    // Remove PID and port files after final flush work finishes, so a successor
    // daemon cannot start while this process is still draining persistent state.
    crate::lifecycle::remove_daemon_files_if_current_process(state.layout.root());

    result
}

/// Issue the ingestion CAS barrier off the async workers: it is a run of
/// `fsync` calls on directories, one per shard touched since the last commit.
async fn sync_blob_store_blocking(state: Arc<DaemonState>) {
    let outcome = tokio::task::spawn_blocking(move || state.sync_blob_store()).await;
    match outcome {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            warn!(%error, "ingestion CAS barrier failed on shutdown")
        }
        Err(error) => {
            warn!(%error, "ingestion CAS barrier task failed on shutdown")
        }
    }
}

#[cfg(unix)]
async fn select_with_signals(
    mut loop_handle: tokio::task::JoinHandle<std::result::Result<(), crate::error::DaemonError>>,
    mut api_handle: tokio::task::JoinHandle<std::result::Result<(), std::io::Error>>,
    mut sweep_handle: tokio::task::JoinHandle<()>,
    embed_handle: tokio::task::JoinHandle<()>,
    mut idle_handle: tokio::task::JoinHandle<()>,
    persist_handle: tokio::task::JoinHandle<()>,
    supervisor_handle: tokio::task::JoinHandle<()>,
    cancel_tx: tokio::sync::watch::Sender<bool>,
) -> Result<()> {
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(DaemonError::Io)?;

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum CompletedTask {
        Reconciliation,
        Api,
        Sweeper,
        Idle,
        Signal,
    }

    let (completed, result) = tokio::select! {
        // NOTE: this arm shuts the daemon down, so the reconciliation loop
        // must only exit for reasons that end the daemon: the cancel signal,
        // or a real startup/runtime error. A background-work supervisor stop
        // parks the loop inside `run_loop` instead of exiting it, precisely
        // because reaching this arm cancels the API task and every other
        // task, the opposite of the stop announcement's "the daemon keeps
        // serving" (FIR-2317).
        result = &mut loop_handle => {
            info!("reconciliation loop exited");
            let _ = cancel_tx.send(true);
            (CompletedTask::Reconciliation, match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(e),
                Err(e) => Err(DaemonError::Io(std::io::Error::other(
                    e.to_string(),
                ))),
            })
        }
        result = &mut api_handle => {
            info!("API server exited");
            let _ = cancel_tx.send(true);
            (CompletedTask::Api, match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(DaemonError::Io(e)),
                Err(e) => Err(DaemonError::Io(std::io::Error::other(
                    e.to_string(),
                ))),
            })
        }
        _ = &mut sweep_handle => {
            info!("session sweeper exited");
            let _ = cancel_tx.send(true);
            (CompletedTask::Sweeper, Ok(()))
        }
        // NOTE: the embedding worker is deliberately NOT a select! arm. Embeddings
        // are a DERIVED index, so the worker exiting (e.g. exhausting its
        // consecutive-panic budget under heavy umbrella-scale load) must NOT shut
        // the daemon down — doing so produced a clean exit(0) that read as an
        // intentional shutdown and left the daemon silently dead (#11). The worker
        // now sets `embed_worker_failed`; the daemon keeps serving
        // graph/locate/reconcile in an embed-degraded state, surfaced LOUDLY via
        // /health. `embed_handle` is handed to `drain_handles` only on a REAL
        // shutdown below.
        _ = &mut idle_handle => {
            info!("idle monitor exited");
            let _ = cancel_tx.send(true);
            (CompletedTask::Idle, Ok(()))
        }
        _ = sigterm.recv() => {
            info!("SIGTERM received, shutting down...");
            let _ = cancel_tx.send(true);
            (CompletedTask::Signal, Ok(()))
        }
        _ = tokio::signal::ctrl_c() => {
            info!("SIGINT received, shutting down...");
            let _ = cancel_tx.send(true);
            (CompletedTask::Signal, Ok(()))
        }
    };

    drain_handles(
        (completed != CompletedTask::Reconciliation).then_some(loop_handle),
        (completed != CompletedTask::Api).then_some(api_handle),
        (completed != CompletedTask::Sweeper).then_some(sweep_handle),
        Some(embed_handle),
        (completed != CompletedTask::Idle).then_some(idle_handle),
        Some(persist_handle),
        Some(supervisor_handle),
    )
    .await;
    result
}

async fn drain_handles(
    loop_handle: Option<
        tokio::task::JoinHandle<std::result::Result<(), crate::error::DaemonError>>,
    >,
    api_handle: Option<tokio::task::JoinHandle<std::result::Result<(), std::io::Error>>>,
    sweep_handle: Option<tokio::task::JoinHandle<()>>,
    embed_handle: Option<tokio::task::JoinHandle<()>>,
    idle_handle: Option<tokio::task::JoinHandle<()>>,
    persist_handle: Option<tokio::task::JoinHandle<()>>,
    supervisor_handle: Option<tokio::task::JoinHandle<()>>,
) {
    let drain_timeout = Duration::from_secs(10);
    info!("draining task handles before cleanup...");
    let mut drain_tasks = Vec::new();

    macro_rules! join_or_warn {
        ($name:expr, $handle:expr) => {
            if let Some(handle) = $handle {
                drain_tasks.push(tokio::spawn(async move {
                    match handle.await {
                        Ok(_) => info!(task = $name, "task drained"),
                        Err(e) => warn!(task = $name, error = %e, "task panicked during drain"),
                    }
                }));
            }
        };
    }

    join_or_warn!("reconciliation", loop_handle);
    join_or_warn!("api", api_handle);
    join_or_warn!("sweeper", sweep_handle);
    join_or_warn!("embedding", embed_handle);
    join_or_warn!("idle-monitor", idle_handle);
    join_or_warn!("persistence", persist_handle);
    join_or_warn!("supervisor-registration", supervisor_handle);

    if tokio::time::timeout(drain_timeout, async {
        for task in drain_tasks {
            let _ = task.await;
        }
    })
    .await
    .is_err()
    {
        warn!("one or more daemon tasks did not stop within 10s, proceeding");
    }
}

#[cfg(not(unix))]
async fn select_with_signals(
    mut loop_handle: tokio::task::JoinHandle<std::result::Result<(), crate::error::DaemonError>>,
    mut api_handle: tokio::task::JoinHandle<std::result::Result<(), std::io::Error>>,
    mut sweep_handle: tokio::task::JoinHandle<()>,
    embed_handle: tokio::task::JoinHandle<()>,
    mut idle_handle: tokio::task::JoinHandle<()>,
    persist_handle: tokio::task::JoinHandle<()>,
    supervisor_handle: tokio::task::JoinHandle<()>,
    cancel_tx: tokio::sync::watch::Sender<bool>,
) -> Result<()> {
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum CompletedTask {
        Reconciliation,
        Api,
        Sweeper,
        Idle,
        Signal,
    }

    let (completed, result) = tokio::select! {
        // NOTE: this arm shuts the daemon down, so the reconciliation loop
        // must only exit for reasons that end the daemon: the cancel signal,
        // or a real startup/runtime error. A background-work supervisor stop
        // parks the loop inside `run_loop` instead of exiting it, precisely
        // because reaching this arm cancels the API task and every other
        // task, the opposite of the stop announcement's "the daemon keeps
        // serving" (FIR-2317).
        result = &mut loop_handle => {
            info!("reconciliation loop exited");
            let _ = cancel_tx.send(true);
            (CompletedTask::Reconciliation, match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(e),
                Err(e) => Err(DaemonError::Io(std::io::Error::other(
                    e.to_string(),
                ))),
            })
        }
        result = &mut api_handle => {
            info!("API server exited");
            let _ = cancel_tx.send(true);
            (CompletedTask::Api, match result {
                Ok(Ok(())) => Ok(()),
                Ok(Err(e)) => Err(DaemonError::Io(e)),
                Err(e) => Err(DaemonError::Io(std::io::Error::other(
                    e.to_string(),
                ))),
            })
        }
        _ = &mut sweep_handle => {
            info!("session sweeper exited");
            let _ = cancel_tx.send(true);
            (CompletedTask::Sweeper, Ok(()))
        }
        // NOTE: the embedding worker is deliberately NOT a select! arm. Embeddings
        // are a DERIVED index, so the worker exiting (e.g. exhausting its
        // consecutive-panic budget under heavy umbrella-scale load) must NOT shut
        // the daemon down — doing so produced a clean exit(0) that read as an
        // intentional shutdown and left the daemon silently dead (#11). The worker
        // now sets `embed_worker_failed`; the daemon keeps serving
        // graph/locate/reconcile in an embed-degraded state, surfaced LOUDLY via
        // /health. `embed_handle` is handed to `drain_handles` only on a REAL
        // shutdown below.
        _ = &mut idle_handle => {
            info!("idle monitor exited");
            let _ = cancel_tx.send(true);
            (CompletedTask::Idle, Ok(()))
        }
        _ = tokio::signal::ctrl_c() => {
            info!("SIGINT received, shutting down...");
            let _ = cancel_tx.send(true);
            (CompletedTask::Signal, Ok(()))
        }
    };

    drain_handles(
        (completed != CompletedTask::Reconciliation).then_some(loop_handle),
        (completed != CompletedTask::Api).then_some(api_handle),
        (completed != CompletedTask::Sweeper).then_some(sweep_handle),
        Some(embed_handle),
        (completed != CompletedTask::Idle).then_some(idle_handle),
        Some(persist_handle),
        Some(supervisor_handle),
    )
    .await;
    result
}

#[cfg(all(test, unix))]
mod tests {
    use super::{
        coverage_drain_verdict, drain_pending_flush, embed_work_outstanding,
        format_singleton_contention, next_embed_error_backoff, parse_duration_secs,
        parse_owner_watch_pid, should_enable_lsp_enrichment, should_flush_now, shutdown_signalled,
        watched_process_is_alive, ControlPlane, CoverageDrainVerdict, DaemonConfig, DaemonState,
        DEFAULT_RUNTIME_SHUTDOWN_GRACE, DEFAULT_SHUTDOWN_ESCALATION_GRACE, RECON_IDLE,
    };
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    #[test]
    fn default_embed_batch_is_backlog_friendly() {
        assert_eq!(DaemonConfig::default().embed_batch_size, 512);
    }

    /// FIR-2254's accounting half. A drained queue over a store that is short
    /// on coverage is the exact state the daemon used to log as `remaining=0`
    /// while `kin graph status` reported hundreds pending, because the worker
    /// asked the queue and the status asked coverage. An empty queue alone must
    /// never be read as finished.
    #[test]
    fn a_drained_queue_over_short_coverage_is_not_finished() {
        assert_eq!(
            coverage_drain_verdict(641, None),
            CoverageDrainVerdict::Backfill { missing: 641 }
        );
        assert_eq!(
            coverage_drain_verdict(0, None),
            CoverageDrainVerdict::Complete
        );
    }

    /// Re-queueing is bounded by what it achieves. The same gap twice running
    /// means the previous re-queue placed nothing the worker could embed, so
    /// the worker reports it and stands down instead of rebuilding the same
    /// queue every interval forever.
    #[test]
    fn a_gap_that_requeueing_cannot_close_is_reported_not_retried() {
        assert_eq!(
            coverage_drain_verdict(641, Some(641)),
            CoverageDrainVerdict::Stalled { missing: 641 }
        );
        // A different gap is a different question, and gets its own attempt.
        assert_eq!(
            coverage_drain_verdict(210, Some(641)),
            CoverageDrainVerdict::Backfill { missing: 210 }
        );
        // Coverage closing outranks the latch entirely.
        assert_eq!(
            coverage_drain_verdict(0, Some(641)),
            CoverageDrainVerdict::Complete
        );
    }

    #[test]
    fn graph_only_authority_disables_lsp_discovery_and_worker() {
        assert!(should_enable_lsp_enrichment(true, false));
        assert!(!should_enable_lsp_enrichment(true, true));
        assert!(!should_enable_lsp_enrichment(false, false));
        assert!(!should_enable_lsp_enrichment(false, true));
    }

    #[tokio::test]
    async fn preacquired_authority_cannot_be_replayed_against_another_repo() {
        let repo_a = tempfile::tempdir().unwrap();
        let repo_b = tempfile::tempdir().unwrap();
        let initialized_a = kin_core::init(repo_a.path()).unwrap();
        let initialized_b = kin_core::init(repo_b.path()).unwrap();
        let repo_b_kin_root = initialized_b.layout.root().to_path_buf();

        let authority = super::acquire_daemon_authority(initialized_a.layout.root()).unwrap();
        let state = DaemonState::open(initialized_b.layout).unwrap();
        let result = super::run_with_authority(
            state,
            DaemonConfig {
                api_port: 0,
                ..DaemonConfig::default()
            },
            authority,
        )
        .await;

        assert!(
            matches!(
                result,
                Err(crate::error::DaemonError::AuthorityMismatch { .. })
            ),
            "repo A authority must not authorize repo B state: {result:?}"
        );
        assert!(
            !repo_b_kin_root.join("daemon.pid").exists()
                && !repo_b_kin_root.join("daemon.port").exists(),
            "authority mismatch must fail before endpoint publication"
        );
    }

    // ── Control-plane classification ──────────────────────────────────────
    //
    // A healthy daemon used to read "my endpoint files are gone" as "the
    // repository is gone" and shut itself down, which is how a refused second
    // start killed the incumbent it lost to. The two states that genuinely end
    // a daemon are distinguishable from the one that is repairable.

    #[tokio::test]
    async fn a_published_endpoint_reads_as_this_daemons_own() {
        let repo = tempfile::tempdir().unwrap();
        let initialized = kin_core::init(repo.path()).unwrap();
        let kin_root = initialized.layout.root().to_path_buf();
        let state = DaemonState::open(initialized.layout).unwrap();
        crate::lifecycle::publish_daemon_endpoint(&kin_root, 51234).unwrap();

        assert_eq!(super::classify_control_plane(&state), ControlPlane::Ours);
    }

    #[tokio::test]
    async fn a_deleted_endpoint_is_repairable_rather_than_fatal() {
        let repo = tempfile::tempdir().unwrap();
        let initialized = kin_core::init(repo.path()).unwrap();
        let kin_root = initialized.layout.root().to_path_buf();
        let state = DaemonState::open(initialized.layout).unwrap();
        crate::lifecycle::publish_daemon_endpoint(&kin_root, 51234).unwrap();

        std::fs::remove_file(kin_root.join("daemon.pid")).unwrap();
        std::fs::remove_file(kin_root.join("daemon.port")).unwrap();

        assert_eq!(
            super::classify_control_plane(&state),
            ControlPlane::EndpointLost
        );
        assert!(
            !super::control_plane_demands_shutdown(&state, 51234, false),
            "a daemon that still owns the repo must repair its endpoint, not exit"
        );
        assert_eq!(
            super::classify_control_plane(&state),
            ControlPlane::Ours,
            "the repair must republish this daemon's own endpoint"
        );
        assert_eq!(
            crate::lifecycle::read_port_file(&kin_root),
            Some(51234),
            "republication must restore the port this daemon actually bound"
        );
    }

    #[tokio::test]
    async fn a_lost_endpoint_is_not_republished_once_shutdown_is_signalled() {
        // Task drain is bounded and does not abort this monitor, and
        // publication can block on the coordination lock, so a repair that
        // started late could land after retirement and advertise an endpoint
        // for a process that is exiting.
        let repo = tempfile::tempdir().unwrap();
        let initialized = kin_core::init(repo.path()).unwrap();
        let kin_root = initialized.layout.root().to_path_buf();
        let state = DaemonState::open(initialized.layout).unwrap();
        crate::lifecycle::publish_daemon_endpoint(&kin_root, 51234).unwrap();
        std::fs::remove_file(kin_root.join("daemon.pid")).unwrap();
        std::fs::remove_file(kin_root.join("daemon.port")).unwrap();

        assert!(
            !super::control_plane_demands_shutdown(&state, 51234, true),
            "a lost endpoint is still not a reason to shut down"
        );
        assert_eq!(
            super::classify_control_plane(&state),
            ControlPlane::EndpointLost,
            "a shutting-down daemon must not republish an endpoint it is about to retire"
        );
    }

    #[tokio::test]
    async fn a_removed_repository_root_ends_the_daemon() {
        let repo = tempfile::tempdir().unwrap();
        let initialized = kin_core::init(repo.path()).unwrap();
        let kin_root = initialized.layout.root().to_path_buf();
        let state = DaemonState::open(initialized.layout).unwrap();
        crate::lifecycle::publish_daemon_endpoint(&kin_root, 51234).unwrap();

        std::fs::remove_dir_all(&kin_root).unwrap();

        assert_eq!(
            super::classify_control_plane(&state),
            ControlPlane::RootGone
        );
        assert!(super::control_plane_demands_shutdown(&state, 51234, false));
    }

    #[tokio::test]
    async fn a_proven_live_successor_endpoint_ends_the_daemon() {
        let repo = tempfile::tempdir().unwrap();
        let initialized = kin_core::init(repo.path()).unwrap();
        let kin_root = initialized.layout.root().to_path_buf();
        let state = DaemonState::open(initialized.layout).unwrap();

        let mut successor = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn a stand-in successor");
        let identity = kin_cli::daemon_client::process_identity(successor.id())
            .expect("read the successor's identity")
            .expect("the successor is running");
        crate::lifecycle::publish_foreign_endpoint_for_test(&kin_root, identity, 51234);

        assert_eq!(
            super::classify_control_plane(&state),
            ControlPlane::Superseded {
                pid: successor.id()
            }
        );
        assert!(super::control_plane_demands_shutdown(&state, 4219, false));
        assert_eq!(
            std::fs::read_to_string(kin_root.join("daemon.port")).unwrap(),
            "51234",
            "yielding to a successor must not disturb the endpoint it published"
        );

        let _ = successor.kill();
        let _ = successor.wait();
    }

    #[tokio::test]
    async fn a_foreign_endpoint_that_proves_nothing_is_repaired_not_obeyed() {
        // PID 1 is alive and is not this process, but a bare-PID record cannot
        // prove that number still names a daemon. This process holds the
        // repository singleton, so no successor can legitimately exist and the
        // record is debris — the exact debris a refusing starter used to leave.
        let repo = tempfile::tempdir().unwrap();
        let initialized = kin_core::init(repo.path()).unwrap();
        let kin_root = initialized.layout.root().to_path_buf();
        let state = DaemonState::open(initialized.layout).unwrap();
        std::fs::write(kin_root.join("daemon.pid"), "1").unwrap();
        std::fs::write(kin_root.join("daemon.port"), "51234").unwrap();

        assert_eq!(
            super::classify_control_plane(&state),
            ControlPlane::EndpointLost
        );
        assert!(!super::control_plane_demands_shutdown(&state, 4219, false));
        assert_eq!(super::classify_control_plane(&state), ControlPlane::Ours);
        assert_eq!(crate::lifecycle::read_port_file(&kin_root), Some(4219));
    }

    // ── Idle shutdown vs work in flight ───────────────────────────────────
    //
    // The idle clock only advances on API traffic, so background work is
    // invisible to it. A CLI autostart injects a 60s timeout, which is shorter
    // than a first ingest and far shorter than the embed drain that ingest
    // queues, and the killed pass restarts from zero on the next command.

    #[test]
    fn an_embedding_backlog_counts_only_while_a_worker_will_drain_it() {
        // An explicit pass is in flight regardless of the background worker.
        assert!(embed_work_outstanding(true, false, false));
        assert!(embed_work_outstanding(true, true, true));
        // Queued work with a live worker is work in progress.
        assert!(embed_work_outstanding(false, true, true));
        // Queued work the worker has stood down from is not: counting it would
        // hold a daemon open forever on a backlog nobody consumes.
        assert!(!embed_work_outstanding(false, true, false));
        // Nothing queued, nothing running.
        assert!(!embed_work_outstanding(false, false, true));
        assert!(!embed_work_outstanding(false, false, false));
    }

    #[tokio::test]
    async fn an_embed_pass_in_flight_survives_the_idle_timeout() {
        let repo = tempfile::tempdir().unwrap();
        let initialized = kin_core::init(repo.path()).unwrap();
        let state = DaemonState::open(initialized.layout).unwrap();
        state.is_initialized.store(true, Ordering::Relaxed);

        // Zero timeout: every check below is past the deadline, so the only
        // thing that can hold the daemon open is the work itself.
        let expired = Duration::ZERO;
        let pass = state.begin_embed_pass();
        assert!(
            !super::ready_for_idle_shutdown(&state, expired, ControlPlane::Ours),
            "an embed pass in flight must outrank an expired idle timeout"
        );

        drop(pass);
        assert!(
            super::ready_for_idle_shutdown(&state, expired, ControlPlane::Ours),
            "a genuinely idle initialized daemon must still idle out"
        );
    }

    /// The idle-window contract at the daemon: an attached client whose session
    /// outlasts the window this daemon was spawned with grows it, and the grown
    /// window is what the shutdown decision then reads.
    ///
    /// The two-sided part is the second half. Growing the window must not stop
    /// the daemon idling out; it must only move when.
    #[tokio::test]
    async fn a_raised_idle_window_is_what_the_shutdown_decision_reads() {
        let repo = tempfile::tempdir().unwrap();
        let initialized = kin_core::init(repo.path()).unwrap();
        let state = DaemonState::open(initialized.layout).unwrap();
        state.is_initialized.store(true, Ordering::Relaxed);

        // Spawned the way a CLI autostart spawns one.
        state.install_idle_timeout(Some(Duration::from_secs(60)));
        assert_eq!(state.idle_timeout(), Some(Duration::from_secs(60)));

        let raise = state.raise_idle_timeout(Duration::from_secs(1800));
        assert_eq!(raise.effective, Some(Duration::from_secs(1800)));
        assert_eq!(raise.raised_from, Some(Duration::from_secs(60)));
        assert_eq!(
            state.idle_timeout(),
            Some(Duration::from_secs(1800)),
            "the monitor reads the window through this accessor, so the raise must land here"
        );

        // The daemon is idle by every other measure, and the grown window is
        // the only thing holding it open.
        let window = state.idle_timeout().expect("a window is installed");
        assert!(
            !super::ready_for_idle_shutdown(&state, window, ControlPlane::Ours),
            "a session that just stated a 1800s need must not be cut off immediately"
        );
        assert!(
            super::ready_for_idle_shutdown(&state, Duration::ZERO, ControlPlane::Ours),
            "growing the window must move when the daemon idles out, never whether"
        );

        // A second client that fits inside the window changes nothing.
        let redundant = state.raise_idle_timeout(Duration::from_secs(300));
        assert!(!redundant.raised());
        assert_eq!(state.idle_timeout(), Some(Duration::from_secs(1800)));
    }

    /// The monitor reads the live window, not the one it was handed at start.
    ///
    /// This is the half the state round-trip above cannot reach: a monitor that
    /// closed over its startup value would keep counting against 60 seconds
    /// however loudly an attached session said 1800, and the state accessor
    /// would look perfectly correct while the daemon still died.
    #[tokio::test]
    async fn the_idle_monitor_counts_against_the_live_window_not_its_startup_one() {
        async fn open_idle_state() -> (tempfile::TempDir, Arc<DaemonState>) {
            let repo = tempfile::tempdir().unwrap();
            let initialized = kin_core::init(repo.path()).unwrap();
            let state = Arc::new(DaemonState::open(initialized.layout).unwrap());
            state.is_initialized.store(true, Ordering::Relaxed);
            (repo, state)
        }
        let short = Duration::from_millis(200);

        // Control. Without it the second half could pass because the monitor
        // never reaches a shutdown decision at all, which is exactly the shape
        // of guard that cannot fail.
        let (_expiring_repo, expiring) = open_idle_state().await;
        expiring.install_idle_timeout(Some(short));
        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        let monitor = tokio::spawn(super::run_idle_monitor(
            Arc::clone(&expiring),
            Some(short),
            4219,
            cancel_tx.clone(),
            cancel_rx,
        ));
        tokio::time::timeout(Duration::from_secs(30), monitor)
            .await
            .expect("an idle daemon on a 200ms window must reach idle shutdown")
            .expect("the idle monitor must not panic");
        assert!(
            *cancel_tx.borrow(),
            "the control monitor must have requested shutdown"
        );

        // The same startup window, raised by an attached client before the
        // monitor's first decision. Counting against the startup value would
        // shut this daemon down inside the wait below.
        let (_raised_repo, raised) = open_idle_state().await;
        raised.install_idle_timeout(Some(short));
        raised.raise_idle_timeout(Duration::from_secs(3600));
        let (cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        let monitor = tokio::spawn(super::run_idle_monitor(
            Arc::clone(&raised),
            Some(short),
            4219,
            cancel_tx.clone(),
            cancel_rx,
        ));
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert!(
            !*cancel_tx.borrow(),
            "a session that raised the window to 3600s must not be shut down after 1.5s"
        );
        assert!(
            !monitor.is_finished(),
            "the monitor must still be watching, not have exited"
        );
        cancel_tx
            .send(true)
            .expect("the monitor still holds a receiver");
        monitor.await.expect("the idle monitor must not panic");
    }

    /// A daemon configured never to idle out stays that way. Nothing an
    /// attached client says may give it a finite lifetime it did not have.
    #[tokio::test]
    async fn a_daemon_that_never_idles_out_cannot_be_given_a_window() {
        let repo = tempfile::tempdir().unwrap();
        let initialized = kin_core::init(repo.path()).unwrap();
        let state = DaemonState::open(initialized.layout).unwrap();

        state.install_idle_timeout(None);
        assert_eq!(state.idle_timeout(), None);

        let raise = state.raise_idle_timeout(Duration::from_secs(1800));
        assert_eq!(raise.effective, None);
        assert_eq!(raise.effective_secs(), 0);
        assert!(!raise.raised());
        assert_eq!(state.idle_timeout(), None);
    }

    #[tokio::test]
    async fn an_endpoint_blip_cannot_shut_down_a_daemon_mid_scan() {
        // The EndpointLost branch used to return on the idle clock alone,
        // before the initialization and reconciliation gates, so a republication
        // failure could end a daemon that had never finished its first scan.
        let repo = tempfile::tempdir().unwrap();
        let initialized = kin_core::init(repo.path()).unwrap();
        let state = DaemonState::open(initialized.layout).unwrap();
        let expired = Duration::ZERO;

        state.is_initialized.store(false, Ordering::Relaxed);
        assert!(
            !super::ready_for_idle_shutdown(&state, expired, ControlPlane::EndpointLost),
            "a first scan still running must outrank a lost endpoint"
        );

        state.is_initialized.store(true, Ordering::Relaxed);
        state
            .reconciliation_status
            .store(crate::state::RECON_PROCESSING, Ordering::Relaxed);
        assert!(
            !super::ready_for_idle_shutdown(&state, expired, ControlPlane::EndpointLost),
            "reconciliation in progress must outrank a lost endpoint"
        );

        state
            .reconciliation_status
            .store(RECON_IDLE, Ordering::Relaxed);
        assert!(
            super::ready_for_idle_shutdown(&state, expired, ControlPlane::EndpointLost),
            "an unreachable daemon with no work left must still idle out"
        );
    }

    // ── Background auto-embed: announced, and opt-out-able ────────────────
    //
    // The pass starts because a store was opened, not because anyone asked for
    // it, so it needs both a line that says it started and a way to say no.
    // The default is unchanged: auto-embed stays on.

    /// Read `auto_embed_enabled` with `KIN_DAEMON_AUTO_EMBED` held at `value`
    /// (`None` removes it) for the duration of the read. The guard restores what
    /// the process had and serializes against every other env-mutating test.
    fn auto_embed_enabled_with(value: Option<&str>) -> bool {
        let _env = match value {
            Some(value) => kin_core::test_env::EnvVarGuard::set(super::AUTO_EMBED_ENV, value),
            None => kin_core::test_env::EnvVarGuard::unset(super::AUTO_EMBED_ENV),
        };
        super::auto_embed_enabled()
    }

    #[test]
    fn auto_embed_is_on_unless_an_operator_spells_out_otherwise() {
        // Absent is the shipped default and stays on.
        assert!(auto_embed_enabled_with(None));
        assert!(auto_embed_enabled_with(Some("1")));
        assert!(auto_embed_enabled_with(Some("true")));
        // The falsy set matches KIN_DAEMON_REQUIRE_TOKEN, whitespace and case
        // included, so one spelling works across the daemon's env surface.
        assert!(!auto_embed_enabled_with(Some("0")));
        assert!(!auto_embed_enabled_with(Some("false")));
        assert!(!auto_embed_enabled_with(Some("no")));
        assert!(!auto_embed_enabled_with(Some("off")));
        assert!(!auto_embed_enabled_with(Some("  OFF  ")));
        // An unparseable value is not silently read as an opt-out: the default
        // is on, and a typo must not disable embedding behind the operator.
        assert!(auto_embed_enabled_with(Some("maybe")));
        assert!(auto_embed_enabled_with(Some("")));
    }

    #[tokio::test]
    async fn background_embed_queues_by_default_and_defers_on_opt_out() {
        let repo = tempfile::tempdir().unwrap();
        let initialized = kin_core::init(repo.path()).unwrap();
        let state = DaemonState::open(initialized.layout).unwrap();

        {
            let _env = kin_core::test_env::EnvVarGuard::unset(super::AUTO_EMBED_ENV);
            assert!(
                super::start_or_defer_background_embed(&state),
                "the default must still build the backlog and start the pass"
            );
        }
        assert!(
            !state.background_embed_paused(),
            "the default must leave the worker running"
        );

        state.resume_background_embed();
        {
            let _env = kin_core::test_env::EnvVarGuard::set(super::AUTO_EMBED_ENV, "0");
            assert!(
                !super::start_or_defer_background_embed(&state),
                "an opt-out must defer the pass rather than queue it"
            );
        }
        assert!(
            state.background_embed_paused(),
            "a deferred pass must stand the worker down, so a daemon holding no \
             drainable backlog can still idle out"
        );
    }

    #[test]
    fn idle_flush_waits_for_mutation_quiet() {
        let idle = Duration::from_secs(2);
        let periodic = Duration::from_secs(30);
        // Mutations still arriving: dirty state is old but the graph is hot —
        // no flush. (The pre-fix predicate compared only `since_save`, so it
        // fired a full-graph save on every >=2s save gap mid-activity.)
        assert!(!should_flush_now(
            Duration::from_secs(10),
            Duration::from_secs(1),
            false,
            idle,
            periodic,
        ));
        // Mutation-quiet past the idle threshold: flush.
        assert!(should_flush_now(
            Duration::from_secs(10),
            Duration::from_secs(3),
            false,
            idle,
            periodic,
        ));
    }

    #[test]
    fn active_embed_pass_suppresses_both_flush_clocks() {
        let idle = Duration::from_secs(2);
        let periodic = Duration::from_secs(30);
        // A starved feed gap mid-pass looks idle; the pass marker suppresses
        // the idle flush so the gap cannot trigger a full-graph save.
        assert!(!should_flush_now(
            Duration::from_secs(10),
            Duration::from_secs(5),
            true,
            idle,
            periodic,
        ));
        // The periodic clock is ALSO suppressed during an embed pass: re-serializing
        // the full graph mid-pass re-derives only enrichment and, on large repos
        // (~955MB mui), the repeated O(graph) writes starved the feed and killed the
        // daemon. The post-pass snapshot persists the final state.
        assert!(!should_flush_now(
            Duration::from_secs(31),
            Duration::from_secs(5),
            true,
            idle,
            periodic,
        ));
        // Once the pass ends, the periodic durability bound fires as before.
        assert!(should_flush_now(
            Duration::from_secs(31),
            Duration::from_secs(5),
            false,
            idle,
            periodic,
        ));
    }

    #[test]
    fn shutdown_grace_parsing_is_robust() {
        let default = Duration::from_secs(25);
        // Absent / empty / unparseable input all fall back to the default.
        assert_eq!(parse_duration_secs(None, default), default);
        assert_eq!(parse_duration_secs(Some(""), default), default);
        assert_eq!(parse_duration_secs(Some("  "), default), default);
        assert_eq!(parse_duration_secs(Some("garbage"), default), default);
        assert_eq!(parse_duration_secs(Some("-5"), default), default);
        // Valid whole-seconds values (with surrounding whitespace) are honoured.
        assert_eq!(
            parse_duration_secs(Some("10"), default),
            Duration::from_secs(10)
        );
        assert_eq!(
            parse_duration_secs(Some("  3 "), default),
            Duration::from_secs(3)
        );
        // 0 is honoured so tests can force the watchdog to escalate immediately
        // once the shutdown signal fires.
        assert_eq!(
            parse_duration_secs(Some("0"), default),
            Duration::from_secs(0)
        );
    }

    #[test]
    fn shutdown_grace_defaults_are_sane() {
        // The escalation backstop must outlast the runtime-teardown bound so the
        // normal (block_on returns → shutdown_timeout → process::exit) path wins
        // the race in the common case; the watchdog only fires when that stalls.
        assert!(
            DEFAULT_SHUTDOWN_ESCALATION_GRACE > DEFAULT_RUNTIME_SHUTDOWN_GRACE,
            "escalation grace must exceed the runtime teardown bound"
        );
    }

    #[test]
    fn embed_error_backoff_doubles_then_caps() {
        let base = Duration::from_secs(5);
        let max = Duration::from_secs(60);

        // First failure starts from the base interval and doubles it.
        let b1 = next_embed_error_backoff(None, base, max);
        assert_eq!(b1, Duration::from_secs(10));
        // Subsequent failures keep doubling…
        let b2 = next_embed_error_backoff(Some(b1), base, max);
        assert_eq!(b2, Duration::from_secs(20));
        let b3 = next_embed_error_backoff(Some(b2), base, max);
        assert_eq!(b3, Duration::from_secs(40));
        // …until they saturate at the cap and never grow unbounded.
        let b4 = next_embed_error_backoff(Some(b3), base, max);
        assert_eq!(b4, max);
        let b5 = next_embed_error_backoff(Some(b4), base, max);
        assert_eq!(b5, max, "backoff must stay clamped at the cap");

        // The backoff is always strictly greater than the idle interval, so a
        // persistent error can never tight-spin at the 5s idle cadence.
        assert!(b1 > base);
    }

    /// Recovery from a failed background batch must precede a foreground
    /// rebuild that was already waiting on `embedding_work`.
    ///
    /// Both rendezvous channels are zero-capacity: the batch cannot report its
    /// synthetic IndexError until the foreground thread has observed real lock
    /// contention, and the foreground cannot acquire until the batch has reset
    /// under that same guard. No sleeps or scheduler timing are involved.
    #[cfg(feature = "vector")]
    #[test]
    fn background_index_recovery_precedes_already_waiting_foreground_rebuild() {
        let repo = tempfile::tempdir().unwrap();
        let initialized = kin_core::init(repo.path()).unwrap();
        let state = Arc::new(DaemonState::open(initialized.layout).unwrap());

        // Prepare one compatible sidecar for both sides of the race. Attach it
        // now as the stale index recovery must detach, then let the foreground
        // `/embed --rebuild` install it fresh after acquiring `embedding_work`.
        let descriptor = kin_db::IndexDescriptor {
            model_id: Some("foreground-rebuild-race-fixture@v1".to_string()),
            graph_root: Some(hex::encode(state.graph.compute_root_hash())),
        };
        let vectors = kin_db::VectorIndex::new(4).unwrap();
        vectors
            .upsert(kin_model::EntityId::new(), &[1.0, 0.0, 0.0, 0.0])
            .unwrap();
        vectors.set_descriptor(descriptor.clone());
        let sidecar = state.layout.root().join("foreground-rebuild-race.kvec");
        vectors.save(&sidecar).unwrap();
        assert!(matches!(
            state
                .graph
                .load_vector_index_compatible(&sidecar, &descriptor),
            kin_db::VectorIndexLoad::Loaded(1)
        ));

        let (batch_started_tx, batch_started_rx) = std::sync::mpsc::sync_channel(0);
        let (foreground_waiting_tx, foreground_waiting_rx) = std::sync::mpsc::sync_channel(0);

        let batch_state = Arc::clone(&state);
        let background = std::thread::spawn(move || {
            super::run_background_embedding_batch(&batch_state, true, move |_| {
                batch_started_tx.send(()).unwrap();
                foreground_waiting_rx.recv().unwrap();
                Err(kin_db::KinDbError::IndexError(
                    "synthetic stale background index".to_string(),
                ))
            })
        });

        batch_started_rx.recv().unwrap();
        let foreground_state = Arc::clone(&state);
        let foreground = std::thread::spawn(move || {
            let _foreground_guard = match foreground_state.embedding_work.try_lock() {
                Ok(_) => panic!("background batch must still own embedding_work"),
                Err(std::sync::TryLockError::WouldBlock) => {
                    foreground_waiting_tx.send(()).unwrap();
                    foreground_state.embedding_work.lock().unwrap()
                }
                Err(std::sync::TryLockError::Poisoned(_)) => {
                    panic!("embedding_work unexpectedly poisoned")
                }
            };

            assert!(
                foreground_state.graph.vector_index_stats().is_none(),
                "the stale background index must be reset before the waiting rebuild acquires"
            );
            assert!(matches!(
                foreground_state
                    .graph
                    .load_vector_index_compatible(&sidecar, &descriptor),
                kin_db::VectorIndexLoad::Loaded(1)
            ));
        });

        let outcome = background.join().unwrap();
        match outcome {
            super::BackgroundEmbeddingBatchOutcome::ResetAfterIndexError(error) => {
                assert!(matches!(error, kin_db::KinDbError::IndexError(_)));
            }
            other => panic!("unexpected background batch outcome: {other:?}"),
        }
        foreground.join().unwrap();

        assert_eq!(
            state.graph.vector_index_stats(),
            Some((4, 1)),
            "no stale recovery may run after the waiting foreground rebuild publishes"
        );
    }

    #[test]
    fn watched_process_liveness() {
        // The current process is obviously alive.
        assert!(watched_process_is_alive(std::process::id() as i32));

        // A child that has exited and been reaped no longer exists, so its PID
        // reads as gone (barring a near-instant PID recycle, which is not a
        // realistic risk inside this test window).
        let mut child = std::process::Command::new("true")
            .spawn()
            .expect("spawn short-lived child");
        let pid = child.id() as i32;
        child.wait().expect("reap child");
        assert!(!watched_process_is_alive(pid));
    }

    #[test]
    fn owner_watchdog_is_opt_in_and_never_derived_from_the_process_tree() {
        let self_pid = std::process::id();

        // Absent or unusable configuration must leave the watchdog disarmed.
        // This is the default for every daemon: unless a spawner explicitly
        // names an owner, nothing can self-terminate.
        assert_eq!(parse_owner_watch_pid(None, self_pid), None);
        assert_eq!(parse_owner_watch_pid(Some(""), self_pid), None);
        assert_eq!(parse_owner_watch_pid(Some("   "), self_pid), None);
        assert_eq!(parse_owner_watch_pid(Some("garbage"), self_pid), None);

        // PID 1 is the decisive rejection. Both daemon spawn paths call
        // setsid(), so a healthy persistent daemon reparents to init the moment
        // the CLI that launched it exits — ppid == 1 is the NORMAL state for a
        // legitimately detached daemon. A watchdog that accepted 1 as an owner
        // would treat "init is alive" as its liveness question and, worse, any
        // getppid()-derived wiring would arm against every daemon on the
        // machine. Ownership is only ever what the spawner states explicitly.
        assert_eq!(parse_owner_watch_pid(Some("1"), self_pid), None);

        // 0 and negatives are process-group / broadcast selectors for kill(2),
        // not owner PIDs; accepting them would make the liveness probe
        // meaningless.
        assert_eq!(parse_owner_watch_pid(Some("0"), self_pid), None);
        assert_eq!(parse_owner_watch_pid(Some("-1"), self_pid), None);

        // A self-watch can never observe a death, so it is misconfiguration
        // rather than a live watchdog.
        let self_pid_text = self_pid.to_string();
        assert_eq!(
            parse_owner_watch_pid(Some(self_pid_text.as_str()), self_pid),
            None
        );

        // A real, explicitly-stated owner arms it (whitespace tolerated).
        assert_eq!(parse_owner_watch_pid(Some("4242"), self_pid), Some(4242));
        assert_eq!(parse_owner_watch_pid(Some(" 4242 "), self_pid), Some(4242));
    }

    #[test]
    fn escalation_backstop_arms_on_the_signal_not_on_a_scheduled_task() {
        // A healthy daemon never arms the force-exit backstop.
        assert!(!shutdown_signalled(false, false, false));

        // Each source arms it on its own.
        assert!(shutdown_signalled(false, true, false));
        assert!(shutdown_signalled(true, false, false));

        // The one that matters: both in-runtime flags unset, because a
        // saturated runtime polls neither the SIGTERM future that sets `cancel`
        // nor the propagation task that writes `is_shutdown`. The OS handler
        // must arm the backstop by itself, or a stop request against a busy
        // daemon has no bound at all.
        assert!(shutdown_signalled(false, false, true));
    }

    #[test]
    fn escalation_arm_loop_fires_when_only_the_os_handler_ran() {
        // The escalation watchdog's arm loop on the real primitives: an
        // AtomicBool standing in for `state.is_shutdown`, the daemon's actual
        // cancel watch-channel, and a flag standing in for the process-global
        // one the signal handler writes.
        //
        // Neither in-runtime flag is ever written here, which is exactly what a
        // saturated runtime looks like: the SIGTERM future that would set
        // `cancel` is never polled, and the propagation task that would write
        // `is_shutdown` is never scheduled. Only the OS handler ran.
        let (_cancel_tx, cancel_rx) = tokio::sync::watch::channel(false);
        let is_shutdown = Arc::new(AtomicBool::new(false));
        let os_requested = Arc::new(AtomicBool::new(false));
        let armed = Arc::new(AtomicBool::new(false));

        let loop_is_shutdown = Arc::clone(&is_shutdown);
        let loop_os_requested = Arc::clone(&os_requested);
        let loop_armed = Arc::clone(&armed);
        std::thread::spawn(move || {
            while !shutdown_signalled(
                loop_is_shutdown.load(Ordering::Relaxed),
                *cancel_rx.borrow(),
                loop_os_requested.load(Ordering::Relaxed),
            ) {
                std::thread::sleep(Duration::from_millis(5));
            }
            loop_armed.store(true, Ordering::Relaxed);
        });

        // Nothing has signalled shutdown yet, so a healthy daemon's watchdog
        // sits disarmed rather than counting down to a force-exit.
        assert!(!armed.load(Ordering::Relaxed));

        // Exactly what the signal handler does, and only that: one relaxed
        // store. No tokio task runs in this test at all.
        os_requested.store(true, Ordering::Relaxed);

        // Bounded wait rather than join(): a regression here must fail the test,
        // not hang CI until the job timeout.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !armed.load(Ordering::Relaxed) && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }

        assert!(
            armed.load(Ordering::Relaxed),
            "the OS handler alone must arm the force-exit backstop; keying it \
             only on flags written from inside the runtime made the \
             saturated-runtime backstop depend on that runtime"
        );
        assert!(
            !is_shutdown.load(Ordering::Relaxed),
            "is_shutdown was never set — the backstop must not depend on it"
        );
    }

    #[test]
    fn pipeline_overlap_off_by_default() {
        // The deterministic serial persist path is the default; only the
        // throughput profile opts into overlap (wired in the daemon binary).
        assert!(!DaemonConfig::default().embed_pipeline_overlap);
    }

    // ── A contended start must name what it lost to ───────────────────────
    //
    // The old refusal said "another kin daemon already owns this repo" and
    // exited 0, so the CLI reported only "daemon exited during startup" and the
    // operator had no way to tell a live holder from a leaked lock fd.

    #[test]
    fn contention_message_names_a_live_holder_and_how_to_clear_it() {
        let message = format_singleton_contention(
            "/repo/.kin",
            Some(crate::lifecycle::SingletonLockHolder {
                pid: 4242,
                alive: true,
                identity_verified: true,
            }),
            &crate::lifecycle::StaleLockReclaim::OwnerAlive(4242),
        );
        assert!(message.contains("4242"), "must name the holder: {message}");
        assert!(
            message.contains("/repo/.kin"),
            "must name the repo: {message}"
        );
        assert!(
            message.contains("kin daemon stop"),
            "must give the operator an action: {message}"
        );
    }

    #[test]
    fn contention_message_distinguishes_a_dead_owner_from_an_unidentified_one() {
        let leaked = format_singleton_contention(
            "/repo/.kin",
            Some(crate::lifecycle::SingletonLockHolder {
                pid: 4242,
                alive: false,
                identity_verified: false,
            }),
            &crate::lifecycle::StaleLockReclaim::Cleared(vec![std::path::PathBuf::from(
                "/repo/.kin/daemon.lock",
            )]),
        );
        assert!(
            leaked.contains("leaked lock fd"),
            "a dead recorded owner is a leaked fd, not a running daemon: {leaked}"
        );
        assert!(
            leaked.contains("reclaimed 1 stale lock"),
            "the reclaim that already ran must be reported: {leaked}"
        );

        let unknown = format_singleton_contention(
            "/repo/.kin",
            None,
            &crate::lifecycle::StaleLockReclaim::OwnerUnknown,
        );
        assert!(
            unknown.contains("names no owner"),
            "an unidentifiable holder must be described as such, not guessed at: {unknown}"
        );

        let compatibility_boundary = format_singleton_contention(
            "/repo/.kin",
            Some(crate::lifecycle::SingletonLockHolder {
                pid: 4242,
                alive: false,
                identity_verified: false,
            }),
            &crate::lifecycle::StaleLockReclaim::CoordinationUnavailable(
                "recorded owner pid 4242 is dead, but compatible older daemons do not participate"
                    .to_string(),
            ),
        );
        assert!(
            compatibility_boundary.contains("Automatic lock-file retirement was refused"),
            "the refusal must disclose the unsupported mixed-version boundary: \
             {compatibility_boundary}"
        );
        assert!(
            compatibility_boundary.contains("cannot be proven safe"),
            "the message must not claim exclusion it cannot enforce: {compatibility_boundary}"
        );
    }

    #[test]
    fn an_identity_verified_dead_owner_does_not_vouch_for_whoever_holds_its_pid_now() {
        let message = format_singleton_contention(
            "/repo/.kin",
            Some(crate::lifecycle::SingletonLockHolder {
                pid: 4242,
                alive: false,
                identity_verified: true,
            }),
            &crate::lifecycle::StaleLockReclaim::OwnerUnknown,
        );
        assert!(
            message.contains("may since have been reused"),
            "a verified-dead owner must not leave the operator believing pid 4242 is still the \
             daemon: {message}"
        );
    }

    // The embed worker keeps at most one flush in flight and always awaits it
    // before scheduling the next. Modeling that bookkeeping with the real
    // `drain_pending_flush` helper proves two flushes can never run at once,
    // regardless of how long any single persist takes — the stable persisted
    // vector order depends on flushes never interleaving.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn pipelined_flushes_never_interleave() {
        let concurrent = Arc::new(AtomicUsize::new(0));
        let peak = Arc::new(AtomicUsize::new(0));
        let completed = Arc::new(AtomicUsize::new(0));

        let mut pending: Option<tokio::task::JoinHandle<super::Result<usize>>> = None;
        const BATCHES: usize = 8;
        for _ in 0..BATCHES {
            // Serialize the previous flush before scheduling the next, exactly as
            // the drain loop does between successful batches.
            drain_pending_flush(&mut pending).await;
            let concurrent = Arc::clone(&concurrent);
            let peak = Arc::clone(&peak);
            let completed = Arc::clone(&completed);
            pending = Some(tokio::task::spawn_blocking(move || {
                let now = concurrent.fetch_add(1, Ordering::SeqCst) + 1;
                peak.fetch_max(now, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(5));
                concurrent.fetch_sub(1, Ordering::SeqCst);
                completed.fetch_add(1, Ordering::SeqCst);
                Ok(0)
            }));
        }
        // The tail flush must always be drained at loop exit.
        drain_pending_flush(&mut pending).await;

        assert!(pending.is_none(), "tail flush must be cleared on drain");
        assert_eq!(completed.load(Ordering::SeqCst), BATCHES, "every flush ran");
        assert_eq!(
            peak.load(Ordering::SeqCst),
            1,
            "at most one flush may run at a time"
        );
    }

    // The point of the lever: when a flush is left in flight (throughput
    // profile), the next batch's prep + GPU forward proceeds concurrently
    // instead of blocking on the persist. The flush parks until the "next
    // batch" signals it has started; if the loop had instead drained the flush
    // before running the next batch, this would deadlock — the timeout guards
    // against that regression.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn in_flight_flush_overlaps_next_batch() {
        let flush_started = Arc::new(AtomicBool::new(false));
        let next_batch_started = Arc::new(AtomicBool::new(false));

        let flush_started_w = Arc::clone(&flush_started);
        let next_batch_started_r = Arc::clone(&next_batch_started);
        let mut pending: Option<tokio::task::JoinHandle<super::Result<usize>>> =
            Some(tokio::task::spawn_blocking(move || {
                flush_started_w.store(true, Ordering::SeqCst);
                // Hold the "persist" open until the next batch is underway.
                while !next_batch_started_r.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Ok(0)
            }));

        // The next batch runs WITHOUT first draining the in-flight flush.
        let overlap = tokio::time::timeout(Duration::from_secs(5), async {
            while !flush_started.load(Ordering::SeqCst) {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
            next_batch_started.store(true, Ordering::SeqCst);
        })
        .await;
        assert!(
            overlap.is_ok(),
            "next batch must make progress while a flush is in flight"
        );

        drain_pending_flush(&mut pending).await;
        assert!(pending.is_none());
    }
}

#[cfg(test)]
mod enrichment_marker_tests {
    use super::{file_already_enriched, load_lsp_enriched_marker, lsp_enriched_marker_path};
    use crate::state::DaemonState;
    use kin_model::EntityStore;

    fn entity(name: &str) -> kin_model::Entity {
        kin_model::Entity {
            id: kin_model::EntityId::new(),
            kind: kin_model::EntityKind::Function,
            name: name.to_string(),
            language: kin_model::LanguageId::Python,
            fingerprint: kin_model::SemanticFingerprint {
                algorithm: kin_model::FingerprintAlgorithm::V1TreeSitter,
                ast_hash: kin_model::Hash256::from_bytes([1; 32]),
                signature_hash: kin_model::Hash256::from_bytes([2; 32]),
                behavior_hash: kin_model::Hash256::from_bytes([3; 32]),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(kin_model::FilePathId::new("src/sessions.py")),
            span: None,
            signature: format!("def {name}()"),
            visibility: kin_model::Visibility::Public,
            role: kin_model::EntityRole::Source,
            doc_summary: None,
            metadata: kin_model::EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn install_language_server_relation(state: &DaemonState) {
        let src = entity("send");
        let dst = entity("adapter_send");
        state.graph.upsert_entity(&src).unwrap();
        state.graph.upsert_entity(&dst).unwrap();
        state
            .graph
            .upsert_relation(&kin_model::Relation {
                id: kin_model::RelationId::new(),
                kind: kin_model::RelationKind::Calls,
                src: kin_model::GraphNodeId::Entity(src.id),
                dst: kin_model::GraphNodeId::Entity(dst.id),
                confidence: 1.0,
                origin: kin_model::RelationOrigin::Lsp,
                created_in: None,
                import_source: None,
                evidence: Vec::new(),
            })
            .unwrap();
    }

    fn write_marker(state: &DaemonState, files: &[&str]) {
        std::fs::write(
            lsp_enriched_marker_path(state),
            serde_json::to_vec(&files.iter().map(|f| f.to_string()).collect::<Vec<_>>()).unwrap(),
        )
        .unwrap();
    }

    /// A marker whose relations are gone must not keep the loss permanent.
    ///
    /// This is what made the persistence defect unrecoverable rather than
    /// merely wasteful: the sweep recorded every file it finished, the
    /// relations did not survive the process, and each later daemon skipped the
    /// same files and re-derived nothing.
    #[test]
    fn a_marker_without_its_relations_is_discarded() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = DaemonState::open(init.layout).unwrap();
        write_marker(&state, &["src/sessions.py"]);

        load_lsp_enriched_marker(&state);

        assert!(
            !file_already_enriched(&state, "src/sessions.py"),
            "a marker the graph cannot corroborate must not skip the file it names"
        );
        load_lsp_enriched_marker(&state);
        assert!(
            !file_already_enriched(&state, "src/sessions.py"),
            "and it stays unhonored while the graph still cannot corroborate it, so the \
             judgment does not depend on having deleted the file"
        );
    }

    /// The other direction, so the reset is not simply "always re-sweep".
    #[test]
    fn a_marker_backed_by_relations_is_honored() {
        let repo_dir = tempfile::tempdir().unwrap();
        let init = kin_core::init(repo_dir.path()).unwrap();
        let state = DaemonState::open(init.layout).unwrap();
        install_language_server_relation(&state);
        write_marker(&state, &["src/sessions.py"]);

        load_lsp_enriched_marker(&state);

        assert!(
            file_already_enriched(&state, "src/sessions.py"),
            "a graph that still holds language-server relations resumes rather than re-sweeping"
        );
        assert!(lsp_enriched_marker_path(&state).exists());
    }
}

#[cfg(test)]
mod lsp_query_column_tests {
    use super::lsp_query_column;

    /// The express case, which is what this exists for.
    ///
    /// `app.handle` at `lib/application.js` has the signature below, so the old
    /// `signature.find(name)` returned 0 and the query landed on `app`. The
    /// language server then answered about the receiver and the walk counted
    /// `app.set`, `res.send` and `res.redirect` as callees of `app.handle`.
    #[test]
    fn a_dotted_name_is_queried_at_its_final_segment() {
        assert_eq!(
            lsp_query_column("app.handle = function handle(", "app.handle", 0),
            4,
            "the cursor belongs on `handle`, not on the `app` receiver"
        );
    }

    /// The declaration's own column still offsets the result.
    #[test]
    fn the_declaration_column_is_carried_through() {
        assert_eq!(
            lsp_query_column("app.handle = function handle(", "app.handle", 6),
            10
        );
    }

    /// An undotted name keeps exactly the behavior it had.
    #[test]
    fn a_plain_name_is_unchanged() {
        assert_eq!(lsp_query_column("function handle(", "handle", 0), 9);
        assert_eq!(lsp_query_column("def send(self):", "send", 4), 8);
    }

    /// A deeper receiver chain still resolves to the last segment.
    #[test]
    fn only_the_final_segment_is_addressed() {
        assert_eq!(
            lsp_query_column("this.router.handle = fn", "this.router.handle", 0),
            12
        );
    }

    /// When the signature does not spell the dotted name out, the segment is
    /// still preferred over the declaration start, because the declaration
    /// start is the receiver again whenever the receiver opens the line.
    #[test]
    fn an_unspelled_dotted_name_falls_back_to_its_segment() {
        assert_eq!(
            lsp_query_column("exports.handle = function handle(", "app.handle", 0),
            8
        );
    }

    /// And a name the signature does not carry at all keeps the old answer
    /// rather than inventing a position.
    #[test]
    fn a_name_absent_from_the_signature_keeps_the_declaration_column() {
        assert_eq!(lsp_query_column("const x = 1", "handle", 3), 3);
    }
}
