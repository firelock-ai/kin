// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Self-limiting background work.
//!
//! The only Kin process on an end user's machine is the daemon, and the work it
//! starts on its own initiative — embedding, reconciling, rebuilding derived
//! indexes — runs with nobody watching. A pass that wedges therefore spends that
//! machine indefinitely and the sole evidence is a warm fan. This module is the
//! product-side answer: every background pass reports persisted progress to a
//! supervisor, and a pass that holds the CPU without advancing that count is
//! stopped and said out loud.
//!
//! Liveness keys on the persisted-progress delta and never on CPU utilization. A
//! busy-spin pegs a core while achieving nothing, so utilization cannot tell a
//! working pass from a wedged one, and a counter that moves only when work is
//! durably recorded can.
//!
//! Three properties are load-bearing and each exists because its absence makes
//! the mechanism silently useless:
//!
//! - **Idle is never stalled.** A pass with nothing to do reports no progress by
//!   definition. Only a pass that has declared itself working is a candidate, so
//!   a quiet daemon is never stopped for being quiet.
//! - **The working mark latches.** [`BackgroundPass::working`] sets the start of
//!   a working stretch only when the pass was not already working. A per-iteration
//!   reset would restart the clock on every turn of the very loop that is wedged,
//!   and the stall could never be observed.
//! - **Stopping is cooperative.** The supervisor raises a flag the pass reads at
//!   its own checkpoint, exactly as trace cancellation does. Nothing is killed
//!   mid-write, and a pass holding a lock releases it on its own terms.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};
use std::time::{Duration, Instant};

use kin_cli::commands::resources::{BackgroundPassReport, DaemonWorkState, ReconcileHealth};

/// The background embedding worker.
pub const PASS_EMBED: &str = "embed";
/// The filesystem reconciliation loop.
pub const PASS_RECONCILE: &str = "reconcile";
/// The LSP enrichment worker.
pub const PASS_LSP: &str = "lsp_enrichment";
/// The startup projection rebuild. Disclosed only; see [`PassEnforcement`].
pub const PASS_PROJECTION: &str = "projection_rebuild";

/// Whether the supervisor may stop a pass, or only report on it.
///
/// Stopping is cooperative: the supervisor raises a flag and the pass reads it at
/// its own checkpoint. A pass with no checkpoint therefore cannot be stopped, and
/// halting one anyway would publish a `stopped` state and a reason for work that
/// is still running. A watchdog that reports a stop it did not perform is worse
/// than one that reports nothing, so the distinction is in the type rather than
/// left to whoever registers next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PassEnforcement {
    /// The pass polls [`BackgroundPass::halted`] and will stop when told.
    Stoppable,
    /// The pass has nowhere to observe a halt. It is disclosed — working
    /// stretch, progress age, CPU — and never claimed to have been stopped.
    DiscloseOnly,
}

/// How long a pass may hold the CPU with no persisted progress before the daemon
/// stops it.
///
/// Generous on purpose. The cost of stopping a healthy pass is lost work a user
/// asked for; the cost of waiting is ten more minutes of a fan. A pass that has
/// been working continuously for this long and has recorded nothing durable in
/// that whole stretch is not slow, it is stuck.
pub const DEFAULT_STALL_THRESHOLD: Duration = Duration::from_secs(600);

/// How much cumulative delay a retry ladder may spend before the work it is
/// retrying is parked with an announced reason.
///
/// Backoff alone bounds the rate of a retry loop and not its lifetime, so a
/// failure that never clears retries forever at the backoff ceiling. This is the
/// lifetime bound.
pub const DEFAULT_RETRY_BUDGET: Duration = Duration::from_secs(1800);

/// How often the supervisor evaluates every registered pass.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// Read a duration from the environment in seconds, falling back to `default`.
///
/// An explicit `0` disables the limit rather than meaning "immediately", because
/// a limit whose off-switch is also its most aggressive setting is a trap.
fn duration_from_env_secs(key: &str, default: Duration) -> Duration {
    match std::env::var(key) {
        Ok(raw) => match raw.trim().parse::<u64>() {
            Ok(secs) => Duration::from_secs(secs),
            Err(_) => default,
        },
        Err(_) => default,
    }
}

/// The configured stall threshold; `KIN_DAEMON_PASS_STALL_SECS` overrides it and
/// `0` disables stopping entirely.
pub fn configured_stall_threshold() -> Duration {
    duration_from_env_secs("KIN_DAEMON_PASS_STALL_SECS", DEFAULT_STALL_THRESHOLD)
}

/// The configured cumulative retry budget; `KIN_DAEMON_PASS_RETRY_BUDGET_SECS`
/// overrides it and `0` disables parking entirely.
pub fn configured_retry_budget() -> Duration {
    duration_from_env_secs("KIN_DAEMON_PASS_RETRY_BUDGET_SECS", DEFAULT_RETRY_BUDGET)
}

/// One background pass, and everything the supervisor knows about it.
#[derive(Debug)]
pub struct BackgroundPass {
    name: &'static str,
    enforcement: PassEnforcement,
    /// Mirrors `inner.halt.is_some()` so a pass can poll its own checkpoint
    /// without taking the lock. Published after the reason, so a reader that
    /// observes `true` always finds a reason behind it.
    halted: AtomicBool,
    inner: Mutex<PassInner>,
}

#[derive(Debug)]
struct PassInner {
    /// Units of work this pass has durably recorded. Monotonic for the life of
    /// the process, so a delta over any window is meaningful.
    progress: u64,
    /// When `progress` last advanced; `None` until it first does.
    progress_at: Option<Instant>,
    /// Start of the current uninterrupted working stretch; `None` while idle.
    working_since: Option<Instant>,
    /// Start of the current stretch with deferred work owed; `None` when the
    /// pass's retry queue is empty.
    ///
    /// Deliberately independent of `working_since`. A retry ladder that keeps
    /// widening leaves the pass alternating between working on other paths and
    /// having nothing it may admit, so tying this clock to pass activity would
    /// reset it on exactly the ticks a livelock produces.
    deferred_since: Option<Instant>,
    /// Why this pass stopped, once it has.
    halt: Option<String>,
    /// Cumulative delay charged to the retry ladder since the last success.
    retry_spent: Duration,
}

impl BackgroundPass {
    fn new(name: &'static str, enforcement: PassEnforcement) -> Self {
        Self {
            name,
            enforcement,
            halted: AtomicBool::new(false),
            inner: Mutex::new(PassInner {
                progress: 0,
                progress_at: None,
                working_since: None,
                deferred_since: None,
                halt: None,
                retry_spent: Duration::ZERO,
            }),
        }
    }

    /// Whether the supervisor may stop this pass or only report on it.
    pub fn enforcement(&self) -> PassEnforcement {
        self.enforcement
    }

    /// A poisoned lock must not disarm the watchdog. A panic elsewhere in the
    /// daemon is precisely when unattended work is most likely to be wedged, so
    /// the guard is recovered rather than propagated.
    fn lock(&self) -> std::sync::MutexGuard<'_, PassInner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Declare that this pass is consuming CPU.
    ///
    /// Idempotent while already working: the start of the stretch is latched on
    /// the first call and left alone afterwards. Calling this once per loop turn
    /// is the intended usage, and it is correct precisely because repeat calls do
    /// not restart the clock.
    pub fn working(&self, now: Instant) {
        let mut inner = self.lock();
        if inner.working_since.is_none() {
            inner.working_since = Some(now);
        }
    }

    /// Declare that this pass has nothing to do.
    ///
    /// Ends the working stretch, so the next [`working`](Self::working) starts a
    /// fresh one. Call it wherever the pass genuinely has no work — a drained
    /// queue, an empty event batch — and nowhere else: an `idle` on a path the
    /// wedged loop still reaches would clear the very stretch being measured.
    pub fn idle(&self) {
        self.lock().working_since = None;
    }

    /// Record whether deferred work is still owed to this pass, and since when.
    ///
    /// Call it once per loop turn with the pass's own answer to "is my retry
    /// queue non-empty", including on the turns that find nothing to do. That is
    /// what separates the two ways a pass can have no admittable work: a drained
    /// queue is [`idle`](Self::idle), and a queue whose entries are all waiting
    /// out a retry ladder is `waiting_deferred`.
    ///
    /// The distinction exists because the reconcile loop reports itself idle on
    /// every tick of a ladder wait. A path that never stabilizes keeps the loop
    /// deferring and re-deferring forever while each individual tick truthfully
    /// finds nothing it may admit, so the pass reads as idle throughout a
    /// livelock that is spending real CPU.
    ///
    /// This deliberately does not feed the stall watchdog. Holding the working
    /// stretch open across ladder waits would make any flapping file eventually
    /// halt the loop, which is a worse failure than the blind spot. The livelock
    /// becomes visible as a state and an age instead of as a stop.
    pub fn set_deferred(&self, owed: bool, now: Instant) {
        let mut inner = self.lock();
        if owed {
            if inner.deferred_since.is_none() {
                inner.deferred_since = Some(now);
            }
        } else {
            inner.deferred_since = None;
        }
    }

    /// Record `units` of newly persisted work.
    ///
    /// Advancing by zero is not progress and is ignored, so a pass that reports
    /// every completed batch — including empty ones — cannot keep itself alive
    /// with them.
    pub fn advanced(&self, units: u64, now: Instant) {
        if units == 0 {
            return;
        }
        let mut inner = self.lock();
        inner.progress = inner.progress.saturating_add(units);
        inner.progress_at = Some(now);
    }

    /// Whether this pass has been stopped and should wind itself down.
    ///
    /// Polled by the pass at its own checkpoint. Nothing else enforces the stop:
    /// a pass that never checks keeps running, which is why every instrumented
    /// loop checks alongside its shutdown signal.
    pub fn halted(&self) -> bool {
        self.halted.load(Ordering::Relaxed)
    }

    /// Why this pass stopped, if it has.
    pub fn halt_reason(&self) -> Option<String> {
        self.lock().halt.clone()
    }

    /// Stop this pass with an announced reason. The first reason wins, so a pass
    /// that notices the supervisor's verdict and parks itself does not overwrite
    /// the account of why it was stopped.
    pub fn halt(&self, reason: impl Into<String>) {
        let mut inner = self.lock();
        if inner.halt.is_some() {
            return;
        }
        inner.halt = Some(reason.into());
        inner.working_since = None;
        drop(inner);
        self.halted.store(true, Ordering::Relaxed);
    }

    /// Charge `delay` against this pass's cumulative retry budget.
    ///
    /// Returns `true` while the ladder may keep retrying. On exhaustion the pass
    /// is parked with a reason naming what was being retried, so the work stops
    /// visibly instead of retrying until the process is killed. A zero budget
    /// disables the limit.
    pub fn charge_retry(&self, delay: Duration, budget: Duration, retrying: &str) -> bool {
        let spent = {
            let mut inner = self.lock();
            inner.retry_spent = inner.retry_spent.saturating_add(delay);
            inner.retry_spent
        };
        if budget.is_zero() || spent < budget {
            return true;
        }
        self.halt(format!(
            "{retrying} kept failing for {}s of cumulative retry backoff and was parked; \
             the daemon keeps serving and a restart retries it",
            spent.as_secs()
        ));
        false
    }

    /// Clear the retry ladder after a success, so an intermittent failure never
    /// accumulates across healthy stretches into a park.
    pub fn reset_retries(&self) {
        self.lock().retry_spent = Duration::ZERO;
    }

    /// Cumulative retry delay charged since the last success.
    pub fn retry_spent(&self) -> Duration {
        self.lock().retry_spent
    }

    /// Units of work durably recorded so far.
    pub fn progress(&self) -> u64 {
        self.lock().progress
    }

    /// This pass's park, with the readings the verdict was reached on, or
    /// `None` while it is running.
    ///
    /// Read under one lock so the reason and the counts beside it describe the
    /// same instant. `stall_threshold` travels with them because a park is only
    /// legible against the limit it was measured by.
    fn parked_report(
        &self,
        now: Instant,
        stall_threshold: Duration,
    ) -> Option<kin_cli::commands::resources::ReconcileParked> {
        let inner = self.lock();
        let reason = inner.halt.clone()?;
        Some(kin_cli::commands::resources::ReconcileParked {
            reason,
            progress: inner.progress,
            working_seconds: inner
                .working_since
                .map(|since| now.saturating_duration_since(since).as_secs()),
            progress_age_seconds: inner
                .progress_at
                .map(|at| now.saturating_duration_since(at).as_secs()),
            deferred_seconds: inner
                .deferred_since
                .map(|since| now.saturating_duration_since(since).as_secs()),
            stall_threshold_seconds: stall_threshold.as_secs(),
        })
    }

    fn report(&self, now: Instant) -> BackgroundPassReport {
        let inner = self.lock();
        // `working` outranks `waiting_deferred`: a pass burning CPU on this tick
        // is described by that, not by the queue it also owes. `waiting_deferred`
        // outranks `idle`, which is the whole correction: a pass waiting out a
        // ladder is not a pass with nothing to do.
        let state = if inner.halt.is_some() {
            "stopped"
        } else if inner.working_since.is_some() {
            "working"
        } else if inner.deferred_since.is_some() {
            "waiting_deferred"
        } else {
            "idle"
        };
        BackgroundPassReport {
            name: self.name.to_string(),
            state: state.to_string(),
            progress: inner.progress,
            progress_age_seconds: inner
                .progress_at
                .map(|at| now.saturating_duration_since(at).as_secs()),
            working_seconds: inner
                .working_since
                .map(|since| now.saturating_duration_since(since).as_secs()),
            deferred_seconds: inner
                .deferred_since
                .map(|since| now.saturating_duration_since(since).as_secs()),
            stopped_reason: inner.halt.clone(),
        }
    }
}

/// Whether a pass should be stopped at this sweep.
///
/// Total and pure so both directions can be tested against each other with every
/// other input held equal: a wedged pass must be stopped, and a pass reporting
/// progress must not be. A one-sided test would pass for a predicate that stops
/// everything.
///
/// Both conditions are required. Working long enough alone would stop a pass that
/// is advancing steadily through a large backlog, and a stale progress timestamp
/// alone would stop a pass that has just started working after an idle stretch.
fn is_stalled(
    working_for: Option<Duration>,
    since_progress: Option<Duration>,
    threshold: Duration,
) -> bool {
    if threshold.is_zero() {
        return false;
    }
    let Some(working_for) = working_for else {
        return false;
    };
    if working_for < threshold {
        return false;
    }
    // A pass that has never recorded progress is judged from when it started
    // working, not from process start: it has had exactly this stretch to
    // produce something.
    since_progress.unwrap_or(working_for) >= threshold
}

/// Watches every background pass the daemon runs and stops the ones that are
/// spending the machine without advancing.
#[derive(Debug)]
pub struct BackgroundWorkSupervisor {
    stall_threshold: Duration,
    passes: RwLock<BTreeMap<&'static str, Arc<BackgroundPass>>>,
    /// Cumulative process CPU time in milliseconds, sampled by the sweep. Read
    /// by `/health`, which must stay cheap enough to poll.
    cpu_millis: AtomicU64,
    cpu_sampled: AtomicBool,
    /// What the reconcile loop admitted, dropped, and last failed at.
    ///
    /// Held here rather than filled in by whoever assembles a report, because a
    /// surface that forgets to attach it publishes a default — no failures, no
    /// dropped events — which is indistinguishable from a healthy loop and is
    /// the exact false all-clear these probes exist to end. Owned by the
    /// supervisor, every disclosure it builds carries them.
    reconcile: ReconcileProbes,
}

impl Default for BackgroundWorkSupervisor {
    fn default() -> Self {
        Self::new(configured_stall_threshold())
    }
}

impl BackgroundWorkSupervisor {
    pub fn new(stall_threshold: Duration) -> Self {
        Self {
            stall_threshold,
            passes: RwLock::new(BTreeMap::new()),
            cpu_millis: AtomicU64::new(0),
            cpu_sampled: AtomicBool::new(false),
            reconcile: ReconcileProbes::default(),
        }
    }

    /// The reconcile loop's probe handle, for the loop to record into.
    pub fn reconcile(&self) -> &ReconcileProbes {
        &self.reconcile
    }

    /// The reconcile loop's complete account of itself, park included.
    ///
    /// The probes know what the loop admitted and dropped; only the supervisor
    /// knows whether it stopped the pass. Assembled here rather than by each
    /// surface, because a surface that reads the probes alone publishes a
    /// parked loop as an ordinary quiet one, and the status string beside it
    /// says `parked-by-supervisor` with nothing to explain it. Every disclosure
    /// this daemon builds goes through here.
    pub fn reconcile_report(&self, now: Instant) -> ReconcileHealth {
        let mut report = self.reconcile.report(now);
        report.parked = self
            .registered(PASS_RECONCILE)
            .and_then(|pass| pass.parked_report(now, self.stall_threshold));
        report
    }

    fn passes(
        &self,
    ) -> std::sync::RwLockReadGuard<'_, BTreeMap<&'static str, Arc<BackgroundPass>>> {
        self.passes.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// The handle for `name`, registering it on first use.
    ///
    /// Registration is lazy so a pass that a build never spawns — the embedding
    /// worker without its feature, the reconcile loop on a bare repository —
    /// never appears in the report claiming to be idle when it does not exist.
    pub fn pass(&self, name: &'static str) -> Arc<BackgroundPass> {
        self.register(name, PassEnforcement::Stoppable)
    }

    /// The handle for a pass the supervisor may report on but never stop.
    ///
    /// For work with no checkpoint between start and finish. It still answers
    /// "why is my fan on" through its working stretch and progress age, which is
    /// the disclosure the product owes; what it does not do is claim a stop that
    /// could not happen.
    pub fn disclosed_pass(&self, name: &'static str) -> Arc<BackgroundPass> {
        self.register(name, PassEnforcement::DiscloseOnly)
    }

    fn register(&self, name: &'static str, enforcement: PassEnforcement) -> Arc<BackgroundPass> {
        if let Some(pass) = self.passes().get(name) {
            return Arc::clone(pass);
        }
        let mut passes = self.passes.write().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(
            passes
                .entry(name)
                .or_insert_with(|| Arc::new(BackgroundPass::new(name, enforcement))),
        )
    }

    /// An already-registered pass, without registering one.
    pub fn registered(&self, name: &str) -> Option<Arc<BackgroundPass>> {
        self.passes().get(name).map(Arc::clone)
    }

    pub fn stall_threshold(&self) -> Duration {
        self.stall_threshold
    }

    /// Evaluate every pass and stop the stalled ones. Returns the halt reason of
    /// each pass stopped by this sweep, for logging.
    pub fn sweep(&self, now: Instant) -> Vec<String> {
        let passes: Vec<Arc<BackgroundPass>> = self.passes().values().map(Arc::clone).collect();
        let mut stopped = Vec::new();
        for pass in passes {
            let (working_for, since_progress, progress, already_halted) = {
                let inner = pass.lock();
                (
                    inner
                        .working_since
                        .map(|since| now.saturating_duration_since(since)),
                    inner
                        .progress_at
                        .map(|at| now.saturating_duration_since(at)),
                    inner.progress,
                    inner.halt.is_some(),
                )
            };
            if already_halted {
                continue;
            }
            if !is_stalled(working_for, since_progress, self.stall_threshold) {
                continue;
            }
            // A pass with no checkpoint cannot honour a halt, so raising one
            // would publish `stopped` for work that is still running. It stays
            // disclosed — its working stretch and progress age keep climbing
            // where a user can see them — and is not announced as stopped.
            if pass.enforcement() == PassEnforcement::DiscloseOnly {
                continue;
            }
            let working_for = working_for.unwrap_or_default();
            let reason = format!(
                "the {} pass held the CPU for {}s without recording any progress \
                 (still at {progress} units) and was stopped; the daemon keeps serving and a \
                 restart retries it",
                pass.name(),
                working_for.as_secs(),
            );
            pass.halt(reason.clone());
            stopped.push(reason);
        }
        stopped
    }

    /// Sample this process's cumulative CPU time.
    ///
    /// Sampled on the sweep rather than on each `/health` read: the answer moves
    /// slowly, a process refresh is not free, and a health endpoint that got
    /// more expensive the more it was polled would be its own runaway.
    ///
    /// The PID comes from `sysinfo::get_current_pid` rather than from the
    /// standard library. Both name this process, but the zero-file-search guard
    /// reads any `process::` path as a subprocess launch in an answer path, and
    /// the crate's own accessor states the intent without arguing with a guard
    /// that is right to be blunt. A platform that cannot report its own PID
    /// leaves the total unsampled, which reads as absent rather than as zero.
    pub fn sample_process_cpu(&self) {
        let Ok(pid) = sysinfo::get_current_pid() else {
            return;
        };
        let mut system = sysinfo::System::new();
        system.refresh_processes_specifics(
            sysinfo::ProcessesToUpdate::Some(&[pid]),
            true,
            sysinfo::ProcessRefreshKind::nothing().with_cpu(),
        );
        if let Some(process) = system.process(pid) {
            self.cpu_millis
                .store(process.accumulated_cpu_time(), Ordering::Relaxed);
            self.cpu_sampled.store(true, Ordering::Relaxed);
        }
    }

    /// Cumulative CPU seconds this daemon has spent, or `None` before the first
    /// sample. Reported rather than inferred: an absent value says the daemon
    /// does not know, which is not the same as zero.
    pub fn daemon_cpu_seconds(&self) -> Option<f64> {
        if !self.cpu_sampled.load(Ordering::Relaxed) {
            return None;
        }
        Some(self.cpu_millis.load(Ordering::Relaxed) as f64 / 1000.0)
    }

    /// Per-pass state for the disclosure surfaces.
    pub fn reports(&self, now: Instant) -> Vec<BackgroundPassReport> {
        self.passes()
            .values()
            .map(|pass| pass.report(now))
            .collect()
    }

    /// Whether any pass has been stopped. Drives the `attention` health status.
    pub fn any_stopped(&self) -> bool {
        self.passes().values().any(|pass| pass.halted())
    }

    /// The complete disclosure: cumulative CPU and every pass's progress age.
    pub fn work_state(&self, now: Instant) -> DaemonWorkState {
        DaemonWorkState {
            daemon_cpu_seconds: self.daemon_cpu_seconds(),
            // The supervisor watches background passes; the authority cache is
            // not one, so the caller that can see both fills this in.
            authority_loads: None,
            passes: self.reports(now),
            reconcile: self.reconcile_report(now),
        }
    }

    /// Whether the reconcile loop's own account of itself is degraded. Drives
    /// the `attention` health status beside `any_stopped`.
    pub fn reconcile_degraded(&self, now: Instant) -> bool {
        self.reconcile_report(now).degraded()
    }
}

/// One recorded fault: what failed, when it failed on the monotonic clock, and
/// when it failed on the wall clock.
///
/// Both clocks are kept because they answer different questions. The age a
/// surface reports has to come from the monotonic mark, or a clock adjustment
/// makes a fresh failure look hours old. The wall-clock stamp is what lines the
/// same failure up against a log or another machine's account of the incident,
/// and it cannot be derived from the monotonic one after the fact.
#[derive(Debug, Clone)]
struct RecordedFault {
    message: String,
    at: Instant,
    wall_clock: chrono::DateTime<chrono::Utc>,
}

impl RecordedFault {
    fn new(message: impl Into<String>, now: Instant) -> Self {
        Self {
            message: message.into(),
            at: now,
            wall_clock: chrono::Utc::now(),
        }
    }
}

/// Persist the durable last-admission marker after a complete pass succeeded.
///
/// Called beside [`ReconcileProbes::record_admission_success`] rather than from
/// inside it, for two reasons. The probes hold a mutex while they record, and
/// doing file I/O under it would put a disk write on a lock every admission
/// waits behind. And the probes deliberately know nothing about the store's
/// layout, which keeps them a pure in-memory disclosure.
///
/// The write itself is `kin_core::last_admission::record`, which every complete
/// admission in the product goes through, daemon and conversion alike. This
/// remains as the daemon's own entry point so the three call sites here keep
/// naming the probes and the marker together, and so the reason for the split
/// above stays beside them.
pub fn record_durable_admission(layout: &kin_core::KinLayout, tracked_artifacts: u64) {
    kin_core::last_admission::record(layout, tracked_artifacts);
}

/// Persist the relation-kind census of `graph` for this store.
///
/// Called where the relation set was just settled: at the end of a completed
/// enrichment sweep, and at the end of a commit that installed its change in
/// the live graph. Those are the moments a process both changed the relations
/// and knows it finished, which is what makes the record interpretable as a
/// baseline rather than as a sample taken mid-flight.
///
/// Never called from a read path. `kin graph status` reads this record and does
/// not write it: a census stamped on every reading would compare each reading
/// against the one before it, so a store that lost a whole relation kind would
/// announce the loss once and then report itself clean forever, which is a
/// quieter version of the defect this record closes.
///
/// The causes recorded beside the counts are the correctness-relevant
/// environment overrides active in THIS process, because this is the process
/// that built the graph. Reading them at status time instead would report the
/// environment of whoever happened to ask.
///
/// A measurement or write failure is logged and swallowed, and the direction of
/// that failure is the safe one: an unwritten census leaves the previous,
/// older one in place, so the next comparison spans a longer window and reports
/// more movement rather than less. Turning it into a sweep or commit failure
/// would fail work that actually succeeded.
pub fn record_relation_census(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    source: kin_core::relation_census::CensusSource,
) {
    let (kinds, entities) = match kin_cli::commands::graph::measure_relation_census_with_entities(
        graph,
    ) {
        Ok(measured) => measured,
        Err(error) => {
            tracing::warn!(
                error = %error,
                "could not measure the relation census; the previous census stays in place and                  the next comparison spans a longer window"
            );
            return;
        }
    };
    let recorded = kin_core::relation_census::RelationCensus::new(
        chrono::Utc::now(),
        source,
        kinds,
        kin_core::relation_census::known_causes(std::env::vars()),
    )
    .with_entities(entities);
    // Offered rather than written. `record` refuses to make a losing census the
    // baseline, which is what keeps a commit from resetting the comparison
    // point to the graph it just damaged and what stops the recovery sweeps
    // after it from burying the loss a second and third time.
    match kin_core::relation_census::record(layout, &recorded) {
        kin_core::relation_census::CensusRecordOutcome::Advanced => {}
        kin_core::relation_census::CensusRecordOutcome::Held {
            held_at,
            held_source,
            losses,
        } => {
            tracing::warn!(
                held_at = %held_at.to_rfc3339(),
                held_source = held_source.label(),
                losses = %losses.join("; "),
                "this pass lost relation ground, so the census baseline stays where it was and                  graph status keeps comparing against it until the graph recovers"
            );
        }
        kin_core::relation_census::CensusRecordOutcome::Failed(error) => {
            tracing::warn!(
                error = %error,
                "could not persist the relation census; graph status will compare against the              previous one until a later pass rewrites it"
            );
        }
    }
}

/// What the filesystem reconciliation loop has actually managed to admit.
///
/// The loop already knew every fact here. It logged an admission failure at
/// `warn!` and moved on, it logged a dropped event at `warn!` and moved on, and
/// no surface a user or agent can reach carried either. So a store whose every
/// admission pass failed for two days answered `kin graph status` with no
/// issues detected, which is not a missing feature but an incorrect answer.
/// These probes are what those log lines publish to.
///
/// Recording is deliberately cheap and never fallible: the call sites are error
/// paths in a loop holding graph-authority locks, and a probe that could block
/// or fail there would be a worse defect than the blindness it fixes.
#[derive(Debug, Default)]
pub struct ReconcileProbes {
    inner: Mutex<ReconcileProbesInner>,
}

#[derive(Debug, Default)]
struct ReconcileProbesInner {
    skipped_events: u64,
    last_error: Option<RecordedFault>,
    admission_failure_streak: u64,
    admission_failures: u64,
    last_admission_error: Option<RecordedFault>,
    last_admission_success: Option<RecordedFault>,
    /// When the currently retained backlog first became non-empty. Cleared the
    /// moment the loop drains it, so the reported age is the age of one
    /// unbroken backlog rather than of the oldest one this daemon ever saw.
    backlog_since: Option<Instant>,
    /// How many host paths the most recent complete scan observed that
    /// repository authority does not track and no observation covered.
    untracked_path_count: u64,
    /// A bounded sample of those paths.
    untracked_paths_sample: Vec<String>,
    /// When the reading above was taken.
    ///
    /// The count alone cannot be read. Zero is written by a pass that genuinely
    /// found nothing untracked AND by an explicit seam that admitted everything,
    /// and neither record expires, so a zero from a commit five minutes ago is
    /// indistinguishable from one measured this instant while the working copy
    /// holds a module the graph has never met (FIR-2820). The stamp is what
    /// separates them, and it is what lets a surface refresh the reading rather
    /// than restate it.
    ///
    /// Carries no message; it is a clock, and `RecordedFault` is reused for the
    /// pair of instants it already keeps.
    untracked_observed: Option<RecordedFault>,
    /// What the last measurement of that reading cost.
    ///
    /// The refresh rate is derived from it rather than fixed, so the walk can
    /// never take more than a bounded share of the daemon's own time on a
    /// working copy large enough for it to matter.
    untracked_measurement_cost: Option<Duration>,
    /// What the most recent complete walk deliberately did not observe.
    excluded: ExcludedHostContent,
    /// The publication error that left a commit's deferred tree unpublished.
    ///
    /// Held beside the admission counters because it is what explains them: once
    /// it is set, every admission failure recorded below is a refusal against
    /// the mismatched tree rather than an independent fault.
    deferred_tree_wedge: Option<RecordedFault>,
}

/// Host content one complete walk declined to observe at all.
///
/// Separate from the untracked count because the two answer different
/// questions. An untracked path is admissible content nothing has taken yet;
/// these are paths the product will not index however long a reader waits, so
/// the honest answer to "where is my file" is different in each case.
///
/// Counts only, never lists. An excluded directory is counted once and never
/// descended into, so these stay small enough to read, and a surface that
/// enumerated every derived file would have stopped being a notice.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExcludedHostContent {
    /// Untracked entries the effective ignore rules excluded.
    pub ignored: u64,
    /// Untracked leaves outside Kin's regular-file and symbolic-link tree.
    pub unsupported: u64,
    /// Untracked entries the graph-owned admission policy excluded.
    ///
    /// Counted apart from `ignored` because they answer different questions. A
    /// path in `ignored` is named by this repository's `.kinignore` or a
    /// built-in default, which an operator edits in the working copy. A path
    /// here is excluded by the durable policy compiled from the tree's
    /// `.gitignore`/`.kinignore` blobs and the frozen local overlay, and it is
    /// the set that used to fail the whole admission instead of being skipped.
    pub policy_excluded: u64,
}

/// The shortest interval between two measurements of untracked host content.
///
/// One second is the window a caller who writes a file and asks about it in the
/// same breath can still fall inside, and it is disclosed rather than hidden:
/// every surface carrying the count carries the age of the reading beside it.
const UNTRACKED_REFRESH_FLOOR: Duration = Duration::from_secs(1);

/// The share of its own time the refresh may spend, as a divisor.
///
/// A walk that costs three milliseconds refreshes on the floor above. One that
/// costs half a second refreshes every five, so the measurement can never take
/// more than a tenth of the daemon under continuous polling.
const UNTRACKED_REFRESH_DUTY_DIVISOR: u32 = 10;

/// How many untracked paths a disclosure names outright.
///
/// A working copy can hold thousands of them, and a surface that printed every
/// one would bury the count that matters. Five is enough to recognize the file
/// you just wrote.
const UNTRACKED_SAMPLE_LIMIT: usize = 5;

impl ReconcileProbes {
    fn lock(&self) -> std::sync::MutexGuard<'_, ReconcileProbesInner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// A reconcile event errored and was dropped, leaving that path's
    /// enrichment stale.
    pub fn record_event_skipped(&self, error: impl std::fmt::Display, now: Instant) {
        let mut inner = self.lock();
        inner.skipped_events = inner.skipped_events.saturating_add(1);
        inner.last_error = Some(RecordedFault::new(error.to_string(), now));
    }

    /// A complete exact-tree admission attempt failed. Extends the streak.
    pub fn record_admission_failure(&self, error: impl std::fmt::Display, now: Instant) {
        let mut inner = self.lock();
        inner.admission_failures = inner.admission_failures.saturating_add(1);
        inner.admission_failure_streak = inner.admission_failure_streak.saturating_add(1);
        inner.last_admission_error = Some(RecordedFault::new(error.to_string(), now));
    }

    /// A complete exact-tree admission attempt succeeded. Ends the streak.
    ///
    /// Success clears the streak but keeps `admission_failures`, so a store that
    /// fails half its passes and recovers each time still reports that it is
    /// doing so. Only the consecutive count drives the verdict.
    pub fn record_admission_success(&self, now: Instant) {
        let mut inner = self.lock();
        inner.admission_failure_streak = 0;
        inner.last_admission_success = Some(RecordedFault::new(String::new(), now));
        // A complete admission that succeeded is proof the graph's tree reached
        // repository authority, which is exactly the divergence a wedge names.
        // Clearing it here rather than on a timer means the state can only leave
        // the surfaces by being resolved.
        inner.deferred_tree_wedge = None;
    }

    /// A commit's deferred tree was left unpublished because the publication
    /// restoring it failed as well.
    ///
    /// The daemon is not merely failing admissions at this point: the derived
    /// graph holds a tree repository authority never accepted, so every later
    /// admission is refused against the mismatched tree until this process
    /// restarts. Recorded rather than logged alone, because the log line is
    /// gone by the time anyone reads a status surface.
    pub fn record_deferred_tree_wedge(&self, error: impl std::fmt::Display, now: Instant) {
        let mut inner = self.lock();
        inner.deferred_tree_wedge = Some(RecordedFault::new(error.to_string(), now));
    }

    /// Repository authority accepted the tree the graph holds again.
    ///
    /// The counterpart to [`Self::record_deferred_tree_wedge`], for the paths
    /// that resolve the divergence without going through a complete admission:
    /// a later deferral whose restoring publication succeeds, and a commit whose
    /// own transaction carries the tree across.
    pub fn clear_deferred_tree_wedge(&self) {
        self.lock().deferred_tree_wedge = None;
    }

    /// Whether the loop finished a tick still holding work.
    ///
    /// Called every tick with the loop's own backlog predicate. The first tick
    /// that reports a backlog starts the clock and later ticks leave it alone,
    /// so the age measures one unbroken backlog. A tick that reports none stops
    /// it.
    pub fn observe_backlog(&self, retained: bool, now: Instant) {
        let mut inner = self.lock();
        if !retained {
            inner.backlog_since = None;
        } else if inner.backlog_since.is_none() {
            inner.backlog_since = Some(now);
        }
    }

    /// What one complete scan saw on the host that it did not admit.
    ///
    /// `paths` are admissible content authority does not carry and this pass did
    /// not take; `excluded` is what the same walk declined to observe at all.
    /// Both come from one scan and are recorded together so the two halves of
    /// "why is my file missing" can never describe different moments.
    ///
    /// Replaces the previous record rather than accumulating. The scan behind it
    /// is complete, so its answer is the current truth about the working copy,
    /// and a count that only ever grew would keep naming files a commit has
    /// since admitted or a delete has since removed.
    pub fn record_untracked_observation<T: std::fmt::Display>(
        &self,
        paths: impl IntoIterator<Item = T>,
        excluded: ExcludedHostContent,
    ) {
        let mut count: u64 = 0;
        let mut sample = Vec::new();
        for path in paths {
            count = count.saturating_add(1);
            if sample.len() < UNTRACKED_SAMPLE_LIMIT {
                sample.push(path.to_string());
            }
        }
        let mut inner = self.lock();
        inner.untracked_path_count = count;
        inner.untracked_paths_sample = sample;
        inner.excluded = excluded;
        inner.untracked_observed = Some(RecordedFault::new(String::new(), Instant::now()));
    }

    /// How long ago the untracked reading was taken, or `None` if none has been.
    ///
    /// The question a surface asks before it repeats the reading as a fact about
    /// now. `None` is the strongest answer here and not the weakest: a daemon
    /// that has never measured has no basis at all for the zero its counter
    /// carries.
    pub fn untracked_observation_age(&self, now: Instant) -> Option<Duration> {
        self.lock()
            .untracked_observed
            .as_ref()
            .map(|observed| now.saturating_duration_since(observed.at))
    }

    /// Whether the untracked reading is old enough to be worth measuring again.
    ///
    /// The interval is derived from what the last measurement cost rather than
    /// fixed, because the two working copies this has to serve are three
    /// milliseconds apart and a thousand. The floor is what a caller writing a
    /// file and asking about it immediately can be behind by; the duty rule is
    /// the ceiling on what the walk may spend, so a large repository refreshes
    /// less often instead of continuously.
    ///
    /// A reading nothing has ever taken is always due. That is the case with no
    /// measurement behind it at all, and it is the one a fixed interval would
    /// have treated as freshly measured.
    pub fn untracked_refresh_due(&self, now: Instant) -> bool {
        let inner = self.lock();
        let Some(observed) = inner.untracked_observed.as_ref() else {
            return true;
        };
        let interval = inner
            .untracked_measurement_cost
            .map(|cost| cost * UNTRACKED_REFRESH_DUTY_DIVISOR)
            .unwrap_or(UNTRACKED_REFRESH_FLOOR)
            .max(UNTRACKED_REFRESH_FLOOR);
        now.saturating_duration_since(observed.at) >= interval
    }

    /// Record a measurement of untracked host paths taken outside a reconcile
    /// pass.
    ///
    /// Deliberately narrower than [`Self::record_untracked_observation`]: it
    /// replaces the untracked reading and its clock and leaves the excluded
    /// counts exactly as the last complete walk measured them. This pass did not
    /// measure exclusions, so restating them would be a second authority for a
    /// fact it never observed.
    pub fn record_untracked_measurement<T: std::fmt::Display>(
        &self,
        paths: impl IntoIterator<Item = T>,
        cost: Duration,
    ) {
        let mut count: u64 = 0;
        let mut sample = Vec::new();
        for path in paths {
            count = count.saturating_add(1);
            if sample.len() < UNTRACKED_SAMPLE_LIMIT {
                sample.push(path.to_string());
            }
        }
        let mut inner = self.lock();
        inner.untracked_path_count = count;
        inner.untracked_paths_sample = sample;
        inner.untracked_measurement_cost = Some(cost);
        inner.untracked_observed = Some(RecordedFault::new(String::new(), Instant::now()));
    }

    /// The disclosure surfaces' view of all of it.
    pub fn report(&self, now: Instant) -> ReconcileHealth {
        let inner = self.lock();
        let age = |fault: &RecordedFault| now.saturating_duration_since(fault.at).as_secs();
        ReconcileHealth {
            skipped_events: inner.skipped_events,
            last_error: inner.last_error.as_ref().map(|fault| fault.message.clone()),
            last_error_age_seconds: inner.last_error.as_ref().map(age),
            last_error_at: inner
                .last_error
                .as_ref()
                .map(|fault| fault.wall_clock.to_rfc3339()),
            admission_failure_streak: inner.admission_failure_streak,
            admission_failures: inner.admission_failures,
            last_admission_error: inner
                .last_admission_error
                .as_ref()
                .map(|fault| fault.message.clone()),
            last_admission_success_age_seconds: inner.last_admission_success.as_ref().map(age),
            last_admission_success_at: inner
                .last_admission_success
                .as_ref()
                .map(|fault| fault.wall_clock.to_rfc3339()),
            backlog_age_seconds: inner
                .backlog_since
                .map(|since| now.saturating_duration_since(since).as_secs()),
            untracked_path_count: inner.untracked_path_count,
            untracked_paths_sample: inner.untracked_paths_sample.clone(),
            untracked_observed_age_seconds: inner.untracked_observed.as_ref().map(age),
            untracked_observed_at: inner
                .untracked_observed
                .as_ref()
                .map(|observed| observed.wall_clock.to_rfc3339()),
            ignored_path_count: inner.excluded.ignored,
            unsupported_path_count: inner.excluded.unsupported,
            policy_excluded_path_count: inner.excluded.policy_excluded,
            parked: None,
            deferred_tree_wedge: inner.deferred_tree_wedge.as_ref().map(|fault| {
                kin_cli::commands::resources::DeferredTreeWedge {
                    error: fault.message.clone(),
                    age_seconds: age(fault),
                    at: Some(fault.wall_clock.to_rfc3339()),
                }
            }),
        }
    }
}

/// Run the supervisor until shutdown.
///
/// Deliberately does nothing but observe and announce. It starts no work, takes
/// no graph lock, and touches no store, so it can keep answering for a daemon
/// whose real work has wedged — which is the only condition under which it
/// matters at all.
pub async fn run_background_work_supervisor(
    supervisor: Arc<BackgroundWorkSupervisor>,
    mut cancel: tokio::sync::watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            _ = tokio::time::sleep(SWEEP_INTERVAL) => {}
            _ = cancel.changed() => return,
        }
        if *cancel.borrow() {
            return;
        }
        supervisor.sample_process_cpu();
        for reason in supervisor.sweep(Instant::now()) {
            tracing::error!("{reason}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(base: Instant, secs: u64) -> Instant {
        base + Duration::from_secs(secs)
    }

    #[test]
    fn an_idle_pass_is_never_stalled_however_long_it_has_been_quiet() {
        assert!(!is_stalled(
            None,
            Some(Duration::from_secs(86_400)),
            Duration::from_secs(60)
        ));
    }

    fn reconcile_pass() -> Arc<BackgroundPass> {
        BackgroundWorkSupervisor::default().pass(PASS_RECONCILE)
    }

    /// A pass with deferred work owed reports a state of its own, so a retry
    /// ladder that never converges stops reading as a pass with nothing to do.
    #[test]
    fn deferred_work_is_reported_separately_from_idle() {
        let base = Instant::now();
        let pass = reconcile_pass();

        assert_eq!(pass.report(base).state, "idle");
        assert_eq!(pass.report(base).deferred_seconds, None);

        pass.set_deferred(true, base);
        let report = pass.report(at(base, 4_021));
        assert_eq!(report.state, "waiting_deferred");
        assert_eq!(report.deferred_seconds, Some(4_021));
        assert_eq!(
            report.working_seconds, None,
            "a waiting pass holds no working stretch"
        );
    }

    /// Draining the queue returns the pass to true idle, so the state cannot
    /// latch on and report a livelock that has since resolved.
    #[test]
    fn a_drained_queue_returns_the_pass_to_idle() {
        let base = Instant::now();
        let pass = reconcile_pass();
        pass.set_deferred(true, base);
        pass.set_deferred(false, at(base, 10));

        let report = pass.report(at(base, 20));
        assert_eq!(report.state, "idle");
        assert_eq!(report.deferred_seconds, None);
    }

    /// The clock latches on the first tick that owes work and is not restarted
    /// by later ticks that still owe it. Without this a loop polling every few
    /// hundred milliseconds would report an age of roughly one tick forever.
    #[test]
    fn the_deferred_clock_is_not_restarted_by_repeat_reports() {
        let base = Instant::now();
        let pass = reconcile_pass();
        pass.set_deferred(true, base);
        pass.set_deferred(true, at(base, 10));
        pass.set_deferred(true, at(base, 20));

        assert_eq!(pass.report(at(base, 30)).deferred_seconds, Some(30));
    }

    /// The blast-radius guard. Deferred work must never make the watchdog stop
    /// the loop: holding a working stretch open across ladder waits would let
    /// any flapping file halt reconciliation, which is worse than the blind spot
    /// this change closes.
    #[test]
    fn deferred_work_alone_never_stalls_a_pass() {
        let base = Instant::now();
        let supervisor = BackgroundWorkSupervisor::new(Duration::from_secs(60));
        let pass = supervisor.pass(PASS_RECONCILE);
        pass.set_deferred(true, base);

        assert!(supervisor.sweep(at(base, 86_400)).is_empty());
        assert!(!pass.halted());
        assert_eq!(pass.report(at(base, 86_400)).state, "waiting_deferred");
    }

    /// A pass that is actually burning CPU is described by that, not by the
    /// queue it also owes.
    #[test]
    fn working_outranks_waiting_deferred() {
        let base = Instant::now();
        let pass = reconcile_pass();
        pass.set_deferred(true, base);
        pass.working(at(base, 5));

        let report = pass.report(at(base, 30));
        assert_eq!(report.state, "working");
        assert_eq!(
            report.deferred_seconds,
            Some(30),
            "the deferred clock keeps aging underneath the working stretch"
        );
    }

    /// The two clocks are independent, which is the reason this is a second
    /// reading rather than a reuse of the working stretch. A loop alternating
    /// between working and having nothing admittable resets `working_seconds`
    /// every cycle while the deferred age keeps climbing.
    #[test]
    fn the_deferred_clock_survives_an_idle_working_cycle() {
        let base = Instant::now();
        let pass = reconcile_pass();
        pass.set_deferred(true, base);

        for tick in 1..=5 {
            pass.working(at(base, tick * 10));
            pass.idle();
        }

        let report = pass.report(at(base, 100));
        assert_eq!(report.state, "waiting_deferred");
        assert_eq!(report.deferred_seconds, Some(100));
        assert_eq!(report.working_seconds, None);
    }

    #[test]
    fn a_working_pass_with_no_progress_stalls_at_the_threshold() {
        let threshold = Duration::from_secs(60);
        assert!(!is_stalled(Some(Duration::from_secs(59)), None, threshold));
        assert!(is_stalled(Some(Duration::from_secs(60)), None, threshold));
    }

    /// The falsification for the stop rule: the SAME pass, working for the same
    /// stretch, is left alone once it reports progress. Without this the rule
    /// could be "stop everything that works long enough" and the stop test would
    /// still pass.
    #[test]
    fn recent_progress_protects_a_pass_that_has_worked_far_past_the_threshold() {
        let threshold = Duration::from_secs(60);
        let working_for = Duration::from_secs(3_600);
        assert!(is_stalled(Some(working_for), None, threshold));
        assert!(!is_stalled(
            Some(working_for),
            Some(Duration::from_secs(5)),
            threshold
        ));
    }

    /// Progress recorded during an earlier working stretch must not vouch for
    /// this one, and does not: the conjunction requires the current stretch to
    /// be long as well.
    #[test]
    fn a_freshly_started_pass_is_not_stalled_by_an_old_progress_timestamp() {
        assert!(!is_stalled(
            Some(Duration::from_secs(2)),
            Some(Duration::from_secs(9_000)),
            Duration::from_secs(60)
        ));
    }

    #[test]
    fn a_zero_threshold_disables_stopping() {
        assert!(!is_stalled(
            Some(Duration::from_secs(9_000)),
            Some(Duration::from_secs(9_000)),
            Duration::ZERO
        ));
    }

    /// The supervisor must not answer a question it was never told the answer
    /// to. Defaulting this to `Some(0)` would report "this daemon has never
    /// loaded authority" on every surface, which is a claim, and a false one.
    #[test]
    fn the_supervisor_reports_no_authority_load_count_of_its_own() {
        let supervisor = BackgroundWorkSupervisor::new(Duration::from_secs(60));
        assert_eq!(
            supervisor.work_state(Instant::now()).authority_loads,
            None,
            "the count belongs to the authority cache; the supervisor must leave it absent"
        );
    }

    #[test]
    fn the_working_mark_latches_so_a_wedged_loop_cannot_restart_its_own_clock() {
        let supervisor = BackgroundWorkSupervisor::new(Duration::from_secs(60));
        let pass = supervisor.pass(PASS_EMBED);
        let base = Instant::now();

        // A wedged loop calls `working` on every turn. The stretch must still be
        // measured from the first one.
        for turn in 0..10 {
            pass.working(at(base, turn));
        }
        assert!(supervisor.sweep(at(base, 59)).is_empty());

        let stopped = supervisor.sweep(at(base, 61));
        assert_eq!(stopped.len(), 1, "the wedged pass must be stopped");
        assert!(pass.halted());
        assert!(pass
            .halt_reason()
            .expect("a stopped pass carries a reason")
            .contains("without recording any progress"));
    }

    /// A pass with nowhere to read a halt must never be announced as stopped.
    ///
    /// Paired with the test above rather than written alone: the two run the
    /// identical wedged scenario and differ only in how the pass registered, so
    /// a sweep that stopped everything, or one that stopped nothing, fails one
    /// of them. The projection rebuild is the real case — a single `await` with
    /// no loop — and publishing `stopped` for work still running would make the
    /// health surface lie about the one thing it exists to report.
    #[test]
    fn a_disclose_only_pass_is_reported_but_never_claimed_stopped() {
        let supervisor = BackgroundWorkSupervisor::new(Duration::from_secs(60));
        let pass = supervisor.disclosed_pass(PASS_PROJECTION);
        let base = Instant::now();

        pass.working(base);
        assert!(
            supervisor.sweep(at(base, 61)).is_empty(),
            "a pass that cannot observe a halt must not be stopped by the sweep"
        );
        assert!(!pass.halted());
        assert_eq!(pass.halt_reason(), None);
        assert!(!supervisor.any_stopped());

        // It is still disclosed: the working stretch is what answers "why is my
        // fan on" for work the supervisor cannot end.
        let report = supervisor
            .reports(at(base, 61))
            .into_iter()
            .find(|report| report.name == PASS_PROJECTION)
            .expect("a disclose-only pass still reports");
        assert_eq!(report.state, "working");
        assert_eq!(report.working_seconds, Some(61));
    }

    #[test]
    fn registration_records_which_passes_the_supervisor_may_stop() {
        let supervisor = BackgroundWorkSupervisor::new(Duration::from_secs(60));
        assert_eq!(
            supervisor.pass(PASS_LSP).enforcement(),
            PassEnforcement::Stoppable
        );
        assert_eq!(
            supervisor.disclosed_pass(PASS_PROJECTION).enforcement(),
            PassEnforcement::DiscloseOnly
        );
    }

    /// The other half of the same scenario. Only the progress feed differs, so a
    /// guard that stopped every long pass would fail here.
    #[test]
    fn the_same_long_pass_is_untouched_while_it_reports_progress() {
        let supervisor = BackgroundWorkSupervisor::new(Duration::from_secs(60));
        let pass = supervisor.pass(PASS_EMBED);
        let base = Instant::now();

        pass.working(base);
        for minute in 1..30 {
            pass.advanced(64, at(base, minute * 30));
            assert!(
                supervisor.sweep(at(base, minute * 30 + 1)).is_empty(),
                "a pass recording progress must never be stopped"
            );
        }
        assert!(!pass.halted());
        assert_eq!(pass.progress(), 64 * 29);
    }

    #[test]
    fn going_idle_ends_the_working_stretch() {
        let supervisor = BackgroundWorkSupervisor::new(Duration::from_secs(60));
        let pass = supervisor.pass(PASS_RECONCILE);
        let base = Instant::now();

        pass.working(base);
        pass.idle();
        assert!(supervisor.sweep(at(base, 3_600)).is_empty());

        pass.working(at(base, 3_600));
        assert!(supervisor.sweep(at(base, 3_640)).is_empty());
        assert_eq!(supervisor.sweep(at(base, 3_661)).len(), 1);
    }

    #[test]
    fn an_empty_batch_is_not_progress() {
        let supervisor = BackgroundWorkSupervisor::new(Duration::from_secs(60));
        let pass = supervisor.pass(PASS_EMBED);
        let base = Instant::now();

        pass.working(base);
        for turn in 0..10 {
            pass.advanced(0, at(base, turn));
        }
        assert_eq!(supervisor.sweep(at(base, 61)).len(), 1);
    }

    #[test]
    fn a_stopped_pass_is_stopped_once_and_keeps_its_first_reason() {
        let supervisor = BackgroundWorkSupervisor::new(Duration::from_secs(60));
        let pass = supervisor.pass(PASS_EMBED);
        let base = Instant::now();

        pass.working(base);
        assert_eq!(supervisor.sweep(at(base, 61)).len(), 1);
        let first = pass.halt_reason().expect("a reason");
        assert!(supervisor.sweep(at(base, 600)).is_empty());
        pass.halt("a later reason");
        assert_eq!(pass.halt_reason().as_deref(), Some(first.as_str()));
    }

    #[test]
    fn the_retry_ladder_parks_once_its_cumulative_budget_is_spent() {
        let supervisor = BackgroundWorkSupervisor::new(Duration::from_secs(60));
        let pass = supervisor.pass(PASS_EMBED);
        let budget = Duration::from_secs(100);

        assert!(pass.charge_retry(Duration::from_secs(60), budget, "embedding"));
        assert!(!pass.halted());
        assert!(!pass.charge_retry(Duration::from_secs(60), budget, "embedding"));
        assert!(pass.halted());
        assert!(pass
            .halt_reason()
            .expect("a parked pass carries a reason")
            .contains("cumulative retry backoff"));
    }

    /// The falsification for the budget: a ladder that recovers must not carry
    /// its spent delay into the next failure and park a healthy pass.
    #[test]
    fn a_recovered_retry_ladder_starts_its_budget_over() {
        let supervisor = BackgroundWorkSupervisor::new(Duration::from_secs(60));
        let pass = supervisor.pass(PASS_EMBED);
        let budget = Duration::from_secs(100);

        for _ in 0..10 {
            assert!(pass.charge_retry(Duration::from_secs(60), budget, "embedding"));
            pass.reset_retries();
        }
        assert!(!pass.halted());
        assert_eq!(pass.retry_spent(), Duration::ZERO);
    }

    #[test]
    fn a_zero_budget_disables_parking() {
        let supervisor = BackgroundWorkSupervisor::new(Duration::from_secs(60));
        let pass = supervisor.pass(PASS_EMBED);
        for _ in 0..100 {
            assert!(pass.charge_retry(Duration::from_secs(60), Duration::ZERO, "embedding"));
        }
        assert!(!pass.halted());
    }

    #[test]
    fn the_report_discloses_state_progress_and_ages() {
        let supervisor = BackgroundWorkSupervisor::new(Duration::from_secs(600));
        let base = Instant::now();

        let embed = supervisor.pass(PASS_EMBED);
        embed.working(base);
        embed.advanced(128, at(base, 10));
        supervisor.pass(PASS_RECONCILE);

        let reports = supervisor.reports(at(base, 40));
        assert_eq!(reports.len(), 2);

        let embed_report = reports
            .iter()
            .find(|report| report.name == PASS_EMBED)
            .expect("the embed pass is reported");
        assert_eq!(embed_report.state, "working");
        assert_eq!(embed_report.progress, 128);
        assert_eq!(embed_report.progress_age_seconds, Some(30));
        assert_eq!(embed_report.working_seconds, Some(40));
        assert!(embed_report.stopped_reason.is_none());

        let reconcile_report = reports
            .iter()
            .find(|report| report.name == PASS_RECONCILE)
            .expect("the reconcile pass is reported");
        assert_eq!(reconcile_report.state, "idle");
        assert_eq!(reconcile_report.progress_age_seconds, None);
        assert_eq!(reconcile_report.working_seconds, None);
    }

    #[test]
    fn a_stopped_pass_reports_its_reason_and_raises_attention() {
        let supervisor = BackgroundWorkSupervisor::new(Duration::from_secs(60));
        let base = Instant::now();
        let pass = supervisor.pass(PASS_EMBED);

        assert!(!supervisor.any_stopped());
        pass.working(base);
        supervisor.sweep(at(base, 61));

        assert!(supervisor.any_stopped());
        let report = supervisor
            .reports(at(base, 61))
            .into_iter()
            .find(|report| report.name == PASS_EMBED)
            .expect("the embed pass is reported");
        assert_eq!(report.state, "stopped");
        assert!(report.stopped_reason.is_some());
    }

    #[test]
    fn cumulative_cpu_is_absent_until_it_is_sampled_and_present_after() {
        let supervisor = BackgroundWorkSupervisor::new(DEFAULT_STALL_THRESHOLD);
        assert_eq!(supervisor.daemon_cpu_seconds(), None);
        supervisor.sample_process_cpu();
        let sampled = supervisor
            .daemon_cpu_seconds()
            .expect("this process has accumulated CPU time");
        assert!(
            sampled >= 0.0,
            "cumulative CPU must be a real measurement: {sampled}"
        );
    }

    #[test]
    fn registration_is_lazy_so_an_unspawned_pass_never_claims_to_be_idle() {
        let supervisor = BackgroundWorkSupervisor::new(DEFAULT_STALL_THRESHOLD);
        assert!(supervisor.reports(Instant::now()).is_empty());
        assert!(supervisor.registered(PASS_EMBED).is_none());
        supervisor.pass(PASS_EMBED);
        assert!(supervisor.registered(PASS_EMBED).is_some());
        assert_eq!(supervisor.reports(Instant::now()).len(), 1);
    }

    #[test]
    fn repeated_registration_returns_one_shared_pass() {
        let supervisor = BackgroundWorkSupervisor::new(DEFAULT_STALL_THRESHOLD);
        let first = supervisor.pass(PASS_EMBED);
        first.advanced(7, Instant::now());
        let second = supervisor.pass(PASS_EMBED);
        assert_eq!(second.progress(), 7);
        assert_eq!(supervisor.reports(Instant::now()).len(), 1);
    }

    /// Every complete admission failing, for long enough that the last success
    /// is hours old. The streak is what names it.
    #[test]
    fn consecutive_admission_failures_accumulate_into_a_streak() {
        let probes = ReconcileProbes::default();
        let base = Instant::now();
        probes.record_admission_success(base);
        for step in 1..=8 {
            probes.record_admission_failure("ignored churn starved admission", at(base, step * 60));
        }

        let report = probes.report(at(base, 8 * 60));
        assert_eq!(report.admission_failure_streak, 8);
        assert_eq!(report.admission_failures, 8);
        assert_eq!(report.last_admission_success_age_seconds, Some(480));
        assert_eq!(
            report.last_admission_error.as_deref(),
            Some("ignored churn starved admission")
        );
        assert!(report.degraded(), "eight failures in a row is not healthy");
    }

    /// The falsification, and the property that keeps the streak honest: a
    /// success ends it. A counter that only ever climbed would report a store
    /// that failed once an hour ago and has admitted cleanly ever since as
    /// permanently degraded, and nobody would keep reading it.
    #[test]
    fn one_success_clears_the_streak_without_erasing_the_history() {
        let probes = ReconcileProbes::default();
        let base = Instant::now();
        for step in 1..=8 {
            probes.record_admission_failure("transient", at(base, step * 60));
        }
        assert!(probes.report(at(base, 480)).degraded());

        probes.record_admission_success(at(base, 500));

        let report = probes.report(at(base, 500));
        assert_eq!(report.admission_failure_streak, 0);
        assert_eq!(
            report.admission_failures, 8,
            "the cumulative count survives, so a store that fails half its passes still says so"
        );
        assert!(
            !report.degraded(),
            "a loop that is admitting again is not degraded"
        );
    }

    /// A wedged commit deferral survives every later failure and clears on the
    /// one event that resolves it.
    ///
    /// Both halves are load-bearing. A wedged daemon goes on failing admissions
    /// forever, and each of those failures is a consequence of the wedge rather
    /// than a fresh cause, so a record that any later fault overwrote would
    /// erase the one line naming the restart. A record nothing could clear would
    /// be worse: the state does end, on a complete admission that succeeds, and
    /// a surface that kept reporting it would teach a reader to ignore it.
    #[test]
    fn a_wedged_deferral_outlives_later_failures_and_clears_on_a_successful_admission() {
        let probes = ReconcileProbes::default();
        let base = Instant::now();
        probes.record_deferred_tree_wedge(
            "repository authority moved after the complete workspace observation was planned",
            at(base, 10),
        );

        let report = probes.report(at(base, 70));
        let wedge = report
            .deferred_tree_wedge
            .as_ref()
            .expect("a wedged daemon reports its wedge");
        assert!(
            wedge.error.contains("repository authority moved"),
            "the publication's own error is what a reader acts on: {wedge:?}"
        );
        assert_eq!(wedge.age_seconds, 60);
        assert!(
            wedge.at.is_some(),
            "a wall-clock stamp is what lines this up against the daemon log"
        );
        assert!(report.degraded());

        // The refusals that follow are the wedge, not new information, and they
        // must not displace it.
        for step in 1..=4 {
            probes.record_admission_failure(
                "the complete workspace observation was planned against a tree that is not this \
                 workspace's authority tree",
                at(base, 100 + step * 10),
            );
        }
        assert!(probes.report(at(base, 200)).deferred_tree_wedge.is_some());

        probes.record_admission_success(at(base, 300));
        let recovered = probes.report(at(base, 300));
        assert!(
            recovered.deferred_tree_wedge.is_none(),
            "an admission that succeeded is proof the graph's tree reached authority"
        );
        assert!(!recovered.degraded(), "{:?}", recovered.degraded_reasons());
    }

    /// A dropped reconcile event leaves one path's enrichment stale until that
    /// path changes again, so the count and the reason both have to survive to
    /// a surface.
    #[test]
    fn a_dropped_event_is_counted_and_keeps_its_reason() {
        let probes = ReconcileProbes::default();
        let base = Instant::now();
        probes.record_event_skipped("src/a.rs: parser rejected the transaction", at(base, 10));
        probes.record_event_skipped("src/b.rs: parser rejected the transaction", at(base, 20));

        let report = probes.report(at(base, 30));
        assert_eq!(report.skipped_events, 2);
        assert_eq!(
            report.last_error.as_deref(),
            Some("src/b.rs: parser rejected the transaction"),
            "the most recent error is the one that survives"
        );
        assert_eq!(report.last_error_age_seconds, Some(10));
        assert!(
            report.last_error_at.is_some(),
            "a wall-clock stamp is what lines this up against a log"
        );
        assert!(report.degraded());
    }

    /// Backlog age measures one unbroken backlog. A daemon that drained hours
    /// ago and picked up new work a second ago is not carrying an hours-old
    /// backlog, and reporting one would make the threshold fire on healthy
    /// bursts forever after the first slow day.
    #[test]
    fn backlog_age_measures_the_current_backlog_and_not_the_oldest_one() {
        let probes = ReconcileProbes::default();
        let base = Instant::now();

        probes.observe_backlog(true, at(base, 0));
        probes.observe_backlog(true, at(base, 100));
        assert_eq!(
            probes.report(at(base, 200)).backlog_age_seconds,
            Some(200),
            "a retained backlog ages from when it started, not from the last tick"
        );

        probes.observe_backlog(false, at(base, 300));
        assert_eq!(probes.report(at(base, 300)).backlog_age_seconds, None);

        probes.observe_backlog(true, at(base, 400));
        assert_eq!(
            probes.report(at(base, 405)).backlog_age_seconds,
            Some(5),
            "the next backlog starts its own clock"
        );
    }

    /// The whole-mechanism two-sided check. A daemon that has done nothing at
    /// all reports nothing wrong, because an untouched repository is the most
    /// common state there is and a probe that called it degraded would be
    /// turned off within a day.
    #[test]
    fn a_daemon_that_has_reconciled_nothing_is_not_degraded() {
        let report = ReconcileProbes::default().report(Instant::now());
        assert_eq!(report.skipped_events, 0);
        assert_eq!(report.admission_failure_streak, 0);
        assert_eq!(report.last_admission_success_age_seconds, None);
        assert_eq!(report.backlog_age_seconds, None);
        assert!(!report.degraded());
        assert!(report.degraded_reasons().is_empty());
    }

    /// FIR-2820. A zero nobody measured is not a zero, and it is the reading
    /// three surfaces repeated as an all-clear.
    ///
    /// The counter starts at zero because a `u64` does. Until something walks
    /// the working copy, that zero stands for nothing at all, so the surfaces
    /// need a way to tell it from a measured one and the probe needs to know a
    /// refresh is due. Both hang off the same stamp.
    #[test]
    fn an_unmeasured_untracked_reading_carries_no_clock_and_is_always_due() {
        let probes = ReconcileProbes::default();
        let now = Instant::now();

        let report = probes.report(now);
        assert_eq!(
            report.untracked_path_count, 0,
            "the counter's initial value, which is the whole problem"
        );
        assert_eq!(
            report.untracked_observed_age_seconds, None,
            "and nothing measured it, which is what the surfaces have to be told"
        );
        assert_eq!(report.untracked_observed_at, None);
        assert!(
            probes.untracked_observation_age(now).is_none(),
            "there is no age because there is no observation"
        );
        assert!(
            probes.untracked_refresh_due(now),
            "a reading nothing has ever taken is due the first time anyone asks"
        );
    }

    /// FIR-2820. A measurement stamps its own clock, and the stamp is what
    /// stops the next caller re-walking the working copy.
    #[test]
    fn a_measurement_stamps_its_clock_and_holds_off_the_next_one() {
        let probes = ReconcileProbes::default();
        probes.record_untracked_measurement(
            ["notekeeper/linkgraph.py", "notekeeper/search.py"],
            Duration::from_millis(3),
        );
        let now = Instant::now();

        let report = probes.report(now);
        assert_eq!(report.untracked_path_count, 2);
        assert_eq!(
            report.untracked_paths_sample,
            vec![
                "notekeeper/linkgraph.py".to_string(),
                "notekeeper/search.py".to_string()
            ]
        );
        assert_eq!(
            report.untracked_observed_age_seconds,
            Some(0),
            "a measurement taken this instant is zero seconds old, which is a reading and not \
             an absent one"
        );
        assert!(report.untracked_observed_at.is_some());
        assert!(
            !probes.untracked_refresh_due(now),
            "a reading taken this instant is not due again"
        );
        assert!(
            probes.untracked_refresh_due(now + UNTRACKED_REFRESH_FLOOR),
            "and it is due once the floor has passed"
        );
    }

    /// FIR-2820. What the walk costs sets how often it may run, so a working
    /// copy large enough for the measurement to matter cannot be walked
    /// continuously by a client polling health.
    #[test]
    fn an_expensive_measurement_stretches_its_own_interval() {
        let cheap = ReconcileProbes::default();
        cheap.record_untracked_measurement(std::iter::empty::<&str>(), Duration::from_millis(3));
        let costly = ReconcileProbes::default();
        costly.record_untracked_measurement(std::iter::empty::<&str>(), Duration::from_millis(500));
        let now = Instant::now();

        let just_past_the_floor = now + UNTRACKED_REFRESH_FLOOR + Duration::from_millis(10);
        assert!(
            cheap.untracked_refresh_due(just_past_the_floor),
            "a three-millisecond walk refreshes on the floor"
        );
        assert!(
            !costly.untracked_refresh_due(just_past_the_floor),
            "a half-second walk does not, or continuous polling would spend the daemon on it"
        );
        assert!(
            costly.untracked_refresh_due(
                now + Duration::from_millis(500) * UNTRACKED_REFRESH_DUTY_DIVISOR
            ),
            "it comes due at its own duty interval, which is the ceiling and not a refusal"
        );
    }

    /// FIR-2820. The measurement pass observed no exclusions, so it restates
    /// none.
    ///
    /// Two authorities for one fact is what this avoids. The excluded counts
    /// answer "why will nothing ever index my file" and only a complete walk
    /// measures them; a measurement that zeroed them would turn a real
    /// `.kinignore` rule into silence every time anyone read health.
    #[test]
    fn a_measurement_leaves_the_excluded_counts_to_the_walk_that_measured_them() {
        let probes = ReconcileProbes::default();
        probes.record_untracked_observation(
            ["left/behind.py"],
            ExcludedHostContent {
                ignored: 7,
                unsupported: 2,
                policy_excluded: 4,
            },
        );
        probes.record_untracked_measurement(["fresh.py", "fresher.py"], Duration::from_millis(1));

        let report = probes.report(Instant::now());
        assert_eq!(
            report.untracked_path_count, 2,
            "the untracked reading moved"
        );
        assert_eq!(report.ignored_path_count, 7, "the exclusions did not");
        assert_eq!(report.unsupported_path_count, 2);
        assert_eq!(report.policy_excluded_path_count, 4);
    }
}
