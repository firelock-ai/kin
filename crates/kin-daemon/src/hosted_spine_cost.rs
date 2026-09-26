// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What the hosted spine authority is allowed to cost, and what it has cost.
//!
//! A full authority pass hydrates every committed spine row from Firestore and
//! then double-collects the fleet. Firestore bills one read per row, so on the
//! five-repository hosted fleet one pass is about 43,000 document reads: the
//! pod log on 2026-09-05 recorded 41,496 entity rows and 1,489 edge rows per
//! hydration, and the heads, manifests and fences add a few dozen more.
//!
//! From 2026-09-05 to 2026-09-20 the background refresh ran one of those passes
//! every 60 seconds plus the pass itself, whether or not anything had changed.
//! Firestore billed about 46 million reads a day for it until the spine was
//! switched off with `KIN_DISABLE_SPINE=1`. Nothing in the process counted them.
//!
//! Four rules keep that from coming back.
//!
//! 1. The background cadence checks durable identity first: the admission and
//!    runtime authority in GCS, the active Firestore fence, and the committed
//!    heads, 2 + 2N Firestore reads for N repositories. It runs a full pass
//!    only when no proof is held or that identity moved under the proof, and
//!    at most once per [`COMPLETENESS_REPAIR_FLOOR`] when only the cache's
//!    edge authority was lost. A fleet that nobody publishes to costs 12 reads
//!    a minute instead of a hydration a minute.
//! 2. Every full pass outside an authority transition goes through one
//!    [`HostedSpinePassLimiter`]. One runs at a time, a caller that arrives
//!    while it runs waits for it instead of starting its own, and a new one
//!    starts no sooner than [`FULL_PASS_FLOOR`] after the last one finished.
//!    A pass that failed is retried after [`FAILED_PASS_RETRY_FLOOR`],
//!    doubling up to [`FAILED_PASS_BACKOFF_CAP`], because the inputs a pass
//!    failed on rarely change within seconds. Authority transitions (startup
//!    rollout, admission, adoption, release) run under the publication write
//!    gate for the control plane and are never refused, but they are counted.
//! 3. Readiness and the public spine health route answer from a verdict at
//!    most [`READY_VERDICT_TTL`] old (a refusal at most
//!    [`REFUSED_VERDICT_TTL`] old), taken against the proof, the admitted
//!    evidence and the publication-gate generation this process holds now.
//!    Anything local that changes one of those invalidates it at once, no
//!    verdict is used while a full pass is running, and a ready verdict still
//!    re-reads the GCS admission and runtime authority on every call. Past the
//!    TTL the next caller re-checks and every concurrent caller shares that
//!    one check.
//! 4. Every full pass, identity check, deferral and shared wait is counted,
//!    and the Firestore store reports its billable reads, so `/health` and one
//!    log line every ten minutes say what the spine costs.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// The least time between the end of one full pass and the start of the next,
/// for every caller that is not an authority transition, when the last pass
/// succeeded. The background cadence already asked for a pass at most once a
/// minute; this makes that the limit for everything else as well.
pub(crate) const FULL_PASS_FLOOR: Duration = Duration::from_secs(60);

/// How soon a failed full pass may be retried. A failed pass clears the proof
/// and readiness refuses until one succeeds, so the first retry is sooner than
/// the floor; every further consecutive failure doubles it.
pub(crate) const FAILED_PASS_RETRY_FLOOR: Duration = Duration::from_secs(15);

/// The longest a failing fleet waits between full passes. At about 43,000
/// reads a pass, a permanent failure costs four passes an hour instead of one
/// every few seconds.
pub(crate) const FAILED_PASS_BACKOFF_CAP: Duration = Duration::from_secs(15 * 60);

/// How long a ready verdict may answer readiness. Longer than the background
/// cadence's 60 s interval, so a healthy cadence keeps it fresh and readiness
/// reads no Firestore document at all; short enough that a stalled cadence
/// cannot leave a probe reporting a proof nobody has checked for long.
pub(crate) const READY_VERDICT_TTL: Duration = Duration::from_secs(90);

/// How long a refusal may answer readiness. Short, because a refusal that
/// outlives its cause holds a working pod out of service; long enough that a
/// flood of probes against a refusing pod shares one check.
pub(crate) const REFUSED_VERDICT_TTL: Duration = Duration::from_secs(10);

/// How long a verdict may answer an authenticated spine read: a `/spine/*`
/// query, an xref, or an MCP reference tool. Short, because a read binds its
/// answer to the durable generation it names; long enough that a burst of
/// reads shares one 2 + 2N-read check instead of paying one each. It caps the
/// Firestore reads the read path can cause at one check per 5 s per pod,
/// whatever the request rate.
pub(crate) const QUERY_VERDICT_TTL: Duration = Duration::from_secs(5);

/// How often the background cadence may run a full pass whose only reason is
/// that the cache lost its edge authority while durable identity stayed put.
///
/// Every local mutation of the primary graph marks its cross-repo edges dirty
/// (`begin_graph_authority_mutation`), and a hosted daemon has several paths
/// that mutate: reconcile ticks, language-server relation installs, repository
/// commands. A full pass restores the committed authority, but a daemon that
/// mutates every minute would otherwise re-hydrate every minute, which is the
/// bill this module exists to end. So this repair runs at most four times an
/// hour, whatever the rate of mutation.
pub(crate) const COMPLETENESS_REPAIR_FLOOR: Duration = Duration::from_secs(15 * 60);

/// How often the background cadence logs the cumulative cost counters.
pub(crate) const COST_SUMMARY_INTERVAL: Duration = Duration::from_secs(600);

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The limits one daemon enforces: always [`Self::PRODUCTION`]. A test that has
/// to watch one expire steps [`HostedSpineClock`] past it instead of changing
/// it, so every test runs the limits production runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HostedSpineCostPolicy {
    pub(crate) full_pass_floor: Duration,
    pub(crate) failed_pass_retry_floor: Duration,
    pub(crate) failed_pass_backoff_cap: Duration,
    pub(crate) ready_verdict_ttl: Duration,
    pub(crate) refused_verdict_ttl: Duration,
    pub(crate) query_verdict_ttl: Duration,
}

/// Who is asking a cached verdict, which decides how old it may be.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostedSpineVerdictUse {
    /// `/readiness` and `/spine/health`: public, and polled for the life of
    /// the pod.
    Readiness,
    /// An authenticated read whose answer names a durable generation.
    Query,
}

impl HostedSpineCostPolicy {
    pub(crate) const PRODUCTION: Self = Self {
        full_pass_floor: FULL_PASS_FLOOR,
        failed_pass_retry_floor: FAILED_PASS_RETRY_FLOOR,
        failed_pass_backoff_cap: FAILED_PASS_BACKOFF_CAP,
        ready_verdict_ttl: READY_VERDICT_TTL,
        refused_verdict_ttl: REFUSED_VERDICT_TTL,
        query_verdict_ttl: QUERY_VERDICT_TTL,
    };

    /// The gap the limiter requires after a pass that left
    /// `consecutive_failures` failed passes in a row behind it.
    pub(crate) fn gap_after(&self, consecutive_failures: u32) -> Duration {
        if consecutive_failures == 0 {
            return self.full_pass_floor;
        }
        let doublings = consecutive_failures.saturating_sub(1).min(16);
        self.failed_pass_retry_floor
            .saturating_mul(1u32 << doublings)
            .min(self.failed_pass_backoff_cap)
    }

    pub(crate) fn verdict_ttl(&self, used_for: HostedSpineVerdictUse, ready: bool) -> Duration {
        match used_for {
            HostedSpineVerdictUse::Readiness if ready => self.ready_verdict_ttl,
            HostedSpineVerdictUse::Readiness => self.refused_verdict_ttl,
            HostedSpineVerdictUse::Query => self.query_verdict_ttl,
        }
    }
}

/// Who asked for a full authority pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostedSpinePassTrigger {
    /// The background cadence, after its identity check said one is needed.
    Background,
    /// A semantic query whose per-request identity check found no usable proof.
    Request,
    /// A direct call to `ensure_spine`.
    Direct,
    /// An authority transition under the publication write gate: the startup
    /// rollout, reader admission, adoption, or rollout release.
    Transition,
}

impl HostedSpinePassTrigger {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Background => "background",
            Self::Request => "request",
            Self::Direct => "direct",
            Self::Transition => "transition",
        }
    }
}

/// `Instant::now`, plus whatever a test has advanced it by. The limiter and the
/// verdict cache read time only through this, so a test can step past a
/// sixty-second floor without sleeping for it.
#[derive(Debug, Default)]
pub(crate) struct HostedSpineClock {
    #[cfg(test)]
    advanced: Mutex<Duration>,
}

impl HostedSpineClock {
    pub(crate) fn now(&self) -> Instant {
        #[cfg(test)]
        {
            Instant::now() + *lock(&self.advanced)
        }
        #[cfg(not(test))]
        {
            Instant::now()
        }
    }

    #[cfg(test)]
    pub(crate) fn advance(&self, by: Duration) {
        *lock(&self.advanced) += by;
    }
}

#[derive(Debug, Default)]
struct LimiterState {
    /// The trigger of the full pass running now, if one is, and when it was
    /// admitted.
    in_flight: Option<(HostedSpinePassTrigger, Instant)>,
    /// Limited passes finished so far. A caller waiting on a running pass waits
    /// for this to move.
    finished_passes: u64,
    last_finished: Option<Instant>,
    consecutive_failures: u32,
    last_failure: Option<String>,
    /// The last limited pass stopped before it read a committed row, because
    /// durable identity already showed it could not prove. Such a pass costs a
    /// head listing, so it is retried at the retry floor without doubling.
    last_refused_before_hydration: bool,
}

/// How one limited pass ended, for the limiter's schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum HostedSpinePassEnd {
    /// A proof was installed.
    Proved,
    /// Stopped before reading a committed row. Cheap, so it neither resets
    /// nor lengthens the failure backoff.
    RefusedBeforeHydration(String),
    /// Read committed rows and still failed.
    Failed(String),
}

/// Admits at most one full authority pass at a time, and none sooner than the
/// policy allows after the last one.
pub(crate) struct HostedSpinePassLimiter {
    state: Mutex<LimiterState>,
    finished: tokio::sync::watch::Sender<u64>,
}

/// What the limiter says to a caller that wants a full pass.
pub(crate) enum HostedSpinePassAdmission<'a> {
    /// Run it, and report how it ended through the lease.
    Lead(HostedSpinePassLease<'a>),
    /// Another caller is running one now. Wait for it rather than start a
    /// second.
    InFlight(HostedSpinePassWaiter),
    /// Too soon after the last one.
    Deferred(HostedSpinePassDeferral),
}

/// Why a full pass was refused, in words a refusal can carry.
#[derive(Debug, Clone)]
pub(crate) struct HostedSpinePassDeferral {
    pub(crate) retry_in: Duration,
    pub(crate) consecutive_failures: u32,
    pub(crate) last_failure: Option<String>,
    pub(crate) last_refused_before_hydration: bool,
}

impl HostedSpinePassDeferral {
    pub(crate) fn reason(&self) -> String {
        let mut reason = format!(
            "hosted spine authority re-proof is rate limited: the next full pass is allowed in \
             {} s",
            self.retry_in.as_secs().max(1)
        );
        match &self.last_failure {
            Some(failure) if self.last_refused_before_hydration => reason.push_str(&format!(
                " (the last pass stopped before hydrating: {failure})"
            )),
            Some(failure) => reason.push_str(&format!(
                " (failed passes in a row: {}; the last one failed: {failure})",
                self.consecutive_failures
            )),
            None => {}
        }
        reason
    }
}

/// The right to run one full pass. Dropping it without [`Self::finish`] counts
/// as a failed pass, so a panic inside the pass cannot leave the limiter
/// believing one is still running.
pub(crate) struct HostedSpinePassLease<'a> {
    limiter: &'a HostedSpinePassLimiter,
    clock: &'a HostedSpineClock,
    settled: bool,
}

impl HostedSpinePassLease<'_> {
    pub(crate) fn finish(mut self, end: HostedSpinePassEnd) {
        self.settle(end);
    }

    fn settle(&mut self, end: HostedSpinePassEnd) {
        if self.settled {
            return;
        }
        self.settled = true;
        let now = self.clock.now();
        let finished = {
            let mut state = lock(&self.limiter.state);
            state.in_flight = None;
            state.finished_passes = state.finished_passes.wrapping_add(1);
            state.last_finished = Some(now);
            match end {
                HostedSpinePassEnd::Proved => {
                    state.consecutive_failures = 0;
                    state.last_failure = None;
                    state.last_refused_before_hydration = false;
                }
                HostedSpinePassEnd::RefusedBeforeHydration(reason) => {
                    state.last_failure = Some(reason);
                    state.last_refused_before_hydration = true;
                }
                HostedSpinePassEnd::Failed(reason) => {
                    state.consecutive_failures = state.consecutive_failures.saturating_add(1);
                    state.last_failure = Some(reason);
                    state.last_refused_before_hydration = false;
                }
            }
            state.finished_passes
        };
        self.limiter.finished.send_replace(finished);
    }
}

impl Drop for HostedSpinePassLease<'_> {
    fn drop(&mut self) {
        self.settle(HostedSpinePassEnd::Failed(
            "the hosted spine authority pass ended without reporting an outcome".to_string(),
        ));
    }
}

/// A caller's place in line behind a pass another caller is running.
pub(crate) struct HostedSpinePassWaiter {
    receiver: tokio::sync::watch::Receiver<u64>,
    seen: u64,
}

impl HostedSpinePassWaiter {
    /// Wait until the pass that was running at admission has finished.
    pub(crate) async fn wait(mut self) {
        let seen = self.seen;
        // The sender lives as long as the limiter, and the limiter as long as
        // the daemon state the caller borrows, so this cannot end early.
        let _ = self.receiver.wait_for(|finished| *finished != seen).await;
    }
}

impl Default for HostedSpinePassLimiter {
    fn default() -> Self {
        let (finished, _) = tokio::sync::watch::channel(0);
        Self {
            state: Mutex::new(LimiterState::default()),
            finished,
        }
    }
}

impl HostedSpinePassLimiter {
    pub(crate) fn admit<'a>(
        &'a self,
        clock: &'a HostedSpineClock,
        policy: &HostedSpineCostPolicy,
        trigger: HostedSpinePassTrigger,
    ) -> HostedSpinePassAdmission<'a> {
        let now = clock.now();
        let mut state = lock(&self.state);
        if state.in_flight.is_some() {
            return HostedSpinePassAdmission::InFlight(HostedSpinePassWaiter {
                receiver: self.finished.subscribe(),
                seen: state.finished_passes,
            });
        }
        if let Some(deferral) = Self::deferral(&state, now, policy) {
            return HostedSpinePassAdmission::Deferred(deferral);
        }
        state.in_flight = Some((trigger, now));
        HostedSpinePassAdmission::Lead(HostedSpinePassLease {
            limiter: self,
            clock,
            settled: false,
        })
    }

    fn deferral(
        state: &LimiterState,
        now: Instant,
        policy: &HostedSpineCostPolicy,
    ) -> Option<HostedSpinePassDeferral> {
        let gap = if state.last_refused_before_hydration {
            policy.failed_pass_retry_floor
        } else {
            policy.gap_after(state.consecutive_failures)
        };
        let allowed_at = state.last_finished? + gap;
        (now < allowed_at).then(|| HostedSpinePassDeferral {
            retry_in: allowed_at - now,
            consecutive_failures: state.consecutive_failures,
            last_failure: state.last_failure.clone(),
            last_refused_before_hydration: state.last_refused_before_hydration,
        })
    }

    /// When the limited pass running now was admitted, if one is running.
    /// While it runs, the cache may already hold the generation it is loading
    /// beside a proof for the one before, so no verdict taken before it began
    /// may answer.
    pub(crate) fn in_flight_since(&self) -> Option<Instant> {
        lock(&self.state).in_flight.map(|(_, since)| since)
    }

    /// Whether the last limited pass stopped before hydrating.
    pub(crate) fn last_refused_before_hydration(&self) -> bool {
        lock(&self.state).last_refused_before_hydration
    }

    /// Why the last limited pass did not prove, if it did not.
    pub(crate) fn last_failure(&self) -> Option<String> {
        lock(&self.state).last_failure.clone()
    }

    /// How long until a pass would be admitted, if it would not be now.
    pub(crate) fn retry_in(
        &self,
        clock: &HostedSpineClock,
        policy: &HostedSpineCostPolicy,
    ) -> Option<Duration> {
        let now = clock.now();
        let state = lock(&self.state);
        Self::deferral(&state, now, policy).map(|deferral| deferral.retry_in)
    }

    /// An authority transition proved the fleet, so the failures before it say
    /// nothing about the next pass.
    pub(crate) fn record_transition(&self, succeeded: bool) {
        if succeeded {
            let mut state = lock(&self.state);
            state.consecutive_failures = 0;
            state.last_failure = None;
            state.last_refused_before_hydration = false;
        }
    }

    pub(crate) fn consecutive_failures(&self) -> u32 {
        lock(&self.state).consecutive_failures
    }
}

/// One cached verdict, the key it was taken under, and when.
struct StoredVerdict<K, R> {
    checked_at: Instant,
    key: K,
    outcome: std::result::Result<(), R>,
}

/// The last cached-authority verdict, and the single flight that refreshes it.
///
/// `K` is everything local the verdict depended on; a lookup whose current
/// key differs misses. `R` is the refusal it carries.
pub(crate) struct HostedSpineVerdictCache<K, R> {
    slot: Mutex<Option<StoredVerdict<K, R>>>,
    refresh: tokio::sync::Mutex<()>,
}

impl<K, R> Default for HostedSpineVerdictCache<K, R> {
    fn default() -> Self {
        Self {
            slot: Mutex::new(None),
            refresh: tokio::sync::Mutex::new(()),
        }
    }
}

impl<K: Clone, R: Clone> HostedSpineVerdictCache<K, R> {
    /// The cached verdict, if it is younger than the TTL `used_for` allows, was
    /// taken no earlier than `not_before`, and `is_current` accepts the key it
    /// was taken under.
    pub(crate) fn fresh(
        &self,
        now: Instant,
        policy: &HostedSpineCostPolicy,
        used_for: HostedSpineVerdictUse,
        not_before: Option<Instant>,
        is_current: impl FnOnce(&K) -> bool,
    ) -> Option<std::result::Result<(), R>> {
        let (key, outcome) = {
            let slot = lock(&self.slot);
            let stored = slot.as_ref()?;
            if not_before.is_some_and(|since| stored.checked_at < since) {
                return None;
            }
            let age = now.saturating_duration_since(stored.checked_at);
            if age >= policy.verdict_ttl(used_for, stored.outcome.is_ok()) {
                return None;
            }
            (stored.key.clone(), stored.outcome.clone())
        };
        // Compared outside the slot lock, so the caller may take its own.
        is_current(&key).then_some(outcome)
    }

    /// Record a verdict. `checked_at` and `key` must be read BEFORE the check
    /// ran, so a change that lands during the check leaves a stale key behind
    /// and the next lookup misses.
    pub(crate) fn store(&self, checked_at: Instant, key: K, outcome: std::result::Result<(), R>) {
        *lock(&self.slot) = Some(StoredVerdict {
            checked_at,
            key,
            outcome,
        });
    }

    /// Serialize re-checks. Take it while holding the publication read gate,
    /// never before, so every path acquires the two in the same order.
    pub(crate) async fn refresh_turn(&self) -> tokio::sync::MutexGuard<'_, ()> {
        self.refresh.lock().await
    }
}

/// The publication gate, and a count of the writers that have held it.
///
/// Readers hold the gate across an authority read and writers hold it across a
/// transition. A verdict taken before a write says nothing about the state
/// after it, so the verdict cache keys on [`Self::write_generation`].
pub(crate) struct SpineRefreshGate {
    lock: tokio::sync::RwLock<()>,
    writes: AtomicU64,
}

/// A writer's hold on the gate. The generation moves when it is released,
/// while the lock is still held, so no reader can see the old generation after
/// the write.
pub(crate) struct SpineRefreshWriteGuard<'a> {
    _guard: tokio::sync::RwLockWriteGuard<'a, ()>,
    writes: &'a AtomicU64,
}

impl Drop for SpineRefreshWriteGuard<'_> {
    fn drop(&mut self) {
        self.writes.fetch_add(1, Ordering::SeqCst);
    }
}

impl Default for SpineRefreshGate {
    fn default() -> Self {
        Self {
            lock: tokio::sync::RwLock::new(()),
            writes: AtomicU64::new(0),
        }
    }
}

impl SpineRefreshGate {
    pub(crate) async fn read(&self) -> tokio::sync::RwLockReadGuard<'_, ()> {
        self.lock.read().await
    }

    pub(crate) async fn write(&self) -> SpineRefreshWriteGuard<'_> {
        SpineRefreshWriteGuard {
            _guard: self.lock.write().await,
            writes: &self.writes,
        }
    }

    pub(crate) fn write_generation(&self) -> u64 {
        self.writes.load(Ordering::SeqCst)
    }
}

#[derive(Debug, Clone)]
struct LastPass {
    trigger: HostedSpinePassTrigger,
    succeeded: bool,
    duration: Duration,
    document_reads: Option<u64>,
    finished_at: Instant,
}

/// Monotonic counters for everything the hosted spine authority spends.
#[derive(Debug, Default)]
pub(crate) struct HostedSpineCostCounters {
    full_passes_background: AtomicU64,
    full_passes_request: AtomicU64,
    full_passes_direct: AtomicU64,
    full_passes_transition: AtomicU64,
    full_passes_failed: AtomicU64,
    full_passes_deferred: AtomicU64,
    full_passes_shared: AtomicU64,
    completeness_repairs: AtomicU64,
    refused_before_hydration: AtomicU64,
    identity_checks: AtomicU64,
    verdict_cache_hits: AtomicU64,
    last_pass: Mutex<Option<LastPass>>,
}

impl HostedSpineCostCounters {
    pub(crate) fn record_full_pass(
        &self,
        trigger: HostedSpinePassTrigger,
        succeeded: bool,
        duration: Duration,
        document_reads: Option<u64>,
        finished_at: Instant,
    ) {
        let counter = match trigger {
            HostedSpinePassTrigger::Background => &self.full_passes_background,
            HostedSpinePassTrigger::Request => &self.full_passes_request,
            HostedSpinePassTrigger::Direct => &self.full_passes_direct,
            HostedSpinePassTrigger::Transition => &self.full_passes_transition,
        };
        counter.fetch_add(1, Ordering::Relaxed);
        if !succeeded {
            self.full_passes_failed.fetch_add(1, Ordering::Relaxed);
        }
        *lock(&self.last_pass) = Some(LastPass {
            trigger,
            succeeded,
            duration,
            document_reads,
            finished_at,
        });
    }

    pub(crate) fn record_deferred(&self) {
        self.full_passes_deferred.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_refused_before_hydration(&self) {
        self.refused_before_hydration
            .fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_completeness_repair(&self) {
        self.completeness_repairs.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_shared(&self) {
        self.full_passes_shared.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_identity_check(&self) {
        self.identity_checks.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_verdict_cache_hit(&self) {
        self.verdict_cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn full_passes(&self) -> u64 {
        [
            &self.full_passes_background,
            &self.full_passes_request,
            &self.full_passes_direct,
            &self.full_passes_transition,
        ]
        .iter()
        .map(|counter| counter.load(Ordering::Relaxed))
        .sum()
    }
}

/// Full passes counted by who asked for them.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostedSpinePassCounts {
    pub background: u64,
    pub request: u64,
    pub direct: u64,
    pub transition: u64,
}

/// The most recent full pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostedSpinePassReport {
    pub trigger: String,
    pub succeeded: bool,
    pub duration_ms: u64,
    /// Billable Firestore document reads the store made while the pass ran.
    /// Reads other callers made at the same moment land here too, so this is
    /// an upper bound for the pass alone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firestore_document_reads: Option<u64>,
    pub finished_seconds_ago: u64,
}

/// What the hosted spine authority has cost this process, as `/health`
/// reports it under `spine_cost`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostedSpineCostReport {
    /// `KIN_DISABLE_SPINE` is set, so nothing below should move.
    pub spine_disabled: bool,
    /// Full authority passes run: one Firestore cache hydration plus the fleet
    /// double-collect each, and the expensive half of this report.
    pub full_passes: u64,
    pub full_passes_by_trigger: HostedSpinePassCounts,
    pub full_passes_failed: u64,
    /// Callers refused a full pass: too soon after the last one, or, for a
    /// caller that cannot wait, while one was already running.
    pub full_passes_deferred: u64,
    /// Callers that waited for a pass another caller was already running.
    pub full_passes_shared: u64,
    /// Background full passes asked for only because the cache lost its edge
    /// authority while durable identity stayed put; at most one per
    /// `COMPLETENESS_REPAIR_FLOOR`.
    #[serde(default)]
    pub completeness_repairs: u64,
    /// Passes that stopped before reading a committed row, because a committed
    /// head was missing or a source cursor was not its head's. A head listing
    /// each, not a hydration; not counted in `full_passes`.
    #[serde(default)]
    pub refused_before_hydration: u64,
    /// Cheap durable identity checks run by readiness, spine health and the
    /// background cadence: 2 + 2N Firestore document reads each.
    pub identity_checks: u64,
    /// Readiness and spine health answers served from a cached verdict.
    pub verdict_cache_hits: u64,
    /// Failed full passes in a row right now; each doubles the wait before
    /// the next.
    pub consecutive_failed_passes: u32,
    /// How long until the rate limit would admit a full pass, when it would
    /// refuse one now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_full_pass_in_ms: Option<u64>,
    /// What the Firestore store has read, counted the way Firestore bills it.
    /// Absent until the durable backend is constructed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub firestore: Option<kin_spine::DurableReadStats>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_full_pass: Option<HostedSpinePassReport>,
}

/// Everything above, owned by one daemon state.
pub(crate) struct HostedSpineCost<K, R> {
    policy: HostedSpineCostPolicy,
    pub(crate) clock: HostedSpineClock,
    pub(crate) limiter: HostedSpinePassLimiter,
    pub(crate) counters: HostedSpineCostCounters,
    pub(crate) verdicts: HostedSpineVerdictCache<K, R>,
    last_summary: Mutex<Option<Instant>>,
    last_completeness_repair: Mutex<Option<Instant>>,
}

impl<K, R> Default for HostedSpineCost<K, R> {
    fn default() -> Self {
        Self {
            policy: HostedSpineCostPolicy::PRODUCTION,
            clock: HostedSpineClock::default(),
            limiter: HostedSpinePassLimiter::default(),
            counters: HostedSpineCostCounters::default(),
            verdicts: HostedSpineVerdictCache::default(),
            last_summary: Mutex::new(None),
            last_completeness_repair: Mutex::new(None),
        }
    }
}

impl<K, R> HostedSpineCost<K, R> {
    pub(crate) fn policy(&self) -> HostedSpineCostPolicy {
        self.policy
    }

    /// Admit a full pass under the current policy.
    pub(crate) fn admit(&self, trigger: HostedSpinePassTrigger) -> HostedSpinePassAdmission<'_> {
        let policy = self.policy();
        self.limiter.admit(&self.clock, &policy, trigger)
    }

    pub(crate) fn retry_in(&self) -> Option<Duration> {
        let policy = self.policy();
        self.limiter.retry_in(&self.clock, &policy)
    }

    /// Whether the periodic cost summary is due, and if so, claim it.
    /// Whether a completeness repair may run now, and if so, claim it. A claim
    /// is spent even when the pass limiter then defers the pass, so repairs
    /// never run more often than `COMPLETENESS_REPAIR_FLOOR`.
    pub(crate) fn claim_completeness_repair(&self) -> bool {
        let now = self.clock.now();
        let mut last = lock(&self.last_completeness_repair);
        if last.is_some_and(|previous| {
            now.saturating_duration_since(previous) < COMPLETENESS_REPAIR_FLOOR
        }) {
            return false;
        }
        *last = Some(now);
        self.counters.record_completeness_repair();
        true
    }

    pub(crate) fn claim_summary(&self, now: Instant) -> bool {
        let mut last = lock(&self.last_summary);
        match *last {
            Some(previous) if now.saturating_duration_since(previous) < COST_SUMMARY_INTERVAL => {
                false
            }
            Some(_) => {
                *last = Some(now);
                true
            }
            None => {
                // The first call starts the interval; a summary of a process
                // that has only just started says nothing.
                *last = Some(now);
                false
            }
        }
    }

    pub(crate) fn report(
        &self,
        spine_disabled: bool,
        firestore: Option<kin_spine::DurableReadStats>,
    ) -> HostedSpineCostReport {
        let counters = &self.counters;
        let now = self.clock.now();
        let load = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        let last_full_pass = lock(&counters.last_pass)
            .as_ref()
            .map(|pass| HostedSpinePassReport {
                trigger: pass.trigger.as_str().to_string(),
                succeeded: pass.succeeded,
                duration_ms: u64::try_from(pass.duration.as_millis()).unwrap_or(u64::MAX),
                firestore_document_reads: pass.document_reads,
                finished_seconds_ago: now.saturating_duration_since(pass.finished_at).as_secs(),
            });
        HostedSpineCostReport {
            spine_disabled,
            full_passes: counters.full_passes(),
            full_passes_by_trigger: HostedSpinePassCounts {
                background: load(&counters.full_passes_background),
                request: load(&counters.full_passes_request),
                direct: load(&counters.full_passes_direct),
                transition: load(&counters.full_passes_transition),
            },
            full_passes_failed: load(&counters.full_passes_failed),
            full_passes_deferred: load(&counters.full_passes_deferred),
            full_passes_shared: load(&counters.full_passes_shared),
            completeness_repairs: load(&counters.completeness_repairs),
            refused_before_hydration: load(&counters.refused_before_hydration),
            identity_checks: load(&counters.identity_checks),
            verdict_cache_hits: load(&counters.verdict_cache_hits),
            consecutive_failed_passes: self.limiter.consecutive_failures(),
            next_full_pass_in_ms: self
                .retry_in()
                .map(|wait| u64::try_from(wait.as_millis()).unwrap_or(u64::MAX)),
            firestore,
            last_full_pass,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy() -> HostedSpineCostPolicy {
        HostedSpineCostPolicy::PRODUCTION
    }

    #[test]
    fn a_failing_pass_backs_off_by_doubling_to_the_cap_and_a_success_resets_to_the_floor() {
        let policy = policy();
        assert_eq!(policy.gap_after(0), FULL_PASS_FLOOR);
        assert_eq!(policy.gap_after(1), FAILED_PASS_RETRY_FLOOR);
        assert_eq!(policy.gap_after(2), FAILED_PASS_RETRY_FLOOR * 2);
        assert_eq!(policy.gap_after(3), FAILED_PASS_RETRY_FLOOR * 4);
        assert_eq!(policy.gap_after(7), FAILED_PASS_BACKOFF_CAP);
        assert_eq!(
            policy.gap_after(u32::MAX),
            FAILED_PASS_BACKOFF_CAP,
            "the cap holds however long the failure lasts, with no overflow"
        );
    }

    #[test]
    fn the_limiter_admits_one_pass_at_a_time_and_none_inside_the_floor() {
        let clock = HostedSpineClock::default();
        let limiter = HostedSpinePassLimiter::default();
        let policy = policy();

        let HostedSpinePassAdmission::Lead(lease) =
            limiter.admit(&clock, &policy, HostedSpinePassTrigger::Background)
        else {
            panic!("an idle limiter must admit the first pass");
        };
        assert!(limiter.in_flight_since().is_some());
        assert!(
            matches!(
                limiter.admit(&clock, &policy, HostedSpinePassTrigger::Request),
                HostedSpinePassAdmission::InFlight(_)
            ),
            "a second caller must wait for the running pass, not start its own"
        );
        lease.finish(HostedSpinePassEnd::Proved);
        assert!(limiter.in_flight_since().is_none());

        let HostedSpinePassAdmission::Deferred(deferral) =
            limiter.admit(&clock, &policy, HostedSpinePassTrigger::Request)
        else {
            panic!("a pass right after a successful one must be refused");
        };
        assert!(deferral.retry_in <= FULL_PASS_FLOOR);
        assert!(deferral.reason().contains("rate limited"));

        clock.advance(FULL_PASS_FLOOR);
        assert!(
            matches!(
                limiter.admit(&clock, &policy, HostedSpinePassTrigger::Request),
                HostedSpinePassAdmission::Lead(_)
            ),
            "the floor is a wait, not a ban"
        );
    }

    #[test]
    fn a_dropped_lease_counts_as_a_failed_pass_and_releases_the_limiter() {
        let clock = HostedSpineClock::default();
        let limiter = HostedSpinePassLimiter::default();
        let policy = policy();
        match limiter.admit(&clock, &policy, HostedSpinePassTrigger::Direct) {
            HostedSpinePassAdmission::Lead(lease) => drop(lease),
            _ => panic!("an idle limiter must admit the first pass"),
        }
        assert!(
            limiter.in_flight_since().is_none(),
            "an unwound pass must not wedge the limiter"
        );
        assert_eq!(limiter.consecutive_failures(), 1);
        let HostedSpinePassAdmission::Deferred(deferral) =
            limiter.admit(&clock, &policy, HostedSpinePassTrigger::Direct)
        else {
            panic!("a failed pass is retried after the retry floor, not at once");
        };
        assert!(deferral.retry_in <= FAILED_PASS_RETRY_FLOOR);
        assert!(deferral
            .reason()
            .contains("ended without reporting an outcome"));

        limiter.record_transition(true);
        assert_eq!(
            limiter.consecutive_failures(),
            0,
            "a transition that proved the fleet clears the failure streak"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_waiter_returns_once_the_running_pass_finishes() {
        let clock = HostedSpineClock::default();
        let limiter = std::sync::Arc::new(HostedSpinePassLimiter::default());
        let policy = policy();
        let lease = match limiter.admit(&clock, &policy, HostedSpinePassTrigger::Background) {
            HostedSpinePassAdmission::Lead(lease) => lease,
            _ => panic!("an idle limiter must admit the first pass"),
        };
        let HostedSpinePassAdmission::InFlight(waiter) =
            limiter.admit(&clock, &policy, HostedSpinePassTrigger::Request)
        else {
            panic!("the second caller must be told to wait");
        };
        let waiting = tokio::spawn(waiter.wait());
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !waiting.is_finished(),
            "the waiter returned before the pass ended"
        );
        lease.finish(HostedSpinePassEnd::Failed("injected".to_string()));
        tokio::time::timeout(Duration::from_secs(5), waiting)
            .await
            .expect("the waiter must return once the pass it waited on finishes")
            .unwrap();
    }

    #[test]
    fn a_verdict_misses_past_its_ttl_and_when_its_key_moved() {
        use HostedSpineVerdictUse::{Query, Readiness};
        let clock = HostedSpineClock::default();
        let cache = HostedSpineVerdictCache::<u64, String>::default();
        let policy = policy();
        let taken = clock.now();
        cache.store(taken, 7, Ok(()));
        assert_eq!(
            cache.fresh(clock.now(), &policy, Readiness, None, |key| *key == 7),
            Some(Ok(()))
        );
        assert_eq!(
            cache.fresh(clock.now(), &policy, Readiness, None, |key| *key == 8),
            None,
            "a verdict taken under another key must not answer"
        );
        assert_eq!(
            cache.fresh(
                clock.now(),
                &policy,
                Readiness,
                Some(taken + Duration::from_millis(1)),
                |key| *key == 7
            ),
            None,
            "a verdict taken before a running pass began must not answer"
        );
        clock.advance(QUERY_VERDICT_TTL);
        assert_eq!(
            cache.fresh(clock.now(), &policy, Query, None, |key| *key == 7),
            None,
            "an authenticated read may use a verdict only for the short query TTL"
        );
        assert_eq!(
            cache.fresh(clock.now(), &policy, Readiness, None, |key| *key == 7),
            Some(Ok(())),
            "readiness may use the same verdict for longer"
        );
        clock.advance(READY_VERDICT_TTL);
        assert_eq!(
            cache.fresh(clock.now(), &policy, Readiness, None, |key| *key == 7),
            None,
            "a ready verdict past its TTL must not answer"
        );

        cache.store(clock.now(), 7, Err("refused".to_string()));
        clock.advance(REFUSED_VERDICT_TTL - Duration::from_millis(1));
        assert_eq!(
            cache.fresh(clock.now(), &policy, Readiness, None, |key| *key == 7),
            Some(Err("refused".to_string()))
        );
        clock.advance(Duration::from_millis(1));
        assert_eq!(
            cache.fresh(clock.now(), &policy, Readiness, None, |key| *key == 7),
            None,
            "a refusal lives only its own, shorter TTL"
        );
    }

    #[test]
    fn a_pass_refused_before_hydrating_is_retried_at_the_floor_without_doubling() {
        let clock = HostedSpineClock::default();
        let limiter = HostedSpinePassLimiter::default();
        let policy = policy();
        for _ in 0..5 {
            let HostedSpinePassAdmission::Lead(lease) =
                limiter.admit(&clock, &policy, HostedSpinePassTrigger::Background)
            else {
                panic!("a cheap refusal must be retried at the retry floor, every time");
            };
            lease.finish(HostedSpinePassEnd::RefusedBeforeHydration(
                "repo kin-db source cursor is ahead of its committed head".to_string(),
            ));
            let HostedSpinePassAdmission::Deferred(deferral) =
                limiter.admit(&clock, &policy, HostedSpinePassTrigger::Background)
            else {
                panic!("a retry inside the floor must be refused");
            };
            assert!(deferral.retry_in <= FAILED_PASS_RETRY_FLOOR);
            assert!(deferral.reason().contains("stopped before hydrating"));
            clock.advance(FAILED_PASS_RETRY_FLOOR);
        }
        assert_eq!(
            limiter.consecutive_failures(),
            0,
            "a refusal before hydrating is not a costly failure and must not escalate"
        );
    }

    #[tokio::test]
    async fn releasing_the_write_gate_moves_its_generation() {
        let gate = SpineRefreshGate::default();
        assert_eq!(gate.write_generation(), 0);
        drop(gate.read().await);
        assert_eq!(gate.write_generation(), 0, "a reader moves nothing");
        drop(gate.write().await);
        assert_eq!(gate.write_generation(), 1);
    }
}
