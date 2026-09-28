// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The daemon binding a launcher performs in the background at startup.
//!
//! `kin mcp start` used to resolve (and, cold, spawn and wait for) its repo
//! daemon before reading a single byte of stdio, so a client saw no frames at
//! all until the daemon served, without even the `initialize` response. On a
//! flagship-scale store that is minutes of silence against handshake probes
//! measured in seconds. The stdio server needs no daemon for `initialize` or
//! `tools/list`; only `tools/call` does.
//!
//! This type is the seam between the two: the launcher starts the stdio loop
//! immediately, runs the binding on a background task, and publishes its
//! progress here. The server consults it on `tools/call`, waiting for the bind
//! within the call's own readiness budget and reporting how far the daemon has
//! come while it waits. Only a budget that runs out gets the honest answer
//! that the daemon is still starting, never a hang and never a failure as if
//! no daemon could ever exist.
//!
//! The handle carries a second gate for the same reason it carries the first.
//! Moving the bind behind the loop made the handshake fast; it did not make it
//! free. A bind that resolves cold STARTS a daemon, and a daemon that starts
//! opens the store and schedules the background embedding pass, so a session
//! that asked Kin nothing was paying minutes of CPU or GPU and gigabytes of
//! resident memory for a repository nobody had queried (FIR-3099: 1.80 GiB and
//! 99 percent of a core sixty seconds after a handshake, on a 657.8 KiB store).
//! So spawning is admitted rather than assumed: the launcher may attach to a
//! daemon that is already serving, which costs nothing, and waits here for the
//! server to admit a spawn. The server admits it on the first `tools/call`,
//! which is the first moment a caller has actually asked for a graph answer.
//!
//! This crate is an answer surface under the zero-file-search rule and carries
//! no filesystem primitive. The startup-phase detail in the still-starting
//! report comes from a probe the launcher injects; the daemon-lifecycle IO
//! behind that probe lives in the launcher's declared IO boundary.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::server::BoundRepo;

/// Where the launcher's startup daemon binding currently stands.
#[derive(Debug, Clone)]
pub enum StartupBindingState {
    /// The binding task is still resolving, spawning, or waiting on a daemon.
    Pending,
    /// A daemon is bound and `tools/call` forwarding can proceed.
    Bound(BoundRepo),
    /// The binding settled without a daemon. `tools/call` falls through to the
    /// ordinary daemon-unavailable handling, which names the remedy.
    Unbound {
        /// Why nothing bound, for the launcher's stderr log; tool results keep
        /// using the standard unavailable message, which is remedy-focused.
        #[allow(dead_code)]
        reason: String,
    },
}

/// How far a starting daemon has come, as the launcher can observe it.
///
/// Two facts, both the daemon's own: the phase its lifecycle markers put it
/// in, and what its last complete open of this store cost, which it recorded
/// itself when that open finished. The second is the only measure of "how
/// far" there is before the daemon publishes an endpoint, because a daemon
/// answers nothing until it does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StartupProgress {
    /// What the daemon's startup is doing now.
    pub phase: &'static str,
    /// What the last complete open of this store cost, when one is recorded.
    pub last_open: Option<Duration>,
}

impl StartupProgress {
    /// Progress for a phase alone, with no recorded open to compare against.
    pub const fn phase(phase: &'static str) -> Self {
        Self {
            phase,
            last_open: None,
        }
    }
}

/// How the launcher answers "how far has the starting daemon come" for the
/// still-starting report. Injected rather than computed here: the phase is
/// read from the daemon's lifecycle markers, and that filesystem IO belongs to
/// the launcher's daemon-lifecycle boundary, not to this crate.
pub type StartupPhaseProbe = Box<dyn Fn() -> StartupProgress + Send + Sync>;

/// Handle shared between the launcher's background binding task and the stdio
/// server loop.
///
/// The launcher creates it `Pending`, hands one clone to the binding task and
/// one to the server, and the task settles it exactly once. The server only
/// ever reads it, plus a bounded wait so a warm daemon that binds in
/// milliseconds is never reported as still starting.
pub struct StartupDaemonBinding {
    state: tokio::sync::watch::Sender<StartupBindingState>,
    /// The launcher-injected startup-phase probe, once the binding task knows
    /// which repository it is binding.
    phase_probe: Mutex<Option<StartupPhaseProbe>>,
    /// Whether an operator pin (`--repo`/`KIN_MCP_REPO`) bound successfully.
    /// The workspace-roots binder must not repoint such a binding, and with the
    /// bind running behind the loop this is only known once it settles.
    pinned_by_operator: AtomicBool,
    /// Whether a caller has asked for a graph answer yet, which is what admits
    /// starting a daemon for this repository. A watch channel rather than a
    /// flag because the launcher's binding task waits on it.
    spawn_admitted: tokio::sync::watch::Sender<bool>,
    /// When a caller first asked for a graph answer, which is when the daemon
    /// this server waits on was asked for.
    admitted_at: Mutex<Option<Instant>>,
    began: Instant,
}

impl std::fmt::Debug for StartupDaemonBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StartupDaemonBinding")
            .field("state", &*self.state.borrow())
            .field("pinned_by_operator", &self.pinned_by_operator())
            .field("daemon_spawn_admitted", &self.daemon_spawn_admitted())
            .finish_non_exhaustive()
    }
}

impl StartupDaemonBinding {
    pub fn new() -> std::sync::Arc<Self> {
        let (state, _) = tokio::sync::watch::channel(StartupBindingState::Pending);
        std::sync::Arc::new(Self {
            state,
            phase_probe: Mutex::new(None),
            pinned_by_operator: AtomicBool::new(false),
            spawn_admitted: tokio::sync::watch::channel(false).0,
            admitted_at: Mutex::new(None),
            began: Instant::now(),
        })
    }

    /// Install the launcher's startup-phase probe for the repository being
    /// bound, so the not-ready report can say how far that daemon's startup
    /// has come. Re-installable: registry mode retargets the report when it
    /// picks a different repository than the launch directory.
    pub fn set_phase_probe(&self, probe: StartupPhaseProbe) {
        if let Ok(mut guard) = self.phase_probe.lock() {
            *guard = Some(probe);
        }
    }

    /// Record that `--repo`/`KIN_MCP_REPO` names a repository this process can
    /// see, before its daemon has been resolved.
    ///
    /// The pin used to be published only by `resolve_bound`, which meant it was
    /// unknown until the daemon bound. That was already a race with the
    /// client's `roots/list` answer, and deferring the daemon start until the
    /// first `tools/call` would have widened it into the normal case: on a cold
    /// repository the roots answer ALWAYS arrives first, and a binder reading
    /// `false` here is free to follow the client off the repository the
    /// operator pinned. A pin that names no repository still does not count,
    /// which is the distinction this keeps.
    pub fn note_operator_pin(&self) {
        self.pinned_by_operator.store(true, Ordering::Release);
    }

    /// Settle the binding with a bound daemon. `pinned_by_operator` marks a
    /// successful `--repo`/`KIN_MCP_REPO` bind, which workspace roots must
    /// never repoint.
    ///
    /// `send_replace`, not `send`: a plain watch send fails when no receiver
    /// is subscribed, and this channel routinely has none, because the server
    /// only subscribes while a `tools/call` is actually waiting. A settle must
    /// never be lost to that.
    pub fn resolve_bound(&self, bound: BoundRepo, pinned_by_operator: bool) {
        self.pinned_by_operator
            .store(pinned_by_operator, Ordering::Release);
        self.state.send_replace(StartupBindingState::Bound(bound));
    }

    /// Settle the binding without a daemon.
    pub fn resolve_unbound(&self, reason: impl Into<String>) {
        self.state.send_replace(StartupBindingState::Unbound {
            reason: reason.into(),
        });
    }

    /// Record that a caller has asked for a graph answer, which admits starting
    /// a daemon for this repository.
    ///
    /// Called by the stdio loop on `tools/call` and by nothing else: the
    /// handshake, the tool list and the client's workspace roots are all things
    /// a client sends before it has asked Kin anything, and none of them is a
    /// reason to open a store and start an embedding pass. Idempotent, and
    /// `send_replace` rather than `send` for the same reason the state channel
    /// uses it: there is usually no subscriber, because the launcher's binding
    /// task subscribes only while it is actually waiting.
    ///
    /// Returns whether this call was the FIRST admission. That call is the one
    /// that starts the daemon, so it is the only one that can be waiting on a
    /// cold open rather than on a daemon somebody else already paid for, and
    /// the caller sizes its wait against the answer.
    pub fn admit_daemon_spawn(&self) -> bool {
        let first = !self.spawn_admitted.send_replace(true);
        if first {
            if let Ok(mut admitted_at) = self.admitted_at.lock() {
                admitted_at.get_or_insert_with(Instant::now);
            }
        }
        first
    }

    /// Whether a `tools/call` has admitted starting a daemon.
    ///
    /// Read by every bind path that could start one, including the
    /// workspace-roots binder, which runs inline in the stdio loop and so must
    /// ask rather than wait.
    pub fn daemon_spawn_admitted(&self) -> bool {
        *self.spawn_admitted.borrow()
    }

    /// Resolve once a `tools/call` has admitted starting a daemon.
    ///
    /// For the launcher's background binding task, which has somewhere to wait.
    /// Returns immediately when admission already happened.
    pub async fn await_daemon_spawn_admission(&self) {
        let mut receiver = self.spawn_admitted.subscribe();
        loop {
            if *receiver.borrow_and_update() {
                return;
            }
            if receiver.changed().await.is_err() {
                // The sender lives in this same struct, so this arm is
                // unreachable while `self` is alive. Returning rather than
                // spinning keeps a future refactor from wedging the binder.
                return;
            }
        }
    }

    pub fn pinned_by_operator(&self) -> bool {
        self.pinned_by_operator.load(Ordering::Acquire)
    }

    /// The current state, cloned out of the watch channel.
    pub fn snapshot(&self) -> StartupBindingState {
        self.state.borrow().clone()
    }

    fn is_settled(&self) -> bool {
        !matches!(*self.state.borrow(), StartupBindingState::Pending)
    }

    /// Wait up to `grace` for the binding to settle. Returns whether it did.
    ///
    /// Returns the instant the binding settles, so a warm daemon that binds in
    /// well under a second costs a caller nothing. The server calls this in
    /// short steps across a call's whole readiness budget, reporting progress
    /// between them.
    pub async fn wait_until_settled(&self, grace: Duration) -> bool {
        if self.is_settled() {
            return true;
        }
        let mut receiver = self.state.subscribe();
        let settled = tokio::time::timeout(grace, async {
            loop {
                if !matches!(*receiver.borrow_and_update(), StartupBindingState::Pending) {
                    return;
                }
                if receiver.changed().await.is_err() {
                    // The sender lives in this same struct, so this arm is
                    // unreachable while `self` is alive; return rather than
                    // spin if it ever is not.
                    return;
                }
            }
        })
        .await;
        settled.is_ok() && self.is_settled()
    }

    /// The honest account of a `tools/call` whose readiness budget ran out
    /// while the binding was still pending: what is still loading, how far
    /// along it is, how long this call waited before saying so, and what the
    /// caller should do (retry, not remediate).
    ///
    /// `waited` is stated rather than left to be inferred, so a reader can
    /// tell a call that gave the daemon its whole budget from one that did
    /// not, and knows which knob widens it. The `(<phase>; <n>s so far)`
    /// detail keeps its shape, because callers read the phase and the elapsed
    /// seconds out of it.
    pub fn starting_report(&self, tool: &str, waited: Duration) -> String {
        let (progress, elapsed) = self.progress_and_elapsed();
        format!(
            "kin-mcp cannot answer '{tool}' yet: the repo daemon is still starting \
             ({}; {}s so far), {}. This call waited {}s for it, its whole readiness budget. \
             The MCP transport is up and `initialize` and `tools/list` are served; retry this \
             call and it waits again from where the daemon has got to, or raise {} to let one \
             call wait longer. This is startup latency, not a failure: do not restart the MCP \
             server or re-run `kin init`.",
            progress.phase,
            elapsed.as_secs(),
            yardstick(elapsed, progress.last_open),
            waited.as_secs(),
            crate::daemon_delegate::DAEMON_PATIENCE_ENV,
        )
    }

    /// One line on how far the daemon this server is waiting on has come, for
    /// a progress notification while a call waits.
    pub fn progress_line(&self) -> String {
        let (progress, elapsed) = self.progress_and_elapsed();
        format!(
            "{}; {}",
            progress.phase,
            how_far(elapsed, progress.last_open)
        )
    }

    /// The probe's reading, and how long it has been since a caller first
    /// asked for a daemon (or since this server started, before one has).
    fn progress_and_elapsed(&self) -> (StartupProgress, Duration) {
        let since = self
            .admitted_at
            .lock()
            .ok()
            .and_then(|admitted_at| *admitted_at)
            .unwrap_or(self.began);
        (self.startup_progress(), since.elapsed())
    }

    /// The daemon's startup progress from the launcher's injected probe, or
    /// the resolve phase while no probe is installed (nothing has named a
    /// repository to bind yet).
    fn startup_progress(&self) -> StartupProgress {
        if let Ok(guard) = self.phase_probe.lock() {
            if let Some(probe) = guard.as_ref() {
                return probe();
            }
        }
        StartupProgress::phase("phase: resolving which repository daemon to bind")
    }
}

/// How far a start that has run `elapsed` has come: the time so far, measured
/// against what the last open of the same store cost.
pub fn how_far(elapsed: Duration, last_open: Option<Duration>) -> String {
    format!(
        "{}s so far, {}",
        elapsed.as_secs(),
        yardstick(elapsed, last_open)
    )
}

/// `elapsed` against what the last open of the same store cost.
///
/// The comparison is labelled as one. The daemon publishes nothing until it
/// can serve, so the last open is the only yardstick there is, and a store can
/// open slower than last time (a busier machine, a larger graph); past the
/// yardstick the line says so rather than claiming a percentage over 100.
fn yardstick(elapsed: Duration, last_open: Option<Duration>) -> String {
    match last_open {
        Some(last) if !last.is_zero() && elapsed < last => format!(
            "about {}% of the {}s the last open of this store took",
            (elapsed.as_secs_f64() / last.as_secs_f64() * 100.0).floor() as u64,
            last.as_secs().max(1)
        ),
        Some(last) if !last.is_zero() => format!(
            "longer than the {}s the last open of this store took",
            last.as_secs().max(1)
        ),
        _ => "and this store has no recorded open to compare against".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[tokio::test(start_paused = true)]
    async fn a_pending_binding_reports_not_settled_after_the_grace() {
        let binding = StartupDaemonBinding::new();
        assert!(
            !binding.wait_until_settled(Duration::from_secs(10)).await,
            "a binding nobody settles must report unsettled once the grace elapses"
        );
        assert!(matches!(binding.snapshot(), StartupBindingState::Pending));
    }

    #[tokio::test(start_paused = true)]
    async fn a_binding_that_settles_mid_grace_is_seen_settling() {
        let binding = StartupDaemonBinding::new();
        let waiter = std::sync::Arc::clone(&binding);
        let wait =
            tokio::spawn(async move { waiter.wait_until_settled(Duration::from_secs(10)).await });
        tokio::time::sleep(Duration::from_millis(50)).await;
        binding.resolve_bound(
            BoundRepo {
                root: PathBuf::from("/repo"),
                daemon_url: "http://127.0.0.1:4242".to_string(),
            },
            true,
        );
        assert!(
            wait.await.unwrap(),
            "a settle during the grace must be observed as settled, not timed out"
        );
        assert!(binding.pinned_by_operator());
        assert!(matches!(
            binding.snapshot(),
            StartupBindingState::Bound(BoundRepo { .. })
        ));
    }

    #[tokio::test]
    async fn an_already_settled_binding_waits_for_nothing() {
        let binding = StartupDaemonBinding::new();
        binding.resolve_unbound("not a Kin repository");
        let began = Instant::now();
        assert!(binding.wait_until_settled(Duration::from_secs(30)).await);
        assert!(
            began.elapsed() < Duration::from_secs(5),
            "a settled binding must answer immediately, not sit out the grace"
        );
    }

    /// The whole of FIR-3099 in one assertion: nothing about creating a
    /// binding, settling it, or pinning it admits starting a daemon. Only a
    /// `tools/call` does, and the stdio loop is the only caller of
    /// `admit_daemon_spawn`.
    /// A pin is known as soon as the launch directory resolves, not when its
    /// daemon does, because the workspace-roots binder asks before then.
    #[test]
    fn an_operator_pin_is_published_before_its_daemon_binds() {
        let binding = StartupDaemonBinding::new();
        assert!(!binding.pinned_by_operator());
        binding.note_operator_pin();
        assert!(
            binding.pinned_by_operator(),
            "a pin must be readable while the binding is still pending, or a roots answer that \
             arrives first repoints the repository the operator named"
        );
        assert!(matches!(binding.snapshot(), StartupBindingState::Pending));
        // Settling later must not unset it.
        binding.resolve_bound(
            BoundRepo {
                root: PathBuf::from("/repo"),
                daemon_url: "http://127.0.0.1:4242".to_string(),
            },
            true,
        );
        assert!(binding.pinned_by_operator());
    }

    #[test]
    fn a_fresh_binding_does_not_admit_starting_a_daemon() {
        let binding = StartupDaemonBinding::new();
        assert!(
            !binding.daemon_spawn_admitted(),
            "a server that has been asked nothing must not admit starting a daemon"
        );
        binding.resolve_bound(
            BoundRepo {
                root: PathBuf::from("/repo"),
                daemon_url: "http://127.0.0.1:4242".to_string(),
            },
            true,
        );
        assert!(
            !binding.daemon_spawn_admitted(),
            "attaching to a daemon that was already serving is not a caller asking for one"
        );
        assert!(
            binding.admit_daemon_spawn(),
            "the first tool call to ask for a graph answer is the one that starts the daemon"
        );
        assert!(binding.daemon_spawn_admitted());
        assert!(
            !binding.admit_daemon_spawn(),
            "a second tool call is not paying for a cold start and must not claim it is"
        );
        assert!(
            binding.daemon_spawn_admitted(),
            "admission is idempotent: a second tool call must not unset it"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn the_binder_waits_for_admission_and_wakes_on_it() {
        let binding = StartupDaemonBinding::new();
        let waiter = std::sync::Arc::clone(&binding);
        let wait = tokio::spawn(async move { waiter.await_daemon_spawn_admission().await });
        tokio::time::sleep(Duration::from_secs(3600)).await;
        assert!(
            !wait.is_finished(),
            "with no tool call the binding task must still be waiting an hour later,              not have started a daemon"
        );
        binding.admit_daemon_spawn();
        wait.await.unwrap();
    }

    #[tokio::test]
    async fn admission_that_already_happened_is_not_waited_for() {
        let binding = StartupDaemonBinding::new();
        binding.admit_daemon_spawn();
        let began = Instant::now();
        binding.await_daemon_spawn_admission().await;
        assert!(
            began.elapsed() < Duration::from_secs(5),
            "an already-admitted spawn must not make the binder wait for a second call"
        );
    }

    #[test]
    fn the_starting_report_carries_the_injected_phase() {
        let binding = StartupDaemonBinding::new();
        // Before a probe is installed, the report still explains itself.
        let report = binding.starting_report("kin_graph_status", Duration::from_secs(300));
        assert!(
            report.contains("resolving which repository"),
            "with no probe the report carries the resolve phase: {report}"
        );
        assert!(
            report.contains("kin_graph_status") && report.contains("retry"),
            "the report must name the tool and the retry remedy: {report}"
        );
        assert!(
            report.contains("not a failure"),
            "the report must say this is startup latency, not a defect: {report}"
        );

        // The launcher's probe is read at report time, so the phase moves as
        // the daemon's startup does, not as of when the probe was installed.
        let phase = std::sync::Arc::new(Mutex::new(
            "phase: the daemon process is up and loading the repository graph",
        ));
        let probe_phase = std::sync::Arc::clone(&phase);
        binding.set_phase_probe(Box::new(move || {
            StartupProgress::phase(*probe_phase.lock().unwrap())
        }));
        assert!(binding
            .starting_report("kin_graph_status", Duration::from_secs(300))
            .contains("loading the repository graph"));

        *phase.lock().unwrap() = "phase: the daemon is listening and finishing readiness checks";
        assert!(binding
            .starting_report("kin_graph_status", Duration::from_secs(300))
            .contains("finishing readiness checks"));
    }

    /// The report names the wait this call spent and the knob that widens it,
    /// so a reader can tell a call that gave the daemon its whole budget from
    /// one that did not, and knows what to change.
    #[test]
    fn the_starting_report_states_the_budget_this_call_waited() {
        let binding = StartupDaemonBinding::new();
        let report = binding.starting_report("kin_graph_status", Duration::from_secs(300));
        assert!(
            report.contains("waited 300s") && report.contains("whole readiness budget"),
            "the wait has to be visible in the report: {report}"
        );
        assert!(
            report.contains(crate::daemon_delegate::DAEMON_PATIENCE_ENV),
            "the report must name the knob that lets a call wait longer: {report}"
        );
    }

    /// The phase and elapsed seconds sit in one parenthetical a caller can
    /// parse, as they always have, with the yardstick after it.
    #[test]
    fn the_starting_report_keeps_the_phase_and_elapsed_detail_callers_parse() {
        let binding = StartupDaemonBinding::new();
        binding.set_phase_probe(Box::new(|| StartupProgress {
            phase: "phase: the daemon process is up and loading the repository graph",
            last_open: Some(Duration::from_secs(600)),
        }));
        let report = binding.starting_report("find_references", Duration::from_secs(300));
        assert!(
            report.starts_with(
                "kin-mcp cannot answer 'find_references' yet: the repo daemon is still starting"
            ),
            "{report}"
        );
        let open = report
            .find("(phase: the daemon process is up and loading the repository graph; ")
            .expect("the phase opens the detail");
        let detail = &report[open..=open + report[open..].find(')').expect("detail closes")];
        let seconds = detail
            .rsplit("; ")
            .next()
            .and_then(|tail| tail.strip_suffix("s so far)"))
            .expect("the detail ends with the elapsed seconds");
        assert!(seconds.parse::<u64>().is_ok(), "{detail}");
        assert!(report.contains("of the 600s the last open of this store took"));
        assert!(report.contains("This is startup latency, not a failure"));
    }

    /// How far along a start is comes from the only yardstick a client has
    /// before the daemon answers: what the last open of the same store cost.
    #[test]
    fn how_far_a_start_has_come_is_measured_against_the_last_open() {
        let line = how_far(Duration::from_secs(90), Some(Duration::from_secs(360)));
        assert!(
            line.contains("90s") && line.contains("about 25%") && line.contains("360s"),
            "{line}"
        );
        let over = how_far(Duration::from_secs(400), Some(Duration::from_secs(360)));
        assert!(
            over.contains("longer than the 360s") && !over.contains('%'),
            "past the yardstick the line says so rather than claiming over 100%: {over}"
        );
        let unknown = how_far(Duration::from_secs(12), None);
        assert!(
            unknown.contains("12s") && unknown.contains("no recorded open"),
            "{unknown}"
        );
    }

    /// The progress line counts from the moment a caller asked for a daemon,
    /// and carries the probe's phase and yardstick.
    #[test]
    fn the_progress_line_carries_phase_and_yardstick() {
        let binding = StartupDaemonBinding::new();
        binding.set_phase_probe(Box::new(|| StartupProgress {
            phase: "phase: the daemon process is up and loading the repository graph",
            last_open: Some(Duration::from_secs(240)),
        }));
        binding.admit_daemon_spawn();
        let line = binding.progress_line();
        assert!(
            line.contains("loading the repository graph")
                && line.contains("of the 240s the last open of this store took"),
            "{line}"
        );
    }
}
