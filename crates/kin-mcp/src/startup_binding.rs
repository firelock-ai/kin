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
//! progress here. The server consults it on `tools/call`, giving a
//! fast-settling bind a bounded moment, then answering honestly that the
//! daemon is still starting instead of hanging or failing as if no daemon
//! could ever exist.
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

/// How the launcher answers "how far has the starting daemon come" for the
/// still-starting report. Injected rather than computed here: the phase is
/// read from the daemon's lifecycle markers, and that filesystem IO belongs to
/// the launcher's daemon-lifecycle boundary, not to this crate.
pub type StartupPhaseProbe = Box<dyn Fn() -> &'static str + Send + Sync>;

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
    began: Instant,
}

impl std::fmt::Debug for StartupDaemonBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StartupDaemonBinding")
            .field("state", &*self.state.borrow())
            .field("pinned_by_operator", &self.pinned_by_operator())
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
    /// The grace exists for the warm case: a daemon that is already serving
    /// binds in well under a second, and a `tools/call` racing that bind must
    /// get its real answer, not a spurious "still starting". A cold start does
    /// not fit any reasonable grace and is reported honestly instead.
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

    /// The honest account of a `tools/call` that arrived while the binding is
    /// still pending: what is happening, how long it has been happening, and
    /// what the caller should do (retry, not remediate).
    pub fn starting_report(&self, tool: &str) -> String {
        let phase = self.startup_phase();
        let elapsed = self.began.elapsed().as_secs();
        format!(
            "kin-mcp cannot answer '{tool}' yet: the repo daemon is still starting \
             ({phase}; {elapsed}s so far). The MCP transport is up and `initialize` and \
             `tools/list` are served; retry this call once the daemon is ready. Large \
             repositories can take minutes on a fully cold start. This is startup latency, \
             not a failure: do not restart the MCP server or re-run `kin init`."
        )
    }

    /// The daemon's startup phase from the launcher's injected probe, or the
    /// resolve phase while no probe is installed (nothing has named a
    /// repository to bind yet).
    fn startup_phase(&self) -> &'static str {
        if let Ok(guard) = self.phase_probe.lock() {
            if let Some(probe) = guard.as_ref() {
                return probe();
            }
        }
        "phase: resolving which repository daemon to bind"
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

    #[test]
    fn the_starting_report_carries_the_injected_phase() {
        let binding = StartupDaemonBinding::new();
        // Before a probe is installed, the report still explains itself.
        let report = binding.starting_report("kin_graph_status");
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
        binding.set_phase_probe(Box::new(move || *probe_phase.lock().unwrap()));
        assert!(binding
            .starting_report("kin_graph_status")
            .contains("loading the repository graph"));

        *phase.lock().unwrap() = "phase: the daemon is listening and finishing readiness checks";
        assert!(binding
            .starting_report("kin_graph_status")
            .contains("finishing readiness checks"));
    }
}
