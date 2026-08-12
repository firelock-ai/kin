// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Daemon-owned on-demand trigger for one complete exact-tree admission.
//!
//! This module runs no admission of its own. It calls the same
//! [`crate::loop_runner::sync_filesystem_with_graph`] seam the watch loop and
//! `/commands/commit` already use, so a requested pass inherits the same
//! completion proof, authority compare-and-swap, mass-deletion guard, and
//! enrichment ordering as an ambient one. A second implementation would be a
//! second set of rules to keep in step, and the one thing a recovery path must
//! not do is admit differently from the loop it is recovering.
//!
//! What it adds is an answer, and a pass that outlives the request asking for
//! it. The pass itself returns `()`, and a store's operator needs to know
//! whether it moved anything and whether it worked, so the graph is measured on
//! both sides of the call and the reconcile probes are read afterwards. Those
//! two facts are different: a pass can succeed and admit nothing, which is the
//! settled case, and a pass can fail while the request that carried it returns
//! cleanly, which is the case the probes exist to publish.

use anyhow::Result;
use kin_cli::commands::admit::{
    census_moved, summary_lines, AdmitReport, AdmitResponse, ADMIT_SCHEMA,
};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use crate::state::DaemonState;

/// The complete exact-tree admission this daemon currently has in flight.
///
/// The pass runs in a task of its own rather than inside the request that asked
/// for it, because a request can be dropped and this pass must not be. The seam
/// publishes repository authority BEFORE it enriches and its one await sits
/// between the two, so a client that hangs up mid-pass (an HTTP timeout, an
/// interrupt) would otherwise leave the tree admitted with nothing parsed for
/// it, and nothing re-enriches a file that did not change. A detached pass has
/// no such midpoint: it finishes, or it dies with the daemon and reports
/// nothing.
///
/// The slot is also what makes a second request safe. Attaching it to the
/// running pass is the difference between reporting that pass's real transition
/// and re-observing an already-published tree, finding no deltas, and calling
/// that a complete admission.
///
/// What an attached request gets is the running pass's transition, and that
/// pass observed the tree when it started. A request that arrives afterwards
/// and needs the tree as of its own arrival asks again once this one reports;
/// the answer it gets meanwhile is true about the pass it names.
#[derive(Default)]
pub(crate) struct AdmissionRuns {
    inner: Mutex<Option<InFlightAdmission>>,
}

struct InFlightAdmission {
    outcome: tokio::sync::watch::Receiver<AdmissionRunState>,
}

#[derive(Clone)]
enum AdmissionRunState {
    Running,
    /// The pass ended and this is what it did. Shared rather than recomputed,
    /// so every caller waiting on one pass reports one outcome.
    Finished(Arc<Result<AdmitResponse, String>>),
}

/// The right to run a pass, or a seat at the one already running.
enum AdmissionClaim {
    Started(
        tokio::sync::watch::Sender<AdmissionRunState>,
        tokio::sync::watch::Receiver<AdmissionRunState>,
    ),
    Attached(tokio::sync::watch::Receiver<AdmissionRunState>),
}

impl AdmissionRuns {
    fn lock(&self) -> std::sync::MutexGuard<'_, Option<InFlightAdmission>> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn claim(&self) -> AdmissionClaim {
        let mut slot = self.lock();
        if let Some(running) = slot.as_ref() {
            return AdmissionClaim::Attached(running.outcome.clone());
        }
        let (sender, receiver) = tokio::sync::watch::channel(AdmissionRunState::Running);
        *slot = Some(InFlightAdmission {
            outcome: receiver.clone(),
        });
        AdmissionClaim::Started(sender, receiver)
    }

    fn release(&self) {
        *self.lock() = None;
    }
}

/// Clears the in-flight slot when the pass ends, however it ends.
///
/// A pass that panics has to leave the slot empty, or the daemon spends the
/// rest of its life attaching callers to a run that will never report.
struct RunningPass {
    state: Arc<DaemonState>,
}

impl Drop for RunningPass {
    fn drop(&mut self) {
        self.state.admission_runs.release();
    }
}

/// One observation of the graph counts an admission can change.
struct GraphCensus {
    tracked: usize,
    entities: usize,
}

fn census(state: &DaemonState) -> GraphCensus {
    GraphCensus {
        tracked: state.graph.resolved_tree().len(),
        entities: state.graph.entity_count(),
    }
}

/// Run one complete exact-tree admission and report what it did, or report what
/// the pass already running is doing.
///
/// Never returns `Err` for a failed admission. A refused pass is an outcome the
/// operator has to see the counters and the cause for, and turning it into a
/// transport-level error would strip both and leave `kin admit` printing an
/// HTTP status. The CLI exits nonzero off `AdmitReport::admitted` instead.
/// Transport, initialization, and authority problems still refuse at the
/// handler, because those mean no pass ran at all.
///
/// `Err` is reserved for the two cases where no outcome was established: the
/// repository authority context could not be resolved, and the pass stopped
/// without reporting. Neither may read as success.
pub(crate) async fn execute(state: &Arc<DaemonState>) -> Result<AdmitResponse> {
    let mut outcome = match state.admission_runs.claim() {
        AdmissionClaim::Attached(outcome) => outcome,
        AdmissionClaim::Started(sender, outcome) => {
            let owned = Arc::clone(state);
            tokio::spawn(async move {
                // Dropped after the send, and during an unwind if the pass
                // panics, so the slot never outlives the run it names.
                let _running = RunningPass {
                    state: Arc::clone(&owned),
                };
                let finished = run_pass(&owned).await.map_err(|error| error.to_string());
                let _ = sender.send(AdmissionRunState::Finished(Arc::new(finished)));
            });
            outcome
        }
    };

    loop {
        if let AdmissionRunState::Finished(finished) = outcome.borrow_and_update().clone() {
            return match finished.as_ref() {
                Ok(response) => Ok(response.clone()),
                Err(error) => Err(anyhow::anyhow!(error.clone())),
            };
        }
        if outcome.changed().await.is_err() {
            // The task carrying the pass ended without publishing an outcome,
            // which is a panic or a daemon shutdown. What the pass managed to
            // publish before that is unknown from here, and the one answer that
            // must never be given is a successful one.
            return Err(anyhow::anyhow!(
                "the complete exact-tree admission stopped without reporting an outcome; read \
                 `kin graph status` for the state it left behind"
            ));
        }
    }
}

async fn run_pass(state: &DaemonState) -> Result<AdmitResponse> {
    let repository_id =
        crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(state)?
            .repository_id()
            .clone();
    let before = census(state);

    // The same seam `/commands/commit` calls. It takes the coordination gate
    // itself, so this must not already hold it.
    let outcome = crate::loop_runner::sync_filesystem_with_graph(state).await;

    // Record the outcome on the same probes the ambient loop records to. A pass
    // requested here is a complete exact-tree admission by every measure that
    // matters to a reader of `kin graph status` or `/health`, and leaving it out
    // would make an operator's own recovery attempt the one admission the
    // health surfaces cannot see. Recording from the pass rather than from the
    // request also means a caller that hung up mid-pass still leaves the
    // outcome on the surfaces that answer for the store.
    let now = Instant::now();
    let probes = state.background_work.reconcile();
    let failure = match &outcome {
        Ok(()) => {
            probes.record_admission_success(now);
            None
        }
        Err(error) => {
            let cause = crate::error::cause_first(&anyhow::anyhow!(error.to_string()));
            probes.record_admission_failure(&cause, now);
            Some(annotate_admission_failure(cause))
        }
    };

    // The census is reported as measured on both sides, whatever the outcome.
    // The seam publishes repository authority before it enriches, so a pass that
    // fails afterwards has already moved the tree; rewriting the after side to
    // match the before side would report that move as if it had never happened,
    // on exactly the path where an operator most needs to know it did.
    // `summary_lines` derives its wording from the two sides instead.
    let after = census(state);

    // The durable freshness marker is stamped from the after side, and only for
    // a pass that succeeded. Stamping a failed pass would record that the store
    // is current at the exact moment it was refused, which is the false
    // freshness this marker exists to prevent, reached by the other door.
    if failure.is_none() {
        crate::background_work::record_durable_admission(&state.layout, after.tracked as u64);
    }

    let embeddings = state.graph.embedding_status();
    let report = AdmitReport {
        schema: ADMIT_SCHEMA.to_string(),
        repository_id,
        tracked_before: before.tracked,
        tracked_after: after.tracked,
        entities_before: before.entities,
        entities_after: after.entities,
        embeddings_indexed: embeddings.indexed,
        embeddings_total: embeddings.total,
        reconcile: probes.report(now),
        admitted: failure.is_none(),
        failure,
    };

    let lines = summary_lines(&report);
    let mutated = census_moved(&report);
    Ok(AdmitResponse {
        lines,
        mutated,
        report: Some(report),
    })
}

/// The mass-deletion refusal names an environment variable, and the variable is
/// read by the daemon rather than by the process the operator just typed into.
///
/// Without this, the obvious next move is `KIN_ALLOW_MASS_DELETION=1 kin admit`,
/// which sets it on the CLI, changes nothing, and refuses identically. An
/// operator who tries that twice concludes the override is broken.
fn annotate_admission_failure(cause: String) -> String {
    if cause.contains("KIN_ALLOW_MASS_DELETION") {
        format!(
            "{cause}. That variable is read by the daemon process, not by this command, so set it \
             where the daemon starts: stop it with `kin daemon stop`, then re-run with \
             KIN_ALLOW_MASS_DELETION=1 exported so the daemon it starts inherits it"
        )
    } else {
        cause
    }
}
