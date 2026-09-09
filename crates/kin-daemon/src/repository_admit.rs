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
    graph_moved, summary_lines, AdmitReport, AdmitResponse, ADMIT_SCHEMA,
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

/// One observation of what an admission can change.
///
/// The two counts are cardinalities and cannot see a content-only edit: a pass
/// that rewrites a tracked file's bytes leaves both exactly where they were.
/// `tree` is the third reading, and it is the one that moves when the other two
/// do not (FIR-2961).
struct GraphCensus {
    tracked: usize,
    entities: usize,
    /// The resolved tree's own hash, or `None` when it would not compute.
    ///
    /// `None` is carried rather than substituted, so a reading that could not be
    /// taken never reaches a reader as a tree that did not move.
    tree: Option<kin_model::Hash256>,
}

fn census(state: &DaemonState) -> GraphCensus {
    let tree = state.graph.resolved_tree();
    GraphCensus {
        tracked: tree.len(),
        entities: state.graph.entity_count(),
        tree: kin_model::compute_resolved_tree_hash(&tree).ok(),
    }
}

/// Whether the tree moved across the pass, when both sides could be read.
///
/// Three-way on purpose, matching every other freshness reading in this store:
/// moved, did not move, and nobody could look. Collapsing the third into "did
/// not move" is the whole defect, reintroduced one layer down.
fn tree_moved(before: &GraphCensus, after: &GraphCensus) -> Option<bool> {
    match (before.tree.as_ref(), after.tree.as_ref()) {
        (Some(before), Some(after)) => Some(before != after),
        _ => None,
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

/// The watcher loss this pass is entitled to clear, captured before it runs.
///
/// Two rules, and both of them are about a pass clearing a loss it never
/// covered.
///
/// Captured BEFORE the seam, because the pass observes the working copy when it
/// starts. A loss signal that arrives while it runs stands for writes its tree
/// observation may never have reached, so reading the record afterwards would
/// clear a loss nothing recovered.
///
/// And nothing at all when the seam will walk nothing.
/// `sync_filesystem_with_graph` returns `Ok(())` on two conditions without
/// touching the working copy, filesystem reconcile disabled and a bare Git
/// repository, so a pass over either reports a clean success having looked at
/// no file. Both endpoints that reach this module refuse those conditions ahead
/// of the pass, and that is exactly why this does not depend on them: a
/// recovery that leaned on a caller's guard would be one refactor away from
/// healing a blind store. The predicates are the seam's own rather than a copy,
/// so the two cannot drift apart.
fn watcher_loss_this_pass_can_cover(state: &DaemonState) -> crate::watcher_loss::RecoveryCapture {
    if state.filesystem_reconcile_disabled()
        || crate::loop_runner::is_bare_repository(state.layout.working_dir())
    {
        return crate::watcher_loss::RecoveryCapture::Clean;
    }
    crate::watcher_loss::capture(&state.layout)
}

async fn run_pass(state: &DaemonState) -> Result<AdmitResponse> {
    let repository_id =
        crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(state)?
            .repository_id()
            .clone();
    let before = census(state);
    let watcher_loss = watcher_loss_this_pass_can_cover(state);

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

    // Read the PREVIOUS admission's clock before this pass records its own.
    // `record_admission_success` below overwrites it and the report is built
    // afterwards, so reading it there names this very pass at an age of zero,
    // which says nothing about why there was nothing left to admit. The watch
    // loop drains its file watcher every 100ms and admits what it finds, so a
    // write can be admitted between an operator's edit and the `kin admit` they
    // run about it; this is the clock that lets the summary say so.
    let prior_admission_at = state
        .background_work
        .reconcile_report(now)
        .last_admission_success_at;

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
        // The only path in the product that clears a watcher loss, and
        // deliberately not the line above it. The ambient watch tick reaches
        // `record_durable_admission` too, and an ambient tick admits what the
        // watcher told it about, which for a loss that named no path is nothing
        // at all. Putting the clear there would let every 100ms tick heal a gap
        // no tick ever observed. This module is the explicit request, which is
        // what the contract requires: fail loud, and let a person or an agent
        // decide to admit.
        crate::watcher_loss::record_recovery(&state.layout, watcher_loss);
    }
    // Refreshed whatever the outcome, and before the report below reads the
    // reconcile surface, so `kin admit` answers with the state its own pass
    // left rather than the state it found.
    probes.record_watcher_loss(crate::watcher_loss::standing(
        &state.layout,
        state.layout.working_dir(),
    ));

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
        // Read through the supervisor rather than off the probes, so an
        // explicit admission run against a store whose ambient loop is parked
        // says so. The probes alone report a quiet loop and a parked one
        // identically.
        reconcile: state.background_work.reconcile_report(now),
        tree_moved: tree_moved(&before, &after),
        prior_admission_at,
        admitted: failure.is_none(),
        failure,
    };

    let lines = summary_lines(&report);
    // The wider question, so a content-only admission is not published as a
    // no-op to every caller that reads this flag rather than the prose.
    let mutated = graph_moved(&report);
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::watcher_loss::{self, RecoveryCapture};

    fn open_test_state(repo: &tempfile::TempDir) -> Arc<DaemonState> {
        let init = kin_core::init(repo.path()).unwrap();
        Arc::new(DaemonState::open(init.layout).unwrap())
    }

    /// The founder's contract in one test: rescan loss fails loud, and only an
    /// explicit `kin admit` clears it.
    ///
    /// The bounded half is driven through the SAME seam and the SAME success
    /// bookkeeping the watch loop runs, `sync_filesystem_with_graph` followed by
    /// `record_admission_success` and `record_durable_admission`, because that
    /// is where a clearing call would most naturally be put and where it must
    /// not be. Both paths reach that bookkeeping; only this module is the
    /// explicit one.
    #[tokio::test]
    async fn only_an_explicit_full_admission_clears_a_watcher_loss() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        std::fs::write(
            state.layout.working_dir().join("admitted.rs"),
            "pub fn admitted() -> u8 {\n    7\n}\n",
        )
        .unwrap();

        watcher_loss::record_loss(&state.layout, 1, Some("rescan: kernel dropped"));
        assert!(
            watcher_loss::read(&state.layout).recovery_required(),
            "the fixture must start with a loss standing, or neither half below can fail"
        );

        // One ambient reconcile round, ending exactly as the loop's own
        // successful tick ends.
        crate::loop_runner::sync_filesystem_with_graph(&state)
            .await
            .expect("the ambient seam admits the fixture");
        let now = Instant::now();
        state
            .background_work
            .reconcile()
            .record_admission_success(now);
        crate::background_work::record_durable_admission(
            &state.layout,
            state.graph.resolved_tree().len() as u64,
        );

        assert!(
            watcher_loss::read(&state.layout).recovery_required(),
            "an ordinary bounded watch tick must not clear a watcher loss"
        );

        let response = execute(&state).await.expect("the pass reported an outcome");
        let report = response.report.expect("a reported pass carries its report");
        assert!(report.admitted, "{:?}", report.failure);

        assert!(
            !watcher_loss::read(&state.layout).recovery_required(),
            "a completed explicit admission clears the generation it covered"
        );
    }

    /// A pass that FAILED clears nothing. Clearing before the outcome is known
    /// would report a recovered store on the one path where no recovery
    /// happened.
    ///
    /// The failure is the mass-deletion guard, which refuses a walk that removes
    /// more than three quarters of a baseline of at least sixteen files. It is
    /// used here because it fails the seam itself rather than a layer above it,
    /// which is the shape a real refused recovery has.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_failed_pass_leaves_the_loss_standing() {
        let repo = tempfile::tempdir().unwrap();
        for index in 0..20 {
            std::fs::write(
                repo.path().join(format!("member{index}.txt")),
                format!("admitted {index}\n"),
            )
            .unwrap();
        }
        let state = open_test_state(&repo);
        crate::loop_runner::sync_filesystem_with_graph(&state)
            .await
            .expect("the fixture admits its twenty members");

        for index in 0..20 {
            std::fs::remove_file(repo.path().join(format!("member{index}.txt"))).unwrap();
        }
        watcher_loss::record_loss(&state.layout, 1, None);

        let response = execute(&state).await.expect("the pass reported an outcome");
        let report = response.report.expect("a reported pass carries its report");
        assert!(
            !report.admitted,
            "the fixture must actually fail the pass, or this asserts nothing"
        );

        assert!(
            watcher_loss::read(&state.layout).recovery_required(),
            "a pass that did not succeed must leave the loss standing"
        );
    }

    /// A pass over a store the admission seam will not walk clears nothing.
    ///
    /// `sync_filesystem_with_graph` returns `Ok(())` without touching the
    /// working copy when filesystem reconcile is disabled, so the pass reports a
    /// clean success having observed no file at all. A recovery keyed only on
    /// that success would heal a blind store from a pass that never looked.
    #[tokio::test]
    async fn a_pass_whose_seam_walks_nothing_clears_nothing() {
        let repo = tempfile::tempdir().unwrap();
        let state = open_test_state(&repo);
        std::fs::write(
            state.layout.working_dir().join("unseen.rs"),
            "pub fn unseen() {}\n",
        )
        .unwrap();
        state
            .filesystem_reconcile_disabled
            .store(true, std::sync::atomic::Ordering::Relaxed);

        watcher_loss::record_loss(&state.layout, 1, None);
        assert_eq!(
            watcher_loss_this_pass_can_cover(&state),
            RecoveryCapture::Clean,
            "a seam that will walk nothing covers nothing"
        );

        let response = execute(&state).await.expect("the pass reported an outcome");
        let report = response.report.expect("a reported pass carries its report");
        assert!(
            report.admitted,
            "the seam skips silently, so the pass still reports success: {:?}",
            report.failure
        );
        assert_eq!(
            report.tracked_after, 0,
            "the fixture must exercise a pass that observed nothing"
        );

        assert!(
            watcher_loss::read(&state.layout).recovery_required(),
            "a pass that observed no file must not clear a watcher loss"
        );
    }
}
