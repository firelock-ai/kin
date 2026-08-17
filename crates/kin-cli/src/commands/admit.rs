// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Wire types and CLI transport for requesting one complete exact-tree
//! admission on demand.
//!
//! The daemon admits a complete exact tree on startup, on `kin commit`, and on
//! whatever the watcher happened to observe. None of those is a trigger an
//! operator can pull. A store whose graph fell behind its working tree, because
//! ingest was interrupted or because ignore rules changed what is admissible,
//! therefore waits for an organic churn burst to recover, and a quiet daemon
//! idles out before one arrives. This command is that trigger.
//!
//! It is not a second admission implementation. It asks the daemon to run the
//! same complete exact-tree pass its own loop runs, so an admission requested
//! here inherits the same completion proof, authority compare-and-swap, and
//! mass-deletion guard as every ambient one.
//!
//! Three properties matter beyond the request itself. The CLI registers a daemon
//! session for the duration and releases it afterwards, because a daemon with no
//! registered session idles out while a long first pass is still running, and an
//! admission killed at its midpoint is the failure this command exists to
//! resolve. The outcome is read back from the reconcile probes rather than
//! inferred from the request succeeding, because a pass that ran and admitted
//! nothing and a pass that ran and failed are different answers. And the request
//! is not the pass: the daemon runs the admission detached from the connection
//! that asked for it, so this command waits by attaching to that pass, and an
//! attempt that goes unanswered leaves the outcome unknown rather than
//! canceled. The one answer it may never produce is a completed admission it
//! did not see reported.

use anyhow::{Context, Result};
use kin_model::{AuthorId, OperationId, RepositoryId};
use serde::{Deserialize, Serialize};

use crate::commands::resources::ReconcileHealth;

pub const ADMIT_SCHEMA: &str = "kin.admit.v1";

/// Vendor recorded for the session this command holds.
///
/// Anything other than `kin-daemon` counts as an external session and suppresses
/// idle shutdown, which is the whole reason the lease is taken. Naming the CLI
/// specifically also means an operator reading `kin daemon sessions` mid-pass
/// sees what is holding the daemon open.
pub const ADMIT_SESSION_VENDOR: &str = "kin-cli";

/// Client name recorded for the session this command holds.
pub const ADMIT_SESSION_CLIENT: &str = "kin admit";

/// A requested admission carries no options.
///
/// It deliberately has no mass-deletion confirmation of its own. The guard is
/// evaluated inside the shared admission pass and its override is read from the
/// daemon's environment, so a flag here would have to be a second control over
/// the same guard reaching it by a different route, and two controls over one
/// guard are two rules that can come to disagree. A refused admission reports
/// the guard's own counts and names the variable instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdmitRequest {
    pub operation_id: OperationId,
    pub actor: AuthorId,
}

/// What one requested admission did, measured on both sides of the pass.
///
/// Counts are stated before and after rather than as a delta, so a pass that
/// admitted nothing is distinguishable from a pass that could not run. The
/// reconcile probes ride along because the request returning success only says
/// the daemon accepted the call; whether the admission itself succeeded is what
/// [`ReconcileHealth::admission_failure_streak`] and
/// `last_admission_success_age_seconds` answer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AdmitReport {
    pub schema: String,
    pub repository_id: RepositoryId,
    /// Tracked artifacts in graph authority before the pass.
    pub tracked_before: usize,
    /// Tracked artifacts in graph authority after the pass.
    pub tracked_after: usize,
    /// Graph entities before the pass.
    pub entities_before: usize,
    /// Graph entities after the pass.
    pub entities_after: usize,
    /// Retrievable objects the vector index holds after the pass, and the total
    /// that want an embedding. An admission adds graph objects; embedding them
    /// is the background pass that follows, so this is reported rather than
    /// waited on.
    pub embeddings_indexed: usize,
    pub embeddings_total: usize,
    /// The reconcile probes read AFTER the pass. This is the outcome surface:
    /// the request can succeed while the admission inside it failed.
    pub reconcile: ReconcileHealth,
    /// False when the pass itself failed. The request still returns its report
    /// so the operator sees the counters and the recorded cause; the CLI exits
    /// nonzero.
    pub admitted: bool,
    /// Present only when the pass failed: the recorded cause, verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdmitResponse {
    #[serde(default)]
    pub lines: Vec<String>,
    #[serde(default)]
    pub mutated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<AdmitReport>,
}

/// Whether the graph counts this pass reported actually moved.
///
/// Asked on the failure path as well as the success path, because the admission
/// seam publishes repository authority before it enriches: a pass that fails
/// afterwards has still moved the tree, and both the summary and `mutated` have
/// to say so rather than describe the store the operator no longer has.
pub fn census_moved(report: &AdmitReport) -> bool {
    report.tracked_after != report.tracked_before || report.entities_after != report.entities_before
}

/// Render the operator-facing summary for one admission report.
///
/// Kept separate from transport so the wording is asserted directly rather than
/// through a daemon round trip.
pub fn summary_lines(report: &AdmitReport) -> Vec<String> {
    let mut lines = Vec::new();
    let tracked_delta = report.tracked_after as i64 - report.tracked_before as i64;
    let entity_delta = report.entities_after as i64 - report.entities_before as i64;

    if !report.admitted {
        // Cause first: the operator needs the reason before the counters.
        let cause = report
            .failure
            .as_deref()
            .or(report.reconcile.last_admission_error.as_deref())
            .unwrap_or("no cause recorded");
        lines.push(format!("Complete exact-tree admission failed: {cause}"));
        if census_moved(report) {
            // Authority crossed before the failure. Calling that unchanged is
            // the one wording an operator cannot recover from, because it
            // describes a settled store while the real one is half admitted:
            // the tree published and the semantic enrichment for it did not.
            lines.push(format!(
                "Graph authority moved before the failure: {} tracked artifacts \
                 ({tracked_delta:+}), {} entities ({entity_delta:+}). Enrichment for that \
                 transition is incomplete; re-run `kin admit` once the cause above is resolved.",
                report.tracked_after, report.entities_after
            ));
        } else {
            lines.push(format!(
                "Graph authority is unchanged: {} tracked artifacts, {} entities.",
                report.tracked_before, report.entities_before
            ));
        }
        return lines;
    }

    if tracked_delta == 0 && entity_delta == 0 {
        lines.push(format!(
            "Admitted the complete exact tree; nothing changed. {} tracked artifacts, {} entities.",
            report.tracked_after, report.entities_after
        ));
    } else {
        lines.push(format!(
            "Admitted the complete exact tree: {} tracked artifacts ({tracked_delta:+}), {} \
             entities ({entity_delta:+}).",
            report.tracked_after, report.entities_after
        ));
    }

    // An admission adds graph objects; embedding them is the pass that follows.
    // Saying so is the difference between an operator waiting for retrieval to
    // improve and an operator concluding the admission did not work.
    if report.embeddings_total > report.embeddings_indexed {
        lines.push(format!(
            "Embeddings: {} of {} indexed; the remainder is queued for the background embed pass.",
            report.embeddings_indexed, report.embeddings_total
        ));
    } else if report.embeddings_total > 0 {
        lines.push(format!(
            "Embeddings: {} of {} indexed.",
            report.embeddings_indexed, report.embeddings_total
        ));
    }

    // The probes are the reason this command reports an outcome at all rather
    // than exiting zero on a successful request, so a degraded reconcile state
    // is printed even on a pass that itself succeeded.
    for reason in report.reconcile.degraded_reasons() {
        lines.push(format!("Attention: {reason}"));
    }

    lines
}

/// Consecutive attempts that could not reach the daemon at all before this says
/// so on stderr. One dropped request proves nothing: a daemon busy with a long
/// pass can drop one and still be there. A run of them is worth announcing.
const ADMIT_UNREACHABLE_WARN_AFTER: u32 = 4;

/// Consecutive unreachable attempts before the wait ends without a verdict.
///
/// A daemon that has answered nothing for this long is gone, and the honest
/// report is that the admission's outcome is unknown from here rather than that
/// it failed.
const ADMIT_UNREACHABLE_GIVE_UP_AFTER: u32 = 20;

/// Backstop on total unanswered attempts against a daemon that keeps proving it
/// is alive. Nothing should reach it, and a wait with no ceiling at all is a
/// hang wearing a progress line.
const ADMIT_UNANSWERED_GIVE_UP_AFTER: u32 = 288;

/// Pause between attempts, so a dispatch that fails instantly cannot spin.
const ADMIT_RETRY_PAUSE: std::time::Duration = std::time::Duration::from_secs(2);

/// What a command waiting on an admission does after one unanswered dispatch.
///
/// There is deliberately no success in this enum. Nothing coming back
/// establishes nothing about the pass, so an unanswered attempt has exactly two
/// continuations, and reporting a completed admission is not one of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdmitWaitStep {
    /// The daemon is still answering, so the pass it is running is still the
    /// pass this command asked for. Attach again.
    KeepWaiting,
    GiveUp(AdmitWaitEnd),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AdmitWaitEnd {
    /// The daemon stopped answering anything at all.
    DaemonUnreachable,
    /// The daemon kept answering and the pass never reported.
    NoOutcomeInBudget,
}

impl AdmitWaitEnd {
    fn explain(self, attempts: u32) -> String {
        match self {
            Self::DaemonUnreachable => format!(
                "the kin daemon stopped answering for {attempts} consecutive attempts while a \
                 complete exact-tree admission was in flight, so whether that pass finished is \
                 unknown from here; read `kin graph status` for the state the store is in, then \
                 re-run `kin admit`"
            ),
            Self::NoOutcomeInBudget => format!(
                "the kin daemon is still answering, but the complete exact-tree admission has not \
                 reported an outcome across {attempts} attempts, so whether it finished is \
                 unknown from here; read `kin graph status` for the state the store is in"
            ),
        }
    }
}

/// Decide the next step from the states this command can actually observe: what
/// the last dispatch established, whether the daemon is answering at all, and
/// how long each has been true.
fn admit_wait_step(daemon_reachable: bool, unanswered: u32, unreachable: u32) -> AdmitWaitStep {
    if !daemon_reachable && unreachable >= ADMIT_UNREACHABLE_GIVE_UP_AFTER {
        return AdmitWaitStep::GiveUp(AdmitWaitEnd::DaemonUnreachable);
    }
    if unanswered >= ADMIT_UNANSWERED_GIVE_UP_AFTER {
        return AdmitWaitStep::GiveUp(AdmitWaitEnd::NoOutcomeInBudget);
    }
    AdmitWaitStep::KeepWaiting
}

/// Ask for one complete exact-tree admission and wait for that pass to report.
///
/// The request is not the pass. The daemon runs the admission detached from the
/// connection that asked for it, so an unanswered attempt means the pass is
/// still running or the daemon is gone, never that it was canceled, and a later
/// attempt joins the same pass rather than starting a competing one. That is
/// what makes waiting by re-attaching correct where a silent transport retry
/// was not: a retry that re-observes an already-published tree finds nothing to
/// do and reports a complete admission that enriched none of it.
async fn wait_for_admission(
    client: &crate::daemon_client::DaemonClient,
    request: &AdmitRequest,
) -> Result<AdmitResponse> {
    let mut unanswered = 0u32;
    let mut unreachable = 0u32;
    loop {
        let unanswered_error = match client.admit(request).await {
            crate::daemon_client::AdmitDispatch::Answered(response) => return Ok(response),
            crate::daemon_client::AdmitDispatch::Refused(error) => return Err(error),
            crate::daemon_client::AdmitDispatch::Unanswered(error) => error,
        };

        // Liveness is a separate question from the answer, and the request that
        // went unanswered cannot settle it: a daemon still working and a daemon
        // that died look the same from a connection that produced nothing.
        let reachable = client.is_reachable().await;
        unanswered = unanswered.saturating_add(1);
        unreachable = if reachable {
            0
        } else {
            unreachable.saturating_add(1)
        };

        match admit_wait_step(reachable, unanswered, unreachable) {
            AdmitWaitStep::GiveUp(end) => {
                let attempts = if reachable { unanswered } else { unreachable };
                return Err(unanswered_error.context(end.explain(attempts)));
            }
            AdmitWaitStep::KeepWaiting => {
                if reachable {
                    eprintln!(
                        "kin admit: no answer yet after {unanswered} attempt(s); the daemon is up \
                         and still running the pass. Interrupting this command stops the waiting, \
                         not the admission."
                    );
                } else if unreachable >= ADMIT_UNREACHABLE_WARN_AFTER {
                    eprintln!(
                        "kin admit: {unreachable} consecutive attempts could not reach the \
                         daemon; still retrying, and the outcome of the pass is unknown until one \
                         of them answers."
                    );
                }
                tokio::time::sleep(ADMIT_RETRY_PAUSE).await;
            }
        }
    }
}

pub async fn run() -> Result<()> {
    let cwd = std::env::current_dir().context("resolve current directory")?;
    let layout = crate::commands::require_repository_layout_at(&cwd)?;
    let base_url = crate::daemon_client::resolve_daemon_url(&layout)
        .await?
        .ok_or_else(|| {
            crate::daemon_client::daemon_required_error(
                "admitting the complete exact tree",
                &layout,
            )
        })?;
    // Explicit authority with no session header: this publishes against HEAD
    // authority, so an ambient `KIN_SESSION_ID` inherited from a surrounding
    // agent session would scope the request to a workspace it must not touch.
    // The lease taken below is a liveness hold, not a scope.
    let client = crate::daemon_client::DaemonClient::from_base_url_with_explicit_authority(
        base_url,
        crate::daemon_client::resolve_daemon_auth_token_for_layout(&layout),
        None,
    )?;

    // Hold a session for the pass. A daemon with no registered session idles
    // out on its own timer, and a complete exact-tree admission on a large
    // store outlives that window, so without this the command's own request can
    // be killed by the daemon it is talking to.
    let session_id = client
        .start_session(
            ADMIT_SESSION_VENDOR,
            ADMIT_SESSION_CLIENT,
            &cwd,
            std::process::id(),
            kin_model::session::SessionCapabilities::default(),
        )
        .await
        .context("register the daemon session that keeps this admission alive")?;

    // One operation identity for the whole wait, however many attempts it
    // takes: every attempt after the first joins the pass the first one started
    // rather than asking for another.
    let request = AdmitRequest {
        operation_id: OperationId::new(),
        actor: crate::commands::require_commit_author()?,
    };
    let outcome = wait_for_admission(&client, &request).await;

    // Release the lease on every path. A leaked lease keeps the daemon awake
    // indefinitely, which is the same defect as the one this command fixes
    // pointed the other way.
    if let Err(error) = client.end_session(&session_id).await {
        tracing::warn!(
            error = %error,
            session = %session_id,
            "failed to release the admission session lease; it will expire on its idle timeout"
        );
    }

    let response = outcome?;
    for line in &response.lines {
        println!("{line}");
    }
    match response.report.as_ref() {
        Some(report) if !report.admitted => {
            let cause = report
                .failure
                .as_deref()
                .or(report.reconcile.last_admission_error.as_deref())
                .unwrap_or("no cause recorded");
            Err(anyhow::anyhow!(
                "complete exact-tree admission failed: {cause}"
            ))
        }
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(admitted: bool) -> AdmitReport {
        AdmitReport {
            schema: ADMIT_SCHEMA.to_string(),
            repository_id: RepositoryId::new("admit-summary").unwrap(),
            tracked_before: 31,
            tracked_after: 4210,
            entities_before: 0,
            entities_after: 9977,
            embeddings_indexed: 49,
            embeddings_total: 14187,
            reconcile: ReconcileHealth::default(),
            admitted,
            failure: (!admitted)
                .then(|| "host entry changed after exact-tree admission".to_string()),
        }
    }

    #[test]
    fn a_successful_admission_names_both_sides_of_the_transition() {
        let text = summary_lines(&report(true)).join("\n");
        assert!(text.contains("4210 tracked artifacts (+4179)"), "{text}");
        assert!(text.contains("9977 entities (+9977)"), "{text}");
        assert!(!text.contains("failed"), "{text}");
    }

    /// A pass refused before the seam published changed nothing, so the cause
    /// has to lead and the counters have to say they are unchanged.
    #[test]
    fn a_failed_admission_leads_with_its_cause_and_refuses_to_claim_a_change() {
        let mut refused = report(false);
        // The pre-publish refusals: the mass-deletion guard and the planning
        // errors, where the census genuinely did not move.
        refused.tracked_after = refused.tracked_before;
        refused.entities_after = refused.entities_before;
        assert!(!census_moved(&refused));

        let text = summary_lines(&refused).join("\n");
        let first = text.lines().next().unwrap_or_default();
        assert!(
            first.starts_with("Complete exact-tree admission failed: host entry changed"),
            "{text}"
        );
        assert!(text.contains("Graph authority is unchanged"), "{text}");
        assert!(!text.contains("4210"), "{text}");
    }

    /// A pass that fails AFTER the seam published has already moved graph
    /// authority, and the report has to say so.
    ///
    /// The seam publishes the complete exact tree before it enriches, and the
    /// reachable post-publish failure is the host-entry check. Calling that an
    /// unchanged store describes a repository the operator no longer has: the
    /// tree crossed authority and the enrichment for it did not, which is the
    /// one state that needs a second pass.
    #[test]
    fn a_failed_pass_that_already_published_reports_the_authority_it_moved() {
        let published = report(false);
        assert!(
            census_moved(&published),
            "the fixture must describe a pass that published before it failed"
        );

        let text = summary_lines(&published).join("\n");
        let first = text.lines().next().unwrap_or_default();
        assert!(
            first.starts_with("Complete exact-tree admission failed:"),
            "{text}"
        );
        assert!(!text.contains("unchanged"), "{text}");
        assert!(
            text.contains("Graph authority moved before the failure"),
            "{text}"
        );
        assert!(text.contains("4210 tracked artifacts (+4179)"), "{text}");
        assert!(
            text.contains("Enrichment for that transition is incomplete"),
            "{text}"
        );
    }

    /// Nothing coming back establishes nothing about the pass, so no run of
    /// counters may turn an unanswered dispatch into a finished admission.
    #[test]
    fn an_unanswered_dispatch_never_reads_as_a_finished_admission() {
        // A daemon that keeps answering is a pass still running, however long
        // it has been running: attempts alone never end the wait.
        for unanswered in [
            1,
            ADMIT_UNREACHABLE_GIVE_UP_AFTER,
            ADMIT_UNANSWERED_GIVE_UP_AFTER - 1,
        ] {
            assert_eq!(
                admit_wait_step(true, unanswered, 0),
                AdmitWaitStep::KeepWaiting
            );
        }

        // One refused connection proves nothing. A run of them is the daemon
        // being gone, and that ends the wait with no verdict on the pass.
        assert_eq!(admit_wait_step(false, 1, 1), AdmitWaitStep::KeepWaiting);
        assert_eq!(
            admit_wait_step(
                false,
                ADMIT_UNREACHABLE_GIVE_UP_AFTER,
                ADMIT_UNREACHABLE_GIVE_UP_AFTER
            ),
            AdmitWaitStep::GiveUp(AdmitWaitEnd::DaemonUnreachable)
        );
        assert_eq!(
            admit_wait_step(true, ADMIT_UNANSWERED_GIVE_UP_AFTER, 0),
            AdmitWaitStep::GiveUp(AdmitWaitEnd::NoOutcomeInBudget)
        );

        // Both endings report an unknown outcome rather than naming one.
        for end in [
            AdmitWaitEnd::DaemonUnreachable,
            AdmitWaitEnd::NoOutcomeInBudget,
        ] {
            let text = end.explain(ADMIT_UNREACHABLE_GIVE_UP_AFTER);
            assert!(text.contains("unknown"), "{text}");
            assert!(text.contains("kin graph status"), "{text}");
            assert!(!text.contains("admitted"), "{text}");
        }
    }

    /// A pass that ran and admitted nothing is a real answer, and it must not
    /// read like a pass that could not run.
    #[test]
    fn an_admission_that_changed_nothing_says_so_without_reading_as_a_failure() {
        let mut settled = report(true);
        settled.tracked_before = 4210;
        settled.entities_before = 9977;
        settled.embeddings_indexed = 14187;
        let text = summary_lines(&settled).join("\n");
        assert!(text.contains("nothing changed"), "{text}");
        assert!(!text.contains("failed"), "{text}");
        assert!(text.contains("14187 of 14187 indexed"), "{text}");
    }

    /// The request succeeding is not the outcome. A degraded reconcile state is
    /// reported even when this pass itself admitted cleanly, because that is the
    /// condition the probes exist to publish.
    #[test]
    fn a_degraded_reconcile_state_is_reported_on_an_otherwise_clean_pass() {
        let mut degraded = report(true);
        degraded.reconcile.skipped_events = 4;
        degraded.reconcile.last_error = Some("parse failed".to_string());
        degraded.reconcile.last_error_age_seconds = Some(12);
        let text = summary_lines(&degraded).join("\n");
        assert!(text.contains("Attention:"), "{text}");
        assert!(text.contains("4 reconcile event(s) errored"), "{text}");
    }

    /// Unembedded objects after an admission are the expected steady state, and
    /// an operator who is not told so reads the store as still broken.
    #[test]
    fn pending_embedding_work_is_named_as_queued_rather_than_missing() {
        let text = summary_lines(&report(true)).join("\n");
        assert!(
            text.contains("49 of 14187 indexed; the remainder is queued"),
            "{text}"
        );
    }
}
