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
//! Two properties matter beyond the request itself. The CLI registers a daemon
//! session for the duration and releases it afterwards, because a daemon with no
//! registered session idles out while a long first pass is still running, and an
//! admission killed at its midpoint is the failure this command exists to
//! resolve. And the outcome is read back from the reconcile probes rather than
//! inferred from the request succeeding, because a pass that ran and admitted
//! nothing and a pass that ran and failed are different answers.

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

/// Render the operator-facing summary for one admission report.
///
/// Kept separate from transport so the wording is asserted directly rather than
/// through a daemon round trip.
pub fn summary_lines(report: &AdmitReport) -> Vec<String> {
    let mut lines = Vec::new();

    if !report.admitted {
        // Cause first: the operator needs the reason before the counters, and
        // the counters below describe a tree the pass did not change.
        let cause = report
            .failure
            .as_deref()
            .or(report.reconcile.last_admission_error.as_deref())
            .unwrap_or("no cause recorded");
        lines.push(format!("Complete exact-tree admission failed: {cause}"));
        lines.push(format!(
            "Graph authority is unchanged: {} tracked artifacts, {} entities.",
            report.tracked_before, report.entities_before
        ));
        return lines;
    }

    let tracked_delta = report.tracked_after as i64 - report.tracked_before as i64;
    let entity_delta = report.entities_after as i64 - report.entities_before as i64;
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

    let outcome = client
        .admit(&AdmitRequest {
            operation_id: OperationId::new(),
            actor: AuthorId::new(kin_core::whoami()),
        })
        .await;

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
            failure: (!admitted).then(|| "host entry changed after exact-tree admission".to_string()),
        }
    }

    #[test]
    fn a_successful_admission_names_both_sides_of_the_transition() {
        let text = summary_lines(&report(true)).join("\n");
        assert!(text.contains("4210 tracked artifacts (+4179)"), "{text}");
        assert!(text.contains("9977 entities (+9977)"), "{text}");
        assert!(!text.contains("failed"), "{text}");
    }

    /// The counters describe a tree the failed pass did not change, so the cause
    /// has to lead and the counters have to say they are unchanged.
    #[test]
    fn a_failed_admission_leads_with_its_cause_and_refuses_to_claim_a_change() {
        let text = summary_lines(&report(false)).join("\n");
        let first = text.lines().next().unwrap_or_default();
        assert!(
            first.starts_with("Complete exact-tree admission failed: host entry changed"),
            "{text}"
        );
        assert!(text.contains("Graph authority is unchanged"), "{text}");
        assert!(!text.contains("4210"), "{text}");
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
