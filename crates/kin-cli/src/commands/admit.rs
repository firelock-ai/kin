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
    /// Whether the admitted tree's CONTENT moved, when the daemon could measure
    /// it.
    ///
    /// The two census counters above cannot answer this and were read as if they
    /// could. A pass that rewrites the body of a tracked file adds no artifact
    /// and no entity, so both deltas are zero and the summary said
    /// `nothing changed` over an admission that moved the workspace tree hash
    /// from `70fda9ae` to `c078181f` and its generation from 5 to 6, both
    /// visible three lines apart in the same output. To an operator who had just
    /// edited a file, "nothing changed" reads as "your edit is still not
    /// admitted", which is the opposite of what happened (FIR-2961).
    ///
    /// `None` means nobody looked: an older daemon that does not report it, or a
    /// tree hash that would not compute on one side. It is never collapsed into
    /// `false`, because "the content did not move" and "nothing measured it" are
    /// the two answers this field exists to keep apart.
    #[serde(default)]
    pub tree_moved: Option<bool>,
    /// Wall-clock time of the admission that ran BEFORE this pass, RFC 3339.
    ///
    /// Read on the daemon before this pass records its own success, because the
    /// probes keep one last-success clock and this pass overwrites it. Present
    /// so a settled answer can name what settled it: the watch loop admits on a
    /// 100ms poll, so an operator who edits a file and immediately runs
    /// `kin admit` is often told nothing changed by a pass that is correct and
    /// unhelpful. `None` means no earlier admission is recorded, which is not
    /// the same as one having happened at an unknown time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prior_admission_at: Option<String>,
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

/// Whether this pass moved graph authority at all, by any measure it has.
///
/// Kept beside [`census_moved`] rather than folded into it, because that
/// function is named for the census and answers honestly about the census. This
/// is the question every caller of it actually meant: an admission that rewrote
/// a tracked file's bytes moved authority without moving either count, and a
/// surface deriving "did anything happen" from cardinalities alone reports that
/// as a no-op (FIR-2961).
///
/// An unmeasured tree (`tree_moved: None`) contributes nothing rather than a
/// `false`, so this can only ever be more true than `census_moved`, never less.
pub fn graph_moved(report: &AdmitReport) -> bool {
    census_moved(report) || report.tree_moved == Some(true)
}

/// The one wording that means this pass did not admit the working copy.
///
/// A constant rather than a literal in two places, because the exit-status
/// guard below keys on it: if the summary's wording drifts and the guard's copy
/// does not, the guard silently stops recognizing a failure it is printing.
pub const ADMIT_FAILURE_PREFIX: &str = "Complete exact-tree admission failed: ";

/// The cause this admission must exit non-zero for, or `None` when it admitted.
///
/// Extracted from `run` so the decision is asserted directly rather than through
/// a daemon round trip, and widened past the check it used to be (FIR-3098).
///
/// A stranger on the v0.6.4 candidate watched `kin admit` print
/// `Complete exact-tree admission failed: ...` and exit 0. The check on
/// `report.admitted` was already here and already correct; the hole was the arm
/// beside it. `report` is `Option<AdmitReport>` carrying `#[serde(default)]`, so
/// a response that omits the object deserializes to `None` and fell through to
/// `Ok(())` while the failure the daemon had already rendered sat in `lines` on
/// its way to the operator's terminal.
///
/// So the rule is no longer "the report says it failed". It is that success is
/// the one answer this may not give unless something established it:
///
///   a report that says the pass failed        -> its recorded cause
///   no report at all                          -> no outcome was established
///   a summary line that announces the failure -> that line
///
/// The third arm is deliberately redundant with the first. It keys on the text
/// the operator actually read, so any future response shape that renders a
/// failure into `lines` without a matching report is caught by what it says
/// rather than by what it forgot to set.
pub fn admission_failure(response: &AdmitResponse) -> Option<String> {
    if let Some(report) = response.report.as_ref() {
        if !report.admitted {
            return Some(
                report
                    .failure
                    .as_deref()
                    .or(report.reconcile.last_admission_error.as_deref())
                    .unwrap_or("no cause recorded")
                    .to_string(),
            );
        }
    }
    if let Some(line) = response
        .lines
        .iter()
        .find(|line| line.starts_with(ADMIT_FAILURE_PREFIX))
    {
        return Some(line[ADMIT_FAILURE_PREFIX.len()..].to_string());
    }
    if response.report.is_none() {
        return Some(
            "the daemon returned no admission report, so whether the working copy was admitted \
             is unknown; read `kin graph status` for the state it left behind"
                .to_string(),
        );
    }
    None
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
        lines.push(format!("{ADMIT_FAILURE_PREFIX}{cause}"));
        if graph_moved(report) {
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
        // Three answers, not two. The counts agreeing is the weakest of the
        // three premises a "nothing changed" needs, and on its own it is
        // satisfied by every content-only edit there is.
        match report.tree_moved {
            Some(true) => lines.push(format!(
                "Admitted the complete exact tree; content changed, with no artifact or entity \
                 added or removed. {} tracked artifacts, {} entities.",
                report.tracked_after, report.entities_after
            )),
            Some(false) => lines.push(match report.prior_admission_at.as_deref() {
                // Naming the basis rather than only the verdict, the way
                // kin#1254 did for the `Tree:` line. "Nothing changed" is true
                // and reads as "your edit was not taken" to the one reader most
                // likely to see it: someone who just edited a file. What settles
                // that is WHEN the tree became current, so say it.
                Some(at) => format!(
                    "Admitted the complete exact tree; nothing was left to admit, because the \
                     working copy was already admitted at {at}. {} tracked artifacts, {} \
                     entities.",
                    report.tracked_after, report.entities_after
                ),
                None => format!(
                    "Admitted the complete exact tree; nothing changed, and no earlier \
                     admission is recorded to say when the tree became current. {} tracked \
                     artifacts, {} entities.",
                    report.tracked_after, report.entities_after
                ),
            }),
            None => lines.push(format!(
                "Admitted the complete exact tree. {} tracked artifacts, {} entities, and \
                 neither count moved; this daemon does not report whether content moved, so \
                 this is not a statement that the tree is unchanged.",
                report.tracked_after, report.entities_after
            )),
        }
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
    match admission_failure(&response) {
        Some(cause) => Err(anyhow::anyhow!(
            "complete exact-tree admission failed: {cause}"
        )),
        None => Ok(()),
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
            tree_moved: Some(true),
            prior_admission_at: None,
            admitted,
            failure: (!admitted)
                .then(|| "host entry changed after exact-tree admission".to_string()),
        }
    }

    /// The stranger's own pass: a content-only edit, admitted successfully, with
    /// both counts standing exactly still.
    fn content_only_pass(tree_moved: Option<bool>) -> AdmitReport {
        let mut settled = report(true);
        settled.tracked_before = 8;
        settled.tracked_after = 8;
        settled.entities_before = 39;
        settled.entities_after = 39;
        settled.tree_moved = tree_moved;
        settled
    }

    /// One response as the daemon actually sends it, so a test cannot assert a
    /// shape the wire never carries.
    fn response(report: Option<AdmitReport>) -> AdmitResponse {
        let lines = report.as_ref().map(summary_lines).unwrap_or_default();
        AdmitResponse {
            lines,
            mutated: false,
            report,
        }
    }

    /// FIR-3098, the arm that already worked. Kept as the control: without it a
    /// guard that returned `Some` for everything would pass every test below.
    #[test]
    fn a_failed_report_exits_nonzero_with_its_recorded_cause() {
        let cause = admission_failure(&response(Some(report(false))))
            .expect("a report that says the pass failed must exit nonzero");
        assert!(
            cause.contains("host entry changed after exact-tree admission"),
            "the recorded cause is the news: {cause}"
        );
    }

    /// FIR-3098, the hole. A stranger on the v0.6.4 candidate watched
    /// `kin admit` print `Complete exact-tree admission failed:` and exit 0.
    ///
    /// The check on `report.admitted` was already present and already right, at
    /// the candidate sha as well as on main, so the exit status did not come
    /// from a missing check. It came from the arm beside it: `report` carries
    /// `#[serde(default)]`, so a response that omits the object decodes to
    /// `None` and fell through to `Ok(())` while the failure the daemon had
    /// already rendered travelled to the terminal in `lines`. That is why the
    /// rule is now about what was established rather than about one field.
    #[test]
    fn a_failure_line_with_no_report_still_exits_nonzero() {
        let rendered = summary_lines(&report(false));
        let wire = AdmitResponse {
            lines: rendered.clone(),
            mutated: false,
            report: None,
        };
        assert!(
            rendered
                .first()
                .is_some_and(|line| line.starts_with(ADMIT_FAILURE_PREFIX)),
            "fixture check: the failure the operator reads is in the lines"
        );
        let cause = admission_failure(&wire)
            .expect("a printed failure must never exit zero, whatever the report field holds");
        assert!(
            cause.contains("host entry changed after exact-tree admission"),
            "{cause}"
        );
    }

    /// A response that established no outcome at all is not a success either.
    ///
    /// No report and no lines is the shape a future transport change, or a
    /// daemon that answered before it ran the pass, would produce. Success is
    /// the one answer that must not be given for it.
    #[test]
    fn a_response_with_no_outcome_exits_nonzero() {
        let cause = admission_failure(&AdmitResponse {
            lines: Vec::new(),
            mutated: false,
            report: None,
        })
        .expect("a response that established nothing must not read as success");
        assert!(cause.contains("no admission report"), "{cause}");
    }

    /// The control every assertion above depends on. A guard that refused
    /// everything would satisfy all three and break `kin admit` completely.
    #[test]
    fn a_real_admission_exits_zero() {
        assert_eq!(admission_failure(&response(Some(report(true)))), None);
        assert_eq!(
            admission_failure(&response(Some(content_only_pass(Some(true))))),
            None
        );
    }

    /// The wording and the guard are one string, checked to be one string.
    ///
    /// The line-scanning arm of `admission_failure` keys on the prefix the
    /// summary prints. If the summary's wording ever drifts and the guard's copy
    /// does not, that arm silently stops recognizing a failure it is printing,
    /// which is the exact defect shape it was added to close.
    #[test]
    fn the_summary_uses_the_prefix_the_exit_guard_keys_on() {
        let first = summary_lines(&report(false))
            .first()
            .cloned()
            .expect("a failed pass renders a cause line first");
        assert!(first.starts_with(ADMIT_FAILURE_PREFIX), "{first}");
    }

    /// FIR-2961. The stranger edited one tracked file, ran `kin admit`, and was
    /// told `nothing changed` by a pass that moved the workspace tree hash from
    /// `70fda9ae` to `c078181f` and its generation from 5 to 6. Both counts held
    /// at 8 and 39 across it, because a content-only edit adds no artifact and
    /// no entity, so the two premises the wording rested on were both true and
    /// the wording was false.
    #[test]
    fn a_content_only_admission_is_not_reported_as_nothing_changed() {
        let text = summary_lines(&content_only_pass(Some(true))).join("\n");
        assert!(
            !text.contains("nothing changed"),
            "a pass that moved the tree must not claim nothing changed: {text}"
        );
        assert!(text.contains("content changed"), "{text}");
        assert!(text.contains("8 tracked artifacts"), "{text}");
        assert!(text.contains("39 entities"), "{text}");
    }

    /// The control the test above needs to mean anything. A pass over a tree
    /// that genuinely did not move still says so, or the fix is just a surface
    /// that never gives an all-clear.
    #[test]
    fn a_pass_over_an_unmoved_tree_still_reports_nothing_changed() {
        let text = summary_lines(&content_only_pass(Some(false))).join("\n");
        assert!(text.contains("nothing changed"), "{text}");
        assert!(!text.contains("content changed"), "{text}");
    }

    /// A settled pass names WHEN the tree became current.
    ///
    /// "Nothing changed" is true and reads as "your edit was not taken" to the
    /// one reader most likely to see it, someone who edited a file a second
    /// earlier. Measured on kin 0.6.2 at 510be53f9: the watch loop drains its
    /// file watcher every 100ms and admits what it finds, so an admit issued
    /// 1.0s after a write reported nothing changed 6 times out of 6, while one
    /// issued immediately reported the content change 6 out of 6. The pass was
    /// right both times. What was missing was the basis, so this asserts the
    /// clock is named AND that the bare wording is gone, because a branch that
    /// appended a time without replacing the sentence would pass a weaker test.
    #[test]
    fn a_settled_pass_names_when_the_tree_became_current() {
        let mut settled = content_only_pass(Some(false));
        settled.prior_admission_at = Some("2026-08-30T20:04:00Z".to_string());
        let text = summary_lines(&settled).join("\n");
        assert!(
            text.contains("already admitted at 2026-08-30T20:04:00Z"),
            "a settled pass must name when the tree became current: {text}"
        );
        assert!(
            !text.contains("nothing changed"),
            "the basis replaces the bare wording rather than sitting beside it: {text}"
        );
    }

    /// And the third answer stays three-way. No recorded admission is not the
    /// same as one at an unknown time, so the absence is named rather than
    /// rendered as a bare "nothing changed" that a reader would take for a
    /// basis it does not have.
    #[test]
    fn a_settled_pass_with_no_recorded_admission_says_so_rather_than_inventing_one() {
        let settled = content_only_pass(Some(false));
        assert!(settled.prior_admission_at.is_none(), "fixture precondition");
        let text = summary_lines(&settled).join("\n");
        assert!(
            text.contains("no earlier admission is recorded"),
            "an absent clock must be named as absent: {text}"
        );
        assert!(!text.contains("already admitted at"), "{text}");
    }

    /// An unmeasured tree is the third answer and must render as neither of the
    /// other two. An older daemon reports no `tree_moved`, and turning that into
    /// a `false` puts the defect straight back, one field further down.
    #[test]
    fn an_unmeasured_tree_claims_neither_outcome() {
        let text = summary_lines(&content_only_pass(None)).join("\n");
        assert!(
            !text.contains("nothing changed"),
            "an unmeasured tree is not an unchanged tree: {text}"
        );
        assert!(!text.contains("content changed"), "{text}");
        assert!(
            text.contains("does not report whether content moved"),
            "{text}"
        );
        assert!(text.contains("8 tracked artifacts"), "{text}");
    }

    /// `graph_moved` is what every "did anything happen" caller meant, and the
    /// three readings have to come out in this order or `mutated` publishes a
    /// content-only admission as a no-op.
    #[test]
    fn graph_moved_is_true_for_a_content_only_pass_and_unmeasured_never_invents_one() {
        assert!(!census_moved(&content_only_pass(Some(true))));
        assert!(graph_moved(&content_only_pass(Some(true))));
        assert!(!graph_moved(&content_only_pass(Some(false))));
        assert!(!graph_moved(&content_only_pass(None)));
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
        // The tree stood still too. A refusal before the publish moves nothing,
        // and this fixture has to say so on every reading, not only the census,
        // or the wording it grades is chosen by the wrong branch.
        refused.tree_moved = Some(false);
        assert!(!census_moved(&refused));
        assert!(!graph_moved(&refused));

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
        // The tree stood still too, which this fixture has to say now that the
        // wording rests on three readings rather than two. Equal counts alone
        // are what a content-only edit also produces, and that case is the one
        // `a_content_only_admission_is_not_reported_as_nothing_changed` grades.
        settled.tree_moved = Some(false);
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
