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
//! What it adds is an answer. The pass itself returns `()`, and a store's
//! operator needs to know whether it moved anything and whether it worked, so
//! the graph is measured on both sides of the call and the reconcile probes are
//! read afterwards. Those two facts are different: a pass can succeed and admit
//! nothing, which is the settled case, and a pass can fail while the request
//! that carried it returns cleanly, which is the case the probes exist to
//! publish.

use anyhow::Result;
use kin_cli::commands::admit::{summary_lines, AdmitReport, AdmitResponse, ADMIT_SCHEMA};
use std::time::Instant;

use crate::state::DaemonState;

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

/// Run one complete exact-tree admission and report what it did.
///
/// Never returns `Err` for a failed admission. A refused pass is an outcome the
/// operator has to see the counters and the cause for, and turning it into a
/// transport-level error would strip both and leave `kin admit` printing an
/// HTTP status. The CLI exits nonzero off `AdmitReport::admitted` instead.
/// Transport, initialization, and authority problems still refuse at the
/// handler, because those mean no pass ran at all.
pub(crate) async fn execute(state: &DaemonState) -> Result<AdmitResponse> {
    let repository_id =
        crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(state)?
            .repository_id()
            .clone();
    let before = census(state);

    // The same seam `/commands/commit` calls. It takes the coordination gate
    // itself, so this handler must not already hold it.
    let outcome = crate::loop_runner::sync_filesystem_with_graph(state).await;

    // Record the outcome on the same probes the ambient loop records to. A pass
    // requested here is a complete exact-tree admission by every measure that
    // matters to a reader of `kin graph status` or `/health`, and leaving it out
    // would make an operator's own recovery attempt the one admission the
    // health surfaces cannot see.
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

    let after = census(state);
    let embeddings = state.graph.embedding_status();
    let mut report = AdmitReport {
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
    // A failed pass publishes nothing, so the two sides of the census describe
    // one unchanged tree. Saying so outright keeps the summary from reading a
    // concurrent tick's work as this pass's.
    if !report.admitted {
        report.tracked_after = report.tracked_before;
        report.entities_after = report.entities_before;
    }

    let lines = summary_lines(&report);
    let mutated = report.admitted
        && (report.tracked_after != report.tracked_before
            || report.entities_after != report.entities_before);
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
