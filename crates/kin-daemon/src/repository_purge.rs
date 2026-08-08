// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Daemon-owned retirement of tracked paths that ignore rules now cover.
//!
//! Ignore rules deliberately never hide tracked paths, so adding a rule cannot
//! turn graph-owned identity into a deletion. The cost of that safety is a
//! backlog: a repository that admitted derived output before a rule existed
//! keeps carrying it. This module is the deliberate operator action that
//! retires the backlog, and nothing here runs without an explicit confirmation.
//!
//! The removal is published as one complete exact-tree observation, the same
//! transition shape the watch loop admits, with one difference: the scan is
//! given a tracked set that omits the covered paths. Those paths are then
//! untracked and ignored, so the walk skips them and the planner reports them
//! as removed. Doing it through a real completed walk rather than a synthesized
//! delta means the purge inherits the same completion proof, authority
//! compare-and-swap, and mass-deletion guard as every other admission.

use anyhow::{Context, Result};
use kin_cli::commands::purge_ignored::{
    summary_lines, PublishedTransition, PurgeIgnoredReport, PurgeIgnoredRequest,
    PurgeIgnoredResponse, PURGE_IGNORED_SCHEMA, REPORTED_PATH_SAMPLE,
};
use kin_db::EntityStore;
use kin_model::{RepoPath, TransactionDelta, TreeDelta};
use std::collections::BTreeSet;

use crate::error::DaemonError;
use crate::state::DaemonState;

fn invalid(message: String) -> DaemonError {
    DaemonError::Graph(kin_db::KinDbError::Model(
        kin_model::ModelError::InvalidOperation(message),
    ))
}

/// Plan and, when confirmed, publish the retirement of ignored tracked paths.
pub(crate) fn execute(
    state: &DaemonState,
    request: &PurgeIgnoredRequest,
) -> Result<PurgeIgnoredResponse> {
    let working_dir = state.layout.working_dir();
    let ignore = kin_index::RepositoryIgnore::load(working_dir)
        .map_err(kin_index::IndexError::from)
        .context("load repository ignore rules")?;
    let previous = state.graph.resolved_tree();

    let mut tracked = Vec::new();
    let mut graph_only = BTreeSet::new();
    for artifact in previous.artifacts_by_path() {
        tracked.push(artifact.path.clone());
        if kin_core::source_projection_disposition(&artifact.path, artifact.entry)?
            != kin_core::SourceProjectionDisposition::Materialized
        {
            graph_only.insert(artifact.path.clone());
        }
    }

    // The same rule source the daemon's own admission reads, so what this
    // command reports and what a tick retracts can never be two different sets.
    let covered =
        kin_index::tracked_paths_retracted_by_ignore(&ignore, tracked.iter(), graph_only.iter());
    let purge_set = covered.paths().iter().cloned().collect::<BTreeSet<_>>();

    let sample_paths = purge_set
        .iter()
        .take(REPORTED_PATH_SAMPLE)
        .map(|path| path.to_string())
        .collect::<Vec<_>>();
    let mut report = PurgeIgnoredReport {
        schema: PURGE_IGNORED_SCHEMA.to_string(),
        repository_id:
            crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(state)?
                .repository_id()
                .clone(),
        kinignore_present: ignore.is_configured(),
        tracked_total: covered.tracked_total(),
        purge_count: purge_set.len(),
        retained_total: covered.tracked_total().saturating_sub(purge_set.len()),
        sample_truncated: purge_set.len() > sample_paths.len(),
        sample_paths,
        applied: false,
        authority_generation: None,
        published: None,
    };

    if !request.confirm || purge_set.is_empty() {
        let lines = summary_lines(&report);
        return Ok(PurgeIgnoredResponse {
            lines,
            mutated: false,
            report: Some(report),
        });
    }

    let expected_roots = crate::loop_runner::current_authority_roots(state)?;
    let retained_tracked = tracked
        .iter()
        .filter(|path| !purge_set.contains(*path))
        .collect::<Vec<&RepoPath>>();
    let scan = kin_index::scan_repository_preserving_graph_only(
        working_dir,
        &ignore,
        retained_tracked.into_iter(),
        graph_only.iter(),
    )
    .map_err(kin_index::IndexError::from)
    .context("walk the working directory for the purge observation")?;
    let observed =
        crate::commit_deltas::observed_tree_from_complete_scan(&state.blobs, &scan, &previous)?;
    let deltas = kin_core::plan_observed_tree_deltas(&previous, observed.entries().clone())?;

    let removed = deltas
        .iter()
        .filter(|delta| matches!(delta, TreeDelta::Removed { .. }))
        .count();
    // The guard exists so an unconfirmed observation cannot wipe a tree. A
    // repository whose graph is mostly build output trips it legitimately, so
    // the operator confirms this purge specifically rather than disabling the
    // guard for every observation the daemon makes.
    if crate::loop_runner::should_block_mass_deletion(
        removed as u64,
        previous.len() as u64,
        request.confirm_mass_deletion,
    ) {
        return Err(invalid(format!(
            "this purge removes {removed} of {} tracked paths; re-run with \
             --confirm-mass-deletion to accept a removal that large",
            previous.len()
        ))
        .into());
    }

    let desired_tree = previous
        .apply(&deltas)
        .map_err(|error| invalid(format!("invalid purge tree transition: {error}")))?;
    let admitted = crate::repository_commit::AdmittedWorkspaceTree::from_complete_observation(
        observed.completion(),
        expected_roots,
        previous.clone(),
        desired_tree,
    );

    // Raise the graph-authority writer guard before touching the live graph.
    // The handler's coordination gate excludes other writers, but the seqlock
    // readers (mcp graph status, xref reads) take no gate at all: they sample
    // the authority epoch, read, and revalidate. Without this guard the epoch
    // never moves and `active_writers` stays zero, so a reader spanning a purge
    // of up to 1.28M artifacts revalidates a torn view as stable. Dropping the
    // guard also invalidates cross-repo spine edges pointing at purged
    // artifacts, which would otherwise still be served as complete.
    let graph_mutation = state.begin_graph_authority_mutation();
    let generation = crate::loop_runner::publish_exact_workspace_tree(state, &admitted)?;
    // Untracking an artifact while its entities keep ranking is the exposure a
    // purge exists to close, so the enrichment goes with the tree entry and it
    // goes before the graph is asked to accept a tree that no longer carries it.
    crate::loop_runner::evict_enrichment_for_removed_paths(state, &deltas)?;
    state.graph.apply_transaction_delta(&TransactionDelta {
        entity_deltas: Vec::new(),
        relation_deltas: Vec::new(),
        tree_deltas: deltas.clone(),
        ..TransactionDelta::default()
    })?;
    drop(graph_mutation);
    // VFS paging cursors, the /vfs/version endpoint, and the version half of the
    // xref read check all key on this. Skipping it after the single largest tree
    // transition the system can make would leave every projection reader
    // believing nothing changed.
    state.bump_version();

    report.applied = true;
    report.authority_generation = generation;
    report.published = Some(published_composition(&deltas));
    let lines = summary_lines(&report);
    Ok(PurgeIgnoredResponse {
        lines,
        mutated: true,
        report: Some(report),
    })
}

/// Count what the published transition actually did.
///
/// The purge plans from a complete working-directory walk, exactly as the watch
/// loop does, so the transition also carries any addition or modification made
/// since the last tick. Reporting the planned purge set alone would name a
/// number the transition did not do.
fn published_composition(deltas: &[TreeDelta]) -> PublishedTransition {
    let mut published = PublishedTransition::default();
    for delta in deltas {
        match delta {
            TreeDelta::Removed { .. } => published.removed += 1,
            TreeDelta::Added { .. } => published.added += 1,
            _ => published.modified += 1,
        }
    }
    published
}
