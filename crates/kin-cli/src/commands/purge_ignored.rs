// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Wire types and CLI transport for retiring tracked paths that ignore rules
//! now cover.
//!
//! Admission retracts a tracked path once the rules cover it, so the backlog a
//! repository built up before a rule existed clears on its own. This surface
//! exists for the operator who wants to see the set first, or to retire it now
//! rather than on the next observation.
//!
//! The default is a dry run. It names how many tracked paths the current rules
//! cover, how many would remain, and a bounded sample of the paths themselves.
//! Nothing moves until `--confirm`.
//!
//! Retiring a path removes the artifact and the entities, layout, and index
//! presence derived from it, because those are what let it rank. The file stays
//! on disk; this untracks rather than deletes.

use anyhow::{Context, Result};
use kin_model::{AuthorId, OperationId, RepositoryId};
use serde::{Deserialize, Serialize};

pub const PURGE_IGNORED_SCHEMA: &str = "kin.purge-ignored.v1";

/// How many purged paths the report carries back.
///
/// A purge can cover millions of paths. The count is the decision input; the
/// sample only lets an operator confirm the rules match what they expected.
pub const REPORTED_PATH_SAMPLE: usize = 50;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PurgeIgnoredRequest {
    /// Publish the removal. Without it the daemon only reports what it would do.
    pub confirm: bool,
    /// Confirm a purge that removes more than 75% of a non-trivial tree.
    ///
    /// A repository whose graph is mostly build output legitimately trips the
    /// mass-deletion guard, and that is exactly the case this command exists to
    /// fix, so the operator can accept it without disabling the guard globally.
    pub confirm_mass_deletion: bool,
    pub operation_id: OperationId,
    pub actor: AuthorId,
}

/// What the published transition actually did.
///
/// A confirmed purge plans from a complete working-directory walk, the same
/// shape the watch loop admits, so it can also carry an addition or
/// modification made since the last tick. Reporting only the planned purge set
/// would name a number the transition did not do.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PublishedTransition {
    pub removed: usize,
    pub added: usize,
    pub modified: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PurgeIgnoredReport {
    pub schema: String,
    pub repository_id: RepositoryId,
    /// Whether the repository states its own rules in `.kinignore`.
    pub kinignore_present: bool,
    /// Tracked paths before this purge.
    pub tracked_total: usize,
    /// Tracked paths the current ignore rules cover.
    pub purge_count: usize,
    /// Tracked paths that remain.
    pub retained_total: usize,
    /// Up to [`REPORTED_PATH_SAMPLE`] of the covered paths, in path order.
    pub sample_paths: Vec<String>,
    /// True when `sample_paths` is shorter than `purge_count`.
    pub sample_truncated: bool,
    /// False for a dry run.
    pub applied: bool,
    /// Present only when this purge published a transition.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_generation: Option<u64>,
    /// What the published transition did. `None` for a dry run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published: Option<PublishedTransition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurgeIgnoredResponse {
    #[serde(default)]
    pub lines: Vec<String>,
    #[serde(default)]
    pub mutated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<PurgeIgnoredReport>,
}

/// Render the operator-facing summary for one purge report.
///
/// Kept separate from transport so the wording is asserted directly rather than
/// through a daemon round trip.
pub fn summary_lines(report: &PurgeIgnoredReport) -> Vec<String> {
    let mut lines = Vec::new();
    if !report.kinignore_present {
        lines.push(
            "This repository has no .kinignore; the built-in defaults decided this set."
                .to_string(),
        );
    }
    lines.push(format!(
        "{} of {} tracked paths are covered by ignore rules; {} would remain.",
        report.purge_count, report.tracked_total, report.retained_total
    ));
    for path in &report.sample_paths {
        lines.push(format!("  {path}"));
    }
    if report.sample_truncated {
        lines.push(format!(
            "  ... {} more",
            report.purge_count.saturating_sub(report.sample_paths.len())
        ));
    }
    if report.purge_count == 0 {
        lines.push("Nothing to purge.".to_string());
    } else if let Some(published) = report.published {
        // Report what the transition did, not what was planned. A confirmed
        // purge admits a complete working-directory observation, so it can
        // carry an edit made since the last watch-loop tick, and claiming the
        // planned count would describe a transition that did not happen.
        lines.push(format!(
            "Published: {} removed, {} added, {} modified.",
            published.removed, published.added, published.modified
        ));
        if published.removed != report.purge_count {
            lines.push(format!(
                "Note: {} paths were reported as covered; the observation also carried \
                 concurrent working-directory changes.",
                report.purge_count
            ));
        }
    } else if report.applied {
        lines.push(format!("Untracked {} paths.", report.purge_count));
    } else {
        lines.push("Dry run; nothing changed. Re-run with --confirm to untrack these.".to_string());
    }
    lines
}

pub async fn run(confirm: bool, confirm_mass_deletion: bool) -> Result<()> {
    let cwd = std::env::current_dir().context("resolve current directory")?;
    let layout = crate::commands::require_repository_layout_at(&cwd)?;
    let base_url = crate::daemon_client::resolve_daemon_url(&layout)
        .await?
        .ok_or_else(|| {
            crate::daemon_client::daemon_required_error("retiring tracked paths", &layout)
        })?;
    let client = crate::daemon_client::DaemonClient::from_base_url_for_layout(base_url, &layout)?;
    let response = client
        .purge_ignored(&PurgeIgnoredRequest {
            confirm,
            confirm_mass_deletion,
            operation_id: OperationId::new(),
            actor: AuthorId::new(kin_core::whoami()),
        })
        .await?;
    for line in &response.lines {
        println!("{line}");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report(purge_count: usize, applied: bool, kinignore_present: bool) -> PurgeIgnoredReport {
        PurgeIgnoredReport {
            schema: PURGE_IGNORED_SCHEMA.to_string(),
            repository_id: RepositoryId::new("purge-summary").unwrap(),
            kinignore_present,
            tracked_total: 100,
            purge_count,
            retained_total: 100 - purge_count,
            sample_paths: vec!["target/debug/app.o".to_string()],
            sample_truncated: purge_count > 1,
            applied,
            authority_generation: applied.then_some(7),
            published: applied.then_some(PublishedTransition {
                removed: purge_count,
                added: 0,
                modified: 0,
            }),
        }
    }

    #[test]
    fn dry_run_summary_names_counts_and_refuses_to_claim_a_change() {
        let lines = summary_lines(&report(40, false, true));
        let text = lines.join("\n");
        assert!(text.contains("40 of 100 tracked paths"), "{text}");
        assert!(text.contains("60 would remain"), "{text}");
        assert!(text.contains("target/debug/app.o"), "{text}");
        assert!(text.contains("... 39 more"), "{text}");
        assert!(text.contains("Dry run; nothing changed"), "{text}");
        assert!(!text.contains("Untracked"), "{text}");
        assert!(!text.contains("no .kinignore"), "{text}");
    }

    #[test]
    fn applied_summary_reports_the_published_transition_not_the_planned_set() {
        let lines = summary_lines(&report(40, true, true));
        let text = lines.join("\n");
        assert!(
            text.contains("Published: 40 removed, 0 added, 0 modified."),
            "{text}"
        );
        assert!(!text.contains("Dry run"), "{text}");
    }

    /// A confirmed purge admits a complete observation, so it can carry an edit
    /// made since the last watch-loop tick. The summary must describe what the
    /// transition did rather than repeating the planned count.
    #[test]
    fn a_transition_wider_than_the_purge_set_is_reported_as_such() {
        let mut wider = report(40, true, true);
        wider.published = Some(PublishedTransition {
            removed: 40,
            added: 2,
            modified: 1,
        });
        let text = summary_lines(&wider).join("\n");
        assert!(
            text.contains("Published: 40 removed, 2 added, 1 modified."),
            "{text}"
        );
        assert!(!text.contains("Untracked 40 paths."), "{text}");

        // A removal count that disagrees with the reported set is called out.
        let mut fewer = report(40, true, true);
        fewer.published = Some(PublishedTransition {
            removed: 38,
            added: 0,
            modified: 0,
        });
        let text = summary_lines(&fewer).join("\n");
        assert!(text.contains("Published: 38 removed"), "{text}");
        assert!(text.contains("40 paths were reported as covered"), "{text}");
    }

    #[test]
    fn an_unconfigured_repository_is_told_the_defaults_decided_the_set() {
        let text = summary_lines(&report(40, false, false)).join("\n");
        assert!(text.contains("no .kinignore"), "{text}");
        assert!(
            text.contains("built-in defaults decided this set"),
            "{text}"
        );
    }

    #[test]
    fn an_empty_purge_says_so_rather_than_offering_confirm() {
        let mut empty = report(0, false, true);
        empty.sample_paths.clear();
        empty.sample_truncated = false;
        let text = summary_lines(&empty).join("\n");
        assert!(text.contains("Nothing to purge."), "{text}");
        assert!(!text.contains("--confirm"), "{text}");
    }
}
