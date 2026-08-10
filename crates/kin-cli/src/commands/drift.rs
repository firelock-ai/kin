// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Wire types and CLI transport for daemon-owned projection drift reporting.
//!
//! Drift compares the derived working-copy projection against the exact
//! workspace tree repository-v6 authority owns. Content for every compared path
//! is loaded from repository authority, never from the working copy, and paths
//! the workspace tree does not track are never read: untracked host bytes are
//! not graph-owned, so they cannot drift. The observation is bound to one exact
//! workspace generation and is refused rather than reported when authority
//! moves underneath it.

use anyhow::{bail, Context, Result};
use kin_model::{
    AuthorId, OperationId, RepoPath, RepositoryId, RootBundle, WorkspaceHead, WorkspaceId,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const DRIFT_SCHEMA: &str = "kin.projection-drift.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DriftRequest {
    #[serde(default)]
    pub json: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DriftReport {
    pub schema: String,
    pub authority: String,
    pub repository_id: RepositoryId,
    pub authority_generation: u64,
    pub roots: RootBundle,
    pub workspace_id: WorkspaceId,
    pub workspace_generation: u64,
    pub workspace_head: WorkspaceHead,
    /// Tracked members of the exact workspace tree, including members this host
    /// cannot materialize.
    pub tracked_artifacts: usize,
    /// Materializable tracked members actually compared against the projection.
    pub compared_entries: usize,
    pub drift_count: usize,
    pub drift: Vec<String>,
    /// The same divergences as `drift`, positionally, as byte-exact repository
    /// paths in lowercase hex.
    ///
    /// Defaulted rather than required so a report from a daemon that predates
    /// this field still deserializes. `kin doctor --heal` then refuses for want
    /// of paths instead of healing nothing and calling it clean.
    #[serde(default)]
    pub drifted_paths_hex: Vec<String>,
    pub clean: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftResponse {
    #[serde(default)]
    pub lines: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<DriftReport>,
}

pub async fn run(json: bool) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    let daemon_url = crate::daemon_client::resolve_daemon_url(&layout)
        .await?
        .ok_or_else(|| {
            crate::daemon_client::daemon_required_error("projection drift reporting", &layout)
        })?;
    let daemon = crate::daemon_client::DaemonClient::from_base_url_for_layout(daemon_url, &layout)?;
    let response = daemon.drift(&DriftRequest { json }).await?;
    if json {
        let report = response
            .report
            .ok_or_else(|| anyhow::anyhow!("daemon drift response omitted its report"))?;
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        for line in response.lines {
            println!("{line}");
        }
    }
    Ok(())
}

pub const HEAL_SCHEMA: &str = "kin.projection-heal.v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HealReport {
    pub schema: String,
    pub repository_id: RepositoryId,
    pub authority_generation: u64,
    pub observed_drift: usize,
    /// Byte-exact repository paths restored from graph authority, in lowercase
    /// hex, in the order they were restored.
    pub restored_paths_hex: Vec<String>,
    pub remaining_drift: usize,
    pub clean: bool,
}

/// `kin doctor --heal` — rematerialize the derived projection from graph truth.
///
/// Heal is the write half of `--drift` and owns no authority of its own: it
/// observes drift through the daemon, restores each diverged path through the
/// daemon-owned exact checkout that already publishes a repository transaction
/// for it, and then re-observes. Nothing here reads the working copy or repairs
/// from it; every restored byte comes from repository authority.
///
/// It refuses rather than reporting success whenever it cannot prove the
/// projection ended clean: a heal that quietly restored nothing is
/// indistinguishable from a projection that never drifted.
///
/// This DISCARDS uncommitted changes to any tracked file that diverges, with no
/// undo. It is not a merge. There is deliberately no dirty-tree refusal in front
/// of it: divergence is exactly what drift reports, so a check that refused on a
/// modified tracked file would refuse every heal this command exists to perform.
/// The warning therefore lives in the help text and the capability note, where a
/// caller reads it before running rather than after losing an edit.
pub async fn heal(json: bool) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    let daemon_url = crate::daemon_client::resolve_daemon_url(&layout)
        .await?
        .ok_or_else(|| {
            crate::daemon_client::daemon_required_error("projection healing", &layout)
        })?;
    let daemon = crate::daemon_client::DaemonClient::from_base_url_for_layout(daemon_url, &layout)?;

    let observed = drift_report(&daemon).await?;
    let selections = healable_selections(
        observed.clean,
        observed.drift_count,
        &observed.drifted_paths_hex,
    )?;

    let mut restored_paths_hex = Vec::with_capacity(selections.len());
    for selected in &selections {
        let request = crate::commands::checkout::CheckoutRequest {
            path: None,
            path_hex: Some(hex::encode(selected.as_bytes())),
            change_id: None,
            operation_id: OperationId::new(),
            actor: AuthorId::new(kin_core::whoami()),
        };
        daemon.checkout(&request).await.with_context(|| {
            format!("restore {selected} from repository authority while healing the projection")
        })?;
        restored_paths_hex.push(hex::encode(selected.as_bytes()));
    }

    let after = drift_report(&daemon).await?;
    let report = HealReport {
        schema: HEAL_SCHEMA.to_string(),
        repository_id: after.repository_id.clone(),
        authority_generation: after.authority_generation,
        observed_drift: observed.drift_count,
        restored_paths_hex,
        remaining_drift: after.drift_count,
        clean: after.clean,
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        for line in render_heal_lines(&report) {
            println!("{line}");
        }
    }

    if !report.clean {
        bail!(
            "projection heal restored {} path(s) but {} tracked path(s) still diverge from graph \
             authority: {}. Rerun `kin doctor --drift` to see them, and `kin commit` if the \
             working-copy state is what you meant to keep.",
            report.restored_paths_hex.len(),
            report.remaining_drift,
            after.drift.join("; ")
        );
    }
    Ok(())
}

async fn drift_report(daemon: &crate::daemon_client::DaemonClient) -> Result<DriftReport> {
    daemon
        .drift(&DriftRequest { json: true })
        .await?
        .report
        .ok_or_else(|| anyhow::anyhow!("daemon drift response omitted its report"))
}

/// The distinct paths a heal will restore, or a refusal explaining why the
/// report cannot be acted on.
///
/// A drift count with no accompanying paths is the version-skew case: an older
/// daemon reports divergence in prose only. Healing "every path it named"
/// would then restore nothing and report a clean projection, so it refuses.
fn healable_selections(
    clean: bool,
    drift_count: usize,
    drifted_paths_hex: &[String],
) -> Result<Vec<RepoPath>> {
    if clean {
        return Ok(Vec::new());
    }
    if drifted_paths_hex.is_empty() {
        bail!(
            "the daemon reported {drift_count} diverged path(s) without naming them, so there is \
             nothing to restore exactly; this daemon predates byte-exact drift paths. Restart it \
             with `kin daemon stop` so the current build takes over, then rerun `kin doctor \
             --heal`."
        );
    }
    if drifted_paths_hex.len() != drift_count {
        bail!(
            "the daemon reported {drift_count} diverged path(s) but named {}; refusing to heal a \
             report that does not describe one consistent observation",
            drifted_paths_hex.len()
        );
    }

    let mut seen = BTreeSet::new();
    let mut selections = Vec::new();
    for encoded in drifted_paths_hex {
        // Reuse the checkout parser so a reserved or malformed path is refused
        // here, with the same wording, rather than being sent to the daemon.
        let selected = crate::commands::checkout::parse_checkout_path(None, Some(encoded))
            .with_context(|| format!("drifted path '{encoded}' is not restorable"))?;
        if seen.insert(selected.as_bytes().to_vec()) {
            selections.push(selected);
        }
    }
    Ok(selections)
}

pub fn render_heal_lines(report: &HealReport) -> Vec<String> {
    let mut lines = vec![
        "Kin repository-v6 projection heal".to_string(),
        format!("Authority generation: {}", report.authority_generation),
    ];
    if report.observed_drift == 0 {
        lines.push(
            "No drift: the derived projection already matched graph authority, so nothing was \
             restored."
                .to_string(),
        );
        return lines;
    }
    lines.push(format!(
        "Restored {} of {} diverged path(s) from graph-owned content",
        report.restored_paths_hex.len(),
        report.observed_drift
    ));
    if report.clean {
        lines.push("The derived projection now matches graph authority.".to_string());
    } else {
        lines.push(format!(
            "{} tracked path(s) still diverge.",
            report.remaining_drift
        ));
    }
    lines
}

pub fn render_lines(report: &DriftReport) -> Vec<String> {
    let mut lines = vec![
        "Kin repository-v6 projection drift".to_string(),
        format!("Authority generation: {}", report.authority_generation),
        format!(
            "Workspace {} generation {} ({})",
            report.workspace_id,
            report.workspace_generation,
            render_head(&report.workspace_head)
        ),
        format!(
            "Compared {} of {} tracked artifact(s) against graph-owned content",
            report.compared_entries, report.tracked_artifacts
        ),
    ];
    if report.clean {
        lines.push("No drift: the derived projection matches graph authority.".to_string());
        return lines;
    }
    lines.push(format!(
        "{} tracked path(s) diverge from graph-owned workspace truth:",
        report.drift_count
    ));
    for detail in &report.drift {
        lines.push(format!("  {detail}"));
    }
    lines.push(
        "Restore graph truth with `kin checkout <path>`, or admit the working-copy state with \
         `kin commit`."
            .to_string(),
    );
    lines
}

fn render_head(head: &WorkspaceHead) -> String {
    match head {
        WorkspaceHead::Symbolic { target } => format!("on {target}"),
        WorkspaceHead::Detached { .. } => "detached".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::{healable_selections, render_heal_lines, HealReport, HEAL_SCHEMA};
    use kin_model::RepositoryId;

    fn hex_of(path: &[u8]) -> String {
        hex::encode(path)
    }

    /// A clean report has nothing to restore, and must not be treated as a
    /// report that failed to name its paths.
    #[test]
    fn a_clean_projection_selects_nothing() {
        assert!(healable_selections(true, 0, &[]).unwrap().is_empty());
    }

    /// The version-skew trap: an older daemon reports divergence in prose only.
    /// Healing "each named path" would then restore nothing and re-observe a
    /// projection that is still dirty, so the refusal has to come first and
    /// name the remedy.
    #[test]
    fn drift_with_no_named_paths_refuses_instead_of_healing_nothing() {
        let error = healable_selections(false, 3, &[])
            .expect_err("a report naming no paths must not produce an empty heal");
        let message = error.to_string();

        assert!(message.contains("without naming them"), "{message}");
        assert!(message.contains("kin daemon stop"), "{message}");
    }

    /// A report whose count and path list disagree describes no single
    /// observation, so acting on either number would be a guess.
    #[test]
    fn a_count_that_disagrees_with_the_named_paths_is_refused() {
        let error = healable_selections(false, 2, &[hex_of(b"src/lib.rs")])
            .expect_err("an inconsistent report must be refused");

        assert!(
            error.to_string().contains("one consistent observation"),
            "{error}"
        );
    }

    /// Repository paths are bytes, not UTF-8. A path that is not valid UTF-8
    /// must survive the hex round trip into the checkout selection unchanged.
    #[test]
    fn byte_exact_paths_survive_the_hex_round_trip() {
        let raw = b"src/\xff/mod.rs";
        let selections = healable_selections(false, 1, &[hex_of(raw)]).unwrap();

        assert_eq!(selections.len(), 1);
        assert_eq!(selections[0].as_bytes(), raw);
    }

    /// One path reported twice is one restore. Issuing the same repository
    /// transaction twice would be wasted work, and the second would describe a
    /// path that no longer drifts.
    #[test]
    fn repeated_paths_collapse_to_one_selection() {
        let encoded = hex_of(b"src/lib.rs");
        let selections =
            healable_selections(false, 2, &[encoded.clone(), encoded.clone()]).unwrap();

        assert_eq!(selections.len(), 1);
        assert_eq!(selections[0].as_bytes(), b"src/lib.rs");
    }

    /// Reserved control state is never a heal target. The refusal comes from
    /// the checkout parser, so heal and checkout cannot disagree about what is
    /// selectable.
    #[test]
    fn reserved_control_paths_are_refused_before_reaching_the_daemon() {
        for reserved in [&b".kin/config"[..], &b".git/config"[..]] {
            let error = healable_selections(false, 1, &[hex_of(reserved)])
                .expect_err("reserved control state must not be a heal target");
            assert!(
                error.to_string().contains("not restorable"),
                "{error} for {}",
                String::from_utf8_lossy(reserved)
            );
        }
    }

    fn heal_report(observed: usize, restored: usize, remaining: usize) -> HealReport {
        HealReport {
            schema: HEAL_SCHEMA.to_string(),
            repository_id: RepositoryId::new("heal-fixture").unwrap(),
            authority_generation: 7,
            observed_drift: observed,
            restored_paths_hex: (0..restored)
                .map(|index| hex_of(format!("src/file{index}.rs").as_bytes()))
                .collect(),
            remaining_drift: remaining,
            clean: remaining == 0,
        }
    }

    /// A heal that found nothing says so, rather than claiming a repair it
    /// never performed.
    #[test]
    fn healing_a_clean_projection_claims_no_repair() {
        let rendered = render_heal_lines(&heal_report(0, 0, 0)).join("\n");

        assert!(
            rendered.contains("already matched graph authority"),
            "{rendered}"
        );
        assert!(!rendered.contains("Restored"), "{rendered}");
    }

    /// A partial heal reports what is left rather than reading as success.
    #[test]
    fn a_partial_heal_reports_the_remainder() {
        let rendered = render_heal_lines(&heal_report(3, 2, 1)).join("\n");

        assert!(rendered.contains("Restored 2 of 3"), "{rendered}");
        assert!(
            rendered.contains("1 tracked path(s) still diverge"),
            "{rendered}"
        );
        assert!(
            !rendered.contains("now matches graph authority"),
            "a partial heal must not claim the projection matches: {rendered}"
        );
    }

    /// The success wording is reachable, so the partial-heal assertion above
    /// cannot pass merely because the line never renders.
    #[test]
    fn a_complete_heal_reports_the_projection_matching_again() {
        let rendered = render_heal_lines(&heal_report(2, 2, 0)).join("\n");

        assert!(rendered.contains("Restored 2 of 2"), "{rendered}");
        assert!(
            rendered.contains("now matches graph authority"),
            "{rendered}"
        );
    }
}
