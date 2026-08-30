// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Wire types and CLI transport for daemon-owned repository-v6 merges.

use anyhow::Result;
use kin_model::{
    ArtifactId, AuthorId, EntityId, OperationId, RefName, RelationId, RepositoryId, RootBundle,
    SemanticChangeId, WorkspaceId,
};
use serde::{Deserialize, Serialize};

use super::repository_authority::parse_ref_name;

pub const MERGE_REPORT_SCHEMA: &str = "kin.merge.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MergeRequest {
    /// Branch whose semantic and exact-tree state is merged into the active
    /// workspace branch.
    pub source: RefName,
    pub operation_id: OperationId,
    pub actor: AuthorId,
}

/// The exact identity a merge conflict is reported against.
///
/// Identity is never a path: artifacts carry stable `ArtifactId`, so a move on
/// one side and an edit on the other are still the same artifact.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "scope", rename_all = "snake_case", deny_unknown_fields)]
pub enum MergeConflictScope {
    Entity {
        entity: EntityId,
        /// Qualified name and file at whichever side still carries the entity,
        /// for a refusal a human can act on. Identity stays the id.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        name: Option<String>,
    },
    Relation {
        relation: RelationId,
    },
    Artifact {
        artifact: ArtifactId,
        /// Path the artifact occupies on one side. Absent when both sides
        /// removed the location the base held.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        path: Option<String>,
    },
    /// Both sides placed distinct artifacts at one repository path. The
    /// per-artifact three-way is clean; the composed tree is not.
    Path {
        path: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MergeConflict {
    #[serde(flatten)]
    pub scope: MergeConflictScope,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MergeOutcome {
    /// The source branch is already an ancestor of the active branch.
    AlreadyUpToDate,
    /// The active branch is an ancestor of the source branch, so the merge is
    /// a ref and workspace advance with no merge change.
    FastForward,
    /// A merge change joining both heads was published.
    Merged,
    /// Composition did not settle every identity, so the merge is held as a
    /// durable merge-transaction record instead of published. No ref moved and
    /// the workspace stayed at the record's restore point.
    Conflicted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MergeReport {
    pub schema: String,
    pub authority: String,
    pub repository_id: RepositoryId,
    pub authority_generation: u64,
    pub roots: RootBundle,
    pub workspace_id: WorkspaceId,
    pub target_ref: RefName,
    pub source_ref: RefName,
    pub base_change: SemanticChangeId,
    pub ours_change: SemanticChangeId,
    pub theirs_change: SemanticChangeId,
    pub outcome: MergeOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merge_change: Option<SemanticChangeId>,
    pub entity_delta_count: usize,
    pub relation_delta_count: usize,
    pub tree_delta_count: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MergeResponse {
    #[serde(default)]
    pub lines: Vec<String>,
    #[serde(default)]
    pub mutated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<MergeReport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<OperationId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_generation: Option<u64>,
    #[serde(default)]
    pub idempotent: bool,
}

/// A merge that parked conflicts instead of publishing.
///
/// Nonzero because `kin merge` reported success on an unresolved merge: the
/// rc062k run took 27 conflicts and exit 0, so a script reading `$?` believed
/// the merge landed. Git answers 1 there, and matching it would be the
/// compatible choice, except that 1 is also what a failed command returns, so a
/// caller could not tell a parked merge from a broken one. A distinct code is
/// nonzero for every `if ! kin merge`, and readable for a caller that looks.
pub const EXIT_MERGE_CONFLICTED: i32 = 8;

/// Run the merge, returning the process exit code.
///
/// The report is printed either way, in both output modes. The exit code
/// reports the outcome; it does not replace saying what happened.
pub async fn run(source: String, json: bool) -> Result<i32> {
    let source = parse_ref_name(&source)?;
    if !source.is_branch() {
        anyhow::bail!("merge requires a source ref below refs/heads/, found {source}");
    }
    let response = execute(MergeRequest {
        source,
        operation_id: OperationId::new(),
        actor: crate::commands::require_commit_author()?,
    })
    .await?;
    // Read before printing, and from the report rather than by matching the
    // rendered lines, because a phrase in a line is a proxy for the outcome and
    // the outcome is a field.
    let conflicted = response
        .report
        .as_ref()
        .is_some_and(|report| matches!(report.outcome, MergeOutcome::Conflicted));
    if json {
        let report = response
            .report
            .ok_or_else(|| anyhow::anyhow!("daemon merge response omitted its report"))?;
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        for line in response.lines {
            println!("{line}");
        }
    }
    Ok(if conflicted { EXIT_MERGE_CONFLICTED } else { 0 })
}

/// Discover the repository every merge-transaction command is bound to.
pub(crate) fn require_repository_layout() -> Result<kin_core::KinLayout> {
    crate::commands::require_repository_layout()
}

async fn execute(request: MergeRequest) -> Result<MergeResponse> {
    let layout = require_repository_layout()?;
    let daemon_url = crate::daemon_client::resolve_daemon_url(&layout)
        .await?
        .ok_or_else(|| crate::daemon_client::daemon_required_error("merge operations", &layout))?;
    let daemon = crate::daemon_client::DaemonClient::from_base_url_for_layout(daemon_url, &layout)?;
    daemon.merge(&request).await
}
