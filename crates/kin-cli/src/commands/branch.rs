// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Repository-v6 branch reads and fail-closed mutation protocol.

use anyhow::Result;
use kin_model::{RefName, RefTarget, RepositoryId, RootBundle, WorkspaceHead, WorkspaceId};
use serde::{Deserialize, Serialize};

use super::repository_authority::ActiveRepositoryAuthority;

pub const BRANCH_LIST_SCHEMA: &str = "kin.branch-list.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum BranchRequest {
    List,
    Create { name: String },
    Delete { name: String },
    Switch { name: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BranchListEntry {
    pub name: RefName,
    pub target: RefTarget,
    pub active: bool,
    pub default: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BranchListReport {
    pub schema: String,
    pub authority: String,
    pub repository_id: RepositoryId,
    pub authority_generation: u64,
    pub roots: RootBundle,
    pub workspace_id: WorkspaceId,
    pub workspace_generation: u64,
    pub workspace_head: WorkspaceHead,
    pub repository_ref_count: usize,
    pub branch_count: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_ref: Option<RefName>,
    pub branches: Vec<BranchListEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchResponse {
    #[serde(default)]
    pub lines: Vec<String>,
    #[serde(default)]
    pub mutated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<BranchListReport>,
}

pub fn inspect(layout: &kin_core::KinLayout) -> Result<BranchListReport> {
    let authority = ActiveRepositoryAuthority::open(layout)?;
    let lease = authority.manager().read_authority();
    let metadata = lease.metadata();
    let workspace = metadata
        .workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == authority.workspace_id)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "repository {} has no workspace {} in repository-v6 authority",
                authority.repository_id,
                authority.workspace_id
            )
        })?;
    let active_ref = match &workspace.head {
        WorkspaceHead::Symbolic { target } => Some(target),
        WorkspaceHead::Detached { .. } => None,
    };
    let default_ref = metadata.ref_state.default_ref.clone();
    let branches = metadata
        .ref_state
        .refs
        .iter()
        .filter(|repository_ref| repository_ref.name.is_branch())
        .map(|repository_ref| BranchListEntry {
            name: repository_ref.name.clone(),
            target: repository_ref.target.clone(),
            active: active_ref == Some(&repository_ref.name),
            default: default_ref.as_ref() == Some(&repository_ref.name),
        })
        .collect::<Vec<_>>();

    Ok(BranchListReport {
        schema: BRANCH_LIST_SCHEMA.to_string(),
        authority: "repository-v6".to_string(),
        repository_id: authority.repository_id.clone(),
        authority_generation: lease.roots().generation,
        roots: lease.roots().clone(),
        workspace_id: workspace.workspace_id,
        workspace_generation: workspace.generation,
        workspace_head: workspace.head.clone(),
        repository_ref_count: metadata.ref_state.refs.len(),
        branch_count: branches.len(),
        default_ref,
        branches,
    })
}

pub fn list(json: bool) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let report = inspect(&layout)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        for line in render_lines(&report) {
            println!("{line}");
        }
    }
    Ok(())
}

pub fn execute_branch_request(
    layout: &kin_core::KinLayout,
    _graph: &kin_db::InMemoryGraph,
    request: &BranchRequest,
) -> Result<BranchResponse> {
    match request {
        BranchRequest::List => {
            let report = inspect(layout)?;
            Ok(BranchResponse {
                lines: render_lines(&report),
                mutated: false,
                report: Some(report),
            })
        }
        BranchRequest::Create { .. } => {
            super::capabilities::require_ready("branch create")?;
            anyhow::bail!("branch create was declared ready without an executor")
        }
        BranchRequest::Delete { .. } => {
            super::capabilities::require_ready("branch delete")?;
            anyhow::bail!("branch delete was declared ready without an executor")
        }
        BranchRequest::Switch { .. } => {
            super::capabilities::require_ready("branch switch")?;
            anyhow::bail!("branch switch was declared ready without an executor")
        }
    }
}

fn render_lines(report: &BranchListReport) -> Vec<String> {
    if report.branches.is_empty() {
        return vec![format!(
            "(no branches; workspace head is {})",
            render_head(&report.workspace_head)
        )];
    }
    report
        .branches
        .iter()
        .map(|branch| {
            let active = if branch.active { "*" } else { " " };
            let default = if branch.default { " [default]" } else { "" };
            format!(
                "{active} {} -> {}{default}",
                branch.name,
                render_target(&branch.target)
            )
        })
        .collect()
}

fn render_head(head: &WorkspaceHead) -> String {
    match head {
        WorkspaceHead::Symbolic { target } => format!("symbolic {target}"),
        WorkspaceHead::Detached { target } => format!("detached {}", render_target(target)),
    }
}

fn render_target(target: &RefTarget) -> String {
    match target {
        RefTarget::Change { change_id } => format!("change {change_id}"),
        RefTarget::ExternalObject { object } => format!("{:?} {}", object.kind, object.oid),
        RefTarget::Symbolic { target } => format!("symbolic {target}"),
    }
}
