// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Repository-v6 branch reads and exact ref transactions.

use anyhow::{Context, Result};
use kin_model::{
    AuthorId, OperationId, RefExpectation, RefMutation, RefName, RefTarget, RefUpdatePolicy,
    RepositoryCommitReceipt, RepositoryId, RepositoryTransaction, RootBundle, WorkspaceHead,
    WorkspaceId, REPOSITORY_TRANSACTION_SCHEMA_VERSION,
};
use serde::{Deserialize, Serialize};

use super::repository_authority::{parse_ref_name, ActiveRepositoryAuthority};

pub const BRANCH_LIST_SCHEMA: &str = "kin.branch-list.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum BranchRequest {
    List,
    Create { name: RefName },
    Delete { name: RefName },
    Switch { name: RefName },
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
    let layout = discover_layout()?;
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

pub fn create(name: RefName) -> Result<()> {
    let layout = discover_layout()?;
    let response = create_at(&layout, &name)?;
    print_lines(response);
    Ok(())
}

pub fn delete(name: RefName) -> Result<()> {
    let layout = discover_layout()?;
    let response = delete_at(&layout, &name)?;
    print_lines(response);
    Ok(())
}

pub fn parse_branch_ref(name: Option<&str>, ref_hex: Option<&str>) -> Result<RefName> {
    let name = match (name, ref_hex) {
        (Some(name), None) => parse_ref_name(name)?,
        (None, Some(encoded)) => {
            let bytes = hex::decode(encoded)
                .with_context(|| format!("invalid repository ref hex '{encoded}'"))?;
            if hex::encode(&bytes) != encoded {
                anyhow::bail!(
                    "repository ref hex must use canonical lowercase hexadecimal encoding"
                );
            }
            RefName::from_bytes(bytes)
                .map_err(|error| anyhow::anyhow!("invalid byte-exact repository ref: {error}"))?
        }
        (Some(_), Some(_)) => {
            anyhow::bail!("provide either a branch name or --ref-hex, not both")
        }
        (None, None) => anyhow::bail!("provide a branch name or --ref-hex"),
    };
    require_branch_ref(&name)?;
    Ok(name)
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
        BranchRequest::Create { name } => create_at(layout, name),
        BranchRequest::Delete { name } => delete_at(layout, name),
        BranchRequest::Switch { .. } => {
            super::capabilities::require_ready("branch switch")?;
            anyhow::bail!("branch switch was declared ready without an executor")
        }
    }
}

fn create_at(layout: &kin_core::KinLayout, name: &RefName) -> Result<BranchResponse> {
    require_branch_ref(name)?;
    let authority = ActiveRepositoryAuthority::open(layout)?;
    let receipt = create_ref_with_hook(&authority, name, || Ok(()))?;
    let target = receipt
        .operation
        .ref_mutations
        .first()
        .and_then(|mutation| mutation.new_target.as_ref())
        .expect("branch creation receipt contains its target");
    Ok(BranchResponse {
        lines: vec![format!(
            "Created {} at {} (authority generation {})",
            name,
            render_target(target),
            receipt.generation
        )],
        mutated: true,
        report: None,
    })
}

fn create_ref_with_hook(
    authority: &ActiveRepositoryAuthority,
    name: &RefName,
    before_commit: impl FnOnce() -> Result<()>,
) -> Result<RepositoryCommitReceipt> {
    let lease = authority.manager().read_authority();
    let metadata = lease.metadata();
    if metadata
        .ref_state
        .refs
        .iter()
        .any(|repository_ref| &repository_ref.name == name)
    {
        anyhow::bail!("branch {name} already exists");
    }
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
    let target = workspace.base_target.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "cannot create branch {name} from unborn workspace {}",
            workspace.workspace_id
        )
    })?;
    if matches!(target, RefTarget::Symbolic { .. }) {
        anyhow::bail!(
            "workspace {} base target is symbolic instead of resolved",
            workspace.workspace_id
        );
    }
    let transaction = ref_transaction(
        authority,
        lease.roots().clone(),
        "create exact repository branch",
        RefMutation {
            name: name.clone(),
            expected: RefExpectation::MustNotExist,
            new_target: Some(target),
            policy: RefUpdatePolicy::FastForwardOnly,
        },
    );
    drop(lease);
    before_commit()?;
    authority
        .manager()
        .commit_repository_transaction(transaction)
        .with_context(|| format!("create repository-v6 branch {name}"))
}

fn delete_at(layout: &kin_core::KinLayout, name: &RefName) -> Result<BranchResponse> {
    require_branch_ref(name)?;
    let authority = ActiveRepositoryAuthority::open(layout)?;
    let receipt = delete_ref_with_hook(&authority, name, || Ok(()))?;
    Ok(BranchResponse {
        lines: vec![format!(
            "Deleted {} (authority generation {})",
            name, receipt.generation
        )],
        mutated: true,
        report: None,
    })
}

fn delete_ref_with_hook(
    authority: &ActiveRepositoryAuthority,
    name: &RefName,
    before_commit: impl FnOnce() -> Result<()>,
) -> Result<RepositoryCommitReceipt> {
    let lease = authority.manager().read_authority();
    let metadata = lease.metadata();
    let target = metadata
        .ref_state
        .refs
        .iter()
        .find(|repository_ref| &repository_ref.name == name)
        .map(|repository_ref| repository_ref.target.clone())
        .ok_or_else(|| anyhow::anyhow!("branch {name} does not exist"))?;
    if metadata.ref_state.default_ref.as_ref() == Some(name) {
        anyhow::bail!(
            "cannot delete default branch {name}; move the repository default ref atomically first"
        );
    }
    if let Some(workspace) = metadata.workspaces.iter().find(
        |workspace| matches!(&workspace.head, WorkspaceHead::Symbolic { target } if target == name),
    ) {
        anyhow::bail!(
            "cannot delete branch {name}; workspace {} has it checked out",
            workspace.workspace_id
        );
    }
    let transaction = ref_transaction(
        authority,
        lease.roots().clone(),
        "delete exact repository branch",
        RefMutation {
            name: name.clone(),
            expected: RefExpectation::MustEqual { target },
            new_target: None,
            policy: RefUpdatePolicy::ForceWithLease,
        },
    );
    drop(lease);
    before_commit()?;
    authority
        .manager()
        .commit_repository_transaction(transaction)
        .with_context(|| format!("delete repository-v6 branch {name}"))
}

fn ref_transaction(
    authority: &ActiveRepositoryAuthority,
    roots: RootBundle,
    reason: &str,
    mutation: RefMutation,
) -> RepositoryTransaction {
    RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id: OperationId::new(),
        repository_id: authority.repository_id.clone(),
        expected_generation: roots.generation,
        expected_roots: roots,
        actor: AuthorId::new("kin-branch-command"),
        reason: reason.to_string(),
        external_objects: Vec::new(),
        git_authority_delta: None,
        changes: Vec::new(),
        aliases: Vec::new(),
        ref_mutations: vec![mutation],
        default_ref_mutation: None,
        workspace_mutation: None,
        local_overlay_delta: None,
        admission_scan_token: None,
    }
}

fn require_branch_ref(name: &RefName) -> Result<()> {
    if !name.is_branch() {
        anyhow::bail!("branch command requires a ref below refs/heads/, found {name}");
    }
    Ok(())
}

fn discover_layout() -> Result<kin_core::KinLayout> {
    kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))
}

fn print_lines(response: BranchResponse) {
    for line in response.lines {
        println!("{line}");
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
