// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Wire types, parsing, and CLI transport for daemon-owned repository branches.

use anyhow::{Context, Result};
use kin_model::{
    AuthorId, OperationId, RefName, RefTarget, RepositoryId, RootBundle, WorkspaceHead, WorkspaceId,
};
use serde::{Deserialize, Serialize};

use super::repository_authority::parse_ref_name;

pub const BRANCH_LIST_SCHEMA: &str = "kin.branch-list.v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub enum BranchRequest {
    List,
    Create {
        name: RefName,
        operation_id: OperationId,
        actor: AuthorId,
    },
    Delete {
        name: RefName,
        operation_id: OperationId,
        actor: AuthorId,
    },
    Switch {
        name: RefName,
        operation_id: OperationId,
        actor: AuthorId,
    },
}

impl BranchRequest {
    pub fn is_mutation(&self) -> bool {
        !matches!(self, Self::List)
    }
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation_id: Option<OperationId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_generation: Option<u64>,
    #[serde(default)]
    pub idempotent: bool,
}

pub async fn list(json: bool) -> Result<()> {
    let response = execute(BranchRequest::List).await?;
    if json {
        let report = response
            .report
            .ok_or_else(|| anyhow::anyhow!("daemon branch list response omitted its report"))?;
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_lines(response);
    }
    Ok(())
}

pub async fn create(name: RefName) -> Result<()> {
    execute_and_print(mutation_request(name, BranchMutation::Create)).await
}

pub async fn delete(name: RefName) -> Result<()> {
    execute_and_print(mutation_request(name, BranchMutation::Delete)).await
}

pub async fn switch(name: RefName) -> Result<()> {
    execute_and_print(mutation_request(name, BranchMutation::Switch)).await
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

enum BranchMutation {
    Create,
    Delete,
    Switch,
}

fn mutation_request(name: RefName, mutation: BranchMutation) -> BranchRequest {
    let operation_id = OperationId::new();
    let actor = AuthorId::new(kin_core::whoami());
    match mutation {
        BranchMutation::Create => BranchRequest::Create {
            name,
            operation_id,
            actor,
        },
        BranchMutation::Delete => BranchRequest::Delete {
            name,
            operation_id,
            actor,
        },
        BranchMutation::Switch => BranchRequest::Switch {
            name,
            operation_id,
            actor,
        },
    }
}

async fn execute(request: BranchRequest) -> Result<BranchResponse> {
    let layout = crate::commands::require_repository_layout()?;
    let daemon_url = crate::daemon_client::resolve_daemon_url(&layout)
        .await?
        .ok_or_else(|| crate::daemon_client::daemon_required_error("branch operations", &layout))?;
    let daemon = crate::daemon_client::DaemonClient::from_base_url_for_layout(daemon_url, &layout)?;
    daemon.branch(&request).await
}

async fn execute_and_print(request: BranchRequest) -> Result<()> {
    print_lines(execute(request).await?);
    Ok(())
}

fn require_branch_ref(name: &RefName) -> Result<()> {
    if !name.is_branch() {
        anyhow::bail!("branch command requires a ref below refs/heads/, found {name}");
    }
    Ok(())
}

fn print_lines(response: BranchResponse) {
    for line in response.lines {
        println!("{line}");
    }
}
