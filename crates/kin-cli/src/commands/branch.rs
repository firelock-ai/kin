// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_model::{Branch, BranchName, ChangeStore, Hash256, SemanticChangeId};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum BranchRequest {
    List,
    Create { name: String },
    Delete { name: String },
    Switch { name: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchResponse {
    #[serde(default)]
    pub lines: Vec<String>,
    #[serde(default)]
    pub mutated: bool,
}

pub async fn list() -> Result<()> {
    let layout = discover_layout()?;
    print_branch_response(run_daemon_branch(&layout, &BranchRequest::List).await?)
}

pub async fn create(name: String) -> Result<()> {
    let layout = discover_layout()?;
    print_branch_response(run_daemon_branch(&layout, &BranchRequest::Create { name }).await?)
}

pub async fn delete(name: String) -> Result<()> {
    let layout = discover_layout()?;
    print_branch_response(run_daemon_branch(&layout, &BranchRequest::Delete { name }).await?)
}

pub async fn switch(name: String) -> Result<()> {
    let layout = discover_layout()?;
    print_branch_response(run_daemon_branch(&layout, &BranchRequest::Switch { name }).await?)
}

fn discover_layout() -> Result<kin_core::KinLayout> {
    kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))
}

async fn run_daemon_branch(
    layout: &kin_core::KinLayout,
    request: &BranchRequest,
) -> Result<BranchResponse> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url = daemon_url.ok_or_else(|| {
        anyhow::anyhow!(
            "Kin daemon is required for branch commands but no daemon endpoint is available"
        )
    })?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client.branch(request).await.context("daemon branch failed")
}

fn print_branch_response(response: BranchResponse) -> Result<()> {
    for line in response.lines {
        println!("{line}");
    }
    Ok(())
}

pub fn execute_branch_request(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    request: &BranchRequest,
) -> Result<BranchResponse> {
    match request {
        BranchRequest::List => branch_list(layout, graph),
        BranchRequest::Create { name } => branch_create(layout, graph, name),
        BranchRequest::Delete { name } => branch_delete(graph, name),
        BranchRequest::Switch { name } => branch_switch(layout, graph, name),
    }
}

fn branch_list(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
) -> Result<BranchResponse> {
    let branches = graph.list_branches()?;
    let current = kin_core::read_current_branch(layout)?;

    let lines = if branches.is_empty() {
        vec!["No branches".to_string()]
    } else {
        branches
            .iter()
            .map(|branch| {
                let marker = if branch.name == current { "* " } else { "  " };
                format!("{}{} -> {}", marker, branch.name, branch.head)
            })
            .collect()
    };

    Ok(BranchResponse {
        lines,
        mutated: false,
    })
}

fn branch_create(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    name: &str,
) -> Result<BranchResponse> {
    let current = kin_core::read_current_branch(layout)?;
    let current_branch = graph
        .get_branch(&current)?
        .ok_or_else(|| anyhow::anyhow!("current branch '{}' not found in graph", current))?;
    let branch = Branch {
        name: BranchName::new(name),
        head: current_branch.head,
    };
    graph.create_branch(&branch)?;
    Ok(BranchResponse {
        lines: vec![format!(
            "Created branch '{}' at {}",
            name, current_branch.head
        )],
        mutated: true,
    })
}

fn branch_delete(graph: &kin_db::InMemoryGraph, name: &str) -> Result<BranchResponse> {
    graph.delete_branch(&BranchName::new(name))?;
    Ok(BranchResponse {
        lines: vec![format!("Deleted branch '{}'", name)],
        mutated: true,
    })
}

fn branch_switch(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    name: &str,
) -> Result<BranchResponse> {
    let branch = graph.get_branch(&BranchName::new(name))?;
    let Some(branch) = branch else {
        anyhow::bail!("branch '{}' not found", name);
    };

    let blob_store = kin_blobs::BlobStore::new(layout.objects_dir())
        .map_err(|e| anyhow::anyhow!("failed to open blob store: {}", e))?;
    let genesis = kin_core::build_genesis_change();
    let files_written =
        kin_core::checkout_branch(graph, &blob_store, layout, &genesis.id, &branch.head)?;

    kin_core::write_current_branch(layout, &BranchName::new(name))?;
    let mut lines = vec![format!(
        "Switched to branch '{}' at {}",
        branch.name, branch.head
    )];
    if files_written > 0 {
        lines.push(format!("  {} file(s) updated", files_written));
    }
    Ok(BranchResponse {
        lines,
        mutated: false,
    })
}

#[allow(dead_code)]
fn parse_change_id(s: &str) -> Result<SemanticChangeId> {
    let hash = Hash256::from_hex(s)
        .map_err(|_| anyhow::anyhow!("invalid change ID (expected 64 hex chars): {}", s))?;
    Ok(SemanticChangeId::from_hash(hash))
}
