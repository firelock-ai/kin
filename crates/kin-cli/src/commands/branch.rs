// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_model::{BranchName, ChangeStore};

async fn open_snapshot() -> Result<(kin_core::KinLayout, kin_db::SnapshotManager)> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let snapshot = crate::backend::open_snapshot_daemon_first(&layout).await?;
    Ok((layout, snapshot))
}

pub async fn list() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let _snap = crate::backend::open_snapshot_daemon_first_read_only(&layout).await?;
    let graph = &*_snap.graph();

    // We could call the daemon HTTP API for branch list, but read-only snapshot access is fine for listing.
    let branches = graph.list_branches()?;
    let current = kin_core::read_current_branch(&layout)?;

    if branches.is_empty() {
        println!("No branches");
    } else {
        for branch in &branches {
            let marker = if branch.name == current { "* " } else { "  " };
            println!("{}{} -> {}", marker, branch.name, branch.head);
        }
    }

    Ok(())
}

async fn require_daemon_create_branch(
    layout: &kin_core::KinLayout,
    name: &str,
    head: &str,
) -> Result<()> {
    let daemon_url = crate::daemon_client::resolve_daemon_url_if_running_async(layout)
        .await
        .ok_or_else(|| anyhow::anyhow!("Kin daemon is required for branch create"))?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    let payload = serde_json::json!({
        "name": name,
        "head": head,
    });

    let resp = client
        .post(format!(
            "{}/v1/graph/branches",
            daemon_url.trim_end_matches('/')
        ))
        .json(&payload)
        .send()
        .await
        .context("send daemon branch create request")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("daemon branch create failed: HTTP {status}: {body}");
    }
    Ok(())
}

pub async fn create(name: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let snapshot = crate::backend::open_snapshot_daemon_first_read_only(&layout).await?;
    let graph = snapshot.graph();
    let graph = &*graph;

    // Get current branch head to fork from
    let current = kin_core::read_current_branch(&layout)?;
    let _ensured_branch =
        crate::commands::branch_bootstrap::ensure_current_branch(graph, &current)?;
    let current_branch = graph
        .get_branch(&current)?
        .ok_or_else(|| anyhow::anyhow!("current branch '{}' not found in graph", current))?;

    require_daemon_create_branch(&layout, &name, &current_branch.head.to_string()).await?;
    println!(
        "Created branch '{}' at {} (via daemon)",
        name, current_branch.head
    );

    Ok(())
}

async fn require_daemon_delete_branch(layout: &kin_core::KinLayout, name: &str) -> Result<()> {
    let daemon_url = crate::daemon_client::resolve_daemon_url_if_running_async(layout)
        .await
        .ok_or_else(|| anyhow::anyhow!("Kin daemon is required for branch delete"))?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    let resp = client
        .delete(format!(
            "{}/v1/graph/branches/{}",
            daemon_url.trim_end_matches('/'),
            name
        ))
        .send()
        .await
        .context("send daemon branch delete request")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("daemon branch delete failed: HTTP {status}: {body}");
    }
    Ok(())
}

pub async fn delete(name: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let _snapshot = crate::backend::open_snapshot_daemon_first_read_only(&layout).await?;

    require_daemon_delete_branch(&layout, &name).await?;
    println!("Deleted branch '{}' (via daemon)", name);
    Ok(())
}

pub async fn switch(name: String) -> Result<()> {
    let (layout, snapshot) = open_snapshot().await?;
    let graph = snapshot.graph();
    let graph = &*graph;
    let branch = graph.get_branch(&BranchName::new(&name))?;
    match branch {
        Some(b) => {
            // Re-project working directory from target branch's file state.
            let blob_store = kin_blobs::BlobStore::new(layout.objects_dir())
                .map_err(|e| anyhow::anyhow!("failed to open blob store: {}", e))?;
            let genesis = kin_core::build_genesis_change();
            let files_written =
                kin_core::checkout_branch(&graph, &blob_store, &layout, &genesis.id, &b.head)?;

            kin_core::write_current_branch(&layout, &BranchName::new(&name))?;
            println!("Switched to branch '{}' at {}", b.name, b.head);
            if files_written > 0 {
                println!("  {} file(s) updated", files_written);
            }
        }
        None => {
            anyhow::bail!("branch '{}' not found", name);
        }
    }
    Ok(())
}
