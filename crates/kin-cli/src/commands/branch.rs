// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_model::ChangeStore;
use kin_model::{Branch, BranchName};

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

fn try_daemon_create_branch(name: &str, head: &str) -> Result<bool> {
    if std::env::var("KIN_OFFLINE").is_ok() {
        return Ok(false);
    }
    let daemon_url = std::env::var("KIN_DAEMON_URL").unwrap_or_else(|_| "http://127.0.0.1:4219".into());
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;
    
    let payload = serde_json::json!({
        "name": name,
        "head": head,
    });
    
    let resp = client.post(format!("{}/v1/graph/branches", daemon_url.trim_end_matches('/')))
        .json(&payload)
        .send()?;
        
    Ok(resp.status().is_success())
}

pub async fn create(name: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let snapshot = crate::backend::open_snapshot_daemon_first_read_only(&layout).await?;
    let graph = snapshot.graph();
    let graph = &*graph;

    // Get current branch head to fork from
    let current = kin_core::read_current_branch(&layout)?;
    let _ensured_branch = crate::commands::branch_bootstrap::ensure_current_branch(graph, &current)?;
    let current_branch = graph
        .get_branch(&current)?
        .ok_or_else(|| anyhow::anyhow!("current branch '{}' not found in graph", current))?;

    // Try daemon first
    let daemon_success = try_daemon_create_branch(&name, &current_branch.head.to_string()).unwrap_or(false);
    
    if daemon_success {
        println!("Created branch '{}' at {} (via daemon)", name, current_branch.head);
    } else {
        let branch = Branch {
            name: BranchName::new(&name),
            head: current_branch.head,
        };
        graph.create_branch(&branch)?;
        kin_db::SnapshotManager::save_graph(layout.kindb_snapshot_path(), graph)?;
        println!("Created branch '{}' at {} (offline)", name, current_branch.head);
    }

    Ok(())
}

fn try_daemon_delete_branch(name: &str) -> Result<bool> {
    if std::env::var("KIN_OFFLINE").is_ok() {
        return Ok(false);
    }
    let daemon_url = std::env::var("KIN_DAEMON_URL").unwrap_or_else(|_| "http://127.0.0.1:4219".into());
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;
    
    let resp = client.delete(format!("{}/v1/graph/branches/{}", daemon_url.trim_end_matches('/'), name))
        .send()?;
        
    Ok(resp.status().is_success())
}

pub async fn delete(name: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let snapshot = crate::backend::open_snapshot_daemon_first_read_only(&layout).await?;
    let graph = snapshot.graph();
    let graph = &*graph;
    
    let daemon_success = try_daemon_delete_branch(&name).unwrap_or(false);
    
    if daemon_success {
        println!("Deleted branch '{}' (via daemon)", name);
    } else {
        graph.delete_branch(&BranchName::new(&name))?;
        kin_db::SnapshotManager::save_graph(layout.kindb_snapshot_path(), graph)?;
        println!("Deleted branch '{}' (offline)", name);
    }
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
