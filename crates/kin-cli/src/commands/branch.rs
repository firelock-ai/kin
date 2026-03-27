// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_model::ChangeStore;
use kin_model::{Branch, BranchName};

fn open_snapshot() -> Result<(kin_core::KinLayout, kin_db::SnapshotManager)> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let snapshot = crate::backend::open_kindb_snapshot(&layout)?;
    Ok((layout, snapshot))
}

pub async fn list() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let _snap = crate::backend::open_kindb_snapshot(&layout)?;
    let graph = &*_snap.graph();
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

pub async fn create(name: String) -> Result<()> {
    let (layout, snapshot) = open_snapshot()?;
    let graph = snapshot.graph();
    let graph = &*graph;

    // Get current branch head to fork from
    let current = kin_core::read_current_branch(&layout)?;
    let ensured_branch = crate::commands::branch_bootstrap::ensure_current_branch(graph, &current)?;
    let current_branch = graph
        .get_branch(&current)?
        .ok_or_else(|| anyhow::anyhow!("current branch '{}' not found in graph", current))?;

    let branch = Branch {
        name: BranchName::new(&name),
        head: current_branch.head,
    };
    graph.create_branch(&branch)?;
    snapshot.save()?;
    println!("Created branch '{}' at {}", name, current_branch.head);
    if ensured_branch.bootstrapped {
        println!(
            "  Bootstrapped current branch '{}' at {} before branching.",
            current, current_branch.head
        );
    }

    Ok(())
}

pub async fn delete(name: String) -> Result<()> {
    let (_layout, snapshot) = open_snapshot()?;
    let graph = snapshot.graph();
    let graph = &*graph;
    graph.delete_branch(&BranchName::new(&name))?;
    snapshot.save()?;
    println!("Deleted branch '{}'", name);
    Ok(())
}

pub async fn switch(name: String) -> Result<()> {
    let (layout, snapshot) = open_snapshot()?;
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
