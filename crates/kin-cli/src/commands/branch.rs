use anyhow::Result;
use kin_model::{Branch, BranchName, GraphStore};

fn open_graph() -> Result<(kin_core::KinLayout, kin_db::InMemoryGraph)> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let graph = kin_db::InMemoryGraph::new();
    Ok((layout, graph))
}

pub async fn list() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let _snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout))?;
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
    let (layout, graph) = open_graph()?;

    // Get current branch head to fork from
    let current = kin_core::read_current_branch(&layout)?;
    let current_branch = graph
        .get_branch(&current)?
        .ok_or_else(|| anyhow::anyhow!("current branch '{}' not found in graph", current))?;

    let branch = Branch {
        name: BranchName::new(&name),
        head: current_branch.head,
    };
    graph.create_branch(&branch)?;
    println!("Created branch '{}' at {}", name, current_branch.head);

    Ok(())
}

pub async fn delete(name: String) -> Result<()> {
    let (_layout, graph) = open_graph()?;
    graph.delete_branch(&BranchName::new(&name))?;
    println!("Deleted branch '{}'", name);
    Ok(())
}

pub async fn switch(name: String) -> Result<()> {
    let (layout, graph) = open_graph()?;
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
