use std::path::PathBuf;

use anyhow::Result;

pub async fn export(output: Option<String>) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let graph = kin_graph::KuzuGraphStore::open(&layout.graph_dir())?;
    let blob_store = kin_blobs::BlobStore::new(layout.objects_dir())
        .map_err(|e| anyhow::anyhow!("failed to open blob store: {}", e))?;

    let branch_name = kin_core::read_current_branch(&layout)?;
    let genesis = kin_core::build_genesis_change();

    let output_path = output
        .map(PathBuf::from)
        .unwrap_or_else(|| layout.working_dir().join(".git-export"));

    println!("Exporting Kin state to Git at '{}'...", output_path.display());

    let result = kin_git::export_to_git(
        &graph,
        &blob_store,
        genesis.id,
        &branch_name,
        &output_path,
    )
    .map_err(|e| anyhow::anyhow!("git export failed: {}", e))?;

    println!("  Commits exported: {}", result.commits_exported);
    println!("  Branches updated: {}", result.branches_updated);
    println!("  Commits skipped: {}", result.commits_skipped);
    println!("  Git repo: {}", result.git_repo_path);

    Ok(())
}

pub async fn import(path: Option<String>) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let graph = kin_graph::KuzuGraphStore::open(&layout.graph_dir())?;

    let source = path.map(PathBuf::from).unwrap_or_else(|| {
        std::env::current_dir().expect("cannot determine current directory")
    });

    println!("Importing from Git repository at '{}'...", source.display());

    let genesis = kin_core::build_genesis_change();
    let opts = kin_git::ImportOptions::default();

    let imported = kin_git::import_git_history(&source, genesis.id, &opts)
        .map_err(|e| anyhow::anyhow!("git import failed: {}", e))?;

    // Insert imported changes into the graph
    use kin_model::GraphStore;
    let mut count = 0usize;
    for imported_change in &imported {
        graph.create_change(&imported_change.change)?;
        count += 1;
    }

    // Update branch head to the latest imported change
    if let Some(last) = imported.last() {
        let branch_name = kin_core::read_current_branch(&layout)?;
        graph.update_branch_head(&branch_name, &last.change.id)?;
        println!("  Updated branch '{}' to {}", branch_name, last.change.id);
    }

    println!("  Imported {} changes from Git history.", count);

    Ok(())
}

pub async fn sync() -> Result<()> {
    println!("Syncing Kin <-> Git...");

    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    // Step 1: Import from Git -> Kin (if a .git directory exists)
    let git_dir = layout.working_dir().join(".git");
    if git_dir.exists() {
        println!("  Importing from Git -> Kin...");
        import(None).await?;
    } else {
        println!("  No .git directory found, skipping import.");
    }

    // Step 2: Export Kin -> Git
    println!("  Exporting Kin -> Git...");
    export(None).await?;

    println!("Sync complete (bidirectional).");
    Ok(())
}
