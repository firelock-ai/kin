use std::path::PathBuf;

use anyhow::Result;
use kin_model::GraphStore;

fn default_export_path(layout: &kin_core::KinLayout) -> PathBuf {
    layout.working_dir().join(".git-export")
}

fn checked_out_git_repo_path(layout: &kin_core::KinLayout) -> PathBuf {
    layout.working_dir().to_path_buf()
}

pub(crate) fn sync_export_path(layout: &kin_core::KinLayout) -> PathBuf {
    default_export_path(layout)
}

fn resolve_export_path(
    layout: &kin_core::KinLayout,
    output: Option<String>,
    in_place: bool,
) -> Result<PathBuf> {
    let output_path = output
        .map(PathBuf::from)
        .unwrap_or_else(|| default_export_path(layout));

    if output_path == checked_out_git_repo_path(layout) && !in_place {
        anyhow::bail!(
            "refusing to export directly into the checked-out Git repository at {}. Re-run with `--in-place` if you intentionally want Kin export to rewrite local Git refs, or omit `--output` to use {} instead.",
            output_path.display(),
            default_export_path(layout).display(),
        );
    }

    Ok(output_path)
}

pub async fn export(output: Option<String>, in_place: bool) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout))?;
    let graph = &*snap.graph();
    let blob_store = kin_blobs::BlobStore::new(layout.objects_dir())
        .map_err(|e| anyhow::anyhow!("failed to open blob store: {}", e))?;

    let branch_name = kin_core::read_current_branch(&layout)?;
    let ensured_branch =
        crate::commands::branch_bootstrap::ensure_current_branch(graph, &branch_name)?;
    if ensured_branch.bootstrapped {
        snap.save()?;
    }
    let genesis = kin_core::build_genesis_change();

    let output_path = resolve_export_path(&layout, output, in_place)?;

    println!(
        "Exporting Kin state to Git at '{}'...",
        output_path.display()
    );

    let result =
        kin_git::export_to_git(&graph, &blob_store, genesis.id, &branch_name, &output_path)
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
    let snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout))?;
    let graph = snap.graph();
    let graph = &*graph;
    let blob_store = kin_blobs::BlobStore::new(layout.objects_dir())
        .map_err(|e| anyhow::anyhow!("failed to open blob store: {}", e))?;

    let source = path
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().expect("cannot determine current directory"));

    println!("Importing from Git repository at '{}'...", source.display());

    let genesis = kin_core::build_genesis_change();
    let opts = kin_git::ImportOptions::default();

    let imported =
        kin_git::import_git_history_with_blobs(&source, genesis.id, &opts, Some(&blob_store))
            .map_err(|e| anyhow::anyhow!("git import failed: {}", e))?;

    let branch_name = kin_core::read_current_branch(&layout)?;
    let ensured_branch =
        crate::commands::branch_bootstrap::ensure_current_branch(graph, &branch_name)?;
    if ensured_branch.bootstrapped {
        println!(
            "  Bootstrapped semantic branch '{}' at genesis before importing Git history.",
            branch_name
        );
    }

    // Insert imported changes into the graph
    let mut count = 0usize;
    for imported_change in &imported {
        graph.create_change(&imported_change.change)?;
        count += 1;
    }

    // Update branch head to the latest imported change
    if let Some(last) = imported.last() {
        graph.update_branch_head(&branch_name, &last.change.id)?;
        println!("  Updated branch '{}' to {}", branch_name, last.change.id);
    }

    snap.save()?;
    println!("  Imported {} changes from Git history.", count);

    Ok(())
}

pub async fn sync(in_place: bool) -> Result<()> {
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
    let export_target = if in_place {
        checked_out_git_repo_path(&layout)
    } else {
        sync_export_path(&layout)
    };
    println!("  Exporting Kin -> Git at '{}'...", export_target.display());
    export(Some(export_target.to_string_lossy().into_owned()), in_place).await?;

    println!("Sync complete (bidirectional).");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_export_uses_git_export_dir() {
        let dir = tempfile::tempdir().unwrap();
        let layout = kin_core::KinLayout::new(dir.path().join(".kin"));

        assert_eq!(default_export_path(&layout), dir.path().join(".git-export"));
    }

    #[test]
    fn sync_export_uses_git_export_dir_even_when_git_exists() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join(".git")).unwrap();
        let layout = kin_core::KinLayout::new(dir.path().join(".kin"));

        assert_eq!(sync_export_path(&layout), dir.path().join(".git-export"));
    }

    #[test]
    fn sync_export_falls_back_when_git_is_missing() {
        let dir = tempfile::tempdir().unwrap();
        let layout = kin_core::KinLayout::new(dir.path().join(".kin"));

        assert_eq!(sync_export_path(&layout), dir.path().join(".git-export"));
    }

    #[test]
    fn resolve_export_path_blocks_checked_out_repo_without_in_place_flag() {
        let dir = tempfile::tempdir().unwrap();
        let layout = kin_core::KinLayout::new(dir.path().join(".kin"));

        let error = resolve_export_path(
            &layout,
            Some(dir.path().to_string_lossy().into_owned()),
            false,
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("refusing to export directly into the checked-out Git repository"));
    }

    #[test]
    fn resolve_export_path_allows_checked_out_repo_with_in_place_flag() {
        let dir = tempfile::tempdir().unwrap();
        let layout = kin_core::KinLayout::new(dir.path().join(".kin"));

        let path = resolve_export_path(
            &layout,
            Some(dir.path().to_string_lossy().into_owned()),
            true,
        )
        .unwrap();

        assert_eq!(path, dir.path());
    }
}
