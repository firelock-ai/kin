// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Result;
use kin_model::ChangeStore;
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

fn git_output(repo_path: &Path, args: &[&str]) -> Result<std::process::Output> {
    Command::new("git")
        .args(args)
        .current_dir(repo_path)
        .output()
        .map_err(|e| anyhow::anyhow!("failed to run `git {}`: {}", args.join(" "), e))
}

fn is_git_repo(repo_path: &Path) -> bool {
    Command::new("git")
        .args(["rev-parse", "--git-dir"])
        .current_dir(repo_path)
        .output()
        .map(|output| output.status.success())
        .unwrap_or(false)
}

fn is_bare_git_repo(repo_path: &Path) -> Result<bool> {
    let output = git_output(repo_path, &["rev-parse", "--is-bare-repository"])?;
    if !output.status.success() {
        anyhow::bail!(
            "failed to inspect git repo mode at {}: {}",
            repo_path.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim() == "true")
}

fn init_transport_repo(repo_path: &Path, bootstrap_source: Option<&Path>) -> Result<()> {
    if repo_path.exists() {
        std::fs::remove_dir_all(repo_path)
            .map_err(|e| anyhow::anyhow!("failed to reset {}: {}", repo_path.display(), e))?;
    }
    if let Some(source) = bootstrap_source.filter(|path| path.join(".git").exists()) {
        let clone = Command::new("git")
            .args([
                "clone",
                source.to_string_lossy().as_ref(),
                repo_path.to_string_lossy().as_ref(),
            ])
            .output()
            .map_err(|e| anyhow::anyhow!("failed to clone git transport repo: {}", e))?;
        if !clone.status.success() {
            anyhow::bail!(
                "failed to clone git transport repo from {}: {}",
                source.display(),
                String::from_utf8_lossy(&clone.stderr).trim()
            );
        }
        return Ok(());
    }

    std::fs::create_dir_all(repo_path)
        .map_err(|e| anyhow::anyhow!("failed to create {}: {}", repo_path.display(), e))?;
    let init = git_output(repo_path, &["init"])?;
    if !init.status.success() {
        anyhow::bail!(
            "failed to init git transport repo at {}: {}",
            repo_path.display(),
            String::from_utf8_lossy(&init.stderr).trim()
        );
    }
    Ok(())
}

pub(crate) fn ensure_transport_repo(
    repo_path: &Path,
    bootstrap_source: Option<&Path>,
    remote_url: Option<&str>,
) -> Result<()> {
    if !is_git_repo(repo_path) || is_bare_git_repo(repo_path)? {
        init_transport_repo(repo_path, bootstrap_source)?;
    }

    if let Some(url) = remote_url.filter(|value| !value.trim().is_empty()) {
        let trimmed = url.trim();
        let add_remote = git_output(repo_path, &["remote", "add", "origin", trimmed])?;
        if !add_remote.status.success() {
            let set_url = git_output(repo_path, &["remote", "set-url", "origin", trimmed])?;
            if !set_url.status.success() {
                anyhow::bail!(
                    "failed to configure git remote origin in {}: {}",
                    repo_path.display(),
                    String::from_utf8_lossy(&set_url.stderr).trim()
                );
            }
        }
    }

    Ok(())
}

pub(crate) fn git_ref_exists(repo_path: &Path, ref_name: &str) -> Result<bool> {
    let status = Command::new("git")
        .args(["show-ref", "--verify", "--quiet", ref_name])
        .current_dir(repo_path)
        .status()
        .map_err(|e| anyhow::anyhow!("failed to inspect git ref {}: {}", ref_name, e))?;

    match status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => anyhow::bail!(
            "failed to inspect git ref {} in {}",
            ref_name,
            repo_path.display()
        ),
    }
}

pub(crate) fn set_transport_branch_head(
    repo_path: &Path,
    branch_name: &str,
    target_ref: &str,
) -> Result<()> {
    let update_ref = git_output(
        repo_path,
        &[
            "update-ref",
            &format!("refs/heads/{branch_name}"),
            target_ref,
        ],
    )?;
    if !update_ref.status.success() {
        anyhow::bail!(
            "failed to update git transport branch '{}' in {}: {}",
            branch_name,
            repo_path.display(),
            String::from_utf8_lossy(&update_ref.stderr).trim()
        );
    }

    let head = git_output(
        repo_path,
        &["symbolic-ref", "HEAD", &format!("refs/heads/{branch_name}")],
    )
    .map_err(|e| anyhow::anyhow!("failed to set transport branch '{}': {}", branch_name, e))?;
    if !head.status.success() {
        anyhow::bail!(
            "failed to set git transport HEAD to '{}' in {}: {}",
            branch_name,
            repo_path.display(),
            String::from_utf8_lossy(&head.stderr).trim()
        );
    }

    Ok(())
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
    use std::fs;

    fn configure_identity(repo_path: &Path) {
        Command::new("git")
            .args(["config", "user.email", "test@kin.dev"])
            .current_dir(repo_path)
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.name", "Kin Test"])
            .current_dir(repo_path)
            .output()
            .unwrap();
    }

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

    #[test]
    fn ensure_transport_repo_initializes_repo_and_sets_origin() {
        let dir = tempfile::tempdir().unwrap();
        let transport = dir.path().join(".git-export");

        ensure_transport_repo(
            &transport,
            None,
            Some("https://example.com/firelock/kin.git"),
        )
        .unwrap();

        let bare = git_output(&transport, &["rev-parse", "--is-bare-repository"]).unwrap();
        assert!(bare.status.success());
        assert_eq!(String::from_utf8_lossy(&bare.stdout).trim(), "false");
        let remote = git_output(&transport, &["remote", "get-url", "origin"]).unwrap();
        assert!(remote.status.success());
        assert_eq!(
            String::from_utf8_lossy(&remote.stdout).trim(),
            "https://example.com/firelock/kin.git"
        );
    }

    #[test]
    fn set_transport_branch_head_switches_to_requested_branch() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("repo");
        std::fs::create_dir_all(&repo).unwrap();
        git_output(&repo, &["init"]).unwrap();
        configure_identity(&repo);
        fs::write(repo.join("hello.txt"), "world\n").unwrap();
        git_output(&repo, &["add", "."]).unwrap();
        git_output(&repo, &["commit", "-m", "init"]).unwrap();
        git_output(&repo, &["branch", "-M", "master"]).unwrap();
        git_output(&repo, &["branch", "main"]).unwrap();

        set_transport_branch_head(&repo, "main", "refs/heads/main").unwrap();

        let branch = git_output(&repo, &["rev-parse", "--abbrev-ref", "HEAD"]).unwrap();
        assert!(branch.status.success());
        assert_eq!(String::from_utf8_lossy(&branch.stdout).trim(), "main");
    }
}
