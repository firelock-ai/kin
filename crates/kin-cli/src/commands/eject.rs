// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Leave a Kin repository without restoring file-first state.
//!
//! The graph remains authoritative until the last moment. Ejection succeeds
//! only when the checked-out branch resolves completely, every referenced blob
//! verifies, and the working directory is an exact projection of that graph
//! tree. The `.kin/` store is then atomically detached into a recoverable
//! sibling archive. There is no initialization-time filesystem snapshot and no
//! path that silently prefers old raw files over graph truth.

use std::fs;
use std::io::BufRead as _;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context as _, Result};
use kin_model::{ChangeStore as _, ResolvedTree, SemanticChangeId};

/// Verify the graph-derived working tree and detach Kin metadata.
pub async fn run(yes: bool, purge_metadata: bool) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let layout = kin_core::KinLayout::discover(&cwd)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository"))?;
    ensure_real_metadata_directory(&layout)?;

    // Capture daemon-owned truth first. This is the same authority boundary as
    // other read-only product commands, not an opportunistic local file open.
    let live = crate::backend::open_snapshot_explicit_admin_read_only(&layout, "kin eject")
        .await
        .context("open live graph truth before eject")?;
    let branch_name = kin_core::read_current_branch(&layout)?;
    let branch = live.graph().get_branch(&branch_name)?.ok_or_else(|| {
        anyhow::anyhow!(
            "current branch '{}' is missing from graph truth",
            branch_name
        )
    })?;
    let head = branch.head;
    let tree = live
        .graph()
        .resolve_tree_at(&head)
        .context("resolve exact current branch tree")?;
    let blobs = kin_blobs::BlobStore::new(layout.objects_dir())
        .context("open graph blob store before eject")?;
    verify_graph_projection(&layout, &tree, &blobs)?;
    drop(live);

    if !yes && !confirm_eject(&branch_name.to_string(), &head, tree.len(), purge_metadata)? {
        println!("Aborted.");
        return Ok(());
    }

    // Gracefully stop the canonical worker so it flushes its final graph state.
    // A live VFS projection must be stopped explicitly; trusting and killing an
    // arbitrary PID from repository-controlled metadata would be unsafe.
    refuse_live_vfs(&layout)?;
    crate::commands::daemon::stop(false, false)
        .await
        .context("stop the repository daemon before eject")?;

    // Close the race between the initial read and daemon shutdown. Eject is an
    // explicit administrative boundary, so a direct read-only persisted-state
    // comparison is appropriate here after the daemon has exited.
    let persisted = crate::backend::open_kindb_snapshot_read_only(&layout)
        .context("reopen the daemon's persisted graph after shutdown")?;
    let persisted_branch_name = kin_core::read_current_branch(&layout)?;
    if persisted_branch_name != branch_name {
        bail!(
            "current branch changed from '{}' to '{}' while eject was preparing; \
             metadata and working files are unchanged",
            branch_name,
            persisted_branch_name
        );
    }
    let persisted_branch = persisted
        .graph()
        .get_branch(&branch_name)?
        .ok_or_else(|| anyhow::anyhow!("current branch '{}' was not persisted", branch_name))?;
    if persisted_branch.head != head {
        bail!(
            "branch '{}' advanced from {} to {} while eject was preparing; \
             metadata and working files are unchanged",
            branch_name,
            head,
            persisted_branch.head
        );
    }
    let persisted_tree = persisted
        .graph()
        .resolve_tree_at(&head)
        .context("resolve persisted current branch tree")?;
    if persisted_tree != tree {
        bail!(
            "persisted graph tree differs from the live graph tree captured before shutdown; \
             metadata and working files are unchanged"
        );
    }
    verify_graph_projection(&layout, &persisted_tree, &blobs)?;
    drop(persisted);
    drop(blobs);

    let archive = detach_metadata(&layout)?;
    if purge_metadata {
        fs::remove_dir_all(&archive).with_context(|| {
            format!(
                "Kin was detached, but the recoverable metadata archive could not be purged at {}",
                archive.display()
            )
        })?;
        sync_parent_directory(&archive)?;
        println!(
            "Kin ejected from branch '{}' at {}. Working files remain the exact graph projection; \
             Kin metadata was permanently removed.",
            branch_name, head
        );
    } else {
        println!(
            "Kin ejected from branch '{}' at {}. Working files remain the exact graph projection.",
            branch_name, head
        );
        println!("Recoverable Kin metadata archive: {}", archive.display());
        println!(
            "To undo before re-initializing, rename that directory back to {}.",
            layout.root().display()
        );
    }
    Ok(())
}

fn ensure_real_metadata_directory(layout: &kin_core::KinLayout) -> Result<()> {
    let metadata = fs::symlink_metadata(layout.root())
        .with_context(|| format!("inspect {}", layout.root().display()))?;
    if !metadata.file_type().is_dir() {
        bail!(
            "refusing to eject through non-directory Kin metadata at {}",
            layout.root().display()
        );
    }
    Ok(())
}

fn verify_graph_projection(
    layout: &kin_core::KinLayout,
    tree: &ResolvedTree,
    blobs: &kin_blobs::BlobStore,
) -> Result<()> {
    kin_projection::verify_resolved_tree_materialization(layout.working_dir(), tree, blobs).map_err(
        |error| {
            anyhow::anyhow!(
                "working files are not an exact projection of current graph truth: {error}. \
                 Reconcile or commit the working tree and retry; Kin metadata was not removed"
            )
        },
    )
}

fn confirm_eject(
    branch: &str,
    head: &SemanticChangeId,
    artifact_count: usize,
    purge_metadata: bool,
) -> Result<bool> {
    eprintln!();
    eprintln!("Eject Kin repository");
    eprintln!("  Branch: {branch}");
    eprintln!("  Head: {head}");
    eprintln!("  Graph-owned artifacts verified: {artifact_count}");
    eprintln!("  Working files will not be rewritten.");
    if purge_metadata {
        eprintln!(
            "  Kin graph, history, reviews, proofs, and metadata will be permanently deleted."
        );
    } else {
        eprintln!("  Kin metadata will move to a recoverable sibling archive.");
    }
    eprintln!();
    eprint!("Type \"eject\" to continue, or press Enter to abort: ");

    let mut line = String::new();
    std::io::stdin().lock().read_line(&mut line)?;
    Ok(line.trim() == "eject")
}

fn refuse_live_vfs(layout: &kin_core::KinLayout) -> Result<()> {
    let pid_path = layout.root().join("vfs.pid");
    let Ok(raw_pid) = fs::read_to_string(&pid_path) else {
        return Ok(());
    };
    let pid = raw_pid.trim().parse::<u32>().with_context(|| {
        format!(
            "invalid VFS PID metadata at {}; stop Kin VFS manually before eject",
            pid_path.display()
        )
    })?;
    if crate::daemon_client::is_process_alive(pid) {
        bail!(
            "Kin VFS process {pid} is still active. Stop it before eject so no process retains \
             the graph store or recreates projection metadata"
        );
    }
    Ok(())
}

/// Atomically make this directory cease being a Kin repository while keeping
/// the complete graph store recoverable outside the discovery path.
fn detach_metadata(layout: &kin_core::KinLayout) -> Result<PathBuf> {
    ensure_real_metadata_directory(layout)?;
    let archive_parent = layout
        .working_dir()
        .parent()
        .ok_or_else(|| anyhow::anyhow!("repository root has no parent directory"))?;
    let name = format!(
        ".kin-ejected-{}-{}",
        chrono::Utc::now().format("%Y%m%d-%H%M%S"),
        uuid::Uuid::new_v4().simple()
    );
    // Keep the recovery archive outside the ejected working directory. A plain
    // Git checkout must not gain a large untracked metadata directory, and a
    // native repository should likewise be left with only its projected files.
    let archive = archive_parent.join(name);
    fs::rename(layout.root(), &archive).with_context(|| {
        format!(
            "atomically detach {} to {}",
            layout.root().display(),
            archive.display()
        )
    })?;
    if let Err(error) = sync_parent_directory(&archive) {
        let rollback = fs::rename(&archive, layout.root());
        return match rollback {
            Ok(()) => Err(error.context("metadata detach was rolled back")),
            Err(rollback_error) => Err(anyhow::anyhow!(
                "{error}; rollback to {} also failed: {rollback_error}; recoverable metadata remains at {}",
                layout.root().display(),
                archive.display()
            )),
        };
    }
    Ok(archive)
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{} has no parent directory", path.display()))?;
    fs::File::open(parent)
        .with_context(|| format!("open parent directory {}", parent.display()))?
        .sync_all()
        .with_context(|| format!("sync parent directory {}", parent.display()))
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{ArtifactId, GitObjectId, RepoPath, ResolvedArtifact, TreeEntry};

    fn layout(root: &Path) -> kin_core::KinLayout {
        let working_dir = root.join("repo");
        let layout = kin_core::KinLayout::new(working_dir.join(".kin"));
        fs::create_dir_all(layout.objects_dir()).unwrap();
        fs::write(layout.root().join("manifest.json"), b"{}").unwrap();
        layout
    }

    fn artifact(path: RepoPath, entry: TreeEntry) -> ResolvedArtifact {
        ResolvedArtifact::new(ArtifactId::new(), path, entry)
    }

    fn tree(artifacts: impl IntoIterator<Item = ResolvedArtifact>) -> ResolvedTree {
        ResolvedTree::from_artifacts(artifacts).unwrap()
    }

    #[test]
    fn exact_binary_config_and_executable_projection_can_eject() {
        let root = tempfile::tempdir().unwrap();
        let layout = layout(root.path());
        let blobs = kin_blobs::BlobStore::new(layout.objects_dir()).unwrap();
        let binary = blobs.write(&[0, 0xff, 1, 0x80]).unwrap();
        let compose = blobs
            .write(b"services:\n  app:\n    image: example\n")
            .unwrap();
        let script = blobs.write(b"#!/bin/sh\nexit 0\n").unwrap();

        fs::write(layout.working_dir().join("asset.bin"), [0, 0xff, 1, 0x80]).unwrap();
        fs::write(
            layout.working_dir().join("compose.yaml"),
            b"services:\n  app:\n    image: example\n",
        )
        .unwrap();
        fs::write(layout.working_dir().join("run"), b"#!/bin/sh\nexit 0\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(
                layout.working_dir().join("run"),
                fs::Permissions::from_mode(0o755),
            )
            .unwrap();
        }

        let tree = tree([
            artifact(
                RepoPath::from_utf8("asset.bin").unwrap(),
                TreeEntry::blob(binary, false),
            ),
            artifact(
                RepoPath::from_utf8("compose.yaml").unwrap(),
                TreeEntry::blob(compose, false),
            ),
            artifact(
                RepoPath::from_utf8("run").unwrap(),
                TreeEntry::blob(script, true),
            ),
        ]);
        verify_graph_projection(&layout, &tree, &blobs).unwrap();

        let archive = detach_metadata(&layout).unwrap();
        assert!(!layout.root().exists());
        assert!(archive.join("manifest.json").exists());
        assert_eq!(
            fs::read(layout.working_dir().join("asset.bin")).unwrap(),
            [0, 0xff, 1, 0x80]
        );
        assert!(layout.working_dir().join("compose.yaml").exists());
    }

    #[test]
    fn dirty_projection_refuses_before_metadata_moves() {
        let root = tempfile::tempdir().unwrap();
        let layout = layout(root.path());
        let blobs = kin_blobs::BlobStore::new(layout.objects_dir()).unwrap();
        let expected = blobs.write(b"graph truth\n").unwrap();
        fs::write(layout.working_dir().join("tracked.txt"), b"local edit\n").unwrap();
        let tree = tree([artifact(
            RepoPath::from_utf8("tracked.txt").unwrap(),
            TreeEntry::blob(expected, false),
        )]);

        let error = verify_graph_projection(&layout, &tree, &blobs).unwrap_err();
        assert!(error.to_string().contains("exact projection"));
        assert!(layout.root().exists());
        assert_eq!(
            fs::read(layout.working_dir().join("tracked.txt")).unwrap(),
            b"local edit\n"
        );
    }

    #[test]
    fn detached_metadata_can_be_purged_after_atomic_move() {
        let root = tempfile::tempdir().unwrap();
        let layout = layout(root.path());
        let archive = detach_metadata(&layout).unwrap();
        fs::remove_dir_all(&archive).unwrap();
        sync_parent_directory(&archive).unwrap();

        assert!(!layout.root().exists());
        assert!(!archive.exists());
    }

    #[test]
    fn gitlink_without_a_materialized_submodule_fails_loudly() {
        let root = tempfile::tempdir().unwrap();
        let layout = layout(root.path());
        let blobs = kin_blobs::BlobStore::new(layout.objects_dir()).unwrap();
        let tree = tree([artifact(
            RepoPath::from_utf8("vendor/dependency").unwrap(),
            TreeEntry::gitlink(GitObjectId::Sha1([0x42; 20])),
        )]);

        let error = verify_graph_projection(&layout, &tree, &blobs).unwrap_err();
        assert!(error.to_string().contains("gitlink"));
        assert!(layout.root().exists());
    }

    #[cfg(all(unix, not(target_os = "macos")))]
    #[test]
    fn non_utf8_paths_are_verified_without_lossy_conversion() {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt as _;

        let root = tempfile::tempdir().unwrap();
        let layout = layout(root.path());
        let blobs = kin_blobs::BlobStore::new(layout.objects_dir()).unwrap();
        let content = blobs.write(&[0xde, 0xad, 0, 0xff]).unwrap();
        let path = RepoPath::from_bytes(b"asset-\xff.bin".to_vec()).unwrap();
        fs::write(
            layout
                .working_dir()
                .join(OsString::from_vec(path.as_bytes().to_vec())),
            [0xde, 0xad, 0, 0xff],
        )
        .unwrap();
        let tree = tree([artifact(path, TreeEntry::blob(content, false))]);

        verify_graph_projection(&layout, &tree, &blobs).unwrap();
    }
}
