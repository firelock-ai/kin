// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::process::Command;

use anyhow::Result;
use kin_core::{KinConfig, RemoteRefConfig, RemoteTransportKind};
use kin_model::GraphStore;

fn resolve_remote(config: &KinConfig, requested: Option<&str>) -> Result<RemoteRefConfig> {
    if let Some(remote) = config.resolve_remote(requested) {
        return Ok(remote.clone());
    }

    if requested.is_none() {
        if let Some(origin) = detect_git_origin_remote() {
            return Ok(origin);
        }
    }

    Err(anyhow::anyhow!(
        "no remote found. Configure one with `kin remote add origin --host github --transport git-export --url <url> --default`, or ensure a Git origin is set."
    ))
}

fn detect_git_origin_remote() -> Option<RemoteRefConfig> {
    let output = Command::new("git")
        .args(["remote", "get-url", "origin"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let url = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if url.is_empty() {
        return None;
    }

    Some(RemoteRefConfig {
        name: "origin".to_string(),
        host: if url.contains("kinlab") {
            kin_core::RemoteHostKind::KinLab
        } else {
            kin_core::RemoteHostKind::GitHub
        },
        transport: RemoteTransportKind::GitExport,
        url: Some(url),
        publish_review_state: false,
        publish_proofs: false,
    })
}

pub async fn run(remote_name: Option<String>) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let config = KinConfig::load_or_default(&layout.config_path())?;
    let remote = resolve_remote(&config, remote_name.as_deref())?;

    if remote.transport == RemoteTransportKind::NativeKin {
        anyhow::bail!(
            "Native Kin pull requires a KinLab control-plane. Use `kin pull` with a git-export remote."
        );
    }

    // Git-export transport: pull from git, then re-import into Kin
    let working_dir = layout.working_dir();
    let git_dir = working_dir.join(".git");

    if !git_dir.exists() {
        anyhow::bail!(
            "no .git directory found at {}. Cannot pull without a Git repository to update.",
            working_dir.display()
        );
    }

    println!("Pulling from Git remote '{}'...", remote.name);

    let status = Command::new("git")
        .args(["pull"])
        .current_dir(working_dir)
        .status()
        .map_err(|e| anyhow::anyhow!("failed to run git pull: {}", e))?;

    if !status.success() {
        anyhow::bail!("git pull failed with exit code {}", status);
    }

    // Re-import Git history into the Kin graph
    println!("Re-importing Git history into Kin...");

    let snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout))?;
    let graph = snap.graph();
    let graph = &*graph;
    let blob_store = kin_blobs::BlobStore::new(layout.objects_dir())
        .map_err(|e| anyhow::anyhow!("failed to open blob store: {}", e))?;

    let source = working_dir.to_path_buf();
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
            "  Bootstrapped semantic branch '{}' at genesis.",
            branch_name
        );
    }

    let mut count = 0usize;
    for imported_change in &imported {
        graph.create_change(&imported_change.change)?;
        count += 1;
    }

    if let Some(last) = imported.last() {
        graph.update_branch_head(&branch_name, &last.change.id)?;
        println!("  Updated branch '{}' to {}", branch_name, last.change.id);
    }

    snap.save()?;
    println!("Pull complete. Imported {} changes.", count);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_remote_fails_without_config_or_git() {
        let config = KinConfig::default();
        let err = resolve_remote(&config, Some("nonexistent")).unwrap_err();
        assert!(err.to_string().contains("no remote found"));
    }

    #[test]
    fn resolve_remote_with_explicit_nonexistent_name_fails() {
        // Using an explicit name that doesn't exist should always fail,
        // even if a git origin is detectable in the test environment.
        let config = KinConfig::default();
        let err = resolve_remote(&config, Some("does-not-exist")).unwrap_err();
        assert!(err.to_string().contains("no remote found"));
        assert!(
            err.to_string().contains("kin remote add"),
            "error should suggest `kin remote add`"
        );
    }

    #[test]
    fn resolve_remote_uses_configured_remote_when_present() {
        let mut config = KinConfig::default();
        config.remote.refs.push(RemoteRefConfig {
            name: "origin".to_string(),
            host: kin_core::RemoteHostKind::GitHub,
            transport: RemoteTransportKind::GitExport,
            url: Some("https://github.com/user/repo.git".to_string()),
            publish_review_state: false,
            publish_proofs: false,
        });
        config.remote.default = Some("origin".to_string());

        let remote = resolve_remote(&config, None).unwrap();
        assert_eq!(remote.name, "origin");
        assert_eq!(remote.transport, RemoteTransportKind::GitExport);
    }

    #[test]
    fn resolve_remote_finds_named_remote() {
        let mut config = KinConfig::default();
        config.remote.refs.push(RemoteRefConfig {
            name: "upstream".to_string(),
            host: kin_core::RemoteHostKind::KinLab,
            transport: RemoteTransportKind::NativeKin,
            url: Some("https://kinlab.ai/api/orgs/my-org/repos/my-repo".to_string()),
            publish_review_state: true,
            publish_proofs: true,
        });

        let remote = resolve_remote(&config, Some("upstream")).unwrap();
        assert_eq!(remote.name, "upstream");
        assert_eq!(remote.transport, RemoteTransportKind::NativeKin);
    }
}
