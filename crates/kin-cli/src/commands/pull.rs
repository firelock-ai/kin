// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::process::Command;

use anyhow::Result;
use kin_core::{KinConfig, RemoteRefConfig, RemoteTransportKind};
use kin_model::GraphStore;

use crate::commands::remote;

fn resolve_remote(config: &KinConfig, requested: Option<&str>) -> Result<RemoteRefConfig> {
    if let Some(remote) = config.resolve_remote(requested) {
        return Ok(remote.clone());
    }

    if requested.is_none() {
        if let Some(origin) = remote::detect_git_origin_remote() {
            return Ok(origin);
        }
    }

    Err(anyhow::anyhow!(
        "no remote found. Configure one with `kin remote add origin --host github --transport git-export --url <url> --default`, or ensure a Git origin is set."
    ))
}

fn git_command_with_optional_auth(token: Option<&str>) -> Command {
    let mut command = Command::new("git");
    if let Some(token) = token {
        command.env("GIT_CONFIG_COUNT", "1");
        command.env("GIT_CONFIG_KEY_0", "http.extraHeader");
        command.env(
            "GIT_CONFIG_VALUE_0",
            format!("Authorization: Bearer {}", token),
        );
    }
    command
}

pub async fn run(remote_name: Option<String>) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let config = KinConfig::load_or_default(&layout.config_path())?;
    let remote = resolve_remote(&config, remote_name.as_deref())?;

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

    let status = if remote.transport == RemoteTransportKind::NativeKin {
        let fallback_org_id = std::env::var("KIN_ORG_ID")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "kin-open-core".to_string());
        let fallback_repo_id = working_dir
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| {
                anyhow::anyhow!("could not determine repository id from workspace path")
            })?
            .to_string();
        let target = remote::resolve_native_remote_target(
            remote.url.as_deref(),
            &fallback_org_id,
            &fallback_repo_id,
        )?;
        let token = remote::native_remote_bearer_token(&target.base_url).ok_or_else(|| {
            anyhow::anyhow!(
                "no KinLab auth token available for {}. Run `kin auth login --base-url {}` first.",
                target.base_url,
                target.base_url
            )
        })?;
        git_command_with_optional_auth(Some(&token))
            .args(["pull", "--ff-only", "origin"])
            .current_dir(working_dir)
            .status()
            .map_err(|e| anyhow::anyhow!("failed to run authenticated git pull: {}", e))?
    } else {
        Command::new("git")
            .args(["pull"])
            .current_dir(working_dir)
            .status()
            .map_err(|e| anyhow::anyhow!("failed to run git pull: {}", e))?
    };

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
