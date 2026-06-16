// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_core::{KinConfig, RemoteRefConfig, RemoteTransportKind};
use kin_model::ChangeStore;

use crate::commands::{native_sync, remote};

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

pub async fn run(remote_name: Option<String>) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let config = KinConfig::load_or_default(&layout.config_path())?;
    let remote = resolve_remote(&config, remote_name.as_deref())?;
    let branch_name = kin_core::read_current_branch(&layout)?;

    if remote.transport == RemoteTransportKind::NativeKin {
        let working_dir = layout.working_dir();
        let fallback_org_id = std::env::var("KIN_ORG_ID")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "kin-open-core".to_string());
        let fallback_repo_id = remote::resolve_repo_id(&layout)?;
        let target = remote::resolve_native_remote_target(
            remote.url.as_deref(),
            &fallback_org_id,
            &fallback_repo_id,
        )?;
        println!(
            "Pulling branch '{}' from native Kin remote '{}'...",
            branch_name, remote.name
        );

        let current_tree = native_sync::ensure_clean_working_tree(&layout)?;
        let mut sync_state_store = kin_core::SyncStateStore::load(&layout);

        // Attempt delta sync if we have a previous sync point for this remote.
        let delta_result = if let Some(prev) = sync_state_store.get(&remote.name) {
            println!(
                "  Attempting delta sync (last synced: {})...",
                prev.last_synced_at
            );
            match native_sync::fetch_delta(&target, &prev.last_synced_at, &prev.remote_head).await {
                Ok(Some(delta)) => {
                    if delta.default_branch != branch_name.to_string() {
                        anyhow::bail!(
                            "native pull currently supports only the remote default branch ('{}'), but the current branch is '{}'. Switch branches or use a matching remote default branch first.",
                            delta.default_branch,
                            branch_name
                        );
                    }
                    let stats =
                        native_sync::apply_delta_to_working_tree(&layout, &delta, &current_tree)?;
                    Some((stats, delta.remote_head))
                }
                Ok(None) => {
                    println!("  Delta endpoint unavailable, falling back to full snapshot...");
                    None
                }
                Err(e) => {
                    println!(
                        "  Delta sync failed ({}), falling back to full snapshot...",
                        e
                    );
                    None
                }
            }
        } else {
            None
        };

        let used_delta;
        let (written, removed, remote_head_for_state) = if let Some((stats, remote_head)) =
            delta_result
        {
            used_delta = true;
            (stats.written_files, stats.removed_files, Some(remote_head))
        } else {
            used_delta = false;
            // Full snapshot fallback (first pull or delta unavailable)
            let snapshot = native_sync::fetch_snapshot(&target).await?;
            if snapshot.default_branch != branch_name.to_string() {
                anyhow::bail!(
                    "native pull currently supports only the remote default branch ('{}'), but the current branch is '{}'. Switch branches or use a matching remote default branch first.",
                    snapshot.default_branch,
                    branch_name
                );
            }
            let stats =
                native_sync::sync_snapshot_to_working_tree(&layout, &snapshot, &current_tree)?;
            (stats.written_files, stats.removed_files, None)
        };

        if written == 0 && removed == 0 {
            println!(
                "Already up to date with native Kin remote {}.",
                target.repo_locator()
            );
            return Ok(());
        }

        let original_dir = std::env::current_dir()?;
        std::env::set_current_dir(working_dir)?;
        let commit_result =
            crate::commands::commit::run("pull from KinLab native remote".to_string(), true).await;
        std::env::set_current_dir(&original_dir)?;
        commit_result?;

        // Record sync state so the next pull can use delta sync.
        let snap =
            crate::backend::open_snapshot_explicit_admin_read_only(&layout, "kin pull").await?;
        let graph = &*snap.graph();
        if let Ok(Some(branch)) = graph.get_branch(&branch_name) {
            let local_head = branch.head.to_string();
            let remote_head = remote_head_for_state.unwrap_or_else(|| local_head.clone());
            sync_state_store.record_sync(&remote.name, &remote_head, &local_head);
            if let Err(e) = sync_state_store.save(&layout) {
                // Non-fatal: next pull will just use full snapshot again.
                eprintln!("warning: failed to save sync state: {}", e);
            }
        }

        let mode = if used_delta { "delta" } else { "snapshot" };
        println!(
            "Pull complete ({} sync). Updated {} file(s) and removed {} file(s) from {}.",
            mode,
            written,
            removed,
            target.repo_locator()
        );
        return Ok(());
    }

    // Git-export transport pull is not yet enabled: re-importing a fetched Git
    // history into Kin would mutate local graph snapshots directly, bypassing the
    // daemon-owned authority. Fail fast with a clear, friendly message instead of
    // doing throwaway fetch work and erroring at the end. (`kin push` over
    // git-export already works; only the inbound re-import is pending.)
    anyhow::bail!(
        "Pull over a git-export remote ('{remote}') is not yet enabled in this build.\n\
         Inbound Git re-import would rewrite local graph snapshots outside the daemon, so it is coming in a later alpha.\n\
         For a working pull today, configure a native Kin remote: `kin remote add {remote} --transport native-kin --url <url> --default`.\n\
         To bring in external Git history offline, use `kin init --git-history ...` or `kin migrate`.",
        remote = remote.name
    );
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
