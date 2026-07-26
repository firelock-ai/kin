// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result};
use kin_core::{KinConfig, RemoteHostKind, RemoteRefConfig, RemoteTransportKind};
use kin_model::BranchName;

use crate::commands::{native_sync, remote};

fn is_git_url(url: &str) -> bool {
    if remote::explicit_native_remote_target(url).is_some() {
        return false;
    }
    // URLs targeting a KinLab host are native remotes, not git.
    if looks_like_kinlab_host(url) {
        return false;
    }
    // Use forge detection for known forges, fall back to .git suffix for generic servers.
    kin_migrate::detect_forge(url).is_some() || url.ends_with(".git")
}

fn looks_like_kinlab_host(url: &str) -> bool {
    url.split("://")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .is_some_and(|host| {
            let host_lower = host.to_ascii_lowercase();
            host_lower.starts_with("kinlab.") || host_lower.contains(".kinlab.")
        })
}

fn derive_target_dir(url: &str, path: Option<String>) -> PathBuf {
    path.map(PathBuf::from).unwrap_or_else(|| {
        // If forge detection succeeds, use the repo name from parsed coordinates.
        if let Some(forge) = kin_migrate::detect_forge(url) {
            return PathBuf::from(&forge.repo);
        }
        // Fallback: extract from URL path.
        let name = url
            .rsplit('/')
            .next()
            .unwrap_or("repo")
            .trim_end_matches(".git");
        PathBuf::from(name)
    })
}

fn configure_native_remote(
    layout: &kin_core::KinLayout,
    target: &remote::NativeRemoteTarget,
) -> Result<()> {
    let config_path = layout.config_path();
    let mut config = KinConfig::load_or_default(&config_path)?;
    let remote_ref = RemoteRefConfig {
        name: "origin".to_string(),
        host: RemoteHostKind::KinLab,
        transport: RemoteTransportKind::NativeKin,
        url: Some(target.repo_locator()),
        publish_review_state: true,
        publish_proofs: true,
    };

    if let Some(existing) = config
        .remote
        .refs
        .iter_mut()
        .find(|remote| remote.name == "origin")
    {
        *existing = remote_ref;
    } else {
        config.remote.refs.push(remote_ref);
    }
    config.remote.default = Some("origin".to_string());
    config.save(&config_path)?;
    Ok(())
}

fn ensure_empty_clone_dir(dir: &std::path::Path) -> Result<()> {
    if dir.exists() {
        let mut entries = fs::read_dir(dir)
            .with_context(|| format!("failed to inspect clone target {}", dir.display()))?;
        if entries.next().transpose()?.is_some() {
            anyhow::bail!(
                "clone target {} already exists and is not empty",
                dir.display()
            );
        }
        return Ok(());
    }

    fs::create_dir_all(dir)
        .with_context(|| format!("failed to create clone target {}", dir.display()))?;
    Ok(())
}

fn set_default_branch(layout: &kin_core::KinLayout, branch_name: &str) -> Result<()> {
    if branch_name.trim().is_empty() || branch_name == "main" {
        return Ok(());
    }

    let config_path = layout.config_path();
    let mut config = KinConfig::load_or_default(&config_path)?;
    config.default_branch = branch_name.to_string();
    config.save(&config_path)?;
    kin_core::write_current_branch(layout, &BranchName::new(branch_name))?;
    Ok(())
}

async fn clone_native(target: remote::NativeRemoteTarget, path: Option<String>) -> Result<()> {
    let local_dir = derive_target_dir(&target.repo_locator(), path);
    ensure_empty_clone_dir(&local_dir)?;

    println!("Cloning KinLab repository {}...", target.repo_locator());

    let snapshot = native_sync::fetch_snapshot(&target).await?;
    if snapshot.files.is_empty() {
        anyhow::bail!(
            "KinLab repository {} is not ready for native clone yet. The hosted projection is empty.",
            target.repo_locator()
        );
    }

    let init = kin_core::init(&local_dir)?;
    set_default_branch(&init.layout, &snapshot.default_branch)?;

    println!(
        "Materializing {} file(s) from KinLab...",
        snapshot.files.len()
    );
    native_sync::sync_snapshot_to_working_tree(&init.layout, &snapshot, &Default::default())?;

    let original_dir = std::env::current_dir()?;
    std::env::set_current_dir(&local_dir)?;
    let commit_result =
        crate::commands::commit::run("clone from KinLab native remote".to_string(), true).await;
    std::env::set_current_dir(&original_dir)?;
    commit_result?;

    let layout = kin_core::KinLayout::discover(&local_dir)
        .ok_or_else(|| anyhow::anyhow!("clone completed but Kin layout was not created"))?;
    configure_native_remote(&layout, &target)?;

    println!(
        "Clone complete. Local Kin graph is initialized from KinLab and `origin` now points at {}.",
        target.repo_locator()
    );
    Ok(())
}

pub async fn run(url: String, path: Option<String>) -> Result<()> {
    if let Some(target) = remote::explicit_native_remote_target(&url) {
        return clone_native(target, path).await;
    }

    if !is_git_url(&url) {
        anyhow::bail!("unsupported repository locator: {}", url);
    }

    // Detect the forge and resolve authentication.
    let forge = kin_migrate::detect_forge(&url);
    let clone_url = if let Some(ref forge_info) = forge {
        let token = forge_info.resolve_token_from_env();
        if token.is_some() {
            println!(
                "Authenticated {} clone via {}",
                forge_info.kind,
                forge_info.kind.token_env_var().unwrap_or("token")
            );
        }
        // For SSH URLs, use the original URL (auth is handled by SSH keys).
        // For HTTPS, embed the token if available.
        if forge_info.is_ssh {
            url.clone()
        } else {
            forge_info.https_clone_url(token.as_deref())
        }
    } else {
        url.clone()
    };

    let target = derive_target_dir(&url, path);
    let forge_label = forge
        .as_ref()
        .map(|f| f.kind.to_string())
        .unwrap_or_else(|| "Git".to_string());

    println!("Cloning {} repository {}...", forge_label, url);

    let status = Command::new("git")
        .args(["clone", &clone_url, &target.to_string_lossy()])
        .status()
        .map_err(|e| anyhow::anyhow!("failed to run git clone: {}", e))?;

    if !status.success() {
        anyhow::bail!("git clone failed with exit code {}", status);
    }

    println!("Migrating {} history...", forge_label);

    let scan =
        kin_migrate::scan_repo(&target).map_err(|e| anyhow::anyhow!("scan failed: {}", e))?;
    let plan = kin_migrate::plan_migration(
        &scan,
        kin_migrate::strategy::MigrationStrategy::Snapshot,
        None,
    );
    let result = kin_migrate::execute_migration_persisted(&plan)
        .map_err(|e| anyhow::anyhow!("migration failed: {}", e))?;

    // Configure the forge remote in .kin/config.toml.
    if let Some(ref forge_info) = forge {
        let layout = kin_core::KinLayout::discover(&target)
            .ok_or_else(|| anyhow::anyhow!("migration completed but Kin layout was not found"))?;
        kin_migrate::configure_forge_remote(&layout, forge_info)
            .map_err(|e| anyhow::anyhow!("failed to configure forge remote: {}", e))?;
    }

    print!("{}", result.summary());
    println!(
        "Clone complete. Kin repository ready at {}",
        target.display()
    );

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_github_url_as_git() {
        assert!(is_git_url("https://github.com/user/repo"));
        assert!(is_git_url("https://github.com/user/repo.git"));
        assert!(is_git_url("git@github.com:user/repo.git"));
    }

    #[test]
    fn detects_gitlab_url_as_git() {
        assert!(is_git_url("https://gitlab.com/user/repo"));
        assert!(is_git_url("https://gitlab.com/user/repo.git"));
        assert!(is_git_url("https://gitlab.com/group/subgroup/repo.git"));
    }

    #[test]
    fn detects_bitbucket_url_as_git() {
        assert!(is_git_url("https://bitbucket.org/user/repo.git"));
        assert!(is_git_url("https://bitbucket.org/workspace/repo"));
        assert!(is_git_url("git@bitbucket.org:workspace/repo.git"));
    }

    #[test]
    fn detects_self_hosted_gitlab_as_git() {
        assert!(is_git_url("https://gitlab.mycompany.com/team/repo.git"));
        assert!(is_git_url("git@gitlab.internal.co:group/repo.git"));
    }

    #[test]
    fn detects_self_hosted_bitbucket_as_git() {
        assert!(is_git_url(
            "https://bitbucket.internal.co/scm/proj/repo.git"
        ));
    }

    #[test]
    fn detects_generic_dot_git_suffix_as_git() {
        assert!(is_git_url("https://my-server.example.com/repo.git"));
    }

    #[test]
    fn native_kin_url_is_not_git() {
        assert!(!is_git_url("kinlab://org/repo"));
        assert!(!is_git_url("https://kinlab.example.com/repo"));
        assert!(!is_git_url("https://kinlab.ai/org/repo.git"));
    }

    #[test]
    fn derives_directory_name_from_git_url() {
        let target = derive_target_dir("https://github.com/user/my-project.git", None);
        assert_eq!(target, PathBuf::from("my-project"));
    }

    #[test]
    fn derives_directory_name_from_url_without_git_suffix() {
        let target = derive_target_dir("https://github.com/user/my-project", None);
        assert_eq!(target, PathBuf::from("my-project"));
    }

    #[test]
    fn derives_directory_name_from_gitlab_nested_url() {
        let target = derive_target_dir("https://gitlab.com/group/subgroup/my-project.git", None);
        assert_eq!(target, PathBuf::from("my-project"));
    }

    #[test]
    fn derives_directory_name_from_bitbucket_url() {
        let target = derive_target_dir("https://bitbucket.org/workspace/my-repo.git", None);
        assert_eq!(target, PathBuf::from("my-repo"));
    }

    #[test]
    fn ssh_url_detected_as_git() {
        assert!(is_git_url("git@github.com:org/repo.git"));
        assert!(is_git_url("ssh://git@gitlab.com/org/repo.git"));
        assert!(is_git_url("git@bitbucket.org:workspace/repo.git"));
    }

    #[test]
    fn native_target_directory_uses_repo_name() {
        let target = derive_target_dir("https://kinlab.ai/demo-org/demo-repo.git", None);
        assert_eq!(target, PathBuf::from("demo-repo"));
    }
}
