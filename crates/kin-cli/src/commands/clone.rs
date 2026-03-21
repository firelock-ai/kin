// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::PathBuf;
use std::process::Command;

use anyhow::Result;
use kin_core::{KinConfig, RemoteHostKind, RemoteRefConfig, RemoteTransportKind};

use crate::commands::remote;

fn is_git_url(url: &str) -> bool {
    url.ends_with(".git")
        || url.contains("github.com")
        || url.contains("gitlab.com")
        || url.contains("bitbucket.org")
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

fn derive_target_dir(url: &str, path: Option<String>) -> PathBuf {
    path.map(PathBuf::from).unwrap_or_else(|| {
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

async fn clone_native(target: remote::NativeRemoteTarget, path: Option<String>) -> Result<()> {
    let token = remote::native_remote_bearer_token(&target.base_url).ok_or_else(|| {
        anyhow::anyhow!(
            "no KinLab auth token available for {}. Run `kin auth login --base-url {}` first.",
            target.base_url,
            target.base_url
        )
    })?;
    let projection_url = target.git_projection_url();
    let local_dir = derive_target_dir(&projection_url, path);

    println!("Cloning KinLab repository {}...", projection_url);

    let status = git_command_with_optional_auth(Some(&token))
        .args(["clone", &projection_url, &local_dir.to_string_lossy()])
        .status()
        .map_err(|e| anyhow::anyhow!("failed to run authenticated git clone: {}", e))?;

    if !status.success() {
        anyhow::bail!("authenticated git clone failed with exit code {}", status);
    }

    println!("Importing projected Git history into Kin...");
    let scan =
        kin_migrate::scan_repo(&local_dir).map_err(|e| anyhow::anyhow!("scan failed: {}", e))?;
    let plan = kin_migrate::plan_migration(
        &scan,
        kin_migrate::strategy::MigrationStrategy::Shallow,
        None,
        0,
    );
    let result = kin_migrate::execute_migration_persisted(&plan)
        .map_err(|e| anyhow::anyhow!("migration failed: {}", e))?;
    print!("{}", result.summary());

    let layout = kin_core::KinLayout::discover(&local_dir)
        .ok_or_else(|| anyhow::anyhow!("clone completed but Kin layout was not created"))?;
    configure_native_remote(&layout, &target)?;

    println!(
        "Clone complete. Local Kin graph is initialized and `origin` now points at {}.",
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

    let target = derive_target_dir(&url, path);

    println!("Cloning Git repository {}...", url);

    let status = Command::new("git")
        .args(["clone", &url, &target.to_string_lossy()])
        .status()
        .map_err(|e| anyhow::anyhow!("failed to run git clone: {}", e))?;

    if !status.success() {
        anyhow::bail!("git clone failed with exit code {}", status);
    }

    println!("Migrating Git history...");

    let scan =
        kin_migrate::scan_repo(&target).map_err(|e| anyhow::anyhow!("scan failed: {}", e))?;
    let plan = kin_migrate::plan_migration(
        &scan,
        kin_migrate::strategy::MigrationStrategy::Shallow,
        None,
        0,
    );
    let result = kin_migrate::execute_migration_persisted(&plan)
        .map_err(|e| anyhow::anyhow!("migration failed: {}", e))?;

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
    }

    #[test]
    fn detects_bitbucket_url_as_git() {
        assert!(is_git_url("https://bitbucket.org/user/repo.git"));
    }

    #[test]
    fn detects_generic_dot_git_suffix_as_git() {
        assert!(is_git_url("https://my-server.example.com/repo.git"));
    }

    #[test]
    fn native_kin_url_is_not_git() {
        assert!(!is_git_url("kinlab://org/repo"));
        assert!(!is_git_url("https://kinlab.example.com/repo"));
    }

    #[test]
    fn derives_directory_name_from_git_url() {
        let url = "https://github.com/user/my-project.git";
        let name = url.rsplit('/').next().unwrap().trim_end_matches(".git");
        assert_eq!(name, "my-project");
    }

    #[test]
    fn derives_directory_name_from_url_without_git_suffix() {
        let url = "https://github.com/user/my-project";
        let name = url.rsplit('/').next().unwrap().trim_end_matches(".git");
        assert_eq!(name, "my-project");
    }

    #[test]
    fn ssh_url_detected_as_git() {
        assert!(is_git_url("git@github.com:org/repo.git"));
        assert!(is_git_url("ssh://git@gitlab.com/org/repo.git"));
    }

    #[test]
    fn native_target_directory_uses_repo_name() {
        let target = derive_target_dir("https://kinlab.ai/demo-org/demo-repo.git", None);
        assert_eq!(target, PathBuf::from("demo-repo"));
    }
}
