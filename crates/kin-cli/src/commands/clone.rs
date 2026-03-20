// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Firelock, LLC

use std::path::PathBuf;
use std::process::Command;

use anyhow::Result;

fn is_git_url(url: &str) -> bool {
    url.ends_with(".git")
        || url.contains("github.com")
        || url.contains("gitlab.com")
        || url.contains("bitbucket.org")
}

pub async fn run(url: String, path: Option<String>) -> Result<()> {
    if !is_git_url(&url) {
        anyhow::bail!(
            "Native Kin clone is not yet supported. Use `kin clone` with a Git URL, or manually init and sync."
        );
    }

    let target = path
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            // Derive directory name from the URL (last path segment, minus .git)
            let name = url
                .rsplit('/')
                .next()
                .unwrap_or("repo")
                .trim_end_matches(".git");
            PathBuf::from(name)
        });

    println!("Cloning Git repository {}...", url);

    let status = Command::new("git")
        .args(["clone", &url, &target.to_string_lossy()])
        .status()
        .map_err(|e| anyhow::anyhow!("failed to run git clone: {}", e))?;

    if !status.success() {
        anyhow::bail!("git clone failed with exit code {}", status);
    }

    println!("Initializing Kin repository in {}...", target.display());

    let init_result = kin_core::init(&target)?;
    println!(
        "  Initialized Kin at {}",
        init_result.layout.root().display()
    );

    println!("Migrating Git history...");

    let scan = kin_migrate::scan_repo(&target)
        .map_err(|e| anyhow::anyhow!("scan failed: {}", e))?;
    let plan = kin_migrate::plan_migration(
        &scan,
        kin_migrate::strategy::MigrationStrategy::Shallow,
        None,
        0,
    );
    let result = kin_migrate::execute_migration_persisted(&plan)
        .map_err(|e| anyhow::anyhow!("migration failed: {}", e))?;

    print!("{}", result.summary());
    println!("Clone complete. Kin repository ready at {}", target.display());

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

    #[tokio::test]
    async fn native_kin_url_returns_error() {
        let err = run("kinlab://org/repo".into(), None).await.unwrap_err();
        assert!(err
            .to_string()
            .contains("Native Kin clone is not yet supported"));
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
}
