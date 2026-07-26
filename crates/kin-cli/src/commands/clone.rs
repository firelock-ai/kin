// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Exact Git transport followed by atomic repository-v6 admission.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};

fn derive_target_dir(url: &str, path: Option<String>) -> PathBuf {
    path.map(PathBuf::from).unwrap_or_else(|| {
        let name = url
            .trim_end_matches('/')
            .rsplit(['/', ':'])
            .next()
            .unwrap_or("repo")
            .trim_end_matches(".git");
        PathBuf::from(if name.is_empty() { "repo" } else { name })
    })
}

fn reject_native_remote(url: &str) -> Result<()> {
    let lowercase = url.to_ascii_lowercase();
    if lowercase.starts_with("kin://")
        || lowercase.starts_with("kinlab://")
        || lowercase
            .split("://")
            .nth(1)
            .and_then(|rest| rest.split('/').next())
            .is_some_and(|host| host.starts_with("kinlab.") || host.contains(".kinlab."))
    {
        anyhow::bail!(
            "native Kin clone is fail-closed until repository-v6 remote transfer lands; \
             `kin clone` currently accepts Git transport only"
        );
    }
    Ok(())
}

fn require_available_target(target: &Path) -> Result<bool> {
    match fs::symlink_metadata(target) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(error) => {
            Err(error).with_context(|| format!("inspect clone target {}", target.display()))
        }
        Ok(metadata) if !metadata.file_type().is_dir() => {
            anyhow::bail!("clone target is not a directory: {}", target.display())
        }
        Ok(_) => {
            let mut entries = fs::read_dir(target)
                .with_context(|| format!("inspect clone target {}", target.display()))?;
            if entries.next().transpose()?.is_some() {
                anyhow::bail!(
                    "clone target {} already exists and is not empty",
                    target.display()
                );
            }
            Ok(false)
        }
    }
}

pub async fn run(url: String, path: Option<String>) -> Result<()> {
    reject_native_remote(&url)?;
    let target = derive_target_dir(&url, path);
    let target_created_by_command = require_available_target(&target)?;

    let status = Command::new("git")
        .arg("clone")
        .arg("--")
        .arg(&url)
        .arg(&target)
        .status()
        .context("launch Git clone transport")?;
    if !status.success() {
        anyhow::bail!("Git clone transport failed with {status}");
    }

    let admitted = kin_core::init_from_git(&target);
    let result = match admitted {
        Ok(result) => result,
        Err(error) => {
            if target_created_by_command {
                fs::remove_dir_all(&target).with_context(|| {
                    format!(
                        "exact Kin admission failed ({error}); additionally failed to remove \
                         clone destination created by this invocation: {}",
                        target.display()
                    )
                })?;
            }
            return Err(error).context("admit cloned Git repository into exact Kin authority");
        }
    };

    println!(
        "Cloned Git transport and admitted exact Kin repository authority at {}",
        target.display()
    );
    println!("  Repository: {}", result.repository_id);
    println!("  Workspace: {}", result.workspace_id);
    println!(
        "  Authority generation: {}",
        result.authority.receipt.generation
    );
    println!("  Semantic enrichment: not run");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derives_clone_directory_without_treating_scp_colon_as_a_path_component() {
        assert_eq!(
            derive_target_dir("git@github.com:kin-project/kin.git", None),
            PathBuf::from("kin")
        );
        assert_eq!(
            derive_target_dir("https://github.com/kin-project/kin.git", None),
            PathBuf::from("kin")
        );
    }

    #[test]
    fn native_remote_is_rejected_before_transport() {
        let error = reject_native_remote("kinlab://acme/repo").unwrap_err();
        assert!(error.to_string().contains("fail-closed"));
    }
}
