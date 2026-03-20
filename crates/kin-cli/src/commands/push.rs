// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use serde_json::json;
use std::process::Command;

use crate::commands::remote;

pub async fn run(remote_name: Option<String>) -> Result<()> {
    let plan = remote::load_push_plan(remote_name.as_deref()).await?;
    let push_plan = remote::evaluate_push_plan(&plan);
    remote::render_push_plan(&plan, true);

    match push_plan.decision {
        kin_remote::PushDecision::Publish => {}
        kin_remote::PushDecision::FastForwardRequired => {
            anyhow::bail!(
                "push blocked: remote state must be fast-forwarded or reconciled before publish."
            );
        }
        kin_remote::PushDecision::ApprovalRequired => {
            anyhow::bail!("push blocked: this remote requires approval before publish.");
        }
        kin_remote::PushDecision::SemanticStateRequired => {
            anyhow::bail!(
                "push blocked: no semantic branch/head is available yet. Record Kin state with `kin commit` or import/sync from Git first."
            );
        }
    }

    if plan.remote.transport == kin_core::RemoteTransportKind::GitExport {
        let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
            .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
        let export_target = crate::commands::git::sync_export_path(&layout);
        println!("Publishing via Git export (compatibility mode)...");
        crate::commands::git::export(Some(export_target.to_string_lossy().into_owned()), false)
            .await?;

        // Ensure a git repo exists in the export directory
        let git_dir = export_target.join(".git");
        if !git_dir.exists() {
            let init = Command::new("git")
                .args(["init"])
                .current_dir(&export_target)
                .output()?;
            if !init.status.success() {
                anyhow::bail!(
                    "failed to init git repo in export directory: {}",
                    String::from_utf8_lossy(&init.stderr)
                );
            }

            // Add the remote URL if configured
            if let Some(url) = plan.remote.url.as_deref().filter(|u| !u.trim().is_empty()) {
                let add_remote = Command::new("git")
                    .args(["remote", "add", "origin", url.trim()])
                    .current_dir(&export_target)
                    .output()?;
                if !add_remote.status.success() {
                    // Remote may already exist from a previous partial run; try set-url instead
                    let set_url = Command::new("git")
                        .args(["remote", "set-url", "origin", url.trim()])
                        .current_dir(&export_target)
                        .output()?;
                    if !set_url.status.success() {
                        anyhow::bail!(
                            "failed to configure git remote origin: {}",
                            String::from_utf8_lossy(&set_url.stderr)
                        );
                    }
                }
            }
        }

        // Stage all exported files
        let add = Command::new("git")
            .args(["add", "."])
            .current_dir(&export_target)
            .output()?;
        if !add.status.success() {
            anyhow::bail!(
                "git add failed in export directory: {}",
                String::from_utf8_lossy(&add.stderr)
            );
        }

        // Commit (allow empty so re-pushes of identical state don't fail)
        let commit = Command::new("git")
            .args(["commit", "--allow-empty", "-m", "kin push"])
            .current_dir(&export_target)
            .output()?;
        if !commit.status.success() {
            let stderr = String::from_utf8_lossy(&commit.stderr);
            // "nothing to commit" is fine — we still push
            if !stderr.contains("nothing to commit") {
                anyhow::bail!("git commit failed in export directory: {}", stderr);
            }
        }

        // Determine the branch to push
        let branch_output = Command::new("git")
            .args(["rev-parse", "--abbrev-ref", "HEAD"])
            .current_dir(&export_target)
            .output()?;
        let branch = if branch_output.status.success() {
            String::from_utf8_lossy(&branch_output.stdout)
                .trim()
                .to_string()
        } else {
            "main".to_string()
        };

        // Push to remote
        let push = Command::new("git")
            .args(["push", "-u", "origin", &branch])
            .current_dir(&export_target)
            .output()?;
        if !push.status.success() {
            let stderr = String::from_utf8_lossy(&push.stderr);
            anyhow::bail!(
                "git push failed: {}\nHint: ensure the remote URL is configured. Use `kin remote add {} --host github --transport git-export --url <url> --default`.",
                stderr.trim(),
                plan.remote.name
            );
        }

        let stdout = String::from_utf8_lossy(&push.stdout);
        let push_stderr = String::from_utf8_lossy(&push.stderr);
        if !stdout.trim().is_empty() {
            println!("{}", stdout.trim());
        }
        // git push writes progress to stderr
        if !push_stderr.trim().is_empty() {
            println!("{}", push_stderr.trim());
        }
        println!(
            "Pushed to {} (branch {}) via Git export (compatibility mode).",
            plan.remote.url.as_deref().unwrap_or("origin"),
            branch
        );
        println!(
            "Hint: configure a native Kin remote with `kin remote add --transport native-kin` for full semantic sync."
        );
    } else {
        let remote_url = plan
            .remote
            .url
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "push blocked: this native-kin remote has no URL. Configure a KinLab control-plane base URL with `kin remote add ... --url <base-url>`."
                )
            })?;
        let local_head = plan.local_head.as_deref().ok_or_else(|| {
            anyhow::anyhow!("push blocked: no semantic head is available for native publish.")
        })?;
        let actor = std::env::var("USER")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "cli-user".to_string());
        let endpoint = format!(
            "{}/api/orgs/{}/repos/{}/remotes/{}",
            remote_url.trim_end_matches('/'),
            plan.organization_id,
            plan.repo_id,
            plan.remote.name
        );

        let response = reqwest::Client::new()
            .post(&endpoint)
            .json(&json!({
                "branchName": plan.branch_name,
                "localHead": local_head,
                "expectedRemoteHead": plan.remote_head,
                "approved": plan.approved,
                "publishReviewState": plan.remote.publish_review_state,
                "publishProofs": plan.remote.publish_proofs,
                "actor": actor,
            }))
            .send()
            .await?;
        let status = response.status();
        let payload = response.text().await?;
        if !status.is_success() {
            anyhow::bail!("native publish failed: {} {}", status, payload.trim());
        }

        println!(
            "Published semantic head {} to native Kin remote {} via {}.",
            local_head, plan.remote.name, endpoint
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn git_init_creates_repo_in_export_dir() {
        let dir = tempfile::tempdir().unwrap();
        let export = dir.path().join(".git-export");
        fs::create_dir_all(&export).unwrap();

        let init = Command::new("git")
            .args(["init"])
            .current_dir(&export)
            .output()
            .unwrap();
        assert!(init.status.success());
        assert!(export.join(".git").exists());
    }

    #[test]
    fn git_add_and_commit_in_export_dir() {
        let dir = tempfile::tempdir().unwrap();
        let export = dir.path().join(".git-export");
        fs::create_dir_all(&export).unwrap();

        // Init
        Command::new("git")
            .args(["init"])
            .current_dir(&export)
            .output()
            .unwrap();

        // Configure git user for test environment
        Command::new("git")
            .args(["config", "user.email", "test@kin.dev"])
            .current_dir(&export)
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.name", "Kin Test"])
            .current_dir(&export)
            .output()
            .unwrap();

        // Create a test file
        fs::write(export.join("hello.txt"), "world").unwrap();

        // Add
        let add = Command::new("git")
            .args(["add", "."])
            .current_dir(&export)
            .output()
            .unwrap();
        assert!(add.status.success());

        // Commit
        let commit = Command::new("git")
            .args(["commit", "-m", "kin push"])
            .current_dir(&export)
            .output()
            .unwrap();
        assert!(commit.status.success());
    }

    #[test]
    fn allow_empty_commit_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let export = dir.path().join(".git-export");
        fs::create_dir_all(&export).unwrap();

        Command::new("git")
            .args(["init"])
            .current_dir(&export)
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.email", "test@kin.dev"])
            .current_dir(&export)
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.name", "Kin Test"])
            .current_dir(&export)
            .output()
            .unwrap();

        let commit = Command::new("git")
            .args(["commit", "--allow-empty", "-m", "kin push"])
            .current_dir(&export)
            .output()
            .unwrap();
        assert!(commit.status.success());
    }
}
