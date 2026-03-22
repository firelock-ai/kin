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
        crate::commands::git::ensure_transport_repo(
            &export_target,
            Some(layout.working_dir()),
            plan.remote.url.as_deref(),
        )?;
        println!("Publishing via Git export (compatibility mode)...");
        crate::commands::git::export(Some(export_target.to_string_lossy().into_owned()), false)
            .await?;
        let branch_ref = format!("refs/heads/{}", plan.branch_name);
        if !crate::commands::git::git_ref_exists(&export_target, &branch_ref)? {
            anyhow::bail!(
                "git export did not materialize branch '{}' in {}",
                plan.branch_name,
                export_target.display()
            );
        }

        let push = Command::new("git")
            .args([
                "push",
                "origin",
                &format!("{branch_ref}:refs/heads/{}", plan.branch_name),
            ])
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
        if !push_stderr.trim().is_empty() {
            println!("{}", push_stderr.trim());
        }
        println!(
            "Pushed to {} (branch {}) via Git export (compatibility mode).",
            plan.remote.url.as_deref().unwrap_or("origin"),
            plan.branch_name
        );
        println!(
            "Hint: configure a native Kin remote with `kin remote add --transport native-kin` for full semantic sync."
        );
    } else {
        let target = remote::resolve_native_remote_target(
            plan.remote.url.as_deref(),
            &plan.organization_id,
            &plan.repo_id,
        )?;
        let local_head = plan.local_head.as_deref().ok_or_else(|| {
            anyhow::anyhow!("push blocked: no semantic head is available for native publish.")
        })?;
        if remote::native_remote_bearer_token(&target.base_url).is_none() {
            anyhow::bail!(
                "no KinLab auth token available for {}. Run `kin auth login --base-url {}` or set KIN_REMOTE_BEARER_TOKEN.",
                target.base_url,
                target.base_url
            );
        }

        let endpoint = target.remote_endpoint(&plan.remote.name);
        let actor = remote::default_cli_actor_id(&target.base_url);
        let lease = remote::request_repo_session_lease(
            &target,
            &actor,
            kin_model::SessionTransport::Cli,
            Some(remote::default_cli_session_capabilities()),
            None,
        )
        .await?;
        let response = remote::attach_native_remote_auth(
            reqwest::Client::new().post(&endpoint),
            &target.base_url,
        )
        .json(&json!({
            "branchName": plan.branch_name,
            "localHead": local_head,
            "expectedRemoteHead": plan.remote_head,
            "approved": plan.approved,
            "publishReviewState": plan.remote.publish_review_state,
            "publishProofs": plan.remote.publish_proofs,
            "actor": lease.actor.actor_id,
        }))
        .send()
        .await?;
        let status = response.status();
        let payload = response.text().await?;
        if !status.is_success() {
            anyhow::bail!("native publish failed: {} {}", status, payload.trim());
        }

        println!(
            "Published semantic head {} to native Kin remote {} via {} (session {}).",
            local_head, plan.remote.name, endpoint, lease.session_id
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

        fs::write(export.join("hello.txt"), "world").unwrap();

        let add = Command::new("git")
            .args(["add", "."])
            .current_dir(&export)
            .output()
            .unwrap();
        assert!(add.status.success());

        let commit = Command::new("git")
            .args(["commit", "-m", "kin push"])
            .current_dir(&export)
            .output()
            .unwrap();
        assert!(commit.status.success());
    }
}
