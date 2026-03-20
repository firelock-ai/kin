// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use serde_json::json;

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
        crate::commands::git::export(Some(export_target.to_string_lossy().into_owned()), false)
            .await?;
        println!(
            "Prepared Git export at {}. Run `git push {}` from that repo to publish upstream.",
            export_target.display(),
            plan.remote.name
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
