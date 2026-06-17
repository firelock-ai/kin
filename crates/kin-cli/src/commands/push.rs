// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_model::{ChangeStore, Hash256, SemanticChange, SemanticChangeId};
use serde::Deserialize;
use serde_json::json;
use std::process::Command;

use crate::commands::remote;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NativeRemotePublishPayload {
    published: bool,
    #[serde(default)]
    conflict: Option<NativeRemotePublishConflict>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NativeRemotePublishConflict {
    kind: String,
    message: String,
    #[serde(default)]
    expected_remote_head: Option<String>,
    #[serde(default)]
    lease_session_id: Option<String>,
    #[serde(default)]
    expected_fence_epoch: Option<u64>,
}

fn ensure_native_publish_succeeded(payload: &str) -> Result<()> {
    let response: NativeRemotePublishPayload =
        serde_json::from_str(payload).context("native publish returned an unreadable payload")?;
    if response.published {
        return Ok(());
    }

    let Some(conflict) = response.conflict else {
        anyhow::bail!(
            "native publish failed: server returned published=false without conflict details"
        );
    };

    let mut detail = if conflict.message.trim().is_empty() {
        format!("native publish blocked ({})", conflict.kind)
    } else {
        conflict.message.trim().to_string()
    };

    match conflict.kind.as_str() {
        "divergence" => {
            if let Some(expected_remote_head) = conflict.expected_remote_head.as_deref() {
                detail.push_str(&format!(" Remote head is {}.", expected_remote_head));
            }
        }
        "lease-invalid" => {
            if let Some(session_id) = conflict.lease_session_id.as_deref() {
                detail.push_str(&format!(" Lease {}.", session_id));
            }
            if let Some(expected_fence_epoch) = conflict.expected_fence_epoch {
                detail.push_str(&format!(" Expected fence epoch {}.", expected_fence_epoch));
            }
        }
        _ => {}
    }

    anyhow::bail!("native publish blocked: {}", detail);
}

fn parse_semantic_change_id(value: &str, label: &str) -> Result<SemanticChangeId> {
    let hash = Hash256::from_hex(value)
        .with_context(|| format!("{label} is not a valid semantic change id: {value}"))?;
    Ok(SemanticChangeId::from_hash(hash))
}

fn collect_native_publish_changes<G>(
    graph: &G,
    previous_local_head: Option<&str>,
    local_head: &str,
) -> Result<Vec<SemanticChange>>
where
    G: ChangeStore,
{
    let base = match previous_local_head {
        Some(previous) => parse_semantic_change_id(previous, "previous local head")?,
        None => kin_core::build_genesis_change().id,
    };
    let head = parse_semantic_change_id(local_head, "local head")?;
    graph
        .get_changes_since(&base, &head)
        .context("failed to collect semantic changes for native publish")
}

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
        let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
            .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
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

        // Extract full semantic changes for hosted materialization, plus the
        // legacy entity-level mutation bridge for older control planes.
        let sync_state_store = kin_core::SyncStateStore::load(&layout);
        let has_previous_sync = sync_state_store.get(&plan.remote.name).is_some();
        let publish_changes = {
            let snap =
                crate::backend::open_snapshot_explicit_admin_read_only(&layout, "kin push").await?;
            let graph = &*snap.graph();
            let previous = sync_state_store
                .get(&plan.remote.name)
                .map(|state| state.local_head.as_str());
            let changes = collect_native_publish_changes(graph, previous, local_head)?;
            if !changes.is_empty() {
                let mode = if previous.is_some() { "Delta" } else { "Full" };
                println!(
                    "  {} push: {} semantic change(s) for hosted materialization.",
                    mode,
                    changes.len()
                );
            }
            changes
        };
        let entity_mutations = kin_remote::delta_bridge::mutations_from_changes(&publish_changes);

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

        // Build publish payload — includes entity mutations when available.
        let mut publish_body = json!({
            "branchName": plan.branch_name,
            "localHead": local_head,
            "expectedRemoteHead": plan.remote_head,
            "approved": plan.approved,
            "publishReviewState": plan.remote.publish_review_state,
            "publishProofs": plan.remote.publish_proofs,
            "actor": lease.actor.actor_id,
            "leaseSessionId": lease.session_id,
            "leaseFenceEpoch": lease.fence_epoch,
        });

        if !publish_changes.is_empty() {
            publish_body["semanticChanges"] = json!(&publish_changes);
        }

        if !entity_mutations.is_empty() {
            publish_body["entityMutations"] = json!(entity_mutations);
        }

        let response = remote::attach_native_remote_auth(
            reqwest::Client::new().post(&endpoint),
            &target.base_url,
        )
        .json(&publish_body)
        .send()
        .await?;
        let status = response.status();
        let payload = response.text().await?;
        if !status.is_success() {
            anyhow::bail!("native publish failed: {} {}", status, payload.trim());
        }
        ensure_native_publish_succeeded(&payload)?;

        // Record sync state so next push can compute delta.
        let mut sync_state_store = kin_core::SyncStateStore::load(&layout);
        sync_state_store.record_sync(&plan.remote.name, local_head, local_head);
        if let Err(e) = sync_state_store.save(&layout) {
            eprintln!("warning: failed to save push sync state: {}", e);
        }

        let mode = if has_previous_sync { "delta" } else { "full" };
        println!(
            "Published semantic head {} to native Kin remote {} via {} (session {}, {} push).",
            local_head, plan.remote.name, endpoint, lease.session_id, mode
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn change_with_parent(byte: u8, parents: Vec<SemanticChangeId>) -> SemanticChange {
        SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([byte; 32])),
            parents,
            timestamp: kin_model::Timestamp::now(),
            author: kin_model::AuthorId::new("test"),
            message: format!("change {byte}"),
            entity_deltas: vec![],
            relation_deltas: vec![],
            artifact_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: Some(kin_model::BranchName::new("main")),
        }
    }

    #[test]
    fn native_publish_first_push_collects_changes_since_genesis() {
        let graph = kin_db::InMemoryGraph::new();
        let genesis = kin_core::build_genesis_change();
        graph.create_change(&genesis).unwrap();
        let child = change_with_parent(0x42, vec![genesis.id]);
        graph.create_change(&child).unwrap();

        let changes = collect_native_publish_changes(&graph, None, &child.id.to_string()).unwrap();

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].id, child.id);
    }

    #[test]
    fn native_publish_delta_collects_changes_since_previous_sync() {
        let graph = kin_db::InMemoryGraph::new();
        let genesis = kin_core::build_genesis_change();
        graph.create_change(&genesis).unwrap();
        let first = change_with_parent(0x42, vec![genesis.id]);
        graph.create_change(&first).unwrap();
        let second = change_with_parent(0x43, vec![first.id]);
        graph.create_change(&second).unwrap();

        let changes = collect_native_publish_changes(
            &graph,
            Some(&first.id.to_string()),
            &second.id.to_string(),
        )
        .unwrap();

        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].id, second.id);
    }

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

    #[test]
    fn native_publish_payload_requires_success() {
        let error = ensure_native_publish_succeeded(
            r#"{
                "published": false,
                "conflict": {
                    "kind": "lease-invalid",
                    "message": "Native publish lease is stale. Renew the lease before publishing.",
                    "expectedRemoteHead": null,
                    "leaseSessionId": "lease-123",
                    "expectedFenceEpoch": 4
                }
            }"#,
        )
        .unwrap_err();

        let rendered = error.to_string();
        assert!(rendered.contains("native publish blocked"));
        assert!(rendered.contains("lease-123"));
        assert!(rendered.contains("Expected fence epoch 4"));
    }

    #[test]
    fn native_publish_payload_reports_divergence_conflict() {
        let error = ensure_native_publish_succeeded(
            r#"{
                "published": false,
                "conflict": {
                    "kind": "divergence",
                    "message": "Remote semantic head diverged from the requested base.",
                    "expectedRemoteHead": "abc123def456",
                    "leaseSessionId": null,
                    "expectedFenceEpoch": null
                }
            }"#,
        )
        .unwrap_err();

        let rendered = error.to_string();
        assert!(rendered.contains("native publish blocked"));
        assert!(rendered.contains("Remote semantic head diverged from the requested base."));
        assert!(rendered.contains("Remote head is abc123def456."));
    }

    #[test]
    fn native_publish_payload_rejects_missing_conflict_details() {
        let error = ensure_native_publish_succeeded(
            r#"{
                "published": false,
                "conflict": null
            }"#,
        )
        .unwrap_err();

        assert!(error
            .to_string()
            .contains("published=false without conflict details"));
    }

    #[test]
    fn native_publish_payload_accepts_success() {
        ensure_native_publish_succeeded(
            r#"{
                "published": true,
                "conflict": null
            }"#,
        )
        .unwrap();
    }
}
