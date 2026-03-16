use std::process::Command;

use anyhow::Result;
use kin_core::{KinConfig, RemoteHostKind, RemoteRefConfig, RemoteTransportKind};
use kin_model::provenance::ApprovalDecision;
use kin_model::GraphStore;
use serde_json::Value;

#[derive(Debug, Clone)]
pub(crate) struct PushPlanContext {
    pub(crate) remote: RemoteRefConfig,
    pub(crate) branch_name: String,
    pub(crate) organization_id: String,
    pub(crate) repo_id: String,
    pub(crate) local_head: Option<String>,
    pub(crate) remote_head: Option<String>,
    pub(crate) approved: bool,
    pub(crate) semantic_state_note: Option<String>,
    pub(crate) remote_state_note: Option<String>,
}

pub async fn list() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let config = KinConfig::load_or_default(&layout.config_path())?;

    if config.remote.refs.is_empty() {
        println!("No explicit Kin remotes configured.");
    } else {
        println!(
            "{:<12}  {:<10}  {:<12}  {:<7}  {}",
            "REMOTE", "HOST", "TRANSPORT", "DEFAULT", "URL"
        );
        println!("{}", "-".repeat(72));

        for remote in &config.remote.refs {
            let is_default = config.remote.default.as_deref() == Some(remote.name.as_str());
            println!(
                "{:<12}  {:<10}  {:<12}  {:<7}  {}",
                remote.name,
                remote.host,
                remote.transport,
                if is_default { "yes" } else { "no" },
                remote.url.as_deref().unwrap_or("-"),
            );
        }
    }

    if config.remote.refs.is_empty() {
        if let Some(origin) = detect_git_origin_remote() {
            println!("\nDetected compatibility remote:");
            println!(
                "  {} -> {} ({}, {})",
                origin.name,
                origin.url.as_deref().unwrap_or("-"),
                origin.host,
                origin.transport
            );
        }
    }

    Ok(())
}

pub async fn add(
    name: String,
    host: String,
    transport: String,
    url: Option<String>,
    publish_review_state: bool,
    publish_proofs: bool,
    default: bool,
) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let config_path = layout.config_path();
    let mut config = KinConfig::load_or_default(&config_path)?;

    let host = RemoteHostKind::from_str(&host).ok_or_else(|| {
        anyhow::anyhow!("unknown remote host '{}'; expected github or kinhub", host)
    })?;
    let transport = RemoteTransportKind::from_str(&transport).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown remote transport '{}'; expected git-export or native-kin",
            transport
        )
    })?;

    let entry = RemoteRefConfig {
        name: name.clone(),
        host,
        transport,
        url,
        publish_review_state,
        publish_proofs,
    };

    if let Some(existing) = config
        .remote
        .refs
        .iter_mut()
        .find(|remote| remote.name == name)
    {
        *existing = entry;
    } else {
        config.remote.refs.push(entry);
    }

    if default || config.remote.default.is_none() {
        config.remote.default = Some(name.clone());
    }

    config.save(&config_path)?;

    println!("Configured remote: {}", name);
    println!("  Host: {}", host);
    println!("  Transport: {}", transport);
    if let Some(default_remote) = &config.remote.default {
        println!("  Default remote: {}", default_remote);
    }

    Ok(())
}

pub async fn plan_push(remote: Option<String>) -> Result<()> {
    let plan = load_push_plan(remote.as_deref()).await?;
    render_push_plan(&plan, false);
    Ok(())
}

pub(crate) async fn load_push_plan(requested_remote: Option<&str>) -> Result<PushPlanContext> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let config = KinConfig::load_or_default(&layout.config_path())?;
    let remote = resolve_remote(&config, requested_remote)?;
    let organization_id = std::env::var("KIN_ORG_ID")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "kin-open-core".to_string());
    let repo_id = layout
        .working_dir()
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("could not determine repository id from workspace path"))?
        .to_string();

    let _snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout))?;
    let graph = &*_snap.graph();
    let branch_name = kin_core::read_current_branch(&layout)?;

    let (local_head, approved, semantic_state_note) = if let Some(branch) =
        graph.get_branch(&branch_name)?
    {
        let approvals = graph.get_approvals_for_change(&branch.head)?;
        let approved = approvals
            .iter()
            .any(|approval| approval.decision == ApprovalDecision::Approved);
        (Some(branch.head.to_string()), approved, None)
    } else {
        let available_branches = graph
            .list_branches()?
            .into_iter()
            .map(|branch| branch.name.to_string())
            .collect::<Vec<_>>();
        let note = if available_branches.is_empty() {
            "No semantic branches are stored yet. Record Kin state with `kin commit` or import/sync from Git before publishing.".to_string()
        } else {
            format!(
                    "Current branch pointer '{}' is not present in the Kin graph. Available semantic branches: {}. Repair `.kin/HEAD` or switch branches before publishing.",
                    branch_name,
                    available_branches.join(", ")
                )
        };
        (None, false, Some(note))
    };

    let (remote_head, remote_state_note) = if remote.transport == RemoteTransportKind::NativeKin {
        match remote.url.as_deref().map(str::trim).filter(|value| !value.is_empty()) {
            Some(base_url) => {
                let status = fetch_native_remote_status(
                    base_url,
                    &organization_id,
                    &repo_id,
                    &remote.name,
                )
                .await?;
                (status.remote_head, None)
            }
            None => (
                None,
                Some(
                    "No remote URL is configured for this native-kin remote. Set `--url` to a KinHub control-plane base URL."
                        .to_string(),
                ),
            ),
        }
    } else {
        (None, None)
    };

    Ok(PushPlanContext {
        remote,
        branch_name: branch_name.to_string(),
        organization_id,
        repo_id,
        local_head,
        remote_head,
        approved,
        semantic_state_note,
        remote_state_note,
    })
}

pub(crate) fn evaluate_push_plan(plan: &PushPlanContext) -> kin_remote::PushPlan {
    let remote_ref = map_to_remote_ref(&plan.remote);
    let state = kin_remote::RepoState {
        local_head: plan.local_head.clone(),
        remote_head: plan.remote_head.clone(),
        approved: plan.approved,
    };
    kin_remote::plan_push(&remote_ref, &state)
}

pub(crate) fn render_push_plan(plan: &PushPlanContext, execute_git_export: bool) {
    let decision = evaluate_push_plan(plan);

    println!("Remote: {}", plan.remote.name);
    println!("  Host: {}", plan.remote.host);
    println!("  Transport: {}", plan.remote.transport);
    println!("  URL: {}", plan.remote.url.as_deref().unwrap_or("-"));
    println!("Branch pointer: {}", plan.branch_name);
    println!(
        "Semantic head: {}",
        plan.local_head.as_deref().unwrap_or("-")
    );
    println!(
        "Remote head: {}",
        plan.remote_head.as_deref().unwrap_or("-")
    );
    println!(
        "Approved head: {}",
        if plan.approved { "yes" } else { "no" }
    );
    println!("Decision: {}", format_push_decision(&decision.decision));
    if let Some(note) = &plan.semantic_state_note {
        println!("State: {}", note);
    }
    if let Some(note) = &plan.remote_state_note {
        println!("Remote: {}", note);
    }
    println!(
        "Publish review state: {}",
        if decision.publish_review_state {
            "yes"
        } else {
            "no"
        }
    );
    println!(
        "Publish proofs: {}",
        if decision.publish_proofs { "yes" } else { "no" }
    );

    match plan.remote.transport {
        RemoteTransportKind::GitExport => {
            match &decision.decision {
                kin_remote::PushDecision::Publish if execute_git_export => {
                    println!("Action: preparing Git export in the local compatibility repo.");
                }
                kin_remote::PushDecision::Publish => {
                    println!("Action: Git export transport can be prepared with `kin push`.");
                }
                kin_remote::PushDecision::SemanticStateRequired => {
                    println!(
                        "Action: record Kin state with `kin commit` or `kin git sync` before export."
                    );
                }
                kin_remote::PushDecision::ApprovalRequired => {
                    println!("Action: resolve approval gates, then rerun `kin push`.");
                }
                kin_remote::PushDecision::FastForwardRequired => {
                    println!("Action: reconcile remote divergence before export/publish.");
                }
            }
            println!("Network publish: external `git push` still owns the final GitHub upload.");
        }
        RemoteTransportKind::NativeKin => match &decision.decision {
            kin_remote::PushDecision::Publish => {
                println!("Action: native Kin publish can run with `kin push`.");
            }
            kin_remote::PushDecision::SemanticStateRequired => {
                println!("Action: record Kin state before a native publish can exist.");
            }
            kin_remote::PushDecision::ApprovalRequired => {
                println!("Action: resolve approval gates, then rerun `kin push`.");
            }
            kin_remote::PushDecision::FastForwardRequired => {
                println!("Action: reconcile remote divergence before publish.");
            }
        },
    }
}

fn resolve_remote(config: &KinConfig, requested: Option<&str>) -> Result<RemoteRefConfig> {
    if let Some(remote) = config.resolve_remote(requested) {
        return Ok(remote.clone());
    }

    if requested.is_none() {
        if let Some(origin) = detect_git_origin_remote() {
            return Ok(origin);
        }
    }

    Err(anyhow::anyhow!(
        "no remote found. Configure one with `kin remote add origin --host github --transport git-export --url <url> --default`."
    ))
}

fn map_to_remote_ref(remote: &RemoteRefConfig) -> kin_remote::RemoteRef {
    kin_remote::RemoteRef {
        name: remote.name.clone(),
        host: match remote.host {
            RemoteHostKind::GitHub => kin_remote::HostKind::GitHub,
            RemoteHostKind::KinHub => kin_remote::HostKind::KinHub,
        },
        transport: match remote.transport {
            RemoteTransportKind::GitExport => kin_remote::TransportKind::GitExport,
            RemoteTransportKind::NativeKin => kin_remote::TransportKind::NativeKin,
        },
        capabilities: kin_remote::RemoteCapabilitySet {
            publish_semantic_changes: true,
            publish_review_state: remote.publish_review_state,
            publish_proofs: remote.publish_proofs,
        },
    }
}

fn native_remote_endpoint(
    base_url: &str,
    organization_id: &str,
    repo_id: &str,
    remote_name: &str,
) -> String {
    format!(
        "{}/api/orgs/{}/repos/{}/remotes/{}",
        base_url.trim_end_matches('/'),
        organization_id,
        repo_id,
        remote_name
    )
}

async fn fetch_native_remote_status(
    base_url: &str,
    organization_id: &str,
    repo_id: &str,
    remote_name: &str,
) -> Result<NativeRemoteStatus> {
    let response = reqwest::get(native_remote_endpoint(
        base_url,
        organization_id,
        repo_id,
        remote_name,
    ))
    .await?;
    let status = response.status();
    let payload = response.text().await?;
    if !status.is_success() {
        anyhow::bail!(
            "failed to fetch native remote status: {} {}",
            status,
            payload.trim()
        );
    }

    let parsed: Value = serde_json::from_str(&payload)?;
    let remote = parsed
        .get("remote")
        .and_then(Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("native remote status response is missing `remote`"))?;

    Ok(NativeRemoteStatus {
        remote_head: remote
            .get("remoteHead")
            .and_then(Value::as_str)
            .map(str::to_string),
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativeRemoteStatus {
    pub(crate) remote_head: Option<String>,
}

fn detect_git_origin_remote() -> Option<RemoteRefConfig> {
    let output = Command::new("git")
        .args(["remote", "get-url", "origin"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }

    let url = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if url.is_empty() {
        return None;
    }

    let host = if url.contains("kinhub") {
        RemoteHostKind::KinHub
    } else {
        RemoteHostKind::GitHub
    };

    Some(RemoteRefConfig {
        name: "origin".to_string(),
        host,
        transport: RemoteTransportKind::GitExport,
        url: Some(url),
        publish_review_state: false,
        publish_proofs: false,
    })
}

fn format_push_decision(decision: &kin_remote::PushDecision) -> &'static str {
    match decision {
        kin_remote::PushDecision::Publish => "publish",
        kin_remote::PushDecision::FastForwardRequired => "fast-forward-required",
        kin_remote::PushDecision::ApprovalRequired => "approval-required",
        kin_remote::PushDecision::SemanticStateRequired => "semantic-state-required",
    }
}

#[cfg(test)]
mod tests {
    use super::{
        evaluate_push_plan, format_push_decision, map_to_remote_ref, native_remote_endpoint,
        PushPlanContext,
    };
    use kin_core::{RemoteHostKind, RemoteRefConfig, RemoteTransportKind};

    #[test]
    fn maps_config_remote_to_runtime_remote() {
        let runtime = map_to_remote_ref(&RemoteRefConfig {
            name: "origin".into(),
            host: RemoteHostKind::KinHub,
            transport: RemoteTransportKind::NativeKin,
            url: Some("kinhub://kin/main".into()),
            publish_review_state: true,
            publish_proofs: true,
        });

        assert!(matches!(runtime.host, kin_remote::HostKind::KinHub));
        assert!(matches!(
            runtime.transport,
            kin_remote::TransportKind::NativeKin
        ));
        assert!(runtime.capabilities.publish_review_state);
        assert!(runtime.capabilities.publish_proofs);
    }

    #[test]
    fn formats_push_decisions() {
        assert_eq!(
            format_push_decision(&kin_remote::PushDecision::Publish),
            "publish"
        );
        assert_eq!(
            format_push_decision(&kin_remote::PushDecision::ApprovalRequired),
            "approval-required"
        );
        assert_eq!(
            format_push_decision(&kin_remote::PushDecision::SemanticStateRequired),
            "semantic-state-required"
        );
    }

    #[test]
    fn missing_semantic_state_blocks_publish() {
        let plan = evaluate_push_plan(&PushPlanContext {
            remote: RemoteRefConfig {
                name: "origin".into(),
                host: RemoteHostKind::GitHub,
                transport: RemoteTransportKind::GitExport,
                url: Some("https://github.com/firelock-ai/kin.git".into()),
                publish_review_state: false,
                publish_proofs: false,
            },
            branch_name: "main".into(),
            organization_id: "kin-open-core".into(),
            repo_id: "kin".into(),
            local_head: None,
            remote_head: None,
            approved: false,
            semantic_state_note: Some("No semantic branches are stored yet.".into()),
            remote_state_note: None,
        });

        assert_eq!(
            plan.decision,
            kin_remote::PushDecision::SemanticStateRequired
        );
    }

    #[test]
    fn divergent_native_remote_head_blocks_publish() {
        let plan = evaluate_push_plan(&PushPlanContext {
            remote: RemoteRefConfig {
                name: "origin".into(),
                host: RemoteHostKind::KinHub,
                transport: RemoteTransportKind::NativeKin,
                url: Some("http://127.0.0.1:4010".into()),
                publish_review_state: true,
                publish_proofs: true,
            },
            branch_name: "main".into(),
            organization_id: "kin-open-core".into(),
            repo_id: "kin".into(),
            local_head: Some("change:abc".into()),
            remote_head: Some("change:def".into()),
            approved: true,
            semantic_state_note: None,
            remote_state_note: None,
        });

        assert_eq!(plan.decision, kin_remote::PushDecision::FastForwardRequired);
    }

    #[test]
    fn native_remote_endpoint_joins_base_url_without_double_slash() {
        assert_eq!(
            native_remote_endpoint("http://127.0.0.1:4010/", "kin-open-core", "kin", "origin"),
            "http://127.0.0.1:4010/api/orgs/kin-open-core/repos/kin/remotes/origin"
        );
    }
}
