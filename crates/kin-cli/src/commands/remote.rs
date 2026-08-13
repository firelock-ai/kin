// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

#[cfg(test)]
use std::path::Path;

use anyhow::{Context, Result};
use kin_core::{
    GitRemoteTransportConfig, KinConfig, KinLayout, RemoteHostKind, RemoteRefConfig,
    RemoteTransportKind,
};
use kin_model::provenance::ApprovalDecision;
use kin_model::{ProvenanceStore, SessionCapabilities, SessionLease, SessionTransport};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use url::Url;

use crate::commands::auth;

/// Schema token stamped on every `kin remote list --json` answer.
pub const REMOTE_LIST_SCHEMA: &str = "kin.remote.list.v1";

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativeRemoteTarget {
    pub(crate) base_url: String,
    pub(crate) organization_id: String,
    pub(crate) repo_id: String,
}

impl NativeRemoteTarget {
    pub(crate) fn repo_locator(&self) -> String {
        format!(
            "{}/api/orgs/{}/repos/{}",
            self.base_url.trim_end_matches('/'),
            self.organization_id,
            self.repo_id
        )
    }

    #[cfg(test)]
    pub(crate) fn git_projection_url(&self) -> String {
        format!(
            "{}/{}/{}.git",
            self.base_url.trim_end_matches('/'),
            self.organization_id,
            self.repo_id
        )
    }

    pub(crate) fn remote_endpoint(&self, remote_name: &str) -> String {
        format!("{}/remotes/{}", self.repo_locator(), remote_name)
    }

    pub(crate) fn session_lease_endpoint(&self) -> String {
        format!("{}/session-lease", self.repo_locator())
    }

    pub(crate) fn sessions_endpoint(&self) -> String {
        format!("{}/sessions", self.repo_locator())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativeRemoteStatus {
    pub(crate) remote_head: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct RepoSessionLeaseRequest {
    actor_id: String,
    transport: SessionTransport,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl_seconds: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    capabilities: Option<SessionCapabilities>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RepoSessionLeaseResponse {
    lease: SessionLease,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RepoSessionsResponse {
    sessions: Vec<SessionLease>,
}

fn default_native_remote_base_url() -> String {
    for key in ["KIN_REMOTE_BASE_URL", "KINLAB_URL"] {
        if let Ok(value) = std::env::var(key) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return trimmed.trim_end_matches('/').to_string();
            }
        }
    }
    "https://kinlab.ai".to_string()
}

fn resolve_native_remote_bearer_token_with<F>(mut get_var: F) -> Option<String>
where
    F: FnMut(&str) -> Option<String>,
{
    for key in [
        "KIN_REMOTE_BEARER_TOKEN",
        "KIN_REMOTE_AUTH_TOKEN",
        "KINLAB_TOKEN",
    ] {
        if let Some(value) = get_var(key) {
            let trimmed = value.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

pub(crate) fn native_remote_bearer_token(base_url: &str) -> Option<String> {
    resolve_native_remote_bearer_token_with(|key| std::env::var(key).ok())
        .or_else(|| auth::load_saved_bearer_token(base_url))
}

pub(crate) fn attach_native_remote_auth(
    builder: reqwest::RequestBuilder,
    base_url: &str,
) -> reqwest::RequestBuilder {
    if let Some(token) = native_remote_bearer_token(base_url) {
        builder.bearer_auth(token)
    } else {
        builder
    }
}

fn parse_native_remote_locator(locator: &str) -> Option<NativeRemoteTarget> {
    let trimmed = locator.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }

    if let Some(rest) = trimmed
        .strip_prefix("kinlab://")
        .or_else(|| trimmed.strip_prefix("kin://"))
    {
        let parts: Vec<&str> = rest
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect();
        if parts.len() < 2 {
            return None;
        }
        return Some(NativeRemoteTarget {
            base_url: default_native_remote_base_url(),
            organization_id: parts[0].to_string(),
            repo_id: parts[1].trim_end_matches(".git").to_string(),
        });
    }

    if let (Ok(parsed), Ok(base)) = (
        Url::parse(trimmed),
        Url::parse(&default_native_remote_base_url()),
    ) {
        let same_origin = parsed.scheme() == base.scheme()
            && parsed.host_str() == base.host_str()
            && parsed.port_or_known_default() == base.port_or_known_default();
        if same_origin {
            let parts: Vec<&str> = parsed
                .path_segments()
                .map(|segments| segments.filter(|segment| !segment.is_empty()).collect())
                .unwrap_or_default();
            if parts.len() == 2 {
                let repo_id = parts[1].trim_end_matches(".git");
                if !repo_id.is_empty() {
                    return Some(NativeRemoteTarget {
                        base_url: default_native_remote_base_url(),
                        organization_id: parts[0].to_string(),
                        repo_id: repo_id.to_string(),
                    });
                }
            }
        }
    }

    let marker = "/api/orgs/";
    let idx = trimmed.find(marker)?;
    let base_url = trimmed[..idx].trim_end_matches('/').to_string();
    if base_url.is_empty() {
        return None;
    }

    let rest = &trimmed[idx + marker.len()..];
    let parts: Vec<&str> = rest
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    if parts.len() < 3 || parts[1] != "repos" {
        return None;
    }

    Some(NativeRemoteTarget {
        base_url,
        organization_id: parts[0].to_string(),
        repo_id: parts[2].trim_end_matches(".git").to_string(),
    })
}

#[cfg(test)]
pub(crate) fn explicit_native_remote_target(locator: &str) -> Option<NativeRemoteTarget> {
    parse_native_remote_locator(locator)
}

pub(crate) fn resolve_native_remote_target(
    url: Option<&str>,
    default_org: &str,
    default_repo: &str,
) -> Result<NativeRemoteTarget> {
    if let Some(locator) = url.and_then(parse_native_remote_locator) {
        return Ok(locator);
    }

    let base_url = url
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| value.trim_end_matches('/').to_string())
        .unwrap_or_else(default_native_remote_base_url);

    let organization_id = default_org.trim();
    let repo_id = default_repo.trim();
    if organization_id.is_empty() || repo_id.is_empty() {
        anyhow::bail!(
            "native remote is missing repo identity. Configure `--url` as a full repo locator like https://host/api/orgs/<org>/repos/<repo> or kinlab://<org>/<repo>."
        );
    }

    Ok(NativeRemoteTarget {
        base_url,
        organization_id: organization_id.to_string(),
        repo_id: repo_id.to_string(),
    })
}

pub(crate) fn default_cli_actor_id(base_url: &str) -> String {
    auth::default_cli_actor_id(base_url)
}

pub(crate) fn default_cli_session_capabilities() -> SessionCapabilities {
    SessionCapabilities {
        can_read: true,
        can_write: true,
        can_execute: false,
        can_branch: true,
        can_commit: true,
        max_concurrent_intents: 1,
    }
}

pub(crate) async fn request_repo_session_lease(
    target: &NativeRemoteTarget,
    actor_id: &str,
    transport: SessionTransport,
    capabilities: Option<SessionCapabilities>,
    ttl_seconds: Option<u64>,
) -> Result<SessionLease> {
    let response = attach_native_remote_auth(
        reqwest::Client::new().post(target.session_lease_endpoint()),
        &target.base_url,
    )
    .json(&RepoSessionLeaseRequest {
        actor_id: actor_id.to_string(),
        transport,
        ttl_seconds,
        capabilities,
    })
    .send()
    .await?;
    let status = response.status();
    let payload = response.text().await?;
    if !status.is_success() {
        anyhow::bail!(
            "failed to request native remote session lease: {} {}",
            status,
            payload.trim()
        );
    }

    Ok(serde_json::from_str::<RepoSessionLeaseResponse>(&payload)?.lease)
}

pub(crate) fn upsert_remote_config(
    layout: &KinLayout,
    entry: RemoteRefConfig,
    make_default: bool,
) -> Result<()> {
    // Config is part of the repository namespace handed to exact eject. Share
    // the projection lock so a writer that began before detach cannot mutate
    // the archived config or bind a replacement `.kin` epoch after waiting.
    let projection_freeze = kin_core::ExactProjectionFreeze::acquire_existing(layout.working_dir())
        .context("freeze the existing repository projection before updating remote config")?;
    let config_path = layout.config_path();
    let mut config = KinConfig::load_or_default(&config_path)?;
    if let Some(existing) = config
        .remote
        .refs
        .iter_mut()
        .find(|remote| remote.name == entry.name)
    {
        *existing = entry.clone();
    } else {
        config.remote.refs.push(entry.clone());
    }

    if make_default || config.remote.default.is_none() {
        config.remote.default = Some(entry.name.clone());
    }

    config.save(&config_path)?;
    drop(projection_freeze);
    Ok(())
}

#[cfg(test)]
pub(crate) fn ensure_git_remote(working_dir: &Path, name: &str, url: Option<&str>) -> Result<()> {
    let Some(url) = url.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(());
    };

    let get = kin_git::test_support::fixture_git_in(working_dir)
        .args(["remote", "get-url", name])
        .output()?;
    if get.status.success() {
        let current = String::from_utf8_lossy(&get.stdout).trim().to_string();
        if current == url {
            return Ok(());
        }
        let set = kin_git::test_support::fixture_git_in(working_dir)
            .args(["remote", "set-url", name, url])
            .output()?;
        if !set.status.success() {
            anyhow::bail!(
                "failed to update git remote {}: {}",
                name,
                String::from_utf8_lossy(&set.stderr).trim()
            );
        }
        return Ok(());
    }

    let add = kin_git::test_support::fixture_git_in(working_dir)
        .args(["remote", "add", name, url])
        .output()?;
    if !add.status.success() {
        anyhow::bail!(
            "failed to add git remote {}: {}",
            name,
            String::from_utf8_lossy(&add.stderr).trim()
        );
    }
    Ok(())
}

/// One explicitly configured Kin remote.
#[derive(Debug, Serialize)]
pub struct RemoteEntry {
    pub name: String,
    pub host: String,
    pub transport: String,
    pub default: bool,
    pub url: Option<String>,
}

/// One Git coexistence remote sealed from repository-local Git config.
#[derive(Debug, Serialize)]
pub struct SealedGitRemoteEntry {
    pub name: String,
    pub host: String,
    pub transport: String,
    pub url: Option<String>,
}

/// `count` counts `remotes` alone, never the two lists summed.
///
/// The sealed list is a different kind of thing: those remotes were read out of
/// Git rather than configured in Kin, and a single total would let a caller
/// report configured remotes that do not exist. Its length is its own count.
///
/// Both arrays are always emitted. The text path shows sealed remotes only when
/// no explicit remote is configured, which is a display choice about what is
/// worth crowding a terminal with; a machine surface that dropped them would be
/// hiding state the repository actually holds.
#[derive(Debug, Serialize)]
pub struct RemoteListJson {
    pub schema: &'static str,
    pub count: usize,
    pub remotes: Vec<RemoteEntry>,
    pub sealed_git_remotes: Vec<SealedGitRemoteEntry>,
}

fn collect_remotes(config: &KinConfig) -> Vec<RemoteEntry> {
    config
        .remote
        .refs
        .iter()
        .map(|remote| RemoteEntry {
            name: remote.name.clone(),
            host: remote.host.to_string(),
            transport: remote.transport.to_string(),
            default: config.remote.default.as_deref() == Some(remote.name.as_str()),
            url: remote.url.clone(),
        })
        .collect()
}

fn collect_sealed_git_remotes(config: &KinConfig) -> Vec<SealedGitRemoteEntry> {
    config
        .git
        .remotes
        .iter()
        .map(|sealed| SealedGitRemoteEntry {
            name: sealed.name.clone(),
            host: sealed.host_kind().to_string(),
            transport: RemoteTransportKind::GitExport.to_string(),
            url: sealed.publish_url().map(str::to_string),
        })
        .collect()
}

pub async fn list(json: bool) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    let config = KinConfig::load_or_default(&layout.config_path())?;

    if json {
        let remotes = collect_remotes(&config);
        let payload = RemoteListJson {
            schema: REMOTE_LIST_SCHEMA,
            count: remotes.len(),
            remotes,
            sealed_git_remotes: collect_sealed_git_remotes(&config),
        };
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    if config.remote.refs.is_empty() {
        println!("No explicit Kin remotes configured.");
    } else {
        println!(
            "{:<12}  {:<10}  {:<12}  {:<7}  URL",
            "REMOTE", "HOST", "TRANSPORT", "DEFAULT"
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

    if config.remote.refs.is_empty() && !config.git.remotes.is_empty() {
        println!("\nSealed Git coexistence remotes:");
        for sealed in &config.git.remotes {
            println!(
                "  {} -> {} ({}, {})",
                sealed.name,
                sealed.publish_url().unwrap_or("-"),
                sealed.host_kind(),
                RemoteTransportKind::GitExport
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
    let layout = crate::commands::require_repository_layout()?;
    let host = RemoteHostKind::from_str(&host).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown remote host '{}'; expected github, gitlab, bitbucket, or kinlab",
            host
        )
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

    upsert_remote_config(&layout, entry, default)?;

    let config = KinConfig::load_or_default(&layout.config_path())?;
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

pub async fn lease(
    remote: Option<String>,
    actor_id: Option<String>,
    ttl_seconds: Option<u64>,
    json: bool,
) -> Result<()> {
    let plan = load_push_plan(remote.as_deref()).await?;
    if plan.remote.transport != RemoteTransportKind::NativeKin {
        anyhow::bail!(
            "repo session leases require a native Kin remote. Configure one with `kin remote add <name> --host kinlab --transport native-kin --url kinlab://<org>/<repo>`."
        );
    }

    let target = resolve_native_remote_target(
        plan.remote.url.as_deref(),
        &plan.organization_id,
        &plan.repo_id,
    )?;
    if native_remote_bearer_token(&target.base_url).is_none() {
        anyhow::bail!(
            "no KinLab auth token available for {}. Run `kin auth login --base-url {}` or set KIN_REMOTE_BEARER_TOKEN.",
            target.base_url,
            target.base_url
        );
    }

    let actor_id = actor_id.unwrap_or_else(|| default_cli_actor_id(&target.base_url));
    let lease = request_repo_session_lease(
        &target,
        &actor_id,
        SessionTransport::Cli,
        Some(default_cli_session_capabilities()),
        ttl_seconds,
    )
    .await?;

    if json {
        println!("{}", serde_json::to_string_pretty(&lease)?);
    } else {
        println!("Remote: {}", plan.remote.name);
        println!("Lease session: {}", lease.session_id);
        println!("Actor: {}", lease.actor.actor_id);
        println!(
            "Graph: {}/{}/{}",
            lease.graph.authority, lease.graph.organization_id, lease.graph.repo_id
        );
        println!("Transport: {:?}", lease.transport);
        println!("Expires: {}", lease.expires_at);
        println!(
            "Capabilities: read={} write={} exec={} branch={} commit={} max_intents={}",
            lease.capabilities.can_read,
            lease.capabilities.can_write,
            lease.capabilities.can_execute,
            lease.capabilities.can_branch,
            lease.capabilities.can_commit,
            lease.capabilities.max_concurrent_intents,
        );
    }

    Ok(())
}

pub(crate) async fn load_push_plan(requested_remote: Option<&str>) -> Result<PushPlanContext> {
    let layout = crate::commands::require_repository_layout()?;
    let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout)?;
    let config = KinConfig::load_or_default(&layout.config_path())?;

    let snap =
        crate::backend::open_snapshot_explicit_admin_read_only(&layout, "kin remote").await?;
    let graph = &*snap.graph();
    let authority =
        crate::commands::repository_authority::ActiveRepositoryAuthority::open(&binding)?;
    let workspace = authority.workspace()?;
    let branch_name = match &workspace.head {
        kin_model::WorkspaceHead::Symbolic { target } => target.to_string(),
        kin_model::WorkspaceHead::Detached { .. } => "(detached)".to_string(),
    };
    let current_branch = workspace_branch_short_name(&workspace.head);

    let remote = resolve_remote(&config, requested_remote, current_branch.as_deref())?;
    let fallback_org_id = std::env::var("KIN_ORG_ID")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| "kin-open-core".to_string());
    let fallback_repo_id = std::env::var("KIN_REPO_ID")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| binding.repository_id().as_str().to_string());
    let native_target = if remote.transport == RemoteTransportKind::NativeKin {
        Some(resolve_native_remote_target(
            remote.url.as_deref(),
            &fallback_org_id,
            &fallback_repo_id,
        )?)
    } else {
        None
    };
    let organization_id = native_target
        .as_ref()
        .map(|target| target.organization_id.clone())
        .unwrap_or_else(|| fallback_org_id.clone());
    let repo_id = native_target
        .as_ref()
        .map(|target| target.repo_id.clone())
        .unwrap_or_else(|| fallback_repo_id.clone());

    let (local_head, approved, semantic_state_note) =
        if let Some(head) = authority.current_change_id()? {
            let approvals = graph.get_approvals_for_change(&head)?;
            let approved = approvals
                .iter()
                .any(|approval| approval.decision == ApprovalDecision::Approved);
            (Some(head.to_string()), approved, None)
        } else {
            (
            None,
            false,
            Some(
                "This workspace has no commits yet, so there is no semantic change to publish; \
                 make one with `kin commit`."
                    .to_string(),
            ),
        )
        };

    let (remote_head, remote_state_note) = if let Some(target) = native_target.as_ref() {
        let status = fetch_native_remote_status(target, &remote.name).await?;
        (status.remote_head, None)
    } else {
        (None, None)
    };

    Ok(PushPlanContext {
        remote,
        branch_name,
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
                    println!("Action: updating Kin's Git transport mirror and pushing it.");
                }
                kin_remote::PushDecision::Publish => {
                    println!("Action: Git export transport can be prepared with `kin push`.");
                }
                kin_remote::PushDecision::SemanticStateRequired => {
                    println!("Action: record Kin state with `kin commit` before export.");
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

/// The short branch name sealed Git tracking config is keyed by, taken from the
/// graph-owned workspace head. A detached or non-branch head has no tracking
/// entry and resolves to `None`.
fn workspace_branch_short_name(head: &kin_model::WorkspaceHead) -> Option<String> {
    let kin_model::WorkspaceHead::Symbolic { target } = head else {
        return None;
    };
    if !target.is_branch() {
        return None;
    }
    target
        .as_utf8()
        .and_then(|name| name.strip_prefix("refs/heads/"))
        .filter(|name| !name.is_empty())
        .map(str::to_string)
}

fn resolve_remote(
    config: &KinConfig,
    requested: Option<&str>,
    current_branch: Option<&str>,
) -> Result<RemoteRefConfig> {
    if let Some(remote) = config.resolve_remote(requested) {
        return Ok(remote.clone());
    }

    let sealed = match requested {
        Some(name) => config
            .git
            .remotes
            .iter()
            .find(|remote| remote.name == name)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no Kin remote or sealed Git remote named '{name}'. Configure one with `kin remote add {name} --host <host> --transport git-export --url <url>`."
                )
            })?,
        None => config
            .git
            .publish_remote_for_branch(current_branch)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "no Kin remote is configured and sealed Git coexistence config designates no publish remote{}. Configure one with `kin remote add <name> --host <host> --transport git-export --url <url> --default`.",
                    current_branch
                        .map(|branch| format!(" for branch '{branch}'"))
                        .unwrap_or_default()
                )
            })?,
    };

    sealed_git_remote_ref(sealed).ok_or_else(|| {
        anyhow::anyhow!(
            "sealed Git remote '{}' carries no transport URL, so there is nothing to publish through.",
            sealed.name
        )
    })
}

/// Map one sealed, credential-free Git remote onto the compatibility remote
/// the push planner consumes. Sealed config is validated on load, so a URL that
/// reaches here already carries no credentials or userinfo.
fn sealed_git_remote_ref(sealed: &GitRemoteTransportConfig) -> Option<RemoteRefConfig> {
    Some(RemoteRefConfig {
        name: sealed.name.clone(),
        host: sealed.host_kind(),
        transport: RemoteTransportKind::GitExport,
        url: Some(sealed.publish_url()?.to_string()),
        publish_review_state: false,
        publish_proofs: false,
    })
}

pub(crate) fn resolve_repo_id(layout: &KinLayout) -> Result<String> {
    let explicit_repo_id = std::env::var("KIN_REPO_ID").ok();
    Ok(kin_core::manifest::resolve_repo_id(
        layout,
        explicit_repo_id.as_deref(),
    )?)
}

fn map_to_remote_ref(remote: &RemoteRefConfig) -> kin_remote::RemoteRef {
    kin_remote::RemoteRef {
        name: remote.name.clone(),
        host: match remote.host {
            RemoteHostKind::GitHub => kin_remote::HostKind::GitHub,
            RemoteHostKind::GitLab => kin_remote::HostKind::GitLab,
            RemoteHostKind::Bitbucket => kin_remote::HostKind::Bitbucket,
            RemoteHostKind::KinLab => kin_remote::HostKind::KinLab,
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

fn native_remote_endpoint(target: &NativeRemoteTarget, remote_name: &str) -> String {
    target.remote_endpoint(remote_name)
}

async fn fetch_native_remote_status(
    target: &NativeRemoteTarget,
    remote_name: &str,
) -> Result<NativeRemoteStatus> {
    let response = attach_native_remote_auth(
        reqwest::Client::new().get(native_remote_endpoint(target, remote_name)),
        &target.base_url,
    )
    .send()
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

fn format_push_decision(decision: &kin_remote::PushDecision) -> &'static str {
    match decision {
        kin_remote::PushDecision::Publish => "publish",
        kin_remote::PushDecision::FastForwardRequired => "fast-forward-required",
        kin_remote::PushDecision::ApprovalRequired => "approval-required",
        kin_remote::PushDecision::SemanticStateRequired => "semantic-state-required",
    }
}

pub async fn sessions(remote: Option<String>, json: bool) -> Result<()> {
    let plan = load_push_plan(remote.as_deref()).await?;
    if plan.remote.transport != RemoteTransportKind::NativeKin {
        anyhow::bail!(
            "hosted session visibility requires a native Kin remote. Configure one with `kin remote add <name> --host kinlab --transport native-kin --url kinlab://<org>/<repo>`."
        );
    }

    let target = resolve_native_remote_target(
        plan.remote.url.as_deref(),
        &plan.organization_id,
        &plan.repo_id,
    )?;
    if native_remote_bearer_token(&target.base_url).is_none() {
        anyhow::bail!(
            "no KinLab auth token available for {}. Run `kin auth login --base-url {}` or set KIN_REMOTE_BEARER_TOKEN.",
            target.base_url,
            target.base_url
        );
    }

    let response = attach_native_remote_auth(
        reqwest::Client::new().get(target.sessions_endpoint()),
        &target.base_url,
    )
    .send()
    .await?;
    let status = response.status();
    let payload = response.text().await?;
    if !status.is_success() {
        anyhow::bail!(
            "failed to fetch hosted repo sessions: {} {}",
            status,
            payload.trim()
        );
    }

    let sessions = serde_json::from_str::<RepoSessionsResponse>(&payload)?.sessions;
    if json {
        println!("{}", serde_json::to_string_pretty(&sessions)?);
        return Ok(());
    }

    println!("Remote: {}", plan.remote.name);
    println!("Active hosted sessions: {}", sessions.len());
    for session in sessions {
        println!(
            "- {} ({:?}) expires {}",
            session.actor.actor_id, session.transport, session.expires_at
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::upsert_remote_config;
    use super::{
        ensure_git_remote, evaluate_push_plan, explicit_native_remote_target, format_push_decision,
        map_to_remote_ref, native_remote_endpoint, resolve_native_remote_bearer_token_with,
        resolve_native_remote_target, resolve_remote, workspace_branch_short_name,
        NativeRemoteTarget, PushPlanContext,
    };
    use kin_core::{
        GitBranchTrackingConfig, GitRemoteTransportConfig, KinConfig, RemoteHostKind,
        RemoteRefConfig, RemoteTransportKind,
    };

    fn test_remote(name: &str) -> RemoteRefConfig {
        RemoteRefConfig {
            name: name.to_string(),
            host: RemoteHostKind::KinLab,
            transport: RemoteTransportKind::NativeKin,
            url: Some(format!("kinlab://test/{name}")),
            publish_review_state: true,
            publish_proofs: true,
        }
    }

    fn sealed_remote(name: &str, url: &str) -> GitRemoteTransportConfig {
        GitRemoteTransportConfig {
            name: name.to_string(),
            fetch_urls: vec![url.to_string()],
            push_urls: Vec::new(),
            fetch_refspecs: vec![format!("+refs/heads/*:refs/remotes/{name}/*")],
            push_refspecs: Vec::new(),
        }
    }

    /// `count` describes `remotes` alone.
    ///
    /// Summing the two lists would report configured Kin remotes that were
    /// never configured, so this asserts the count against a config where the
    /// two lengths differ. Were `count` the sum, it would read 3 here.
    #[test]
    fn the_json_count_describes_the_configured_remotes_alone() {
        let mut config = KinConfig::default();
        config.remote.refs = vec![test_remote("origin")];
        config.remote.default = Some("origin".to_string());
        config.git.remotes = vec![
            sealed_remote("upstream", "https://github.invalid/acme/app.git"),
            sealed_remote("mirror", "https://gitlab.invalid/acme/mirror.git"),
        ];

        let remotes = super::collect_remotes(&config);
        let payload = super::RemoteListJson {
            schema: super::REMOTE_LIST_SCHEMA,
            count: remotes.len(),
            remotes,
            sealed_git_remotes: super::collect_sealed_git_remotes(&config),
        };
        let value = serde_json::to_value(&payload).unwrap();

        assert_eq!(value["schema"], super::REMOTE_LIST_SCHEMA);
        assert_eq!(value["count"].as_u64().unwrap(), 1);
        assert_eq!(value["remotes"].as_array().unwrap().len(), 1);
        assert_eq!(value["sealed_git_remotes"].as_array().unwrap().len(), 2);
        assert_eq!(
            value["count"].as_u64().unwrap() as usize,
            value["remotes"].as_array().unwrap().len(),
            "count must track the remotes array, never the two lists summed"
        );
    }

    /// Sealed Git remotes are emitted even when an explicit remote exists.
    ///
    /// The text path shows them only when no explicit remote is configured.
    /// That is a choice about crowding a terminal, and a machine surface that
    /// copied it would drop state the repository actually holds, invisibly.
    #[test]
    fn sealed_git_remotes_survive_an_explicit_remote_being_configured() {
        let mut config = KinConfig::default();
        config.remote.refs = vec![test_remote("origin")];
        config.git.remotes = vec![sealed_remote(
            "upstream",
            "https://github.invalid/acme/app.git",
        )];

        let sealed = super::collect_sealed_git_remotes(&config);
        assert_eq!(sealed.len(), 1);
        assert_eq!(sealed[0].name, "upstream");
        assert_eq!(
            sealed[0].url.as_deref(),
            Some("https://github.invalid/acme/app.git")
        );
        assert_eq!(
            sealed[0].transport,
            RemoteTransportKind::GitExport.to_string()
        );
        assert_eq!(sealed[0].host, RemoteHostKind::GitHub.to_string());

        // The control: with no sealed remotes the list is empty, so the
        // assertions above distinguish presence from a list that is always full.
        config.git.remotes.clear();
        assert!(super::collect_sealed_git_remotes(&config).is_empty());
    }

    /// The default flag marks exactly the configured default, and nothing else.
    #[test]
    fn exactly_the_default_remote_is_flagged_default() {
        let mut config = KinConfig::default();
        config.remote.refs = vec![test_remote("origin"), test_remote("backup")];
        config.remote.default = Some("backup".to_string());

        let remotes = super::collect_remotes(&config);
        let flagged: Vec<&str> = remotes
            .iter()
            .filter(|remote| remote.default)
            .map(|remote| remote.name.as_str())
            .collect();
        assert_eq!(flagged, vec!["backup"]);

        // With no default configured nothing is flagged, so the assertion above
        // is about the configured value rather than about position in the list.
        config.remote.default = None;
        assert!(super::collect_remotes(&config)
            .iter()
            .all(|remote| !remote.default));
    }

    #[cfg(unix)]
    #[test]
    fn blocked_remote_writer_cannot_bind_a_replacement_kin_epoch() {
        let outer = tempfile::tempdir().unwrap();
        let repository = outer.path().join("repository");
        std::fs::create_dir(&repository).unwrap();
        let initialized = kin_core::init(&repository).unwrap();
        let layout = initialized.layout.clone();
        let freeze = kin_core::ExactProjectionFreeze::acquire_existing(&repository).unwrap();

        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();
        let writer_layout = layout.clone();
        let writer = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            finished_tx
                .send(upsert_remote_config(
                    &writer_layout,
                    test_remote("stale-writer"),
                    true,
                ))
                .unwrap();
        });
        started_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        assert!(
            finished_rx
                .recv_timeout(std::time::Duration::from_millis(500))
                .is_err(),
            "remote config writer must wait behind the held projection freeze"
        );

        let detached = outer.path().join("detached-kin");
        std::fs::rename(layout.root(), &detached).unwrap();
        let replacement = kin_core::init(&repository).unwrap();
        let replacement_config_before = std::fs::read(replacement.layout.config_path()).unwrap();
        let detached_config_before = std::fs::read(detached.join("config.toml")).unwrap();

        drop(freeze);
        let error = finished_rx
            .recv_timeout(std::time::Duration::from_secs(2))
            .expect("blocked remote writer must wake after projection freeze release")
            .expect_err("stale remote writer must reject the replacement Kin epoch");
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("replaced")
                || rendered.contains("changed identity")
                || rendered.contains("unavailable"),
            "unexpected stale remote-writer error: {rendered}"
        );
        writer.join().unwrap();

        assert_eq!(
            std::fs::read(replacement.layout.config_path()).unwrap(),
            replacement_config_before,
            "stale writer must not mutate replacement repository config"
        );
        assert_eq!(
            std::fs::read(detached.join("config.toml")).unwrap(),
            detached_config_before,
            "stale writer must not mutate detached repository config"
        );
        assert!(
            KinConfig::load(&replacement.layout.config_path())
                .unwrap()
                .remote
                .refs
                .is_empty(),
            "replacement repository must not inherit the stale remote update"
        );
    }

    #[test]
    fn remote_resolution_fails_closed_without_sealed_git_config() {
        let config = KinConfig::default();
        assert!(config.remote.refs.is_empty());
        assert!(config.git.remotes.is_empty());

        let error = resolve_remote(&config, None, Some("main"))
            .expect_err("resolution must fail closed rather than read a remote out of Git");
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("sealed Git coexistence config designates no publish remote"),
            "unexpected fail-closed error: {rendered}"
        );
        assert!(
            !rendered.contains("origin"),
            "fail-closed resolution must not name a conventional remote: {rendered}"
        );
    }

    #[test]
    fn sealed_branch_tracking_selects_the_publish_remote() {
        let mut config = KinConfig::default();
        config.git.remotes = vec![
            sealed_remote("origin", "https://github.invalid/acme/mirror.git"),
            sealed_remote("release", "https://gitlab.invalid/acme/app.git"),
        ];
        config.git.branches = vec![GitBranchTrackingConfig {
            branch: "main".into(),
            remote: Some("origin".into()),
            merge_refs: vec!["refs/heads/main".into()],
            push_remote: Some("release".into()),
        }];
        config.validate().expect("sealed fixture must validate");

        let resolved =
            resolve_remote(&config, None, Some("main")).expect("sealed tracking must resolve");
        assert_eq!(resolved.name, "release");
        assert_eq!(
            resolved.url.as_deref(),
            Some("https://gitlab.invalid/acme/app.git")
        );
        assert_eq!(resolved.host, RemoteHostKind::GitLab);
        assert_eq!(resolved.transport, RemoteTransportKind::GitExport);
    }

    #[test]
    fn untracked_branch_falls_back_to_the_sealed_push_default() {
        let mut config = KinConfig::default();
        config.git.remotes = vec![
            sealed_remote("origin", "https://github.invalid/acme/mirror.git"),
            sealed_remote("release", "https://bitbucket.invalid/acme/app.git"),
        ];
        config.git.remote_push_default = Some("release".into());
        config.validate().expect("sealed fixture must validate");

        let resolved = resolve_remote(&config, None, Some("feature/unpublished"))
            .expect("push default must resolve for an untracked branch");
        assert_eq!(resolved.name, "release");
        assert_eq!(resolved.host, RemoteHostKind::Bitbucket);
    }

    #[test]
    fn a_branch_publishing_to_the_local_repository_resolves_no_remote() {
        let mut config = KinConfig::default();
        config.git.remotes = vec![sealed_remote(
            "origin",
            "https://github.invalid/acme/app.git",
        )];
        config.git.branches = vec![GitBranchTrackingConfig {
            branch: "main".into(),
            remote: Some(".".into()),
            merge_refs: vec!["refs/heads/main".into()],
            push_remote: None,
        }];
        config.validate().expect("sealed fixture must validate");

        resolve_remote(&config, None, Some("main"))
            .expect_err("a branch tracking the local repository names no transport remote");
    }

    #[test]
    fn a_single_sealed_remote_resolves_without_a_conventional_name() {
        let mut config = KinConfig::default();
        config.git.remotes = vec![sealed_remote(
            "upstream",
            "https://git.acme.invalid/acme/app.git",
        )];
        config.validate().expect("sealed fixture must validate");

        let resolved = resolve_remote(&config, None, Some("main"))
            .expect("an unambiguous sealed remote must resolve");
        assert_eq!(resolved.name, "upstream");
    }

    #[test]
    fn ambiguous_sealed_remotes_fail_closed() {
        let mut config = KinConfig::default();
        config.git.remotes = vec![
            sealed_remote("origin", "https://github.invalid/acme/app.git"),
            sealed_remote("upstream", "https://github.invalid/acme/fork.git"),
        ];
        config.validate().expect("sealed fixture must validate");

        resolve_remote(&config, None, Some("main"))
            .expect_err("two sealed remotes with no tracking must not pick one by convention");
    }

    #[test]
    fn requested_remote_resolves_against_sealed_config() {
        let mut config = KinConfig::default();
        config.git.remotes = vec![sealed_remote("release", "https://kinlab.ai/acme/app.git")];
        config.validate().expect("sealed fixture must validate");

        let resolved = resolve_remote(&config, Some("release"), None)
            .expect("an explicitly requested sealed remote must resolve");
        assert_eq!(resolved.name, "release");
        assert_eq!(resolved.host, RemoteHostKind::KinLab);

        let error = resolve_remote(&config, Some("absent"), None)
            .expect_err("an unknown remote name must fail closed");
        assert!(
            format!("{error:#}").contains("no Kin remote or sealed Git remote named 'absent'"),
            "unexpected unknown-remote error"
        );
    }

    #[test]
    fn a_sealed_remote_without_a_transport_url_fails_closed() {
        let mut config = KinConfig::default();
        config.git.remotes = vec![GitRemoteTransportConfig {
            name: "archive".into(),
            fetch_urls: Vec::new(),
            push_urls: Vec::new(),
            fetch_refspecs: Vec::new(),
            push_refspecs: Vec::new(),
        }];
        config.validate().expect("sealed fixture must validate");

        let error = resolve_remote(&config, None, None)
            .expect_err("a sealed remote with no URL has nothing to publish through");
        assert!(
            format!("{error:#}").contains("carries no transport URL"),
            "unexpected empty-transport error"
        );
    }

    #[test]
    fn sealed_push_urls_win_over_fetch_urls() {
        let mut config = KinConfig::default();
        config.git.remotes = vec![GitRemoteTransportConfig {
            name: "release".into(),
            fetch_urls: vec!["https://github.invalid/acme/read-only.git".into()],
            push_urls: vec!["https://gitlab.invalid/acme/write.git".into()],
            fetch_refspecs: Vec::new(),
            push_refspecs: Vec::new(),
        }];
        config.validate().expect("sealed fixture must validate");

        let resolved =
            resolve_remote(&config, None, None).expect("the sole sealed remote must resolve");
        assert_eq!(
            resolved.url.as_deref(),
            Some("https://gitlab.invalid/acme/write.git")
        );
        assert_eq!(resolved.host, RemoteHostKind::GitLab);
    }

    #[test]
    fn configured_kin_remotes_outrank_sealed_git_remotes() {
        let mut config = KinConfig::default();
        config.remote.refs = vec![test_remote("hosted")];
        config.remote.default = Some("hosted".into());
        config.git.remotes = vec![sealed_remote(
            "origin",
            "https://github.invalid/acme/app.git",
        )];
        config.validate().expect("sealed fixture must validate");

        let resolved = resolve_remote(&config, None, Some("main"))
            .expect("an explicit Kin remote must resolve first");
        assert_eq!(resolved.name, "hosted");
        assert_eq!(resolved.transport, RemoteTransportKind::NativeKin);
    }

    #[test]
    fn workspace_head_supplies_the_short_tracking_branch_name() {
        let branch = kin_model::WorkspaceHead::Symbolic {
            target: kin_model::RefName::branch("feature/publish").unwrap(),
        };
        assert_eq!(
            workspace_branch_short_name(&branch).as_deref(),
            Some("feature/publish")
        );

        let tag = kin_model::WorkspaceHead::Symbolic {
            target: kin_model::RefName::tag("v1").unwrap(),
        };
        assert_eq!(workspace_branch_short_name(&tag), None);
    }

    #[test]
    fn maps_config_remote_to_runtime_remote() {
        let runtime = map_to_remote_ref(&RemoteRefConfig {
            name: "origin".into(),
            host: RemoteHostKind::KinLab,
            transport: RemoteTransportKind::NativeKin,
            url: Some("kinlab://demo/kin".into()),
            publish_review_state: true,
            publish_proofs: true,
        });

        assert!(matches!(runtime.host, kin_remote::HostKind::KinLab));
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
                host: RemoteHostKind::KinLab,
                transport: RemoteTransportKind::NativeKin,
                url: Some("http://127.0.0.1:4010/api/orgs/kin-open-core/repos/kin".into()),
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
        let target = NativeRemoteTarget {
            base_url: "http://127.0.0.1:4010".into(),
            organization_id: "kin-open-core".into(),
            repo_id: "kin".into(),
        };
        assert_eq!(
            native_remote_endpoint(&target, "origin"),
            "http://127.0.0.1:4010/api/orgs/kin-open-core/repos/kin/remotes/origin"
        );
    }

    #[test]
    fn resolve_native_remote_target_extracts_repo_locator() {
        let target = resolve_native_remote_target(
            Some("http://127.0.0.1:4010/api/orgs/demo/repos/kin"),
            "ignored-org",
            "ignored-repo",
        )
        .unwrap();

        assert_eq!(target.base_url, "http://127.0.0.1:4010");
        assert_eq!(target.organization_id, "demo");
        assert_eq!(target.repo_id, "kin");
        assert_eq!(
            target.git_projection_url(),
            "http://127.0.0.1:4010/demo/kin.git"
        );
    }

    #[test]
    fn explicit_native_remote_target_supports_kinlab_scheme() {
        let target = explicit_native_remote_target("kinlab://demo/kin").unwrap();
        assert_eq!(target.organization_id, "demo");
        assert_eq!(target.repo_id, "kin");
    }

    #[test]
    fn explicit_native_remote_target_supports_apex_git_url() {
        let target = explicit_native_remote_target("https://kinlab.ai/demo/kin.git").unwrap();
        assert_eq!(target.base_url, "https://kinlab.ai");
        assert_eq!(target.organization_id, "demo");
        assert_eq!(target.repo_id, "kin");
        assert_eq!(
            target.repo_locator(),
            "https://kinlab.ai/api/orgs/demo/repos/kin"
        );
    }

    #[test]
    fn explicit_native_remote_target_supports_apex_url_without_git_suffix() {
        let target = explicit_native_remote_target("https://kinlab.ai/demo/kin").unwrap();
        assert_eq!(target.base_url, "https://kinlab.ai");
        assert_eq!(target.organization_id, "demo");
        assert_eq!(target.repo_id, "kin");
        assert_eq!(
            target.repo_locator(),
            "https://kinlab.ai/api/orgs/demo/repos/kin"
        );
    }

    #[test]
    fn native_remote_bearer_token_prefers_explicit_remote_token() {
        let token = resolve_native_remote_bearer_token_with(|key| match key {
            "KIN_REMOTE_BEARER_TOKEN" => Some("primary-token".to_string()),
            "KIN_REMOTE_AUTH_TOKEN" => Some("secondary-token".to_string()),
            "KINLAB_TOKEN" => Some("fallback-token".to_string()),
            _ => None,
        });

        assert_eq!(token.as_deref(), Some("primary-token"));
    }

    #[test]
    fn native_remote_bearer_token_falls_back_to_legacy_env_names() {
        let token = resolve_native_remote_bearer_token_with(|key| match key {
            "KIN_REMOTE_BEARER_TOKEN" => None,
            "KIN_REMOTE_AUTH_TOKEN" => Some("secondary-token".to_string()),
            "KINLAB_TOKEN" => Some("fallback-token".to_string()),
            _ => None,
        });

        assert_eq!(token.as_deref(), Some("secondary-token"));
    }

    #[test]
    fn ensure_git_remote_adds_origin_when_missing() {
        let dir = tempfile::tempdir().unwrap();
        kin_git::test_support::fixture_git_in(dir.path())
            .args(["init"])
            .output()
            .unwrap();

        ensure_git_remote(dir.path(), "origin", Some("https://example.com/repo.git")).unwrap();

        let output = kin_git::test_support::fixture_git_in(dir.path())
            .args(["remote", "get-url", "origin"])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "https://example.com/repo.git"
        );
    }

    #[test]
    fn ensure_git_remote_updates_existing_url() {
        let dir = tempfile::tempdir().unwrap();
        kin_git::test_support::fixture_git_in(dir.path())
            .args(["init"])
            .output()
            .unwrap();
        kin_git::test_support::fixture_git_in(dir.path())
            .args(["remote", "add", "origin", "https://example.com/old.git"])
            .output()
            .unwrap();

        ensure_git_remote(dir.path(), "origin", Some("https://example.com/new.git")).unwrap();

        let output = kin_git::test_support::fixture_git_in(dir.path())
            .args(["remote", "get-url", "origin"])
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "https://example.com/new.git"
        );
    }
}
