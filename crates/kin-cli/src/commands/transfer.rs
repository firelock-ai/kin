// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin push`, `kin pull`, and `kin remote plan-push` over exact
//! repository-v6 transfer.
//!
//! The negotiation itself runs in the daemon, not here. The daemon holds this
//! replica's repository authority and every view derived from it, so a pull has
//! to publish and refresh on one path. A CLI that admitted a pack on its own
//! would leave the daemon serving a graph that no longer matches authority.
//!
//! This module resolves what the operator meant (which peer, which ref), hands
//! that to the daemon, and renders the outcome. It never decides what either
//! replica holds.

use anyhow::{bail, Context, Result};
use kin_core::{KinConfig, KinLayout, RemoteTransportKind};
use kin_model::RefName;
use kin_remote::repository_transfer_negotiation::{
    RepositoryPushPlan, RepositoryTransferDirection, RepositoryTransferOutcome,
    RepositoryTransferPlan,
};
use serde::{Deserialize, Serialize};

/// One negotiated transfer, as asked for by the CLI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandTransferRequest {
    /// Base URL of the peer's repository-v6 transfer seam.
    pub remote_base_url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_token: Option<String>,
    /// Defaults to the repository this daemon serves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_id: Option<String>,
    /// Defaults to the local default ref.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_ref: Option<RefName>,
    /// Defaults to `source_ref`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_ref: Option<RefName>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandTransferResponse {
    pub outcome: RepositoryTransferOutcome,
}

/// A negotiated plan that moved nothing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandTransferPlanResponse {
    pub repository_id: String,
    pub source_ref: RefName,
    pub destination_ref: RefName,
    pub remote_base_url: String,
    pub plan: RepositoryPushPlan,
}

/// Where the peer's transfer seam lives, and how to authenticate to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TransferPeer {
    pub(crate) base_url: String,
    pub(crate) token: Option<String>,
}

/// Resolve the peer from an explicit URL or a configured native-Kin remote.
///
/// This fails closed rather than guessing a host. A transfer publishes exact
/// repository history; sending it to a default endpoint nobody named is not a
/// convenience.
pub(crate) fn resolve_peer(
    layout: &KinLayout,
    requested_remote: Option<&str>,
    explicit_url: Option<&str>,
) -> Result<TransferPeer> {
    if let Some(url) = explicit_url.map(str::trim).filter(|url| !url.is_empty()) {
        return Ok(TransferPeer {
            base_url: url.trim_end_matches('/').to_string(),
            token: crate::commands::remote::native_remote_bearer_token(url),
        });
    }

    let config = KinConfig::load_or_default(&layout.config_path())
        .context("load repository remote configuration")?;
    let native = config
        .remote
        .refs
        .iter()
        .filter(|remote| remote.transport == RemoteTransportKind::NativeKin)
        .collect::<Vec<_>>();
    let requested_remote = requested_remote.or(config.remote.default.as_deref());
    let selected = match requested_remote {
        Some(name) => native
            .iter()
            .find(|remote| remote.name == name)
            .copied()
            .with_context(|| {
                format!("no native-kin remote named {name} is configured for this repository")
            })?,
        None => match native.as_slice() {
            [] => bail!(
                "no native-kin remote is configured. Add one with `kin remote add <name> --transport native-kin --url <base-url>`, or pass `--url`."
            ),
            [only] => only,
            many => bail!(
                "{} native-kin remotes are configured ({}); name one with `--remote`.",
                many.len(),
                many.iter()
                    .map(|remote| remote.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        },
    };

    let base_url = selected
        .url
        .as_deref()
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .with_context(|| {
            format!(
                "native-kin remote {} has no transport URL; re-add it with `--url <base-url>`",
                selected.name
            )
        })?;
    let base_url = base_url.trim_end_matches('/').to_string();
    Ok(TransferPeer {
        token: crate::commands::remote::native_remote_bearer_token(&base_url),
        base_url,
    })
}

fn parse_ref(value: Option<&str>) -> Result<Option<RefName>> {
    let Some(value) = value.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    let full = if value.starts_with("refs/") {
        value.as_bytes().to_vec()
    } else {
        format!("refs/heads/{value}").into_bytes()
    };
    RefName::from_bytes(full)
        .map(Some)
        .map_err(|error| anyhow::anyhow!("invalid ref {value}: {error}"))
}

fn layout() -> Result<KinLayout> {
    KinLayout::discover(&std::env::current_dir()?).ok_or_else(|| {
        anyhow::anyhow!(
            "not a Kin repository (no .kin/ found)\nhint: run `kin init .` to initialize one"
        )
    })
}

async fn daemon() -> Result<crate::daemon_client::DaemonClient> {
    crate::daemon_client::DaemonClient::try_connect()
        .await
        .context(
            "no Kin daemon is reachable. Repository authority and every view derived from it live in the daemon, so a transfer must run there.",
        )
}

fn build_request(
    peer: TransferPeer,
    reference: Option<&str>,
    destination: Option<&str>,
) -> Result<CommandTransferRequest> {
    let source_ref = parse_ref(reference)?;
    let destination_ref = parse_ref(destination)?.or_else(|| source_ref.clone());
    Ok(CommandTransferRequest {
        remote_base_url: peer.base_url,
        remote_token: peer.token,
        repository_id: None,
        source_ref,
        destination_ref,
    })
}

pub async fn push(
    remote: Option<String>,
    url: Option<String>,
    reference: Option<String>,
    json: bool,
) -> Result<()> {
    let layout = layout()?;
    let peer = resolve_peer(&layout, remote.as_deref(), url.as_deref())?;
    let request = build_request(peer, reference.as_deref(), None)?;
    let response = daemon().await?.command_push(&request).await?;
    render_outcome(&response.outcome, json)
}

pub async fn pull(
    remote: Option<String>,
    url: Option<String>,
    reference: Option<String>,
    json: bool,
) -> Result<()> {
    let layout = layout()?;
    let peer = resolve_peer(&layout, remote.as_deref(), url.as_deref())?;
    let request = build_request(peer, reference.as_deref(), None)?;
    let response = daemon().await?.command_pull(&request).await?;
    render_outcome(&response.outcome, json)
}

pub async fn plan_push(
    remote: Option<String>,
    url: Option<String>,
    reference: Option<String>,
    json: bool,
) -> Result<()> {
    let layout = layout()?;
    let peer = resolve_peer(&layout, remote.as_deref(), url.as_deref())?;
    let request = build_request(peer, reference.as_deref(), None)?;
    let plan = daemon().await?.command_transfer_plan(&request).await?;
    if json {
        println!("{}", serde_json::to_string_pretty(&plan)?);
        return Ok(());
    }
    println!("Exact repository-v6 push plan");
    println!("Repository:  {}", plan.repository_id);
    println!("Remote:      {}", plan.remote_base_url);
    println!("Source ref:  {}", plan.source_ref);
    println!("Destination: {}", plan.destination_ref);
    println!("{}", render_plan(&plan.plan.plan));
    if !plan.plan.fits_one_envelope {
        println!(
            "This gap does not fit one transfer envelope (limit {} changes). Transfer v1 has no continuation packs, so a push would be refused at pack build.",
            plan.plan.max_changes_per_envelope
        );
    }
    println!(
        "Nothing was published. This plan describes the two leases as they were read, not a reservation of them."
    );
    Ok(())
}

fn render_plan(plan: &RepositoryTransferPlan) -> String {
    match plan {
        RepositoryTransferPlan::UpToDate { head } => match head {
            Some(head) => format!("Up to date at {head}; nothing to transfer."),
            None => "Up to date: neither replica publishes this ref yet.".to_string(),
        },
        RepositoryTransferPlan::FastForward {
            source_head,
            destination_head,
            change_count,
        } => {
            let from = destination_head
                .map(|head| head.to_string())
                .unwrap_or_else(|| "an unborn ref".to_string());
            let count = change_count
                .map(|count| format!("{count} exact change(s)"))
                .unwrap_or_else(|| "the exact closure".to_string());
            format!("Fast-forward from {from} to {source_head}, moving {count}.")
        }
    }
}

fn render_outcome(outcome: &RepositoryTransferOutcome, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(outcome)?);
        return Ok(());
    }
    let verb = match outcome.direction {
        RepositoryTransferDirection::Push => "Pushed",
        RepositoryTransferDirection::Pull => "Pulled",
    };
    println!("{}", render_plan(&outcome.plan));
    match &outcome.receipt {
        None => println!("{verb} nothing: no repository transaction was published."),
        Some(receipt) => {
            println!(
                "{verb} {} onto {} at {}.",
                outcome.repository_id, outcome.destination_ref, receipt.destination_head
            );
            println!("Transfer:  {}", receipt.transfer_id);
            println!("Outcome:   {:?}", receipt.outcome);
            println!(
                "Authority: generation {}",
                receipt.authority_receipt.generation
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bare_branch_name_resolves_to_its_full_ref() {
        assert_eq!(
            parse_ref(Some("main")).unwrap(),
            Some(RefName::branch(b"main").unwrap())
        );
    }

    #[test]
    fn an_explicit_ref_path_is_carried_through_unchanged() {
        assert_eq!(
            parse_ref(Some("refs/tags/v1")).unwrap(),
            Some(RefName::from_bytes(b"refs/tags/v1".to_vec()).unwrap())
        );
    }

    #[test]
    fn an_absent_or_blank_ref_stays_absent_so_the_daemon_picks_the_default() {
        assert_eq!(parse_ref(None).unwrap(), None);
        assert_eq!(parse_ref(Some("   ")).unwrap(), None);
    }

    #[test]
    fn the_destination_ref_defaults_to_the_source_ref() {
        let peer = TransferPeer {
            base_url: "http://127.0.0.1:4010".to_string(),
            token: None,
        };
        let request = build_request(peer, Some("main"), None).unwrap();
        assert_eq!(request.source_ref, request.destination_ref);
        assert_eq!(request.source_ref, Some(RefName::branch(b"main").unwrap()));
    }

    #[test]
    fn an_explicit_url_wins_over_configuration_and_keeps_no_trailing_slash() {
        // Resolution must not need a repository on disk when the operator named
        // the peer outright.
        let temporary = tempfile::TempDir::new().unwrap();
        let layout = KinLayout::new(temporary.path().to_path_buf());
        let peer = resolve_peer(&layout, None, Some("http://127.0.0.1:4010/")).unwrap();
        assert_eq!(peer.base_url, "http://127.0.0.1:4010");
    }
}
