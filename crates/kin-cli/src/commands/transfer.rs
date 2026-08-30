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
use kin_core::{KinConfig, KinLayout, RemoteHostKind, RemoteTransportKind};
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
    /// The hosted organization whose repository this transfer addresses.
    ///
    /// Absent means a peer daemon, which serves the seam at its own root. A
    /// daemon that predates this field defaults it to absent and so keeps
    /// addressing peers exactly as it did, which is why the absent case has to
    /// stay the daemon route rather than becoming an error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_organization_id: Option<String>,
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

/// What happened to the views a daemon derives from repository authority once
/// a transfer's authority had already moved.
///
/// Repository authority is the truth, and it is durable before anything
/// derived from it is touched. A refresh that fails after that point has not
/// failed the transfer and must not be reported as one, but it does leave
/// retrieval answering from state that is behind the admitted head. This is
/// how that partial success is named instead of being flattened into either a
/// clean success or a server error.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum DerivedViewRefresh {
    /// Everything derived from authority matches the admitted head.
    Current,
    /// Authority moved and is durable; these views did not follow it.
    Stale { detail: String },
}

impl DerivedViewRefresh {
    pub fn is_stale(&self) -> bool {
        matches!(self, Self::Stale { .. })
    }
}

/// Whether the graph-owned workspace followed the head a pull admitted.
///
/// Admitting history and moving the working tree are two repository
/// transactions, not one. The first is what a transfer publishes; the second is
/// the same graph-derived projection `kin branch switch` commits, replanned
/// against the ref the pull just moved. Reporting them separately is what keeps
/// a caller from reading "pulled" as "the files on disk changed" when the
/// workspace could not follow, and from reading a workspace that could not
/// follow as a transfer that did not happen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum WorkspaceFollow {
    /// The responding daemon predates this report, so whether the working tree
    /// followed is unknown. Never produced by this build.
    Unreported,
    /// No local workspace was in a position to follow: the pull admitted no
    /// history so no ref moved, hosted snapshot authority owns no working tree,
    /// or this replica's workspace does not track the ref the pull moved.
    NotApplicable { detail: String },
    /// The workspace already stood at the admitted head, so nothing moved.
    AlreadyCurrent { authority_generation: u64 },
    /// The workspace transitioned to the admitted head in one repository
    /// transaction.
    Advanced {
        detail: String,
        authority_generation: u64,
    },
    /// Repository authority moved and is durable; the workspace did not follow
    /// it, and the working tree still shows the head it had before.
    Behind { detail: String },
}

impl WorkspaceFollow {
    /// True when a working tree that was expected to follow did not.
    pub fn is_behind(&self) -> bool {
        matches!(self, Self::Behind { .. })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandTransferResponse {
    pub outcome: RepositoryTransferOutcome,
    /// Defaulted so a response from a daemon that predates this field reads as
    /// the state it in fact reported: a refresh it never surfaced.
    #[serde(default = "derived_views_current")]
    pub derived_views: DerivedViewRefresh,
    /// Defaulted for the same reason as `derived_views`, to the variant that
    /// says the responding daemon reported nothing rather than one that would
    /// claim a transition nobody observed.
    #[serde(default = "workspace_unreported")]
    pub workspace: WorkspaceFollow,
}

fn derived_views_current() -> DerivedViewRefresh {
    DerivedViewRefresh::Current
}

fn workspace_unreported() -> WorkspaceFollow {
    WorkspaceFollow::Unreported
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
    /// The hosted organization whose repository this transfer addresses.
    ///
    /// `None` is a peer daemon, which serves the seam at its own root and has
    /// no organizations. A hosted remote always resolves to `Some`, because
    /// `resolve_peer` refuses one it cannot name an organization for rather
    /// than addressing it as though it were a daemon.
    pub(crate) organization_id: Option<String>,
}

/// Split a peer URL into the base the seam is served from and the organization
/// it names, if any.
///
/// A locator carries both, and they must be taken together: its base URL is the
/// part before `/api/orgs/...`, so keeping the whole locator as the base and
/// lifting only the organization out of it addresses
/// `<base>/api/orgs/<org>/repos/<repo>/api/v1/orgs/<org>/...`, which is nobody's
/// route. Anything that is not a locator is a peer daemon base with no
/// organization.
pub(crate) fn peer_base_and_organization(url: &str) -> (String, Option<String>) {
    match crate::commands::remote::native_remote_locator(url) {
        Some(target) => (
            target.base_url.trim_end_matches('/').to_string(),
            Some(target.organization_id),
        ),
        None => (url.trim().trim_end_matches('/').to_string(), None),
    }
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
        // An explicit `--url` is taken literally. A locator naming an
        // organization addresses that hosted repository; anything else is a
        // peer daemon, which is what `--url http://127.0.0.1:<port>` has always
        // meant and must keep meaning.
        let (base_url, organization_id) = peer_base_and_organization(url);
        return Ok(TransferPeer {
            token: crate::commands::remote::native_remote_bearer_token(&base_url),
            base_url,
            organization_id,
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
    // A locator names both the base and the organization, so split it here
    // rather than treating the whole locator as a base URL.
    let (base_url, located_organization) = peer_base_and_organization(base_url);

    // A KinLab remote is hosted, and a hosted seam is org scoped. The
    // organization comes from the remote's own locator, or from KIN_ORG_ID, and
    // nowhere else: the server never infers one from a bare repository id, so
    // nothing crosses an organization boundary because a default was convenient
    // (founder decision, 2026-08-29).
    //
    // Refusing beats falling back to the daemon route. That route on a hosted
    // host is outside `/api/`, where kinlab.ai's edge serves the static bucket,
    // and the push dies in Google Cloud Storage XML that names neither Kin nor
    // the organization the user forgot to set (FIR-2945).
    let organization_id = match selected.host {
        RemoteHostKind::KinLab => Some(
            located_organization
                .or_else(|| {
                    std::env::var("KIN_ORG_ID")
                        .ok()
                        .map(|value| value.trim().to_string())
                        .filter(|value| !value.is_empty())
                })
                .with_context(|| {
                    format!(
                        "native-kin remote {} is hosted on KinLab, whose transfer seam is scoped \
                         to an organization, and {base_url} names none. Re-add it with a full \
                         locator like `--url kinlab://<org>/<repo>`, or set KIN_ORG_ID.",
                        selected.name
                    )
                })?,
        ),
        _ => None,
    };

    Ok(TransferPeer {
        token: crate::commands::remote::native_remote_bearer_token(&base_url),
        base_url,
        organization_id,
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
    crate::commands::require_repository_layout()
}

/// The daemon a transfer runs in.
///
/// Repository authority and every view derived from it live in the daemon, so
/// the negotiation happens there rather than here, through the CLI's ordinary
/// resolution. This wrapper carries one thing the shared connector cannot:
/// `command` is the surface the operator typed, so a refusal names `kin push`
/// or `kin pull` rather than a generic transfer, and there are three of them.
///
/// The old path was not resolution at all. It read `KIN_DAEMON_URL`, found
/// nothing when it was unset, and reported "no Kin daemon is reachable" over a
/// daemon that was serving and that `kin doctor` named in the same second
/// (FIR-2936).
async fn daemon(command: &str, layout: &KinLayout) -> Result<crate::daemon_client::DaemonClient> {
    crate::daemon_client::DaemonClient::connect_for_command(command, layout).await
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
        remote_organization_id: peer.organization_id,
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
    let response = daemon("kin push", &layout)
        .await?
        .command_push(&request)
        .await?;
    render_outcome(&response, json)
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
    let response = daemon("kin pull", &layout)
        .await?
        .command_pull(&request)
        .await?;
    render_outcome(&response, json)
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
    let plan = daemon("kin remote plan-push", &layout)
        .await?
        .command_transfer_plan(&request)
        .await?;
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
    match plan.plan.pack_count {
        Some(0) | Some(1) | None => {}
        Some(packs) => println!(
            "This gap needs {packs} transfer packs at the negotiated bound of {} changes each. Each pack is published on its own, so an interruption leaves the remote on the last one that landed and a re-run resumes from there.",
            plan.plan.max_changes_per_envelope
        ),
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

fn render_outcome(response: &CommandTransferResponse, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(response)?);
        // The exit contract is not a property of the human rendering. `--json`
        // is the mode a caller chains work from, so it is the mode where an
        // exit status that ignored a working tree left behind would do the most
        // damage. The body still carries the state; this decides the status.
        return workspace_follow_outcome(&response.workspace);
    }
    let outcome = &response.outcome;
    let verb = match outcome.direction {
        RepositoryTransferDirection::Push => "Pushed",
        RepositoryTransferDirection::Pull => "Pulled",
    };
    println!("{}", render_plan(&outcome.plan));
    match outcome.final_receipt() {
        None => println!("{verb} nothing: no repository transaction was published."),
        Some(receipt) => {
            println!(
                "{verb} {} onto {} at {}.",
                outcome.repository_id, outcome.destination_ref, receipt.destination_head
            );
            if outcome.receipts.len() > 1 {
                println!(
                    "Packs:     {} continuation packs, each published on its own",
                    outcome.receipts.len()
                );
            }
            println!("Transfer:  {}", receipt.transfer_id);
            println!("Outcome:   {:?}", receipt.outcome);
            println!(
                "Authority: generation {}",
                receipt.authority_receipt.generation
            );
        }
    }
    if let DerivedViewRefresh::Stale { detail } = &response.derived_views {
        println!(
            "Repository authority moved and is durable, but the views derived from it did not follow: {detail}"
        );
        println!(
            "Search and retrieval answer from behind the admitted head until those views are rebuilt. Restart the daemon to rebuild them."
        );
    }
    render_workspace_follow(&response.workspace)
}

/// Report what the working tree did, and fail the command when it did not
/// follow a head that is now durable.
fn render_workspace_follow(workspace: &WorkspaceFollow) -> Result<()> {
    match workspace {
        WorkspaceFollow::Unreported => {}
        WorkspaceFollow::NotApplicable { detail } => println!("Workspace: {detail}"),
        WorkspaceFollow::AlreadyCurrent {
            authority_generation,
        } => println!(
            "Workspace: already at the admitted head (authority generation {authority_generation})"
        ),
        WorkspaceFollow::Advanced {
            detail,
            authority_generation,
        } => println!("Workspace: {detail} (authority generation {authority_generation})"),
        WorkspaceFollow::Behind { detail } => println!(
            "Repository authority moved and is durable, but this workspace did not follow it: {detail}"
        ),
    }
    workspace_follow_outcome(workspace)
}

/// Decide the command's exit status from what the working tree did, separately
/// from how it was rendered.
///
/// A caller that chains work onto a pull reads the exit status, not the prose.
/// Succeeding after the workspace stayed behind would let that work run against
/// the tree the pull was supposed to replace, which is the one outcome nobody
/// can see from the files alone. Keeping the decision out of the renderer is
/// what makes it hold in every output mode rather than only the one a person
/// reads.
fn workspace_follow_outcome(workspace: &WorkspaceFollow) -> Result<()> {
    if workspace.is_behind() {
        bail!(
            "the admitted history is durable; the working tree still shows the head it had before. Resolve the reason above, then run `kin branch switch` onto the pulled ref to move it."
        );
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
    fn a_locator_gives_up_its_base_and_its_organization_together() {
        // The bug this pins: taking the organization from a locator while
        // keeping the whole locator as the base URL builds
        // `<base>/api/orgs/o/repos/r/api/v1/orgs/o/repos/r/transfer/...`.
        let (base, org) =
            peer_base_and_organization("http://127.0.0.1:8080/api/orgs/acme/repos/kin");
        assert_eq!(base, "http://127.0.0.1:8080");
        assert_eq!(org.as_deref(), Some("acme"));
        // Said as the property rather than as two literals: the base must not
        // still contain the organization path the locator carried.
        assert!(
            !base.contains("/api/orgs/"),
            "the base still carries the locator's own org path: {base}"
        );
    }

    #[test]
    fn a_bare_peer_base_names_no_organization() {
        let (base, org) = peer_base_and_organization("http://127.0.0.1:4010/");
        assert_eq!(base, "http://127.0.0.1:4010");
        assert_eq!(org, None);
    }

    #[test]
    fn a_kinlab_scheme_locator_names_an_organization_and_the_default_host() {
        let (base, org) = peer_base_and_organization("kinlab://acme/kin");
        assert_eq!(org.as_deref(), Some("acme"));
        assert!(!base.is_empty(), "a locator must still resolve a base URL");
        assert!(
            !base.contains("/api/orgs/"),
            "base carries an org path: {base}"
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
            organization_id: None,
        };
        let request = build_request(peer, Some("main"), None).unwrap();
        assert_eq!(request.source_ref, request.destination_ref);
        assert_eq!(request.source_ref, Some(RefName::branch(b"main").unwrap()));
    }

    /// One pull response carrying the workspace report under test. The transfer
    /// itself is deliberately the boring one: what these tests decide is what a
    /// caller reads back, not what the negotiation did.
    fn pull_response(workspace: WorkspaceFollow) -> CommandTransferResponse {
        let main = RefName::branch(b"main").unwrap();
        CommandTransferResponse {
            outcome: RepositoryTransferOutcome {
                direction: RepositoryTransferDirection::Pull,
                repository_id: kin_model::RepositoryId::new(
                    "8e29a0d6-9f2f-4a1c-9a3d-2d5f6c7b8a90".to_string(),
                )
                .unwrap(),
                source_ref: main.clone(),
                destination_ref: main,
                plan: RepositoryTransferPlan::UpToDate { head: None },
                receipts: Vec::new(),
            },
            derived_views: DerivedViewRefresh::Current,
            workspace,
        }
    }

    /// The non-zero exit is a contract of the command, not of the prose. A
    /// caller that chains work onto a pull almost always asks for `--json`, so
    /// an exit status that only held in the human path would fail exactly the
    /// caller it exists for.
    #[test]
    fn a_workspace_that_stayed_behind_fails_the_command_in_every_output_mode() {
        for json in [false, true] {
            let error = render_outcome(
                &pull_response(WorkspaceFollow::Behind {
                    detail: "a tracked path was edited outside Kin".to_string(),
                }),
                json,
            )
            .expect_err("a working tree that did not follow cannot report success");
            assert!(
                error.to_string().contains("still shows the head it had"),
                "refusal must say what the working tree is showing (json={json}): {error}"
            );
        }
    }

    /// The same contract read from the other side: no other state turns a
    /// transfer that landed into a failed command, in either mode.
    #[test]
    fn every_other_state_exits_clean_in_every_output_mode() {
        for workspace in [
            WorkspaceFollow::Unreported,
            WorkspaceFollow::NotApplicable {
                detail: "this pull admitted no history".to_string(),
            },
            WorkspaceFollow::AlreadyCurrent {
                authority_generation: 7,
            },
            WorkspaceFollow::Advanced {
                detail: "Followed refs/heads/main".to_string(),
                authority_generation: 8,
            },
        ] {
            assert!(!workspace.is_behind());
            for json in [false, true] {
                assert!(
                    render_outcome(&pull_response(workspace.clone()), json).is_ok(),
                    "{workspace:?} is not a failed pull (json={json})"
                );
            }
        }
        assert!(WorkspaceFollow::Behind {
            detail: String::new()
        }
        .is_behind());
    }

    /// A daemon that predates this report says nothing about the working tree,
    /// and the default must say exactly that rather than claim a transition
    /// nobody observed.
    #[test]
    fn a_response_without_the_field_reads_as_unreported() {
        let current = pull_response(WorkspaceFollow::Advanced {
            detail: "Followed refs/heads/main".to_string(),
            authority_generation: 3,
        });
        let mut wire = serde_json::to_value(&current).unwrap();
        // Exactly what an older daemon's body looks like: the outcome, and
        // neither optional report.
        let object = wire.as_object_mut().unwrap();
        assert!(object.remove("workspace").is_some());
        assert!(object.remove("derived_views").is_some());
        let decoded: CommandTransferResponse = serde_json::from_value(wire).unwrap();
        assert_eq!(decoded.workspace, WorkspaceFollow::Unreported);
        assert_eq!(decoded.derived_views, DerivedViewRefresh::Current);
        assert!(render_workspace_follow(&decoded.workspace).is_ok());
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
