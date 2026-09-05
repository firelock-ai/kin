// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Clone exact repository authority through native Kin or Git transport.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, ensure, Context, Result};
use kin_core::{RemoteHostKind, RemoteRefConfig, RemoteTransportKind};
use kin_model::{RepositoryId, WorkspaceHead};
use kin_remote::repository_transfer_http::{
    HttpRepositoryTransferTransport, RepositoryTransferEndpoint,
};
use kin_remote::repository_transfer_negotiation::{
    negotiate_replica_identity, RemoteReplicaIdentity, RepositoryTransferPlan,
    RepositoryTransferTransport,
};

use crate::commands::transfer::{CommandTransferRequest, WorkspaceFollow};

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

struct NativeCloneSource {
    endpoint: RepositoryTransferEndpoint,
    repository_id: RepositoryId,
    locator: Option<String>,
}

/// Whether this URL is a Git clone URL rather than a native Kin endpoint.
///
/// A trailing `.git` is the Git clone convention, and it is never part of a
/// native identity: every locator form `native_remote_locator` recognizes
/// strips it before returning a repository id, so a URL still carrying one when
/// the locator declined it was typed as a Git URL. Kin peers are otherwise
/// ordinary HTTP endpoints, so nothing else in a bare URL separates the two.
fn is_git_clone_url(url: &str) -> bool {
    url.trim().trim_end_matches('/').ends_with(".git")
}

fn native_source(url: &str, repository: Option<&str>) -> Result<Option<NativeCloneSource>> {
    let locator = crate::commands::remote::native_remote_locator(url);
    let (base_url, organization_id, located_repository) = match locator {
        Some(target) => (
            target.base_url,
            Some(target.organization_id),
            Some(target.repo_id),
        ),
        None => (url.trim().to_string(), None, None),
    };
    let Some(repository) = repository.or(located_repository.as_deref()) else {
        let lowercase = url.to_ascii_lowercase();
        ensure!(
            !lowercase.starts_with("kin://") && !lowercase.starts_with("kinlab://"),
            "native clone needs a full locator, such as kinlab://<org>/<repository-id>"
        );
        return Ok(None);
    };
    // Reaching negotiation with a Git URL only produced "native remote did not
    // publish an identity this replica can adopt", which blames the remote for
    // the flag that rerouted the clone. The URL is never echoed, because this
    // runs before the credential check below.
    if located_repository.is_none() && is_git_clone_url(url) {
        bail!(
            "a Git clone URL does not take --repository; Git transport carries its own repository path. Drop --repository to clone through Git transport, or pass a native Kin locator such as kinlab://<org>/<repository-id>"
        );
    }
    if let Some(located) = &located_repository {
        ensure!(
            repository == located,
            "--repository disagrees with the native locator"
        );
    }
    let locator_url = url::Url::parse(url).context("parse native clone locator")?;
    ensure!(locator_url.username().is_empty() && locator_url.password().is_none()
        && locator_url.query().is_none() && locator_url.fragment().is_none(),
        "native clone locator must not carry credentials, a query or a fragment; use kin auth login or the native remote token environment");
    let parsed = url::Url::parse(&base_url).context("parse native clone endpoint")?;
    ensure!(
        matches!(parsed.scheme(), "http" | "https"),
        "native clone needs an HTTP or HTTPS endpoint"
    );
    ensure!(parsed.username().is_empty() && parsed.password().is_none() && parsed.query().is_none() && parsed.fragment().is_none(),
        "native clone endpoint must not carry credentials, a query or a fragment; use kin auth login or the native remote token environment");
    let mut endpoint = RepositoryTransferEndpoint::new(base_url);
    endpoint.auth_token = crate::commands::remote::native_remote_bearer_token(&endpoint.base_url);
    endpoint.organization_id = organization_id;
    Ok(Some(NativeCloneSource {
        endpoint,
        repository_id: RepositoryId::new(repository.to_string())
            .context("invalid native repository identity")?,
        locator: located_repository.map(|_| url.to_string()),
    }))
}

fn default_branch(identity: &RemoteReplicaIdentity) -> Result<&str> {
    identity
        .default_ref
        .as_utf8()
        .filter(|_| identity.default_ref.is_branch())
        .and_then(|name| name.strip_prefix("refs/heads/"))
        .filter(|name| !name.is_empty())
        .context("native remote default ref is not a UTF-8 branch that a workspace can track")
}

async fn clone_native(source: NativeCloneSource, target: &Path) -> Result<()> {
    require_available_target(target)?;
    let endpoint = source.endpoint.clone();
    let requested = source.repository_id.clone();
    let identity = tokio::task::spawn_blocking(move || {
        negotiate_replica_identity(&HttpRepositoryTransferTransport::new(endpoint), &requested)
    })
    .await
    .context("native identity negotiation did not complete")?
    .context("native remote did not publish an identity this replica can adopt")?;
    let branch = default_branch(&identity)?.to_string();
    let directory = target.to_path_buf();
    let adopted = identity.repository_id.clone();
    let endpoint = source.endpoint.clone();
    let has_history = identity.default_ref_head.is_some();
    let initialized = tokio::task::spawn_blocking(move || {
        kin_core::init::replica::initialize(&directory, &branch, &adopted, |prepared, case| {
            if !has_history {
                return Ok(None);
            }
            let fetch = || -> anyhow::Result<_> {
                let expectation = kin_remote::repository_transfer::replica_bootstrap_expectation(
                    prepared.repository_id().clone(),
                    prepared.default_ref().clone(),
                    prepared.initial_roots().clone(),
                )?;
                let transport = HttpRepositoryTransferTransport::new(endpoint);
                let pack = transport.export_pack(&adopted, prepared.default_ref(), &expectation)?;
                let bootstrap = kin_remote::repository_transfer::prepare_replica_bootstrap(
                    &pack,
                    &expectation,
                    prepared.workspace_id(),
                    case,
                )?;
                Ok(Some(kin_core::init::replica::ReplicaBootstrapInput {
                    transaction: bootstrap.transaction,
                    bodies: bootstrap.bodies,
                    source_hydration_semantics: bootstrap.source_hydration_semantics,
                }))
            };
            fetch()
                .map_err(|error| kin_core::KinError::Other(format!("native bootstrap: {error:#}")))
        })
    })
    .await
    .context("native replica initialization did not complete")?
    .context("initialize native replica without replacing existing authority")?;
    let target = target
        .canonicalize()
        .context("resolve native clone destination")?;
    let layout = initialized.layout;
    crate::commands::remote::upsert_remote_config(
        &layout,
        RemoteRefConfig {
            name: "origin".to_string(),
            host: if source.locator.is_some() {
                RemoteHostKind::KinLab
            } else {
                RemoteHostKind::Peer
            },
            transport: RemoteTransportKind::NativeKin,
            url: Some(
                source
                    .locator
                    .unwrap_or_else(|| source.endpoint.base_url.clone()),
            ),
            publish_review_state: false,
            publish_proofs: false,
        },
        true,
    )
    .context("persist native clone origin")?;
    materialize_cloned_base(&layout).await;
    let request = CommandTransferRequest {
        remote_base_url: source.endpoint.base_url.clone(),
        remote_token: source.endpoint.auth_token,
        remote_organization_id: source.endpoint.organization_id,
        repository_id: Some(identity.repository_id.to_string()),
        source_ref: Some(identity.default_ref.clone()),
        destination_ref: Some(identity.default_ref.clone()),
    };
    let transferred = async {
        let client = crate::daemon_client::DaemonClient::connect_for_command("kin clone", &layout).await?;
        let response = if has_history { Some(client.command_pull(&request).await?) } else { None };
        if let Some(response) = &response {
        ensure!(response.outcome.repository_id == identity.repository_id,
            "native clone transfer returned a different repository identity");
        ensure!(response.outcome.source_ref == identity.default_ref && response.outcome.destination_ref == identity.default_ref,
            "native clone transfer returned a different default ref");
        for receipt in &response.outcome.receipts {
            ensure!(receipt.repository_id == identity.repository_id,
                "native clone transfer receipt names a different repository");
        }
        match &response.workspace {
            WorkspaceFollow::Advanced { .. } | WorkspaceFollow::AlreadyCurrent { .. } => {},
            WorkspaceFollow::NotApplicable { .. }
                if matches!(response.outcome.plan, RepositoryTransferPlan::UpToDate { .. }) => {},
            other => bail!("native history arrived but the working tree did not follow: {other:?}; use kin branch switch after resolving the reported workspace condition"),
        }
        if response.derived_views.is_stale() {
            bail!("native history and files arrived, but semantic views are stale: {:?}; restart the destination daemon", response.derived_views);
        }
        }
        let status = client.command_status(&crate::commands::status::CommandStatusRequest::new(false)).await?.report;
        ensure!(status.repo_root == target && status.repository.repository_id == identity.repository_id,
            "native clone status does not describe the adopted destination");
        ensure!(status.repository.default_ref.as_ref() == Some(&identity.default_ref)
            && status.workspace.head == WorkspaceHead::Symbolic { target: identity.default_ref.clone() },
            "native clone workspace does not track the adopted default ref");
        ensure!(status.repository.source_cas_verified && !status.workspace.dirty,
            "native clone could not verify its source bodies and exact workspace");
        let history = client.log(&crate::commands::log::LogRequest { count: 1 }).await?.report
            .context("native clone daemon did not report exact history")?;
        let expected_head = match response.as_ref().map(|response| &response.outcome.plan) {
            Some(RepositoryTransferPlan::UpToDate { head }) => *head,
            Some(RepositoryTransferPlan::FastForward { source_head, .. }) => Some(*source_head),
            None => None,
        };
        ensure!(history.repository_id == identity.repository_id && history.start_change == expected_head,
            "native clone history does not reach the transferred head");
        ensure!(identity.default_ref_head.is_none() || expected_head.is_some(),
            "native clone admitted none of the advertised history");
        Ok::<_, anyhow::Error>((status, expected_head))
    }.await;
    let (status, head) = transferred.with_context(|| format!(
        "replica at {} durably adopted repository {}; history may be partially admitted. Retry from that directory with `kin pull`; no existing authority was removed",
        target.display(), identity.repository_id
    ))?;
    println!(
        "Cloned native Kin repository authority at {}",
        target.display()
    );
    println!("  Repository: {}", identity.repository_id);
    println!("  Workspace: {}", initialized.workspace_id);
    println!("  Default ref: {}", identity.default_ref);
    println!("  Authority generation: {}", status.repository.generation);
    if let Some(head) = head {
        println!("  Head: {head}");
    }
    Ok(())
}

/// Persist the cloned replica's workspace base graph section, before this
/// command starts a daemon on it.
///
/// A clone's history does NOT arrive through the transfer receiver. It arrives
/// inside `kin_core::init::replica::initialize`, as one bootstrap transaction
/// committed into a staged layout, so every refresh that hangs off a receive or
/// a workspace transition is on a path this replica never took, and a fresh
/// clone read `Graph section: absent, so every open of this store folds this
/// workspace's base out of history` while naming `kin graph materialize` as the
/// fix. Journey GAP-4. A stranger's first act on a peer's repository should not
/// leave them a store that pays a full history fold at every open.
///
/// Here rather than inside `initialize`, and here rather than after the
/// transfer below, because this is the one moment nothing holds the store:
/// `materialize_workspace_base_offline` takes repository runtime authority
/// first, and the transfer below connects a daemon that holds it. A clone whose
/// own pull then admits more history moves the base again, and the daemon's own
/// follow of that moved ref refreshes the section for it.
///
/// Never fatal, exactly as `kin init` treats the same phase: the replica is
/// durable, complete and verified, and a memoization that did not persist is a
/// slower next open rather than a failed clone. The warning names the retry, and
/// `kin graph status` and `kin doctor` keep reading the state from the store, so
/// a failure here is disclosed rather than papered over.
async fn materialize_cloned_base(layout: &kin_core::KinLayout) {
    let layout = layout.clone();
    let outcome = tokio::task::spawn_blocking(move || {
        crate::commands::repository_authority::materialize_workspace_base_offline(&layout)
    })
    .await;
    let error = match outcome {
        Ok(Ok(_)) => return,
        Ok(Err(error)) => error,
        Err(error) => anyhow::anyhow!("graph-section materialization did not complete: {error}"),
    };
    eprintln!(
        "warning: the clone completed, but preparing its first graph reopen did not; run \
         `kin graph materialize` in the clone to retry: {error:#}"
    );
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

pub async fn run(url: String, path: Option<String>, repository: Option<String>) -> Result<()> {
    let native = native_source(&url, repository.as_deref())?;
    let target = derive_target_dir(&url, path);
    if let Some(source) = native {
        return clone_native(source, &target).await;
    }
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

    // Composed here as plain strings and painted at print time, so a pipe or a
    // test reads the same bytes the admission reported.
    let summary = [
        format!(
            "Cloned Git transport and admitted exact Kin repository authority at {}",
            target.display()
        ),
        format!("  Repository: {}", result.repository_id),
        format!("  Workspace: {}", result.workspace_id),
        format!(
            "  Authority generation: {}",
            result.authority.receipt.generation
        ),
        "  Semantic enrichment: not run".to_string(),
    ];
    for line in &summary {
        println!("{}", crate::output_style::paint_clone_line(line));
    }
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
    fn native_peer_requires_an_explicit_repository_identity() {
        assert!(native_source("http://127.0.0.1:4219", None)
            .unwrap()
            .is_none());
        let source = native_source("http://127.0.0.1:4219", Some("repo"))
            .unwrap()
            .unwrap();
        assert_eq!(source.repository_id.as_str(), "repo");
        assert!(source.endpoint.organization_id.is_none());
    }

    #[test]
    fn native_hosted_locator_preserves_its_organization_and_identity() {
        let source = native_source("kinlab://acme/repo", None).unwrap().unwrap();
        assert_eq!(source.repository_id.as_str(), "repo");
        assert_eq!(source.endpoint.organization_id.as_deref(), Some("acme"));
        assert!(native_source("kinlab://acme/repo", Some("other")).is_err());
    }

    #[test]
    fn a_git_clone_url_is_refused_rather_than_rerouted_onto_the_native_path() {
        for url in [
            "https://github.com/org/repo.git",
            "https://github.com/org/repo.git/",
            "git@github.com:org/repo.git",
            "ssh://git@github.com/org/repo.git",
        ] {
            let error = native_source(url, Some("repo"))
                .err()
                .expect("a Git clone URL does not resolve as a native source");
            assert!(
                error
                    .to_string()
                    .contains("Git clone URL does not take --repository"),
                "{url}: {error}"
            );
        }
        // Without the flag the same URL still falls through to Git transport,
        // which is the path that clones it.
        assert!(native_source("https://github.com/org/repo.git", None)
            .unwrap()
            .is_none());
        // A peer that is not a Git clone URL still takes --repository, and a
        // hosted locator spelled with .git is a native locator, not a Git URL.
        assert!(native_source("http://127.0.0.1:4219", Some("repo"))
            .unwrap()
            .is_some());
        assert_eq!(
            native_source("kinlab://acme/repo.git", None)
                .unwrap()
                .unwrap()
                .repository_id
                .as_str(),
            "repo"
        );
    }

    #[test]
    fn native_credentials_are_not_accepted_in_a_url_that_may_be_reported() {
        assert!(native_source("http://user:secret@127.0.0.1:4219", Some("repo")).is_err());
        assert!(native_source("http://127.0.0.1:4219?token=secret", Some("repo")).is_err());
        assert!(native_source("kinlab://acme/repo?token=secret", None).is_err());
        assert!(native_source("kinlab://user:secret@acme/repo", None).is_err());
        assert!(
            native_source("https://user:secret@kinlab.ai/acme/repo?token=secret", None).is_err()
        );
        assert!(native_source("https://kinlab.ai/acme/repo?token=secret", None).is_err());
    }
}
