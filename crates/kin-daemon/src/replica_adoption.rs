// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Native clone: create a replica that adopts a remote's repository identity.
//!
//! Every exact-transfer surface is identity-exact. The ref advertisement
//! refuses to answer for a repository other than the one its authority
//! records, the transfer expectation carries an identity, pack validation
//! refuses a pack whose replicated alias records name a different repository
//! than the pack header, and admission refuses a pack whose repository is not
//! the one the receiving authority records. That is what makes a transfer
//! trustworthy, and it is also why a replica that minted its own identity can
//! never exchange history with the repository it came from.
//!
//! So a clone has to learn identity before it holds any authority of its own.
//! This module is that step and nothing more: it reads the remote's identity
//! over the native transport, creates a replica that adopts it, admits the
//! remote's history through the ordinary pull path, and then proves the
//! adoption against the authority the replica actually committed. It decides
//! nothing about what either replica holds.
//!
//! Storage-copy replicas are untouched. A replica whose `.kin` was copied
//! already shares an identity, and nothing here runs for it.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use kin_model::{RefName, RepositoryId};
use kin_remote::repository_transfer::RepositoryTransferError;
use kin_remote::repository_transfer_http::{
    HttpRepositoryTransferTransport, RepositoryTransferEndpoint,
};
use kin_remote::repository_transfer_negotiation::{
    negotiate_replica_identity, verify_adopted_replica_identity, RemoteReplicaIdentity,
};
use tracing::info;

use crate::error::DaemonError;
use crate::state::DaemonState;

const BRANCH_PREFIX: &str = "refs/heads/";

/// Why a native clone stopped, named by the step that could not complete.
///
/// The steps are deliberately separate errors. A caller that cannot tell "the
/// remote would not tell me who it is" from "the replica exists but its history
/// did not arrive" cannot decide whether anything is on disk, and the second
/// case leaves a real replica behind that a re-run can resume into.
#[derive(Debug, thiserror::Error)]
pub enum NativeCloneError {
    #[error("the remote would not publish an identity a replica can adopt: {0}")]
    Identity(#[source] RepositoryTransferError),

    #[error(
        "remote default ref {0} is not a branch this replica can be created against; a clone \
         reproduces the remote's default ref rather than inventing one"
    )]
    DefaultRefNotABranch(String),

    #[error("could not create a replica adopting repository {repository_id}: {source}")]
    Initialize {
        repository_id: String,
        #[source]
        source: kin_core::KinError,
    },

    #[error(
        "created the replica adopting repository {repository_id} but could not open it: {source}"
    )]
    Open {
        repository_id: String,
        #[source]
        source: DaemonError,
    },

    /// The replica exists and adopted the identity; its history did not
    /// arrive. Naming that explicitly is what tells a caller the directory is a
    /// real replica to resume into rather than debris to remove.
    #[error(
        "the replica at {path} adopted repository {repository_id}, but admitting the remote's \
         history failed and it holds none: {detail}. Its identity is durable, so a `kin pull` \
         from the same remote resumes this clone"
    )]
    Transfer {
        path: PathBuf,
        repository_id: String,
        detail: String,
    },

    #[error(
        "the replica adopted repository {repository_id} but the adoption did not verify: {source}"
    )]
    Adoption {
        repository_id: String,
        #[source]
        source: RepositoryTransferError,
    },

    /// A blocking step did not run to completion, so nothing is claimed about
    /// what is on disk: the step that would have said so is the one that
    /// failed. Kept separate from every other arm rather than folded into the
    /// nearest one, because attributing a panic to the step before it would
    /// name a cause nobody observed.
    #[error("the {step} step of a native clone did not run to completion: {detail}")]
    Interrupted { step: &'static str, detail: String },
}

/// One completed native clone.
///
/// `Debug` is written by hand because daemon state is not printable and would
/// not describe the clone anyway. What a reader wants is which repository was
/// adopted and where it landed.
pub struct NativeReplicaClone {
    /// Daemon state for the replica that was created, already open on the
    /// adopted identity. The caller owns serving it.
    pub state: Arc<DaemonState>,
    /// What the remote published and this replica adopted.
    pub identity: RemoteReplicaIdentity,
    /// The pull that admitted the remote's history, including whether the
    /// working tree followed it.
    pub transfer: kin_cli::commands::transfer::CommandTransferResponse,
}

impl std::fmt::Debug for NativeReplicaClone {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeReplicaClone")
            .field("repository_id", &self.identity.repository_id)
            .field("default_ref", &self.identity.default_ref)
            .field("path", &self.state.layout.root())
            .field("moved_history", &self.transfer.outcome.moved_history())
            .finish()
    }
}

/// Create a replica at `working_dir` that adopts the remote's repository
/// identity, then admit that remote's history into it.
///
/// `working_dir` must already exist and hold no Kin repository. Creating the
/// directory belongs to whoever chose the destination; refusing an existing
/// replica belongs here, and it refuses by naming the identity already there
/// rather than overwriting it.
///
/// The sequence is four steps and each one can be the last:
///
/// 1. read the remote's identity and default ref over the native transport,
/// 2. create the replica adopting that identity, minting only its workspace,
/// 3. admit the remote's history through the same pull path the route runs,
/// 4. prove the adoption against the authority the replica committed.
///
/// Step 2 is durable on its own. A failure after it leaves a real replica that
/// holds the adopted identity and no history, which is exactly the state a
/// re-run resumes from, so it is reported as [`NativeCloneError::Transfer`]
/// rather than removed.
pub async fn clone_native_replica(
    working_dir: &Path,
    endpoint: RepositoryTransferEndpoint,
    repository_id: &RepositoryId,
) -> Result<NativeReplicaClone, NativeCloneError> {
    let working_dir = working_dir.to_path_buf();
    let requested = repository_id.clone();
    let negotiation_endpoint = endpoint.clone();

    let (identity, state) = tokio::task::spawn_blocking(move || {
        let transport = HttpRepositoryTransferTransport::new(negotiation_endpoint);
        let identity = negotiate_replica_identity(&transport, &requested)
            .map_err(NativeCloneError::Identity)?;
        let branch = default_branch_name(&identity.default_ref)?;
        let adopted = identity.repository_id.clone();
        let init =
            kin_core::init_replica_adopting(&working_dir, branch, &adopted).map_err(|source| {
                NativeCloneError::Initialize {
                    repository_id: adopted.to_string(),
                    source,
                }
            })?;
        let state = DaemonState::open_with_repo_id(init.layout, None).map_err(|source| {
            NativeCloneError::Open {
                repository_id: adopted.to_string(),
                source,
            }
        })?;
        info!(
            repository = %adopted,
            workspace = %init.workspace_id,
            default_ref = %identity.default_ref,
            "initialized replica adopting a remote repository identity"
        );
        Ok::<_, NativeCloneError>((identity, Arc::new(state)))
    })
    .await
    .map_err(|error| NativeCloneError::Interrupted {
        step: "identity and replica creation",
        detail: error.to_string(),
    })??;

    let adopted = identity.repository_id.clone();
    let request = kin_cli::commands::transfer::CommandTransferRequest {
        // A peer daemon serves the seam at its own root and has no
        // organizations; only a hosted KinLab peer is org scoped.
        remote_organization_id: None,
        remote_base_url: endpoint.base_url.clone(),
        remote_token: endpoint.auth_token.clone(),
        repository_id: Some(adopted.to_string()),
        source_ref: Some(identity.default_ref.clone()),
        destination_ref: Some(identity.default_ref.clone()),
    };
    let transfer = crate::api::pull_into_replica(&state, &request)
        .await
        .map_err(|(status, detail)| NativeCloneError::Transfer {
            path: state.layout.root().to_path_buf(),
            repository_id: adopted.to_string(),
            detail: format!("{status}: {detail}"),
        })?;

    let verification_state = Arc::clone(&state);
    let verified_identity = identity.clone();
    let verified_adopted = adopted.clone();
    let verified_outcome = transfer.outcome.clone();
    tokio::task::spawn_blocking(move || {
        let (_, authority) = crate::api::repository_transfer_authority(
            &verification_state,
            verified_adopted.as_str(),
        )
        .map_err(|(_, detail)| RepositoryTransferError::Storage(detail))?;
        verify_adopted_replica_identity(
            &authority,
            &verified_adopted,
            &verified_identity,
            &verified_outcome,
        )
    })
    .await
    .map_err(|error| NativeCloneError::Interrupted {
        step: "adoption verification",
        detail: error.to_string(),
    })?
    .map_err(|source| NativeCloneError::Adoption {
        repository_id: adopted.to_string(),
        source,
    })?;

    Ok(NativeReplicaClone {
        state,
        identity,
        transfer,
    })
}

/// The short branch name a replica is created against.
///
/// `KinConfig` names the default branch, not the full ref, so a remote default
/// ref that is not a UTF-8 branch cannot be reproduced by initialization. That
/// is refused rather than rewritten: a replica created against a ref the remote
/// does not publish would leave a ghost no transfer can ever reconcile.
fn default_branch_name(default_ref: &RefName) -> Result<&str, NativeCloneError> {
    default_ref
        .as_utf8()
        .filter(|_| default_ref.is_branch())
        .and_then(|name| name.strip_prefix(BRANCH_PREFIX))
        .filter(|name| !name.is_empty())
        .ok_or_else(|| NativeCloneError::DefaultRefNotABranch(default_ref.to_string()))
}
