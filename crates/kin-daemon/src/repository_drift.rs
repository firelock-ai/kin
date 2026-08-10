// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Daemon-owned repository-v6 projection drift authority.
//!
//! Drift is answered from graph truth: the exact workspace tree and the content
//! repository authority owns for every tracked member. The working copy is read
//! only to prove whether the derived view still matches that truth, and only at
//! paths the workspace tree already tracks. No raw-filesystem walk, no
//! ranking, no repair, and no answer at all when repository authority cannot be
//! opened.

use anyhow::{Context, Result};
use axum::http::StatusCode;
use kin_cli::commands::drift::{DriftReport, DriftResponse, DRIFT_SCHEMA};

use crate::local_repository_authority::{
    ActiveLocalRepositoryAuthority, RepositoryAuthorityBindRefusal,
};
use crate::state::DaemonState;

/// Attempts allowed to take one generation-bound observation.
///
/// Each attempt is independently pinned to the generation it was taken
/// against; a retry re-observes from scratch rather than stitching a report
/// across generations. Retrying only absorbs a benign race with concurrent
/// authority movement, and a report is still refused rather than published if
/// authority never holds still.
const OBSERVATION_ATTEMPTS: usize = 4;

/// Linear backoff between observation attempts, so a repository still settling
/// its admission does not burn every attempt inside one authority move.
const OBSERVATION_BACKOFF: std::time::Duration = std::time::Duration::from_millis(40);

pub(crate) fn execute(
    state: &DaemonState,
) -> std::result::Result<DriftResponse, (StatusCode, String)> {
    let authority =
        ActiveLocalRepositoryAuthority::open_bound(state).map_err(drift_bind_refusal)?;
    let mut last_conflict = None;
    for attempt in 0..OBSERVATION_ATTEMPTS {
        match report(state, &authority) {
            Ok(response) => return Ok(response),
            Err(error) if is_authority_movement(&error) => {
                last_conflict = Some(error);
                std::thread::sleep(OBSERVATION_BACKOFF * (attempt as u32 + 1));
            }
            Err(error) => return Err(classify_drift_error(error)),
        }
    }
    Err(classify_drift_error(last_conflict.unwrap_or_else(|| {
        drift_conflict("projection drift observation exhausted its attempts")
    })))
}

/// Distinguish "authority moved while this observation ran" from every other
/// failure. Only the former may be retried: a projection or model failure is a
/// real refusal and must surface unchanged.
fn is_authority_movement(error: &anyhow::Error) -> bool {
    if error.downcast_ref::<DriftConflict>().is_some() {
        return true;
    }
    matches!(
        error.downcast_ref::<kin_core::KinError>(),
        Some(kin_core::KinError::RepositoryConflict(_))
    )
}

fn report(
    state: &DaemonState,
    authority: &ActiveLocalRepositoryAuthority,
) -> Result<DriftResponse> {
    let lease = authority.manager.read_authority();
    let roots = lease.roots().clone();
    let workspace = local_workspace(authority, lease.metadata())?.clone();
    workspace
        .validate()
        .context("active repository-v6 workspace is invalid")?;
    drop(lease);

    let observation = kin_core::report_repository_workspace_projection_drift(
        state.layout.working_dir(),
        &workspace.tree,
        &authority.manager,
    )
    .context("observe the derived projection against exact workspace authority")?;

    // The observation is only meaningful as a statement about one exact
    // workspace generation. Repository authority is read-only here and is not
    // held across the observation, so the generation it was taken against is
    // re-proved before anything is reported. A moved generation is refused
    // rather than reported as a drift result that no longer describes any
    // single authority state.
    let lease = authority.manager.read_authority();
    let current_roots = lease.roots().clone();
    let current_workspace = local_workspace(authority, lease.metadata())?.clone();
    drop(lease);
    if current_roots != roots
        || current_workspace.generation != workspace.generation
        || current_workspace.tree_hash != workspace.tree_hash
    {
        return Err(drift_conflict(format!(
            "repository authority moved from generation {} to generation {} while the projection \
             was observed; reopen the drift report against one exact workspace generation",
            roots.generation, current_roots.generation
        )));
    }

    let report = DriftReport {
        schema: DRIFT_SCHEMA.to_string(),
        authority: "repository-v6".to_string(),
        repository_id: authority.repository_id.clone(),
        authority_generation: roots.generation,
        roots,
        workspace_id: workspace.workspace_id,
        workspace_generation: workspace.generation,
        workspace_head: workspace.head.clone(),
        tracked_artifacts: workspace.tree.artifacts().len(),
        compared_entries: observation.compared_entries,
        drift_count: observation.drift.len(),
        clean: observation.is_clean(),
        drift: observation.drift,
        // Byte-exact rather than lossy UTF-8: a repository path is arbitrary
        // bytes, and `kin doctor --heal` restores exactly the paths named here.
        drifted_paths_hex: observation
            .drifted_paths
            .iter()
            .map(|path| hex::encode(path.as_bytes()))
            .collect(),
    };
    Ok(DriftResponse {
        lines: kin_cli::commands::drift::render_lines(&report),
        report: Some(report),
    })
}

#[derive(Debug)]
struct DriftConflict(String);

impl std::fmt::Display for DriftConflict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for DriftConflict {}

fn drift_conflict(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(DriftConflict(message.into()))
}

fn local_workspace<'a>(
    authority: &ActiveLocalRepositoryAuthority,
    metadata: &'a kin_db::PersistedRepositoryAuthority,
) -> Result<&'a kin_model::WorkspaceState> {
    metadata
        .workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == authority.workspace_id)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "repository {} has no workspace {} in repository-v6 authority",
                authority.repository_id,
                authority.workspace_id
            )
        })
}

fn classify_drift_error(error: anyhow::Error) -> (StatusCode, String) {
    if error.downcast_ref::<DriftConflict>().is_some() {
        return (StatusCode::CONFLICT, crate::error::cause_first(&error));
    }
    if let Some(core) = error.downcast_ref::<kin_core::KinError>() {
        let status = match core {
            kin_core::KinError::RepositoryConflict(_)
            | kin_core::KinError::ProjectionConflict(_) => StatusCode::CONFLICT,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        return (status, crate::error::cause_first(&error));
    }
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        crate::error::cause_first(&error),
    )
}

fn drift_bind_refusal(refusal: RepositoryAuthorityBindRefusal) -> (StatusCode, String) {
    let identity = refusal.is_identity_refusal();
    let error = refusal.into_error();
    if identity {
        (StatusCode::CONFLICT, crate::error::cause_first(&error))
    } else {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            crate::error::cause_first(&error),
        )
    }
}
