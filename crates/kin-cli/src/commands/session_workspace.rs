// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Exact repository-v6 session-workspace projection.

use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use kin_model::{
    compute_resolved_tree_hash, ArtifactId, OperationId, RepoPath, ResolvedArtifact, ResolvedTree,
    RootBundle, WorkspaceState,
};
use kin_runtime::workspace::{
    MaterializationSourceKind, MaterializeStrategy, MaterializedWorkspace,
};
use serde::{Deserialize, Serialize};

use super::repository_authority::ActiveRepositoryAuthority;

const SESSION_WORKSPACE_BASE_SCHEMA: u32 = 2;
const MAX_SESSION_MEMBER_BYTES: u64 = 256 * 1024 * 1024;
const MAX_SESSION_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionWorkspaceRequest {
    pub session_dir: String,
    #[serde(default)]
    pub strategy: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionWorkspaceResponse {
    pub root: String,
    pub strategy: String,
    pub source_kind: String,
}

/// Durable three-way-reconcile base record installed inside a session projection.
///
/// The source workspace carries the complete exact tree, admission policy,
/// branch/base binding, and generation from one repository-authority lease.
/// `materialized_artifact_ids` records the subset exposed by a scoped
/// projection without discarding the rest of the source workspace. Consumers
/// must rebind this editable session-local record to repository authority before
/// using it to authorize reconciliation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SessionWorkspaceBase {
    pub schema: u32,
    /// One caller-stable authority operation for this disposable session.
    ///
    /// A session is reconciled at most once. Repeating the exact observation
    /// recovers the same repository receipt; changing the session after that
    /// receipt fails closed and requires a fresh session projection.
    pub reconcile_operation_id: OperationId,
    pub repository_id: kin_model::RepositoryId,
    pub authority_roots: RootBundle,
    pub source_workspace: WorkspaceState,
    pub materialized_artifact_ids: Vec<ArtifactId>,
    pub materialized_tree_hash: kin_model::Hash256,
    pub scope: Option<String>,
}

impl SessionWorkspaceBase {
    pub fn validate(&self) -> Result<()> {
        if self.schema != SESSION_WORKSPACE_BASE_SCHEMA {
            bail!("unsupported session workspace base schema {}", self.schema);
        }
        self.authority_roots
            .validate()
            .context("validate session authority roots")?;
        self.source_workspace
            .validate()
            .context("validate exact source workspace")?;
        if self.source_workspace.repository_id != self.repository_id {
            bail!(
                "session base repository identity {} does not match source workspace {}",
                self.repository_id,
                self.source_workspace.repository_id
            );
        }
        if self.scope.is_some() {
            bail!(
                "scoped exact-session bases are fail-closed until the selected artifact set is \
                 authenticated outside the editable session"
            );
        }
        if self
            .materialized_artifact_ids
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            bail!("session materialized artifact identities are not unique and sorted");
        }
        let expected_materialized = self
            .source_workspace
            .tree
            .artifacts()
            .filter_map(|artifact| {
                match kin_core::source_projection_disposition(&artifact.path, artifact.entry) {
                    Ok(kin_core::SourceProjectionDisposition::Materialized) => {
                        Some(Ok(artifact.artifact_id))
                    }
                    Ok(
                        kin_core::SourceProjectionDisposition::GraphOnlyGitlink
                        | kin_core::SourceProjectionDisposition::GraphOnlyHostUnrepresentable,
                    ) => None,
                    Err(error) => Some(Err(anyhow!(error))),
                }
            })
            .collect::<Result<Vec<_>>>()?;
        if self.materialized_artifact_ids != expected_materialized {
            bail!(
                "full session base materialized set does not exactly cover every \
                 host-representable source artifact"
            );
        }

        let selected = self
            .materialized_artifact_ids
            .iter()
            .map(|artifact_id| {
                self.source_workspace
                    .tree
                    .get(artifact_id)
                    .cloned()
                    .ok_or_else(|| {
                        anyhow!(
                            "session base names artifact {:?} outside its exact source tree",
                            artifact_id
                        )
                    })
                    .and_then(|artifact| {
                        if kin_core::source_projection_disposition(&artifact.path, artifact.entry)?
                            != kin_core::SourceProjectionDisposition::Materialized
                        {
                            bail!(
                                "session base marks graph-only artifact {} as materialized",
                                artifact.path
                            );
                        }
                        Ok(artifact)
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        let selected = ResolvedTree::from_artifacts(selected)
            .map_err(|error| anyhow!("validate materialized session tree: {error}"))?;
        let computed = compute_resolved_tree_hash(&selected)
            .context("compute materialized session tree identity")?;
        if computed != self.materialized_tree_hash {
            bail!(
                "session materialized tree identity mismatch: recorded {}, computed {}",
                self.materialized_tree_hash,
                computed
            );
        }
        Ok(())
    }
}

pub fn create_session_workspace_from_authority(
    layout: &kin_core::KinLayout,
    session_dir: &Path,
    strategy: Option<MaterializeStrategy>,
    scope: Option<&str>,
) -> Result<MaterializedWorkspace> {
    layout
        .check_version()
        .context("repository layout is not repository-v6 compatible")?;
    if scope.is_some() {
        bail!(
            "scoped exact-session materialization is fail-closed until its selected artifact set \
             is authenticated outside the editable session; request a full session"
        );
    }
    let session_name = validate_session_directory(layout, session_dir)?;
    require_exact_copy_strategy(strategy)?;

    // Projection lock first: a session writer that began before exact eject
    // must stay bound to that repository epoch and may not wake onto a
    // replacement `.kin`.
    let projection_freeze = kin_core::ExactProjectionFreeze::acquire_existing(layout.working_dir())
        .context("freeze the existing repository projection before creating a session")?;
    let authority = ActiveRepositoryAuthority::open(layout)?;
    let (source_workspace, authority_roots) = authority.workspace_with_roots()?;
    let selected_tree = select_materialized_tree(&source_workspace.tree, scope)?;
    let selected_artifacts = selected_tree
        .into_artifacts()
        .map(|artifact| {
            kin_core::source_projection_disposition(&artifact.path, artifact.entry)
                .map(|disposition| (artifact, disposition))
        })
        .collect::<kin_core::Result<Vec<_>>>()?;
    let selected_tree = ResolvedTree::from_artifacts(selected_artifacts.into_iter().filter_map(
        |(artifact, disposition)| {
            (disposition == kin_core::SourceProjectionDisposition::Materialized).then_some(artifact)
        },
    ))
    .map_err(|error| anyhow!("select host-materializable session tree: {error}"))?;

    let mut source_bodies = Vec::with_capacity(selected_tree.len());
    let mut source_body_bytes = 0_u64;
    for artifact in selected_tree.artifacts_by_path() {
        let digest = artifact.entry.blob_identity().ok_or_else(|| {
            anyhow!(
                "host-materializable session artifact {} has no repository source identity",
                artifact.path
            )
        })?;
        let body = authority
            .load_source_blob(digest)
            .with_context(|| format!("load exact session source for {}", artifact.path))?;
        let body_len = u64::try_from(body.len())
            .map_err(|_| anyhow!("session source {} exceeds u64", artifact.path))?;
        if body_len > MAX_SESSION_MEMBER_BYTES {
            bail!(
                "session source {} exceeds the per-member materialization limit of {} bytes",
                artifact.path,
                MAX_SESSION_MEMBER_BYTES
            );
        }
        source_body_bytes = source_body_bytes
            .checked_add(body_len)
            .ok_or_else(|| anyhow!("session source byte count overflow"))?;
        if source_body_bytes > MAX_SESSION_TOTAL_BYTES {
            bail!(
                "session source exceeds the total materialization limit of {} bytes",
                MAX_SESSION_TOTAL_BYTES
            );
        }
        source_bodies.push((artifact.path.clone(), artifact.entry, body));
    }

    kin_core::validate_source_tree(
        source_bodies
            .iter()
            .map(|(path, entry, body)| (path, *entry, body.as_slice())),
    )
    .context("validate exact session source tree")?;

    let materialized_artifact_ids = selected_tree
        .artifacts()
        .map(|artifact| artifact.artifact_id)
        .collect();
    let base = SessionWorkspaceBase {
        schema: SESSION_WORKSPACE_BASE_SCHEMA,
        reconcile_operation_id: OperationId::new(),
        repository_id: source_workspace.repository_id.clone(),
        authority_roots,
        source_workspace,
        materialized_artifact_ids,
        materialized_tree_hash: compute_resolved_tree_hash(&selected_tree)
            .context("compute exact materialized session tree identity")?,
        scope: scope.map(str::to_string),
    };
    base.validate()
        .context("validate exact session workspace base")?;
    let base_metadata =
        serde_json::to_vec_pretty(&base).context("encode exact session workspace base")?;

    let (projection, _) = projection_freeze
        .materialize_session_source_tree(
            session_name,
            &base_metadata,
            source_bodies
                .iter()
                .map(|(path, entry, body)| (path, *entry, body.as_slice())),
        )
        .with_context(|| {
            format!(
                "materialize exact repository tree at {} through retained session authority",
                session_dir.display()
            )
        })?;

    Ok(MaterializedWorkspace::from_exact_session(
        projection,
        MaterializeStrategy::Copy,
    ))
}

pub fn materialize_session_workspace(
    layout: &kin_core::KinLayout,
    request: &SessionWorkspaceRequest,
) -> Result<SessionWorkspaceResponse> {
    let strategy = request
        .strategy
        .as_deref()
        .map(str::parse::<MaterializeStrategy>)
        .transpose()
        .map_err(anyhow::Error::msg)?;
    let root = PathBuf::from(&request.session_dir);
    let workspace =
        create_session_workspace_from_authority(layout, &root, strategy, request.scope.as_deref())?;
    Ok(SessionWorkspaceResponse {
        root: workspace.root().display().to_string(),
        strategy: workspace.strategy().to_string(),
        source_kind: match workspace.source_kind() {
            MaterializationSourceKind::ExactTree => "exact-tree",
        }
        .to_string(),
    })
}

fn require_exact_copy_strategy(strategy: Option<MaterializeStrategy>) -> Result<()> {
    match strategy {
        None | Some(MaterializeStrategy::Copy) => Ok(()),
        Some(other) => bail!(
            "session projection strategy '{other}' is unavailable for repository-owned CAS \
             bodies; request 'copy' or omit the strategy"
        ),
    }
}

fn validate_session_directory<'a>(
    layout: &kin_core::KinLayout,
    session_dir: &'a Path,
) -> Result<&'a str> {
    let runs_dir = layout.runs_dir();
    if !session_dir.is_absolute() {
        bail!(
            "session workspace path must be absolute and directly beneath {}",
            runs_dir.display()
        );
    }
    let mut components = session_dir.components().rev();
    let Some(Component::Normal(name)) = components.next() else {
        bail!("session workspace path has no valid leaf name");
    };
    let name = name
        .to_str()
        .ok_or_else(|| anyhow!("session workspace name must be valid UTF-8"))?;
    if !name.starts_with("session-") || name.len() == "session-".len() {
        bail!("session workspace name must use the 'session-<id>' form");
    }
    if session_dir.parent() != Some(runs_dir.as_path()) {
        bail!(
            "session workspace {} must be a direct child of {}",
            session_dir.display(),
            runs_dir.display()
        );
    }

    Ok(name)
}

fn select_materialized_tree(source: &ResolvedTree, scope: Option<&str>) -> Result<ResolvedTree> {
    let Some(scope) = scope else {
        return Ok(source.clone());
    };
    if scope.is_empty() {
        bail!("session scope must not be empty");
    }

    let path = if scope.starts_with("entity:") {
        bail!(
            "entity-scoped session materialization is fail-closed until entity lookup and exact \
             workspace selection share one repository-authority snapshot; use artifact:<path> or \
             artifact-hex:<raw-path-hex>"
        );
    } else if let Some(encoded) = scope.strip_prefix("artifact-hex:") {
        let bytes = hex::decode(encoded).context("decode artifact-hex session scope")?;
        if hex::encode(&bytes) != encoded {
            bail!("artifact-hex session scope must use canonical lowercase hex");
        }
        RepoPath::from_bytes(bytes).context("validate artifact-hex session scope")?
    } else {
        let path = scope
            .strip_prefix("artifact:")
            .or_else(|| scope.strip_prefix("file:"))
            .unwrap_or(scope);
        RepoPath::from_utf8(path.to_string()).context("validate artifact session scope")?
    };

    let artifact = source.artifact_at_path(&path).cloned().ok_or_else(|| {
        anyhow!(
            "session scope artifact '{}' is absent from the exact workspace tree",
            path
        )
    })?;
    ResolvedTree::from_artifacts([ResolvedArtifact::new(
        artifact.artifact_id,
        artifact.path,
        artifact.entry,
    )])
    .map_err(|error| anyhow!("build exact scoped session tree: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{Hash256, TreeEntry};

    fn source_tree() -> (ResolvedTree, ArtifactId, ArtifactId) {
        let compose_id = ArtifactId::new();
        let raw_id = ArtifactId::new();
        let compose = ResolvedArtifact::new(
            compose_id,
            RepoPath::from_utf8("compose.yaml").unwrap(),
            TreeEntry::blob(Hash256::from_bytes([0x61; 32]), false),
        );
        let raw = ResolvedArtifact::new(
            raw_id,
            RepoPath::from_bytes(b"assets/policy-\xff.unknown".to_vec()).unwrap(),
            TreeEntry::blob(Hash256::from_bytes([0x62; 32]), false),
        );
        (
            ResolvedTree::from_artifacts([compose, raw]).unwrap(),
            compose_id,
            raw_id,
        )
    }

    #[test]
    fn artifact_scopes_resolve_against_exact_tree_membership() {
        let (source, compose_id, raw_id) = source_tree();

        let compose = select_materialized_tree(&source, Some("artifact:compose.yaml")).unwrap();
        assert_eq!(compose.len(), 1);
        assert!(compose.get(&compose_id).is_some());

        let encoded = hex::encode(b"assets/policy-\xff.unknown");
        let raw =
            select_materialized_tree(&source, Some(&format!("artifact-hex:{encoded}"))).unwrap();
        assert_eq!(raw.len(), 1);
        assert!(raw.get(&raw_id).is_some());

        let missing = select_materialized_tree(&source, Some("artifact:missing.file")).unwrap_err();
        assert!(missing
            .to_string()
            .contains("absent from the exact workspace tree"));

        let entity = select_materialized_tree(&source, Some("entity:compose")).unwrap_err();
        assert!(
            entity
                .to_string()
                .contains("share one repository-authority snapshot"),
            "{entity}"
        );
    }

    #[test]
    fn session_directory_must_name_a_direct_child_of_runs() {
        let repository = tempfile::tempdir().unwrap();
        let layout = kin_core::KinLayout::new(repository.path().join(".kin"));
        let valid = layout.runs_dir().join("session-test");
        assert_eq!(
            validate_session_directory(&layout, &valid).unwrap(),
            "session-test"
        );

        let nested = layout.runs_dir().join("nested/session-test");
        assert!(validate_session_directory(&layout, &nested).is_err());
        let outside = repository.path().join("session-test");
        assert!(validate_session_directory(&layout, &outside).is_err());
    }
}
