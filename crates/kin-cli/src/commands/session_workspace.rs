// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Exact repository-v6 session-workspace projection.

use std::path::{Component, Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use kin_model::{
    compute_resolved_tree_hash, ArtifactId, RepoPath, ResolvedArtifact, ResolvedTree, RootBundle,
    WorkspaceState,
};
use kin_runtime::workspace::{
    MaterializationSourceKind, MaterializeStrategy, MaterializedWorkspace,
};
use serde::{Deserialize, Serialize};

use super::repository_authority::ActiveRepositoryAuthority;

const SESSION_WORKSPACE_BASE_SCHEMA: u32 = 1;

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
        if self
            .materialized_artifact_ids
            .windows(2)
            .any(|pair| pair[0] >= pair[1])
        {
            bail!("session materialized artifact identities are not unique and sorted");
        }
        if self.scope.is_none()
            && self.materialized_artifact_ids.len() != self.source_workspace.tree.len()
        {
            bail!("full session base does not account for every exact source artifact");
        }
        if self.scope.is_some() && self.materialized_artifact_ids.is_empty() {
            bail!("scoped session base does not name a materialized artifact");
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
    validate_session_directory(layout, session_dir)?;
    require_exact_copy_strategy(strategy)?;

    let authority = ActiveRepositoryAuthority::open(layout)?;
    let (source_workspace, authority_roots) = authority.workspace_with_roots()?;
    let selected_tree = select_materialized_tree(&source_workspace.tree, scope)?;

    let mut source_bodies = Vec::with_capacity(selected_tree.len());
    for artifact in selected_tree.artifacts_by_path() {
        let digest = artifact.entry.blob_identity().ok_or_else(|| {
            anyhow!(
                "session projection cannot materialize gitlink {:?} at {}; the exact gitlink \
                 remains represented in repository authority, but recursive repository \
                 materialization is not implemented",
                artifact.entry,
                artifact.path
            )
        })?;
        let body = authority
            .load_source_blob(digest)
            .with_context(|| format!("load exact session source for {}", artifact.path))?;
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

    std::fs::create_dir(session_dir).with_context(|| {
        format!(
            "create fresh session workspace {}; an existing path is never reused",
            session_dir.display()
        )
    })?;
    kin_core::materialize_session_source_tree(
        session_dir,
        &base_metadata,
        source_bodies
            .iter()
            .map(|(path, entry, body)| (path, *entry, body.as_slice())),
    )
    .with_context(|| {
        format!(
            "materialize exact repository tree at {}; the failed workspace was preserved for inspection",
            session_dir.display()
        )
    })?;

    Ok(MaterializedWorkspace::from_existing(
        session_dir.to_path_buf(),
        MaterializeStrategy::Copy,
        MaterializationSourceKind::ExactTree,
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
        root: workspace.root.display().to_string(),
        strategy: workspace.strategy.to_string(),
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

fn validate_session_directory(layout: &kin_core::KinLayout, session_dir: &Path) -> Result<()> {
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

    let runs_metadata = std::fs::symlink_metadata(&runs_dir)
        .with_context(|| format!("inspect session root {}", runs_dir.display()))?;
    if runs_metadata.file_type().is_symlink() || !runs_metadata.is_dir() {
        bail!(
            "session root {} is not a real directory",
            runs_dir.display()
        );
    }
    if std::fs::symlink_metadata(session_dir).is_ok() {
        bail!(
            "session workspace {} already exists; Kin never reuses a materialized workspace",
            session_dir.display()
        );
    }
    Ok(())
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
    fn session_directory_must_be_a_fresh_direct_child_of_runs() {
        let repository = tempfile::tempdir().unwrap();
        let layout = kin_core::KinLayout::new(repository.path().join(".kin"));
        std::fs::create_dir_all(layout.runs_dir()).unwrap();
        let valid = layout.runs_dir().join("session-test");
        validate_session_directory(&layout, &valid).unwrap();

        let nested = layout.runs_dir().join("nested/session-test");
        assert!(validate_session_directory(&layout, &nested).is_err());
        let outside = repository.path().join("session-test");
        assert!(validate_session_directory(&layout, &outside).is_err());
        std::fs::create_dir(&valid).unwrap();
        assert!(validate_session_directory(&layout, &valid).is_err());
    }
}
