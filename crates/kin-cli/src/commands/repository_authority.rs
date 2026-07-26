// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Coherent read access to the active repository-v6 authority.
//!
//! CLI and daemon command helpers use this boundary instead of reconstructing
//! refs, workspace state, aliases, or source bytes from legacy sidecars, Git,
//! or the working directory.

use std::collections::BTreeSet;
use std::sync::Arc;

use anyhow::{anyhow, Context, Result};
use kin_db::{LocalFileBackend, RepositoryAuthorityManager};
use kin_model::{
    ExternalObjectKind, GitObjectId, RefName, RefTarget, RepositoryId, RepositoryRef,
    SemanticChangeId, WorkspaceId, WorkspaceState,
};

pub(crate) struct ActiveRepositoryAuthority {
    manager: RepositoryAuthorityManager<LocalFileBackend>,
    pub(crate) repository_id: RepositoryId,
    pub(crate) workspace_id: WorkspaceId,
}

impl ActiveRepositoryAuthority {
    pub(crate) fn open(layout: &kin_core::KinLayout) -> Result<Self> {
        layout
            .check_version()
            .context("repository layout is not repository-v6 compatible")?;
        let manifest = kin_core::KinManifest::load(&layout.manifest_path())
            .context("load repository manifest")?;
        let repository_id = RepositoryId::new(manifest.repo_id)
            .map_err(|error| anyhow!("repository manifest has an invalid identity: {error}"))?;
        let workspace_uuid = uuid::Uuid::parse_str(&manifest.workspace_id)
            .context("repository manifest has an invalid workspace identity")?;
        let workspace_id = WorkspaceId::from_uuid(workspace_uuid);
        let manager = RepositoryAuthorityManager::open(
            repository_id.clone(),
            Arc::new(LocalFileBackend::new(layout.kindb_dir())),
        )
        .context("open repository-v6 authority")?;

        Ok(Self {
            manager,
            repository_id,
            workspace_id,
        })
    }

    pub(crate) fn manager(&self) -> &RepositoryAuthorityManager<LocalFileBackend> {
        &self.manager
    }

    pub(crate) fn workspace(&self) -> Result<WorkspaceState> {
        self.manager
            .read_authority()
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == self.workspace_id)
            .cloned()
            .ok_or_else(|| {
                anyhow!(
                    "repository {} has no workspace {} in repository-v6 authority",
                    self.repository_id,
                    self.workspace_id
                )
            })
    }

    pub(crate) fn repository_ref(&self, name: &RefName) -> Option<RepositoryRef> {
        self.manager
            .read_authority()
            .metadata()
            .ref_state
            .refs
            .iter()
            .find(|repository_ref| &repository_ref.name == name)
            .cloned()
    }

    pub(crate) fn resolve_target(&self, target: &RefTarget) -> Result<SemanticChangeId> {
        let mut target = target.clone();
        let mut visited = BTreeSet::new();
        loop {
            match target {
                RefTarget::Change { change_id } => return Ok(change_id),
                RefTarget::ExternalObject { object } => {
                    if object.kind != ExternalObjectKind::Commit {
                        anyhow::bail!(
                            "repository ref target {} is a {:?}, not a commit",
                            object.oid,
                            object.kind
                        );
                    }
                    return self
                        .manager
                        .read_authority()
                        .metadata()
                        .aliases
                        .iter()
                        .find(|alias| alias.oid == object.oid)
                        .map(|alias| alias.change_id)
                        .ok_or_else(|| {
                            anyhow!(
                                "external commit {} has no repository-v6 semantic alias",
                                object.oid
                            )
                        });
                }
                RefTarget::Symbolic { target: name } => {
                    if !visited.insert(name.clone()) {
                        anyhow::bail!("symbolic repository ref cycle reaches {name}");
                    }
                    target = self
                        .repository_ref(&name)
                        .map(|repository_ref| repository_ref.target)
                        .ok_or_else(|| anyhow!("symbolic repository ref {name} is absent"))?;
                }
            }
        }
    }

    pub(crate) fn resolve_named_ref(&self, name: &RefName) -> Result<SemanticChangeId> {
        let repository_ref = self
            .repository_ref(name)
            .ok_or_else(|| anyhow!("repository ref '{name}' was not found"))?;
        self.resolve_target(&repository_ref.target)
    }

    pub(crate) fn current_change_id(&self) -> Result<Option<SemanticChangeId>> {
        self.workspace()?
            .base_target
            .as_ref()
            .map(|target| self.resolve_target(target))
            .transpose()
    }

    pub(crate) fn resolve_git_oid(&self, oid: &GitObjectId) -> Result<SemanticChangeId> {
        self.manager
            .read_authority()
            .metadata()
            .aliases
            .iter()
            .find(|alias| &alias.oid == oid)
            .map(|alias| alias.change_id)
            .ok_or_else(|| anyhow!("Git commit '{oid}' has no imported repository-v6 alias"))
    }

    pub(crate) fn load_source_blob(&self, digest: kin_model::Hash256) -> Result<Vec<u8>> {
        self.manager
            .load_source_blob(digest)
            .with_context(|| format!("load immutable repository source blob {digest}"))?
            .ok_or_else(|| anyhow!("immutable repository source blob {digest} is absent"))
    }

    pub(crate) fn save_source_blob(&self, digest: kin_model::Hash256, data: &[u8]) -> Result<()> {
        self.manager
            .save_source_blob(digest, data)
            .with_context(|| format!("save immutable repository source blob {digest}"))
    }
}

pub(crate) fn parse_ref_name(value: &str) -> Result<RefName> {
    if value.starts_with("refs/") {
        RefName::from_utf8(value)
            .map_err(|error| anyhow!("invalid fully-qualified repository ref: {error}"))
    } else {
        RefName::branch(value.as_bytes()).map_err(|error| anyhow!("invalid branch name: {error}"))
    }
}

pub(crate) fn parse_git_object_id(value: &str) -> Result<GitObjectId> {
    if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        anyhow::bail!("invalid Git object ID '{value}': expected hexadecimal bytes");
    }
    let bytes = hex::decode(value).with_context(|| format!("invalid Git object ID '{value}'"))?;
    match bytes.len() {
        20 => Ok(GitObjectId::sha1(
            bytes
                .try_into()
                .expect("20-byte Git object IDs convert to SHA-1 arrays"),
        )),
        32 => {
            Ok(GitObjectId::sha256(bytes.try_into().expect(
                "32-byte Git object IDs convert to SHA-256 arrays",
            )))
        }
        length => anyhow::bail!(
            "invalid Git object ID '{value}': expected 20 or 32 bytes, found {length}"
        ),
    }
}
