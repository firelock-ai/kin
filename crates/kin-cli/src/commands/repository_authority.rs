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
use kin_db::{LocalFileBackend, RepositoryAuthorityManager, RepositoryAuthorityState};
use kin_model::{
    decode_git_external_object, ExternalObjectId, ExternalObjectKind, GitObjectDependencyKind,
    GitObjectId, RefName, RefTarget, RepositoryId, SemanticChangeId, WorkspaceId, WorkspaceState,
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

    /// Resolve one exact ref target against a caller-owned authority lease.
    ///
    /// Keeping resolution inside the supplied immutable state prevents a
    /// request from mixing ref, alias, and external-object generations. Tags
    /// are peeled only through authority-recorded bodies in Kin's source CAS;
    /// Git and checkout files are never consulted.
    pub(crate) fn resolve_target_in_state(
        &self,
        state: &RepositoryAuthorityState,
        target: &RefTarget,
    ) -> Result<SemanticChangeId> {
        let mut target = target.clone();
        let mut visited_refs = BTreeSet::new();
        let mut visited_objects = BTreeSet::new();
        loop {
            match target {
                RefTarget::Change { change_id } => return Ok(change_id),
                RefTarget::ExternalObject { object } => match object.kind {
                    ExternalObjectKind::Commit => {
                        return state
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
                    ExternalObjectKind::Tag => {
                        if !visited_objects.insert(object) {
                            anyhow::bail!(
                                "external tag cycle reaches repository object {}",
                                object.oid
                            );
                        }
                        target = RefTarget::external_object(self.peel_tag_in_state(state, object)?);
                    }
                    ExternalObjectKind::Tree | ExternalObjectKind::Blob => {
                        anyhow::bail!(
                            "repository ref target {} is a {:?}, not a materializable change",
                            object.oid,
                            object.kind
                        );
                    }
                },
                RefTarget::Symbolic { target: name } => {
                    if !visited_refs.insert(name.clone()) {
                        anyhow::bail!("symbolic repository ref cycle reaches {name}");
                    }
                    target = state
                        .metadata()
                        .ref_state
                        .refs
                        .iter()
                        .find(|repository_ref| repository_ref.name == name)
                        .map(|repository_ref| repository_ref.target.clone())
                        .ok_or_else(|| anyhow!("symbolic repository ref {name} is absent"))?;
                }
            }
        }
    }

    pub(crate) fn resolve_named_ref(&self, name: &RefName) -> Result<SemanticChangeId> {
        let lease = self.manager.read_authority();
        let repository_ref = lease
            .metadata()
            .ref_state
            .refs
            .iter()
            .find(|repository_ref| &repository_ref.name == name)
            .ok_or_else(|| anyhow!("repository ref '{name}' was not found"))?;
        self.resolve_target_in_state(&lease, &repository_ref.target)
    }

    pub(crate) fn current_change_id(&self) -> Result<Option<SemanticChangeId>> {
        let lease = self.manager.read_authority();
        lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == self.workspace_id)
            .ok_or_else(|| {
                anyhow!(
                    "repository {} has no workspace {} in repository-v6 authority",
                    self.repository_id,
                    self.workspace_id
                )
            })?
            .base_target
            .as_ref()
            .map(|target| self.resolve_target_in_state(&lease, target))
            .transpose()
    }

    pub(crate) fn resolve_git_oid(&self, oid: &GitObjectId) -> Result<SemanticChangeId> {
        let lease = self.manager.read_authority();
        lease
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

    fn peel_tag_in_state(
        &self,
        state: &RepositoryAuthorityState,
        object: ExternalObjectId,
    ) -> Result<ExternalObjectId> {
        let record = state
            .metadata()
            .external_objects
            .iter()
            .find(|record| record.object == object)
            .ok_or_else(|| {
                anyhow!(
                    "external tag {} has no repository-v6 object record",
                    object.oid
                )
            })?;
        let body = self.load_source_blob(record.body_hash)?;
        let git_authority = state
            .metadata()
            .git_external_authority
            .as_ref()
            .ok_or_else(|| {
                anyhow!(
                    "external tag {} has no repository-v6 Git authority",
                    object.oid
                )
            })?;
        let decoded = decode_git_external_object(git_authority.object_format, record, &body)
            .with_context(|| format!("decode repository-v6 external tag {}", object.oid))?;
        let mut targets = decoded.dependencies.iter().filter_map(|dependency| {
            (dependency.kind == GitObjectDependencyKind::TagTarget).then_some(dependency.target)
        });
        let target = targets
            .next()
            .ok_or_else(|| anyhow!("external tag {} has no exact target", object.oid))?;
        if targets.next().is_some() {
            anyhow::bail!("external tag {} has multiple exact targets", object.oid);
        }
        Ok(target)
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
