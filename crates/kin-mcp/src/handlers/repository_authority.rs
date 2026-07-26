// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Read-only access to the active repository-v6 authority.
//!
//! MCP handlers must not reconstruct refs, workspace state, aliases, or source
//! bytes from legacy sidecars or the working directory. This module opens one
//! durable repository authority and provides the small set of fail-closed
//! lookups the handlers need.

use std::collections::BTreeSet;
use std::sync::Arc;

use kin_db::{LocalFileBackend, RepositoryAuthorityManager};
use kin_model::{
    ExternalObjectKind, GitObjectId, RefName, RefTarget, RepositoryId, RepositoryRef,
    SemanticChangeId, WorkspaceId, WorkspaceState,
};

use crate::error::{McpError, Result};

pub(crate) struct ActiveRepositoryAuthority {
    manager: RepositoryAuthorityManager<LocalFileBackend>,
    pub repository_id: RepositoryId,
    pub workspace_id: WorkspaceId,
}

impl ActiveRepositoryAuthority {
    pub(crate) fn open(layout: &kin_core::KinLayout) -> Result<Self> {
        let manifest = kin_core::KinManifest::load(&layout.manifest_path()).map_err(|error| {
            McpError::Context(format!(
                "graph authority gap: cannot load repository manifest: {error}"
            ))
        })?;
        let repository_id = RepositoryId::new(manifest.repo_id).map_err(|error| {
            McpError::Context(format!(
                "graph authority gap: repository manifest has an invalid identity: {error}"
            ))
        })?;
        let workspace_uuid = uuid::Uuid::parse_str(&manifest.workspace_id).map_err(|error| {
            McpError::Context(format!(
                "graph authority gap: repository manifest has an invalid workspace identity: \
                 {error}"
            ))
        })?;
        let workspace_id = WorkspaceId::from_uuid(workspace_uuid);
        let manager = RepositoryAuthorityManager::open(
            repository_id.clone(),
            Arc::new(LocalFileBackend::new(layout.kindb_dir())),
        )
        .map_err(|error| {
            McpError::Context(format!(
                "graph authority gap: cannot open repository authority: {error}"
            ))
        })?;

        Ok(Self {
            manager,
            repository_id,
            workspace_id,
        })
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
                McpError::Context(format!(
                    "graph authority gap: repository {} has no workspace {}",
                    self.repository_id, self.workspace_id
                ))
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

    pub(crate) fn repository_refs(&self) -> Vec<RepositoryRef> {
        self.manager
            .read_authority()
            .metadata()
            .ref_state
            .refs
            .clone()
    }

    pub(crate) fn default_ref(&self) -> Option<RefName> {
        self.manager
            .read_authority()
            .metadata()
            .ref_state
            .default_ref
            .clone()
    }

    pub(crate) fn resolve_target(&self, target: &RefTarget) -> Result<SemanticChangeId> {
        let mut target = target.clone();
        let mut visited = BTreeSet::new();
        loop {
            match target {
                RefTarget::Change { change_id } => return Ok(change_id),
                RefTarget::ExternalObject { object } => {
                    if object.kind != ExternalObjectKind::Commit {
                        return Err(McpError::Context(format!(
                            "graph authority gap: external ref target {} is a {:?}, not a commit",
                            object.oid, object.kind
                        )));
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
                            McpError::Context(format!(
                                "graph authority gap: external commit {} has no repository alias",
                                object.oid
                            ))
                        });
                }
                RefTarget::Symbolic { target: name } => {
                    if !visited.insert(name.clone()) {
                        return Err(McpError::Context(format!(
                            "graph authority gap: symbolic repository ref cycle reaches {name}"
                        )));
                    }
                    target = self
                        .repository_ref(&name)
                        .map(|repository_ref| repository_ref.target)
                        .ok_or_else(|| {
                            McpError::Context(format!(
                                "graph authority gap: symbolic repository ref {name} is absent"
                            ))
                        })?;
                }
            }
        }
    }

    pub(crate) fn resolve_named_ref(&self, name: &RefName) -> Result<SemanticChangeId> {
        let repository_ref = self.repository_ref(name).ok_or_else(|| {
            McpError::InvalidParams(format!("repository ref '{name}' was not found"))
        })?;
        self.resolve_target(&repository_ref.target)
    }

    pub(crate) fn current_source_change_id(&self) -> Result<SemanticChangeId> {
        let workspace = self.workspace()?;
        let target = workspace.base_target.as_ref().ok_or_else(|| {
            McpError::Context(format!(
                "graph authority gap: workspace {} has an unborn head",
                workspace.workspace_id
            ))
        })?;
        self.resolve_target(target)
    }

    pub(crate) fn resolve_git_oid(&self, oid: GitObjectId) -> Result<SemanticChangeId> {
        self.manager
            .read_authority()
            .metadata()
            .aliases
            .iter()
            .find(|alias| alias.oid == oid)
            .map(|alias| alias.change_id)
            .ok_or_else(|| {
                McpError::InvalidParams(format!(
                    "Git commit '{oid}' has no imported repository alias"
                ))
            })
    }

    pub(crate) fn load_source_blob(&self, digest: kin_model::Hash256) -> Result<Vec<u8>> {
        self.manager
            .load_source_blob(digest)
            .map_err(|error| {
                McpError::Context(format!(
                    "graph authority gap: cannot load immutable source blob {digest}: {error}"
                ))
            })?
            .ok_or_else(|| {
                McpError::Context(format!(
                    "graph authority gap: immutable source blob {digest} is absent"
                ))
            })
    }
}

pub(crate) fn parse_branch_ref(value: &str) -> Result<RefName> {
    if value.starts_with("refs/") {
        RefName::from_utf8(value).map_err(|error| {
            McpError::InvalidParams(format!("invalid fully-qualified repository ref: {error}"))
        })
    } else {
        RefName::branch(value.as_bytes())
            .map_err(|error| McpError::InvalidParams(format!("invalid branch name: {error}")))
    }
}

pub(crate) fn parse_git_object_id(value: &str) -> Result<GitObjectId> {
    if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(McpError::InvalidParams(format!(
            "invalid Git object ID '{value}': expected hexadecimal bytes"
        )));
    }
    let bytes = hex::decode(value).map_err(|error| {
        McpError::InvalidParams(format!("invalid Git object ID '{value}': {error}"))
    })?;
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
        length => Err(McpError::InvalidParams(format!(
            "invalid Git object ID '{value}': expected 20 or 32 bytes, found {length}"
        ))),
    }
}
