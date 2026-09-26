// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Caller-read expectations, checked before the exact commit publication fence.

use kin_model::EntityStore;

/// Which caller-read expectation a transaction broke.
#[derive(Debug)]
pub(crate) enum StaleBase {
    /// An entity's source changed since the caller read it.
    Source(String),
    /// Repository authority moved since the caller observed the repository
    /// base a unit-addressed operation carries.
    Repository(String),
}

impl StaleBase {
    /// The machine-readable refusal for this conflict. A repository-base
    /// conflict carries the base authority holds now, so the caller retries in
    /// one step.
    pub(crate) fn refusal(
        &self,
        transaction_id: &str,
        current: Option<&kin_mcp::source_unit::RepositoryBase>,
        operations: &[kin_mcp::McpMutationOperation],
    ) -> String {
        match self {
            Self::Source(reason) => {
                kin_mcp::source_base::source_base_conflict(transaction_id, reason)
            }
            Self::Repository(reason) => {
                let source_reads = operations
                    .iter()
                    .enumerate()
                    .filter_map(|(index, operation)| {
                        entity_source_base(operation).map(|base| (index, base.entity_id))
                    })
                    .collect::<Vec<_>>();
                kin_mcp::source_unit::repository_base_conflict(
                    transaction_id,
                    reason,
                    current,
                    &source_reads,
                )
            }
        }
    }
}

/// The entity source base an operation carries, if any.
fn entity_source_base(
    operation: &kin_mcp::McpMutationOperation,
) -> Option<&kin_mcp::source_base::EntitySourceBase> {
    match &operation.payload {
        Some(kin_mcp::McpMutationPayload::EntitySourceBase(expected))
        | Some(kin_mcp::McpMutationPayload::EntitySourcePatch(
            kin_mcp::source_base::EntitySourcePatch {
                source_base: expected,
                ..
            },
        ))
        | Some(kin_mcp::McpMutationPayload::EntityCreate(
            kin_mcp::entity_lifecycle::EntityCreate {
                source_base: Some(expected),
                ..
            },
        ))
        | Some(kin_mcp::McpMutationPayload::EntityRemove(
            kin_mcp::entity_lifecycle::EntityRemove {
                source_base: expected,
            },
        )) => Some(expected),
        _ => None,
    }
}

pub(crate) fn require_source_bases(
    context: &crate::local_repository_authority::LocalRepositoryAuthorityContext,
    authority: &kin_db::RepositoryAuthorityManager<kin_db::LocalFileBackend>,
    base: &crate::repository_commit::NativeCommitBase,
    operations: &[kin_mcp::McpMutationOperation],
) -> Result<(), StaleBase> {
    let repository_bases = operations
        .iter()
        .filter_map(crate::unit_lifecycle::repository_base)
        .collect::<Vec<_>>();
    if !repository_bases.is_empty() {
        let lease = authority.read_authority();
        if lease.roots() != &base.roots {
            return Err(StaleBase::Repository(
                "repository authority changed while preparing the repository-base check".into(),
            ));
        }
        let workspace = lease
            .metadata()
            .workspaces
            .iter()
            .find(|workspace| workspace.workspace_id == context.workspace_id())
            .ok_or_else(|| {
                StaleBase::Repository("the selected workspace no longer exists".into())
            })?;
        let current = kin_mcp::source_base::SourceBaseContext::from_workspace(workspace)
            .map_err(StaleBase::Repository)?;
        // Unit work is planned against the workspace tree, so the base names
        // the tree and head the caller observed. A generation that advanced
        // over the same tree and head (a toolchain run that published nothing)
        // changed nothing the work is planned against and is not a conflict.
        for expected in repository_bases {
            let observed = &expected.context;
            if observed.repository_id != current.repository_id
                || observed.repository_id != context.repository_id().as_str()
                || observed.workspace_id != current.workspace_id
                || observed.workspace_head_hash != current.workspace_head_hash
                || observed.workspace_tree_hash != current.workspace_tree_hash
            {
                return Err(StaleBase::Repository(format!(
                    "the repository, workspace, branch or workspace tree changed since the \
                     repository_base was read (it names workspace generation {}, and the \
                     workspace is now at generation {})",
                    observed.workspace_generation, current.workspace_generation
                )));
            }
        }
    }
    require_entity_source_bases(context, authority, base, operations).map_err(StaleBase::Source)
}

fn require_entity_source_bases(
    context: &crate::local_repository_authority::LocalRepositoryAuthorityContext,
    authority: &kin_db::RepositoryAuthorityManager<kin_db::LocalFileBackend>,
    base: &crate::repository_commit::NativeCommitBase,
    operations: &[kin_mcp::McpMutationOperation],
) -> Result<(), String> {
    let expected = operations
        .iter()
        .filter_map(|operation| match &operation.payload {
            Some(kin_mcp::McpMutationPayload::EntitySourceBase(expected))
            | Some(kin_mcp::McpMutationPayload::EntitySourcePatch(
                kin_mcp::source_base::EntitySourcePatch {
                    source_base: expected,
                    ..
                },
            ))
            | Some(kin_mcp::McpMutationPayload::EntityCreate(
                kin_mcp::entity_lifecycle::EntityCreate {
                    source_base: Some(expected),
                    ..
                },
            ))
            | Some(kin_mcp::McpMutationPayload::EntityRemove(
                kin_mcp::entity_lifecycle::EntityRemove {
                    source_base: expected,
                },
            )) => Some(expected),
            _ => None,
        })
        .collect::<Vec<_>>();
    if expected.is_empty() {
        return Ok(());
    }
    // The caller holds coordination_gate and the authority mutation guard. The
    // root check also refuses a base displaced by another authority writer.
    let lease = authority.read_authority();
    if lease.roots() != &base.roots {
        return Err("repository authority changed while preparing the source-base check".into());
    }
    let workspace = lease
        .metadata()
        .workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == context.workspace_id())
        .ok_or("the selected workspace no longer exists")?;
    let current = kin_mcp::source_base::SourceBaseContext::from_workspace(workspace)?;
    for expected in expected {
        if expected.context != current
            || expected.context.repository_id != context.repository_id().as_str()
        {
            return Err(format!("repository, workspace, branch or workspace revision changed since entity {} was read", expected.entity_id));
        }
        let entity = base
            .graph
            .get_entity(&expected.entity_id)
            .map_err(|error| error.to_string())?
            .ok_or_else(|| format!("entity {} no longer exists", expected.entity_id))?;
        kin_model::require_independent_source(&entity)?;
        let span = entity
            .span
            .as_ref()
            .ok_or("the entity no longer has an exact source span")?;
        let origin = entity
            .file_origin
            .as_ref()
            .ok_or("the entity no longer has a source artifact")?;
        if &span.file != origin
            || span.start_byte != expected.start_byte
            || span.end_byte != expected.end_byte
        {
            return Err(format!(
                "the source span for entity {} changed",
                expected.entity_id
            ));
        }
        let path =
            kin_model::RepoPath::from_utf8(origin.0.clone()).map_err(|error| error.to_string())?;
        let artifact = base
            .tree
            .artifact_at_path(&path)
            .ok_or("the source artifact no longer exists")?;
        let kin_model::TreeEntry::Blob { hash, .. } = artifact.entry else {
            return Err("the source artifact is no longer a regular blob".into());
        };
        if artifact.artifact_id != expected.artifact_id
            || hash.to_string() != expected.source_blob_hash
        {
            return Err(format!(
                "the source artifact or bytes for entity {} changed",
                expected.entity_id
            ));
        }
        let body = crate::repository_commit::load_native_source_blob(context, hash)
            .map_err(|error| error.to_string())?;
        let bytes = body
            .get(span.start_byte..span.end_byte)
            .ok_or("the source span is outside its artifact")?;
        if kin_blobs::digest(bytes).to_string() != expected.body_hash {
            return Err(format!(
                "the exact body for entity {} differs from the caller's source read",
                expected.entity_id
            ));
        }
    }
    Ok(())
}
