// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Caller-read expectations, checked before the exact commit publication fence.

use kin_model::EntityStore;

pub(crate) fn require_source_bases(
    context: &crate::local_repository_authority::LocalRepositoryAuthorityContext,
    authority: &kin_db::RepositoryAuthorityManager<kin_db::LocalFileBackend>,
    base: &crate::repository_commit::NativeCommitBase,
    operations: &[kin_mcp::McpMutationOperation],
) -> Result<(), String> {
    let expected = operations
        .iter()
        .filter_map(|operation| match &operation.payload {
            Some(kin_mcp::McpMutationPayload::EntitySourceBase(expected)) => Some(expected),
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
