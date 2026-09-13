// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The exact source a caller read, carried unchanged into a guarded body edit.
//! This is an optimistic concurrency expectation, not an authorization token.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceBaseSchema {
    #[serde(rename = "kin.entity.source_base.v1")]
    V1,
}

/// One local workspace instant. V1 conservatively refuses any workspace advance,
/// including unrelated edits. A generation alone cannot identify a repository
/// or distinguish branches with identical source bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceBaseContext {
    pub repository_id: String,
    pub workspace_id: String,
    pub workspace_generation: u64,
    pub workspace_head_hash: String,
    pub workspace_tree_hash: String,
}

impl SourceBaseContext {
    pub fn from_workspace(workspace: &kin_model::WorkspaceState) -> Result<Self, String> {
        let head = serde_json::to_vec(&workspace.head).map_err(|error| error.to_string())?;
        Ok(Self {
            repository_id: workspace.repository_id.to_string(),
            workspace_id: workspace.workspace_id.to_string(),
            workspace_generation: workspace.generation,
            workspace_head_hash: kin_blobs::digest(&head).to_string(),
            workspace_tree_hash: workspace.tree_hash.to_string(),
        })
    }
}

/// Closed, versioned identity of the complete entity body served by Kin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntitySourceBase {
    pub schema: SourceBaseSchema,
    pub context: SourceBaseContext,
    pub entity_id: kin_model::EntityId,
    pub artifact_id: kin_model::ArtifactId,
    pub source_blob_hash: String,
    pub start_byte: usize,
    pub end_byte: usize,
    pub body_hash: String,
}

impl EntitySourceBase {
    pub fn from_exact_body(
        context: SourceBaseContext,
        entity: &kin_model::Entity,
        artifact_id: kin_model::ArtifactId,
        source_blob_hash: kin_model::Hash256,
        body: &str,
    ) -> Result<Self, String> {
        let span = entity
            .span
            .as_ref()
            .ok_or("source base requires an exact span")?;
        let base = Self {
            schema: SourceBaseSchema::V1,
            context,
            entity_id: entity.id,
            artifact_id,
            source_blob_hash: source_blob_hash.to_string(),
            start_byte: span.start_byte,
            end_byte: span.end_byte,
            body_hash: kin_blobs::digest(body.as_bytes()).to_string(),
        };
        base.validate()?;
        if body.len() != span.end_byte - span.start_byte {
            return Err("source body length differs from its exact span".into());
        }
        Ok(base)
    }

    pub fn validate(&self) -> Result<(), String> {
        kin_model::RepositoryId::new(self.context.repository_id.clone())
            .map_err(|error| error.to_string())?;
        uuid::Uuid::parse_str(&self.context.workspace_id).map_err(|error| error.to_string())?;
        for hash in [
            &self.context.workspace_head_hash,
            &self.context.workspace_tree_hash,
            &self.source_blob_hash,
            &self.body_hash,
        ] {
            if hash.len() != 64
                || !hash
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            {
                return Err("source base hashes must be 64 lowercase hex characters".into());
            }
        }
        if self.start_byte >= self.end_byte {
            return Err("source base must name a nonempty exact byte span".into());
        }
        Ok(())
    }
}

pub(crate) fn source_base_for_read<G: kin_model::GraphStore>(
    held: &crate::handlers::common::HeldSourceAuthority<'_, G>,
    entity: &kin_model::Entity,
    source: &crate::handlers::common::ExactEntitySource,
) -> crate::error::Result<Option<EntitySourceBase>> {
    use crate::handlers::common::SpanCoherence;
    if source.span_coherence == SpanCoherence::Unverified {
        return Ok(None);
    }
    let Some(context) = held.workspace_sample()?.source_base_context.clone() else {
        // Hosted/historical source has no local workspace to mutate.
        return Ok(None);
    };
    let kin_model::TreeEntry::Blob { hash, .. } = source.entry else {
        return Ok(None);
    };
    let base =
        EntitySourceBase::from_exact_body(context, entity, source.artifact_id, hash, &source.body)
            .map_err(crate::error::McpError::Context)?;
    Ok(Some(base))
}

/// Machine-readable refusal, emitted only after the unchanged staged work is durable.
pub fn source_base_conflict(transaction_id: &str, reason: &str) -> String {
    serde_json::json!({
        "schema": "kin.entity.source_base_conflict.v1",
        "code": "source_base_conflict",
        "transaction_id": transaction_id,
        "applied": false,
        "staged_operations_retained": true,
        "reason": reason,
        "remedy": "Read the current entity, compare it with your retained draft, and submit resolved work in a new transaction (and a new request_id for a keyed mutation). The stale transaction remains available until you explicitly abort it."
    }).to_string()
}

pub fn is_source_base_conflict(text: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(text).is_ok_and(|value| {
        value["schema"] == "kin.entity.source_base_conflict.v1"
            && value["code"] == "source_base_conflict"
            && value["applied"] == false
            && value["staged_operations_retained"] == true
    })
}

/// The schema used by MCP discovery and mirrored by boundary-contracts.
/// Keep a crate-local copy so published kin-mcp sources are self-contained.
pub fn source_base_schema() -> serde_json::Value {
    serde_json::from_str(include_str!("source_base.schema.json"))
        .expect("the checked-in entity source base schema is valid JSON")
}
