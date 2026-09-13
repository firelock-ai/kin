// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Durable editing state, separate from parsed repository publication.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DraftSchema {
    #[serde(rename = "kin.entity.draft.v1")]
    V1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DraftOwner {
    #[serde(rename = "local-bearer-v1")]
    LocalBearerV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DraftScope {
    pub repository_id: kin_model::RepositoryId,
    pub workspace_id: kin_model::WorkspaceId,
    pub entity_id: kin_model::EntityId,
    pub owner: DraftOwner,
}

/// The original read is immutable. Draft text may be empty or syntactically
/// invalid; saving it never changes repository source or semantic authority.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntityDraft {
    pub schema: DraftSchema,
    pub draft_id: uuid::Uuid,
    pub revision: u64,
    pub content_revision: u64,
    pub scope: DraftScope,
    pub original_body: String,
    pub original_source_base: crate::source_base::EntitySourceBase,
    pub body: String,
    pub previous_record_hash: Option<String>,
    pub request_hash: String,
    pub pending_apply: Option<PendingDraftApply>,
    pub applied_receipt: Option<AppliedDraftReceipt>,
}

/// Written before dispatch. A restart must retry these exact arguments with
/// the same session and request ID instead of inventing another mutation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PendingDraftApply {
    pub requested_revision: u64,
    pub draft_revision: u64,
    pub session_id: uuid::Uuid,
    pub request_id: String,
    pub arguments: serde_json::Value,
}

/// Kept with the draft only after the authoritative mutation receipt is saved.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppliedDraftReceipt {
    pub attempt: PendingDraftApply,
    pub receipt: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DraftCreate {
    pub draft_id: uuid::Uuid,
    pub original_source_base: crate::source_base::EntitySourceBase,
    pub original_body: String,
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DraftSave {
    pub draft_id: uuid::Uuid,
    pub expected_revision: u64,
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DraftApply {
    pub draft_id: uuid::Uuid,
    pub expected_revision: u64,
    pub session_id: uuid::Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DraftRead {
    pub draft_id: uuid::Uuid,
    /// Omit for the latest saved revision. Explicit revisions permit recovery
    /// of earlier acknowledged text without pretending it is still latest.
    pub revision: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DraftList {
    pub entity_id: Option<kin_model::EntityId>,
    pub after: Option<uuid::Uuid>,
    pub limit: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DraftSummary {
    pub draft_id: uuid::Uuid,
    pub revision: u64,
    pub content_revision: u64,
    pub scope: DraftScope,
    pub body_bytes: usize,
    pub has_pending_apply: bool,
    pub has_applied_receipt: bool,
}

impl From<&EntityDraft> for DraftSummary {
    fn from(draft: &EntityDraft) -> Self {
        Self {
            draft_id: draft.draft_id,
            revision: draft.revision,
            content_revision: draft.content_revision,
            scope: draft.scope.clone(),
            body_bytes: draft.body.len(),
            has_pending_apply: draft.pending_apply.is_some(),
            has_applied_receipt: draft.applied_receipt.is_some(),
        }
    }
}

pub fn is_tool(name: &str) -> bool {
    matches!(
        name,
        "kin_draft_apply"
            | "kin_draft_capabilities"
            | "kin_draft_create"
            | "kin_draft_save"
            | "kin_draft_read"
            | "kin_draft_list"
    )
}

pub fn tool_definitions() -> Vec<crate::types::ToolDefinition> {
    use serde_json::json;
    [
        ("kin_draft_apply", "Explicitly apply a saved draft through a durable guarded mutation. The first attempt persists its exact body, source base, session and request ID before dispatch. If an attempt is pending, this only resumes that original attempt, even when Save has advanced the draft. The response identifies the attempted content revision and whether current text was applied. A stale original base requires a fresh draft from a current read; old text and history remain intact.", true,
            json!({"draft_id":{"type":"string","format":"uuid"},"expected_revision":{"type":"integer","minimum":1},"session_id":{"type":"string","format":"uuid"}}), vec!["draft_id","expected_revision","session_id"]),
        ("kin_draft_capabilities", "Check durable draft availability before offering Save. Reports actual directory synchronization support, storage quotas, and Apply availability. Authentication and an initialized local repository are required.", false, json!({}), vec![]),
        ("kin_draft_create", "Save a new durable entity draft, including empty or invalid text. Supply a stable client-generated draft UUID so a lost reply can be retried unchanged. Preserve the complete original body and source_base from a current source read. This saves editing state without publishing repository source.", true,
            json!({"draft_id":{"type":"string","format":"uuid"},"original_source_base":crate::source_base::source_base_schema(),"original_body":{"type":"string"},"body":{"type":"string"}}), vec!["draft_id","original_source_base","original_body","body"]),
        ("kin_draft_save", "Save exact draft text with revision compare-and-swap. Empty and invalid text are preserved. A conflicting revision leaves both versions intact for the caller to resolve. Retrying the same draft/revision/text returns its original saved revision, even after later saves. Saving does not apply repository changes.", true,
            json!({"draft_id":{"type":"string","format":"uuid"},"expected_revision":{"type":"integer","minimum":1},"body":{"type":"string"}}), vec!["draft_id","expected_revision","body"]),
        ("kin_draft_read", "Read a durable entity draft without requiring its entity to still exist or its editing session to remain active. Omit revision for the latest saved draft; name an earlier revision to recover earlier acknowledged text. Authentication is still required.", false,
            json!({"draft_id":{"type":"string","format":"uuid"},"revision":{"type":"integer","minimum":1}}), vec!["draft_id"]),
        ("kin_draft_list", "List durable entity drafts for this repository, workspace and local bearer owner, including drafts whose target entities were deleted. Results are ordered by draft UUID; pass next_cursor as after for the next page. The response identifies unresolved recovery evidence.", false,
            json!({"entity_id":{"type":"string","format":"uuid"},"after":{"type":"string","format":"uuid"},"limit":{"type":"integer","minimum":1,"maximum":200,"default":50}}), vec![]),
    ].into_iter().map(|(name, description, writes, properties, required)| crate::types::ToolDefinition {
        name: name.into(), description: description.into(),
        input_schema: json!({"type":"object","properties":properties,"required":required,"additionalProperties":false}),
        annotations: crate::types::ToolAnnotations {
            title: name.replace('_', " "), read_only_hint: !writes, destructive_hint: name == "kin_draft_apply",
            idempotent_hint: true, open_world_hint: false,
        },
    }).collect()
}

pub(crate) async fn forward(
    name: &str,
    arguments: &std::collections::HashMap<String, serde_json::Value>,
) -> crate::error::Result<crate::ToolCallResult> {
    match crate::daemon_delegate::forward_tool_call(name, arguments).await {
        Ok(Some(result)) => Ok(result),
        Ok(None) => Ok(crate::ToolCallResult::error("Durable drafts require the authenticated repository daemon. Start it and retry; no draft was saved.")),
        Err(error) => Ok(crate::ToolCallResult::error(error.to_string())),
    }
}
