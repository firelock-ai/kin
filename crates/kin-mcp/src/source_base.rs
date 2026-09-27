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

/// One local workspace instant. V1 conservatively refuses any advance of the
/// workspace head or tree, including unrelated edits. A generation that
/// advanced over the same head and tree, such as language-server enrichment
/// publishing what it proved, changed no source bytes and is not a conflict.
/// A generation alone cannot identify a repository or distinguish branches
/// with identical source bytes.
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

    /// Well-formed identity: a repository id, a workspace UUID and two
    /// lowercase BLAKE3 hex digests. Freshness is the daemon's check.
    pub fn validate(&self) -> Result<(), String> {
        kin_model::RepositoryId::new(self.repository_id.clone())
            .map_err(|error| error.to_string())?;
        uuid::Uuid::parse_str(&self.workspace_id).map_err(|error| error.to_string())?;
        for hash in [&self.workspace_head_hash, &self.workspace_tree_hash] {
            if !is_lower_hex_digest(hash) {
                return Err("source base hashes must be 64 lowercase hex characters".into());
            }
        }
        Ok(())
    }
}

fn is_lower_hex_digest(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

/// An exact replacement within the original entity body. Anchors are literal
/// UTF-8 text, not regexes, offsets, or instructions to search working files.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntityTextEdit {
    pub old_text: String,
    pub new_text: String,
}

/// Compact guarded source editing. Every anchor addresses the same original
/// body; replacements never become input to later anchors in the batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntitySourcePatch {
    pub source_base: EntitySourceBase,
    pub edits: Vec<EntityTextEdit>,
}

impl EntitySourcePatch {
    pub fn validate(&self) -> Result<(), String> {
        self.source_base.validate()?;
        if self.edits.is_empty() {
            return Err("an entity patch requires at least one exact text edit".into());
        }
        for (index, edit) in self.edits.iter().enumerate() {
            if edit.old_text.is_empty() {
                return Err(format!("patch edit #{index}: old_text must be nonempty"));
            }
            if edit.old_text == edit.new_text {
                return Err(format!("patch edit #{index}: replacement is a no-op"));
            }
        }
        Ok(())
    }

    /// Apply only to the exact body bound by the source base. The daemon also
    /// checks the repository/workspace/artifact binding under authority locks.
    pub fn apply_to_exact_body(&self, body: &str) -> Result<String, String> {
        self.validate()?;
        if body.len() != self.source_base.end_byte - self.source_base.start_byte
            || kin_blobs::digest(body.as_bytes()).to_string() != self.source_base.body_hash
        {
            return Err("entity patch body differs from its source_base".into());
        }
        let mut replacements = Vec::with_capacity(self.edits.len());
        for (index, edit) in self.edits.iter().enumerate() {
            let start = body.find(&edit.old_text).ok_or_else(|| {
                format!("patch edit #{index}: old_text is absent from the original entity body")
            })?;
            // Search again one character after the first match, not after its
            // end: overlapping occurrences ("aa" in "aaa") are ambiguous too.
            let next = start + edit.old_text.chars().next().unwrap().len_utf8();
            if body[next..].contains(&edit.old_text) {
                return Err(format!(
                    "patch edit #{index}: old_text is ambiguous in the original entity body"
                ));
            }
            replacements.push((start, start + edit.old_text.len(), index, &edit.new_text));
        }
        replacements.sort_by_key(|(start, _, _, _)| *start);
        for pair in replacements.windows(2) {
            if pair[0].1 > pair[1].0 {
                return Err(format!(
                    "patch edits #{} and #{} overlap in the original entity body",
                    pair[0].2, pair[1].2
                ));
            }
        }
        let mut patched = body.to_owned();
        for (start, end, _, replacement) in replacements.into_iter().rev() {
            patched.replace_range(start..end, replacement);
        }
        if patched == body {
            return Err("entity patch is a no-op".into());
        }
        Ok(patched)
    }
}

pub fn entity_source_patch_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "properties": {
            "source_base": source_base_schema(),
            "edits": {
                "type": "array", "minItems": 1,
                "description": "Exact unique nonoverlapping anchors in the original entity body. All edits use that same original body, not earlier replacements.",
                "items": {
                    "type": "object",
                    "properties": {
                        "old_text": { "type": "string", "minLength": 1 },
                        "new_text": { "type": "string" }
                    },
                    "required": ["old_text", "new_text"],
                    "additionalProperties": false
                }
            }
        },
        "required": ["source_base", "edits"],
        "additionalProperties": false
    })
}

impl EntitySourceBase {
    pub fn from_exact_body(
        context: SourceBaseContext,
        entity: &kin_model::Entity,
        artifact_id: kin_model::ArtifactId,
        source_blob_hash: kin_model::Hash256,
        body: &str,
    ) -> Result<Self, String> {
        kin_model::require_independent_source(entity)?;
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
        self.context.validate()?;
        for hash in [&self.source_blob_hash, &self.body_hash] {
            if !is_lower_hex_digest(hash) {
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

/// Why a current source read issued no `source_base`: the entity's span carries no
/// recorded source digest, so the bytes it cuts cannot be proven to be the entity's.
///
/// A whole-entity replacement requires a source base, so this names the state as a
/// stable code a caller can tell apart from `source_base_required`, which means only
/// that a base was omitted. Entities derived before source digests were recorded carry
/// none until the repository is re-derived. An older repository may need
/// `kin upgrade`; the current read must actually issue a base before a guarded edit.
pub const SOURCE_BASE_UNAVAILABLE_UNVERIFIED: &str = "source_base_unavailable: this entity's \
span is unverified against its file's bytes, because the graph recorded no source digest for \
it, so no source_base was issued and Kin cannot guard a change to it. Stop and report this \
gap rather than sending an unguarded change. An older repository may need `kin upgrade`; \
reread afterward and proceed only if Kin issues a source_base. If the repository is already \
current or the base remains unavailable, report the unresolved source verification gap.";

/// Machine-readable refusal, emitted only after the unchanged staged work is durable.
pub fn source_base_conflict(transaction_id: &str, reason: &str) -> String {
    serde_json::json!({
        "schema": "kin.entity.source_base_conflict.v1",
        "code": "source_base_conflict",
        "transaction_id": transaction_id,
        "applied": false,
        "staged_operations_retained": true,
        "reason": reason,
        "remedy": "One fresh get_entity_source read and a resend is the fix: read the current entity, compare it with your retained draft, and submit the resolved work with the source_base that read returned, unchanged, in a new transaction (and a new request_id for a keyed mutation). The stale transaction remains available until you explicitly abort it."
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

#[cfg(test)]
mod patch_tests {
    use super::*;

    fn patch(body: &str, edits: &[(&str, &str)]) -> EntitySourcePatch {
        EntitySourcePatch {
            source_base: EntitySourceBase {
                schema: SourceBaseSchema::V1,
                context: SourceBaseContext {
                    repository_id: "patch-test".into(),
                    workspace_id: uuid::Uuid::new_v4().to_string(),
                    workspace_generation: 1,
                    workspace_head_hash: "a".repeat(64),
                    workspace_tree_hash: "b".repeat(64),
                },
                entity_id: kin_model::EntityId::new(),
                artifact_id: kin_model::ArtifactId::new(),
                source_blob_hash: "c".repeat(64),
                start_byte: 0,
                end_byte: body.len(),
                body_hash: kin_blobs::digest(body.as_bytes()).to_string(),
            },
            edits: edits
                .iter()
                .map(|(old, new)| EntityTextEdit {
                    old_text: (*old).into(),
                    new_text: (*new).into(),
                })
                .collect(),
        }
    }

    #[test]
    fn entity_patch_applies_original_body_anchors_and_utf8_exactly() {
        let body = "café a=1 b=2 suffix";
        let patch = patch(
            body,
            &[("1", "2"), ("2", "3"), ("café", "😀"), (" suffix", "")],
        );
        assert_eq!(patch.apply_to_exact_body(body).unwrap(), "😀 a=2 b=3");
    }

    #[test]
    fn entity_patch_rejects_missing_ambiguous_and_overlapping_anchors() {
        for (body, edits, reason) in [
            ("abc", vec![("z", "x")], "absent"),
            ("aaa", vec![("aa", "x")], "ambiguous"),
            ("ééé", vec![("éé", "x")], "ambiguous"),
            ("abc", vec![("ab", "x"), ("bc", "y")], "overlap"),
            ("abc", vec![("ab", "x"), ("ab", "y")], "overlap"),
            ("abc", vec![("a", "x"), ("x", "y")], "absent"),
        ] {
            assert!(patch(body, &edits)
                .apply_to_exact_body(body)
                .unwrap_err()
                .contains(reason));
        }
    }

    #[test]
    fn entity_patch_rejects_stale_body_empty_and_noop_edits() {
        assert!(patch("abc", &[("a", "z")])
            .apply_to_exact_body("abd")
            .unwrap_err()
            .contains("source_base"));
        assert!(patch("abc", &[]).validate().is_err());
        assert!(patch("abc", &[("", "x")]).validate().is_err());
        assert!(patch("abc", &[("a", "a")])
            .validate()
            .unwrap_err()
            .contains("no-op"));
        // Individually different, adjacent replacements can still cancel out.
        assert!(patch("abc", &[("a", "ab"), ("bc", "c")])
            .apply_to_exact_body("abc")
            .unwrap_err()
            .contains("no-op"));
    }

    #[test]
    fn entity_patch_decoder_and_staging_fail_closed() {
        let patch = patch("abc", &[("a", "z")]);
        let operation = serde_json::json!({
            "verb":"patch", "target":patch.source_base.entity_id,
            "payload":{"EntitySourcePatch":patch}, "description":"localized edit"
        });
        let decode = |op| crate::session::parse_staged_operations(&serde_json::json!([op]));
        let valid = decode(operation.clone()).unwrap();
        crate::session::validate_staged_operations(&valid).unwrap();
        assert!(
            crate::session::carries_source_body(&valid[0]),
            "offline commits must refuse patches as source writes"
        );
        for pointer in [
            "/payload/EntitySourcePatch/unknown",
            "/payload/EntitySourcePatch/edits/0/unknown",
            "/payload/EntitySourcePatch/source_base/unknown",
        ] {
            let mut bad = operation.clone();
            let (parent, key) = pointer.rsplit_once('/').unwrap();
            bad.pointer_mut(parent)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert(key.into(), serde_json::json!(true));
            assert!(
                decode(bad).is_err(),
                "unknown field {pointer} must not disappear"
            );
        }
        for (field, value) in [
            ("verb", serde_json::json!("update")),
            ("target", serde_json::json!("abc")),
            ("body", serde_json::json!("")),
            ("destination", serde_json::json!("x.rs")),
        ] {
            let mut bad = operation.clone();
            bad[field] = value;
            assert!(decode(bad)
                .and_then(|ops| crate::session::validate_staged_operations(&ops))
                .is_err());
        }
        for field in ["body", "destination"] {
            let mut bad = operation.clone();
            bad[field] = serde_json::Value::Null;
            assert!(decode(bad).is_err(), "explicit null {field} must refuse");
        }
        let mut bad = operation.clone();
        bad["payload"]["EntitySourcePatch"]["source_base"]["schema"] =
            serde_json::json!("kin.entity.source_base.v2");
        assert!(decode(bad).is_err());
        let mut bad = operation;
        bad["payload"]["EntitySourcePatch"]
            .as_object_mut()
            .unwrap()
            .remove("source_base");
        assert!(decode(bad).is_err());
    }
}
