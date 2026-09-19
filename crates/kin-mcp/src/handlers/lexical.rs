// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Literal membership over graph-owned stored entity fields.
//!
//! Enumerates the complete kind-filtered entity set, then checks the six
//! stored fields directly. This is independent of BM25 tokenization, candidate
//! limits, and derived-index commit/rebuild state. It scans and materializes the
//! scoped graph on every page; the page size bounds the response, not the work.
//!
//! A cursor names the canonical contents of the matching entity set, not a
//! whole-graph revision. Exact source-line enrichment is best effort and only
//! accepts a source body whose coherence with the entity span is verified.
//! No filesystem search or structural-reference claim is involved.

use std::collections::HashMap;

use base64::Engine;
use serde_json::{json, Value};

use kin_model::entity::{Entity, EntityRole};
use kin_model::graph::{EntityFilter, GraphStore};

use super::common::{
    entity_presentation_end_line, entity_presentation_start_line, entity_read_path,
    parse_kind_filter, presentation_line, read_entity_source_exact, HeldSourceAuthority,
    SpanCoherence,
};
use super::repository_authority::RequestRepositoryAuthority;
use crate::error::{McpError, Result};
use crate::types::ToolCallResult;

/// The name this tool is registered and dispatched under.
pub const TOOL_NAME: &str = "lexical_lookup";

pub const LEXICAL_LOOKUP_DESC: &str = "\
Find exact literals, including punctuation, in stored graph fields: entity name, signature, \
doc summary, source body preview, and file import/surface context. Matching folds ASCII \
case only. This enumerates all entities in the requested kind scope and checks those fields \
directly; it does not depend on the lexical index. Previews may be sampled or truncated, \
file paths and unadmitted source are excluded, and a miss cannot prove repository absence. \
A hit is lexical evidence, never a resolved call or reference; use find_references or \
trace_data_flow for structural relationships. Pass the bare literal, not a question about it. \
Hits carry the matched field and excerpt; exact source lines require verified span/source \
coherence, otherwise only the stored entity span is supplied. Results are ordered by entity \
id, without a relevance score. limit bounds one page; total_matching is the exact count in \
these stored fields. Every page scans and materializes the scoped graph. A cursor binds the \
literal, kind and matching entity contents; changed results require a fresh lookup.";

/// The response key carrying this tool's disclosure: what stored fields do and
/// do not cover, and the caution that a hit is not a resolved reference.
pub const DISCLOSURE_KEY: &str = "disclosure";

/// The most hits one page may hold.
const DEFAULT_LIMIT: usize = 20;
const MAX_LIMIT: usize = 100;

const MAX_LITERAL_BYTES: usize = 4096;
const MAX_CURSOR_BYTES: usize = 65_536;
const CURSOR_VERSION: u64 = 1;

/// Byte ceiling passed to [`read_entity_source_exact`] when resolving a body
/// match's exact line. Generous: the body is read and thrown away after one
/// `find`, never returned, so the cost is paid once per hit on one page.
const EXACT_LINE_READ_MAX_BYTES: usize = 2_000_000;

/// The metadata key `kin-parser/src/extract.rs::embedding_body_preview` writes
/// its output under. Not re-exported at `kin_parser`'s crate root (only
/// `kin_parser::DECLARATION_LINE_KEY` and the file-context keys are), so this
/// is the same private local copy `kin-db/src/search/text.rs` keeps for the
/// same reason.
const EMBEDDING_BODY_PREVIEW_KEY: &str = "embedding_body_preview";

/// Which of an entity's own stored fields carried the literal, in the exact
/// priority order `kin-db/src/search/text.rs::entity_fields` weights them
/// (name highest, then signature, doc summary, body preview, import context,
/// surface context).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatchedField {
    Name,
    Signature,
    DocSummary,
    BodyPreview,
    FileImportContext,
    FileSurfaceContext,
}

const FIELD_PRIORITY: [MatchedField; 6] = [
    MatchedField::Name,
    MatchedField::Signature,
    MatchedField::DocSummary,
    MatchedField::BodyPreview,
    MatchedField::FileImportContext,
    MatchedField::FileSurfaceContext,
];

impl MatchedField {
    fn as_str(self) -> &'static str {
        match self {
            MatchedField::Name => "name",
            MatchedField::Signature => "signature",
            MatchedField::DocSummary => "doc_summary",
            MatchedField::BodyPreview => "body_preview",
            MatchedField::FileImportContext => "file_import_context",
            MatchedField::FileSurfaceContext => "file_surface_context",
        }
    }

    /// Whether a match on this field sits at the entity's own declaration
    /// line, so [`entity_presentation_start_line`] answers "the line where the
    /// literal occurs" exactly, with no source read. `false` for the three
    /// fields that are built from the entity's whole body or from file-level
    /// context rather than from its declaration line alone.
    fn anchored_at_declaration(self) -> bool {
        matches!(
            self,
            MatchedField::Name | MatchedField::Signature | MatchedField::DocSummary
        )
    }
}

/// One entity's own copy of the field `field` names, or `None` when the
/// entity carries nothing under that key.
fn field_text(entity: &Entity, field: MatchedField) -> Option<&str> {
    match field {
        MatchedField::Name => Some(entity.name.as_str()).filter(|text| !text.is_empty()),
        MatchedField::Signature => Some(entity.signature.as_str()).filter(|text| !text.is_empty()),
        MatchedField::DocSummary => entity.doc_summary.as_deref(),
        MatchedField::BodyPreview => entity
            .metadata
            .extra
            .get(EMBEDDING_BODY_PREVIEW_KEY)
            .and_then(Value::as_str),
        MatchedField::FileImportContext => entity
            .metadata
            .extra
            .get(kin_parser::FILE_IMPORT_CONTEXT_KEY)
            .and_then(Value::as_str),
        MatchedField::FileSurfaceContext => entity
            .metadata
            .extra
            .get(kin_parser::FILE_SURFACE_CONTEXT_KEY)
            .and_then(Value::as_str),
    }
}

/// The byte offset of `needle`'s first case-insensitive occurrence in
/// `haystack`, or `None`.
///
/// Folds ASCII letters only. Comparing only the ASCII range means the byte length of
/// `haystack` never shifts under folding the way a full Unicode lowercasing
/// pass can for some scripts, so the returned offset stays a valid index into
/// the ORIGINAL string, not a copy of it.
fn find_ascii_insensitive(haystack: &str, needle: &str) -> Option<usize> {
    let hay = haystack.as_bytes();
    let need = needle.as_bytes();
    if need.is_empty() || need.len() > hay.len() {
        return None;
    }
    (0..=(hay.len() - need.len())).find(|&start| {
        need.iter()
            .enumerate()
            .all(|(i, &b)| hay[start + i].eq_ignore_ascii_case(&b))
    })
}

/// The first stored field carrying the whole literal, in field priority order.
fn matched_field(entity: &Entity, literal: &str) -> Option<MatchedField> {
    FIELD_PRIORITY.into_iter().find(|&field| {
        field_text(entity, field)
            .is_some_and(|text| find_ascii_insensitive(text, literal).is_some())
    })
}

/// A short excerpt of the matched field's own text, centered on the literal.
fn excerpt(entity: &Entity, field: MatchedField, literal: &str) -> Option<String> {
    const RADIUS: usize = 80;
    let text = field_text(entity, field)?;
    let start = find_ascii_insensitive(text, literal)?;

    let mut lo = start.saturating_sub(RADIUS);
    while lo > 0 && !text.is_char_boundary(lo) {
        lo -= 1;
    }
    let mut hi = (start + literal.len() + RADIUS).min(text.len());
    while hi < text.len() && !text.is_char_boundary(hi) {
        hi += 1;
    }

    let mut out = String::new();
    if lo > 0 {
        out.push_str("... ");
    }
    out.push_str(text[lo..hi].trim());
    if hi < text.len() {
        out.push_str(" ...");
    }
    Some(out)
}

/// Best-effort exact line for a match outside the declaration (a body
/// preview, or file import/surface context), or `None` when it cannot be
/// confirmed.
///
/// The body preview stored on the entity has its whitespace collapsed to
/// single spaces at extraction time (`kin-parser/src/extract.rs`), which
/// means it carries no newlines to count: the technique that recovers a line
/// from a span's OWN bytes cannot be applied to that preview directly. This
/// instead reads the entity's real span bytes through the same graph-owned,
/// content-addressed source authority `get_entity_source` already reads
/// from, finds the literal's byte offset in that unmodified text, and counts
/// newlines up to it. Soft-fail throughout: no local authority binding, no
/// span, a literal the exact body does not confirm verbatim, or any read
/// error all read as "not confirmable" rather than failing the call --
/// resolving a hit's exact line is this tool's own best effort, never a
/// requirement of answering.
fn resolve_exact_line<G: GraphStore>(
    held: &HeldSourceAuthority<'_, G>,
    entity: &Entity,
    literal: &str,
) -> Option<u32> {
    let span = entity.span.as_ref()?;
    let exact = read_entity_source_exact(held, entity, EXACT_LINE_READ_MAX_BYTES).ok()??;
    if exact.span_coherence == SpanCoherence::Unverified {
        return None;
    }
    let offset = find_ascii_insensitive(&exact.body, literal)?;
    if !exact.body.is_char_boundary(offset) {
        return None;
    }
    let newlines_before = exact.body[..offset].matches('\n').count() as u32;
    Some(presentation_line(span.start_line + newlines_before))
}

/// The line to report for one hit, and how sure this tool is of it.
fn hit_line<G: GraphStore>(
    held: &HeldSourceAuthority<'_, G>,
    entity: &Entity,
    field: MatchedField,
    literal: &str,
) -> (Option<u32>, &'static str) {
    if field.anchored_at_declaration() {
        return (entity_presentation_start_line(entity), "declaration");
    }
    match resolve_exact_line(held, entity, literal) {
        Some(line) => (Some(line), "exact"),
        None => (None, "entity_span_only"),
    }
}

/// One verified occurrence from the graph-owned entity snapshot.
struct Hit {
    entity: Entity,
    field: MatchedField,
}

fn build_hit<G: GraphStore>(held: &HeldSourceAuthority<'_, G>, hit: &Hit, literal: &str) -> Value {
    let (line, line_confidence) = hit_line(held, &hit.entity, hit.field, literal);
    json!({
        "entity_id": hit.entity.id,
        "name": hit.entity.name,
        "kind": hit.entity.kind,
        "language": hit.entity.language,
        "file": entity_read_path(&hit.entity),
        "start_line": entity_presentation_start_line(&hit.entity),
        "end_line": entity_presentation_end_line(&hit.entity),
        "line": line,
        "line_confidence": line_confidence,
        "matched_field": hit.field.as_str(),
        "score": null,
        "excerpt": excerpt(&hit.entity, hit.field, literal),
    })
}

/// Scope and cost travel with every answer, including a zero-match answer.
fn disclosure(total_matching: usize) -> Value {
    json!({
        "answered_by": "stored_graph_fields",
        "matching": "ascii_case_insensitive_literal",
        "complete_for": "matching entities in the requested kind scope over these six stored fields",
        "detail": "Reads stored graph fields: name, signature, doc summary, source body preview, \
                   and file import/surface context. Body previews collapse whitespace and may be \
                   sampled beyond 8000 characters. File paths and unadmitted source are excluded. \
                   No derived text index is required. Exact source-line enrichment is accepted \
                   only when its bytes are verified against the entity span's provenance.",
        "cost": "Every page scans and materializes the scoped graph; limit bounds returned hits, not scan work.",
        "caution": if total_matching == 0 {
            "No matching stored graph field was found in this kind scope. This is not proof of \
             repository absence: previews are bounded, paths are excluded, and unadmitted source \
             is outside this enumeration."
        } else {
            "These are lexical occurrences in stored graph fields, not resolved references. A hit \
             does not mean the entity calls, imports, or is called by anything; use \
             find_references or trace_data_flow for that claim."
        },
    })
}

/// A versioned continuation over one matching-result snapshot. Encoding is
/// opaque for transport, not authentication; every supplied field is checked.
struct LexicalCursor {
    literal: String,
    kind: Option<String>,
    offset: usize,
    total: usize,
    snapshot: String,
}

impl LexicalCursor {
    fn encode(&self) -> String {
        let raw = json!({
            "v": CURSOR_VERSION,
            "l": self.literal,
            "k": self.kind,
            "o": self.offset,
            "t": self.total,
            "s": self.snapshot,
        })
        .to_string();
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
    }

    fn decode(token: &str) -> Option<Self> {
        if token.len() > MAX_CURSOR_BYTES {
            return None;
        }
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token)
            .ok()?;
        let value: Value = serde_json::from_slice(&bytes).ok()?;
        let object = value.as_object()?;
        if object.len() != 6 || value.get("v")?.as_u64()? != CURSOR_VERSION {
            return None;
        }
        let literal = value.get("l")?.as_str()?.to_string();
        if literal.trim().is_empty() || literal.len() > MAX_LITERAL_BYTES {
            return None;
        }
        let kind = match value.get("k")? {
            Value::Null => None,
            Value::String(kind) if !kind.is_empty() && kind.len() <= 64 => Some(kind.clone()),
            _ => return None,
        };
        let offset = usize::try_from(value.get("o")?.as_u64()?).ok()?;
        let total = usize::try_from(value.get("t")?.as_u64()?).ok()?;
        let snapshot = value.get("s")?.as_str()?.to_string();
        if offset == 0
            || offset >= total
            || snapshot.len() != 64
            || !snapshot.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return None;
        }
        Some(Self {
            literal,
            kind,
            offset,
            total,
            snapshot,
        })
    }
}

/// Continue immediately after the rows the response budget actually retained,
/// including a nominal final page that originally needed no continuation.
pub(crate) fn cursor_after_withheld(payload: &Value, kept: usize) -> Option<String> {
    let start = usize::try_from(payload.get("page_offset")?.as_u64()?).ok()?;
    let total = usize::try_from(payload.get("total_matching")?.as_u64()?).ok()?;
    let offset = start.checked_add(kept)?;
    if kept == 0 || offset >= total {
        return None;
    }
    let cursor = LexicalCursor {
        literal: payload.get("literal")?.as_str()?.to_string(),
        kind: match payload.get("kind")? {
            Value::Null => None,
            Value::String(kind) => Some(kind.clone()),
            _ => return None,
        },
        offset,
        total,
        snapshot: payload.get("matching_snapshot")?.as_str()?.to_string(),
    };
    let token = cursor.encode();
    LexicalCursor::decode(&token).map(|_| token)
}

fn optional_string(
    args: &HashMap<String, Value>,
    key: &str,
    max_bytes: usize,
) -> Result<Option<String>> {
    args.get(key)
        .map(|value| {
            let text = value
                .as_str()
                .ok_or_else(|| McpError::InvalidParams(format!("{key} must be a string")))?
                .trim();
            if text.is_empty() || text.len() > max_bytes {
                return Err(McpError::InvalidParams(format!(
                    "{key} must contain 1..{max_bytes} bytes"
                )));
            }
            Ok(text.to_string())
        })
        .transpose()
}

/// Hash canonical per-entity JSON before hashing the ordered digest sequence,
/// so this holds only one serialized entity at a time. Sorting all object keys
/// keeps metadata insertion order from invalidating an otherwise identical view.
fn matching_snapshot(hits: &[Hit], literal: &str, kind: Option<&str>) -> Result<String> {
    let mut digests = Vec::with_capacity(hits.len());
    for hit in hits {
        let mut value = serde_json::to_value(&hit.entity).map_err(McpError::Json)?;
        value.sort_all_objects();
        let bytes = serde_json::to_vec(&value).map_err(McpError::Json)?;
        digests.push(kin_blobs::digest(&bytes).to_string());
    }
    let bytes = serde_json::to_vec(&json!([
        "kin-lexical-matching-snapshot-v1",
        literal,
        kind,
        digests
    ]))
    .map_err(McpError::Json)?;
    Ok(kin_blobs::digest(&bytes).to_string())
}

pub fn handle_lexical_lookup<G: GraphStore>(
    args: &HashMap<String, Value>,
    store: &G,
    repository_authority: Option<&RequestRepositoryAuthority>,
) -> Result<ToolCallResult> {
    let cursor_token = optional_string(args, "cursor", MAX_CURSOR_BYTES)?;
    let cursor = cursor_token
        .as_deref()
        .map(|token| {
            LexicalCursor::decode(token).ok_or_else(|| {
                McpError::InvalidParams(
                    "cursor is invalid or obsolete; omit it to start a fresh lookup".into(),
                )
            })
        })
        .transpose()?;
    let requested_literal = optional_string(args, "literal", MAX_LITERAL_BYTES)?;
    let requested_kind = optional_string(args, "kind", 64)?.map(|kind| kind.to_ascii_lowercase());
    if let Some(cursor) = &cursor {
        if requested_literal
            .as_ref()
            .is_some_and(|literal| literal != &cursor.literal)
            || requested_kind
                .as_ref()
                .is_some_and(|kind| Some(kind) != cursor.kind.as_ref())
        {
            return Err(McpError::InvalidParams(
                "cursor literal/kind mismatch; omit it to start a fresh lookup".into(),
            ));
        }
    }
    let literal = requested_literal
        .or_else(|| cursor.as_ref().map(|c| c.literal.clone()))
        .ok_or_else(|| McpError::InvalidParams("missing required parameter: literal".into()))?;
    let kind = requested_kind.or_else(|| cursor.as_ref().and_then(|c| c.kind.clone()));
    let mut scope = EntityFilter::default();
    if let Some(kind) = kind.as_deref() {
        if kind == "test" {
            scope.roles = Some(vec![EntityRole::Test]);
        } else {
            scope.kinds = Some(parse_kind_filter(kind).ok_or_else(|| {
                McpError::InvalidParams(format!("unsupported entity kind: {kind}"))
            })?);
        }
    }
    let limit = match args.get("limit") {
        Some(value) => value
            .as_u64()
            .ok_or_else(|| McpError::InvalidParams("limit must be a nonnegative integer".into()))?,
        None => DEFAULT_LIMIT as u64,
    }
    .clamp(1, MAX_LIMIT as u64) as usize;
    let offset = cursor.as_ref().map_or(0, |c| c.offset);

    let scoped = store.query_entities(&scope).map_err(McpError::graph)?;
    let scope_languages = crate::edge_coverage::languages_of(&scoped);
    let scope_count = scoped.len();
    let mut verified: Vec<Hit> = scoped
        .into_iter()
        .filter_map(|entity| matched_field(&entity, &literal).map(|field| Hit { entity, field }))
        .collect();
    verified.sort_by_key(|hit| hit.entity.id);
    let snapshot = matching_snapshot(&verified, &literal, kind.as_deref())?;
    if let Some(cursor) = &cursor {
        if cursor.total != verified.len() || cursor.snapshot != snapshot {
            return Err(McpError::InvalidParams(
                "cursor matching-result snapshot changed; omit it to restart the lookup".into(),
            ));
        }
    }

    let total_matching = verified.len();
    let held = HeldSourceAuthority::new(store, repository_authority);
    let page: Vec<Value> = verified
        .iter()
        .skip(offset)
        .take(limit)
        .map(|hit| build_hit(&held, hit, &literal))
        .collect();
    let served_through = offset + page.len();
    let truncated = served_through < total_matching;

    let mut payload = json!({
        "literal": literal,
        "kind": kind,
        "hits": page,
        "total_matching": total_matching,
        "truncated": truncated,
        "matching_snapshot": snapshot,
        "order": "entity_id",
        "page_offset": offset,
    });
    if truncated {
        payload["next_cursor"] = json!(LexicalCursor {
            literal: literal.clone(),
            kind: kind.clone(),
            offset: served_through,
            total: total_matching,
            snapshot: snapshot.clone(),
        }
        .encode());
    }
    payload[DISCLOSURE_KEY] = disclosure(total_matching);

    if total_matching == 0 {
        payload[crate::edge_coverage::EDGE_COVERAGE_KEY] =
            crate::edge_coverage::observe_absence_scope(&scope_languages, Some(scope_count));
    }

    let json_text = serde_json::to_string_pretty(&payload).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json_text))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::entity::{EntityRole, SemanticFingerprint, SourceSpan, Visibility};
    use kin_model::ids::FilePathId;
    use kin_model::{EntityId, EntityKind};
    use kin_model::{EntityMetadata, FingerprintAlgorithm, Hash256, LanguageId};
    use std::collections::HashSet;

    fn fingerprint() -> SemanticFingerprint {
        SemanticFingerprint {
            algorithm: FingerprintAlgorithm::V1TreeSitter,
            ast_hash: Hash256::from_bytes([0; 32]),
            signature_hash: Hash256::from_bytes([0; 32]),
            behavior_hash: Hash256::from_bytes([0; 32]),
            equivalence_hash: Hash256::from_bytes([0; 32]),
            stability_score: 1.0,
        }
    }

    fn entity_with_body(name: &str, body_preview: &str, start_line: u32) -> Entity {
        let mut metadata = EntityMetadata::default();
        metadata.extra.insert(
            EMBEDDING_BODY_PREVIEW_KEY.to_string(),
            Value::String(body_preview.to_string()),
        );
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Go,
            fingerprint: fingerprint(),
            file_origin: Some(FilePathId::new("pkg/cmd/codespace/codespace_selector.go")),
            span: Some(SourceSpan {
                file: FilePathId::new("pkg/cmd/codespace/codespace_selector.go"),
                start_byte: 0,
                end_byte: body_preview.len(),
                start_line,
                start_col: 0,
                end_line: start_line + 10,
                end_col: 0,
            }),
            signature: format!("func {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata,
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    #[test]
    fn matched_field_requires_the_whole_literal_not_one_camel_case_part() {
        // The index would retrieve this entity for a query of "fetchCodespaces"
        // on the "fetch" token alone (camelCase splitting), but its body never
        // carries the whole literal, so a literal-lookup tool must not report
        // it as a hit.
        let entity = entity_with_body("Select", "fetchAll(ctx) then codespaces.List(ctx)", 30);
        assert_eq!(matched_field(&entity, "fetchCodespaces"), None);
    }

    #[test]
    fn matched_field_finds_a_real_occurrence_case_insensitively() {
        let entity = entity_with_body("Select", "cs.FETCHCODESPACES(ctx)", 30);
        assert_eq!(
            matched_field(&entity, "fetchCodespaces"),
            Some(MatchedField::BodyPreview)
        );
    }

    #[test]
    fn matched_field_prefers_name_over_body() {
        let entity = entity_with_body("fetchCodespaces", "return fetchCodespaces(ctx)", 30);
        assert_eq!(
            matched_field(&entity, "fetchCodespaces"),
            Some(MatchedField::Name)
        );
    }

    #[test]
    fn declaration_anchored_fields_never_call_resolve_exact_line() {
        // A name/signature match's line comes from the entity's own span, no
        // source read. This is exercised indirectly: entity_with_body's span
        // has no real backing store, so if `hit_line` tried to resolve an
        // exact line for a name match it would panic or misbehave, not
        // silently succeed.
        assert!(MatchedField::Name.anchored_at_declaration());
        assert!(MatchedField::Signature.anchored_at_declaration());
        assert!(MatchedField::DocSummary.anchored_at_declaration());
        assert!(!MatchedField::BodyPreview.anchored_at_declaration());
        assert!(!MatchedField::FileImportContext.anchored_at_declaration());
        assert!(!MatchedField::FileSurfaceContext.anchored_at_declaration());
    }

    #[test]
    fn excerpt_centers_on_the_match_and_marks_truncation() {
        let long_prefix = "x".repeat(200);
        let body = format!("{long_prefix} cs.fetchCodespaces(ctx) {}", "y".repeat(200));
        let entity = entity_with_body("Select", &body, 30);
        let text = excerpt(&entity, MatchedField::BodyPreview, "fetchCodespaces").expect("excerpt");
        assert!(text.contains("fetchCodespaces"));
        assert!(text.starts_with("..."));
        assert!(text.ends_with("..."));
    }

    #[test]
    fn find_ascii_insensitive_matches_regardless_of_case() {
        assert_eq!(
            find_ascii_insensitive("cs.FetchCodespaces(ctx)", "fetchcodespaces"),
            Some(3)
        );
        assert_eq!(find_ascii_insensitive("no match here", "zzz"), None);
        assert_eq!(find_ascii_insensitive("short", "much longer needle"), None);
    }

    #[test]
    fn cursor_round_trips_literal_kind_and_offset() {
        let cursor = LexicalCursor {
            literal: "fetchCodespaces".to_string(),
            kind: Some("function".to_string()),
            offset: 20,
            total: 57,
            snapshot: "a".repeat(64),
        };
        let decoded = LexicalCursor::decode(&cursor.encode()).expect("decodes");
        assert_eq!(decoded.literal, "fetchCodespaces");
        assert_eq!(decoded.kind, Some("function".to_string()));
        assert_eq!(decoded.offset, 20);
        assert_eq!(decoded.total, 57);
    }

    #[test]
    fn cursor_rejects_a_token_it_did_not_mint() {
        assert!(LexicalCursor::decode("not-a-real-cursor").is_none());
    }

    #[test]
    fn disclosure_names_a_miss_as_unconfirmed_never_as_absent() {
        let block = disclosure(0);
        let caution = block["caution"].as_str().unwrap();
        assert!(caution.contains("not proof"));
    }

    #[test]
    fn disclosure_on_a_hit_still_denies_being_a_reference_edge() {
        let block = disclosure(3);
        let caution = block["caution"].as_str().unwrap();
        assert!(
            caution.contains("not resolved references") || caution.contains("not mean the entity")
        );
    }

    // ── End-to-end: the handler against a real InMemoryGraph + text index ──

    fn store_with_entities(entities: &[Entity]) -> kin_db::InMemoryGraph {
        let graph = kin_db::InMemoryGraph::new();
        for entity in entities {
            kin_model::graph::EntityStore::upsert_entity(&graph, entity).expect("upsert entity");
        }
        graph.flush_text_index().expect("flush text index");
        graph
    }

    fn payload_of(result: &ToolCallResult) -> Value {
        let crate::types::ContentBlock::Text { text } = &result.content[0];
        serde_json::from_str(text).expect("handler must return valid JSON")
    }

    #[test]
    fn handle_lexical_lookup_reports_a_real_hit_with_file_and_matched_field() {
        let _lock = super::super::tests::ENV_MUTEX
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        let hit_entity = entity_with_body("Select", "return cs.fetchCodespaces(ctx)", 30);
        let hit_id = hit_entity.id;
        let miss_entity = entity_with_body("Other", "nothing relevant in here", 5);
        let graph = store_with_entities(&[hit_entity, miss_entity]);

        let mut args: HashMap<String, Value> = HashMap::new();
        args.insert("literal".to_string(), json!("fetchCodespaces"));
        let result = handle_lexical_lookup(&args, &graph, None).expect("handler succeeds");
        let payload = payload_of(&result);

        assert_eq!(payload["total_matching"], json!(1), "{payload}");
        let hits = payload["hits"].as_array().expect("hits array");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0]["entity_id"], json!(hit_id));
        assert_eq!(hits[0]["matched_field"], json!("body_preview"));
        assert_eq!(
            hits[0]["file"],
            json!("pkg/cmd/codespace/codespace_selector.go")
        );
        assert!(payload[DISCLOSURE_KEY].is_object(), "{payload}");
    }

    #[test]
    fn handle_lexical_lookup_a_name_match_reports_its_declaration_line_exactly() {
        let entity = entity_with_body("fetchCodespaces", "unrelated body text", 82);
        let graph = store_with_entities(&[entity]);

        let mut args: HashMap<String, Value> = HashMap::new();
        args.insert("literal".to_string(), json!("fetchCodespaces"));
        let result = handle_lexical_lookup(&args, &graph, None).expect("handler succeeds");
        let payload = payload_of(&result);

        let hits = payload["hits"].as_array().expect("hits array");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0]["matched_field"], json!("name"));
        assert_eq!(hits[0]["line_confidence"], json!("declaration"));
        // `entity_with_body` sets `start_line: 82` (0-based, graph convention);
        // the presentation line is 1-based.
        assert_eq!(hits[0]["line"], json!(83));
    }

    #[test]
    fn handle_lexical_lookup_pages_with_a_cursor_and_the_second_page_finishes() {
        let entities: Vec<Entity> = (0..3)
            .map(|i| {
                entity_with_body(
                    &format!("Caller{i}"),
                    "cs.fetchCodespaces(ctx)",
                    10 + i as u32 * 20,
                )
            })
            .collect();
        let graph = store_with_entities(&entities);

        let mut args: HashMap<String, Value> = HashMap::new();
        args.insert("literal".to_string(), json!("fetchCodespaces"));
        args.insert("limit".to_string(), json!(2));
        let first = handle_lexical_lookup(&args, &graph, None).expect("handler succeeds");
        let first_payload = payload_of(&first);
        assert_eq!(first_payload["total_matching"], json!(3), "{first_payload}");
        assert_eq!(first_payload["hits"].as_array().unwrap().len(), 2);
        assert_eq!(first_payload["truncated"], json!(true));
        let cursor = first_payload["next_cursor"]
            .as_str()
            .expect("a truncated page carries a cursor")
            .to_string();

        let mut second_args: HashMap<String, Value> = HashMap::new();
        second_args.insert("cursor".to_string(), json!(cursor));
        let second = handle_lexical_lookup(&second_args, &graph, None).expect("handler succeeds");
        let second_payload = payload_of(&second);
        assert_eq!(second_payload["hits"].as_array().unwrap().len(), 1);
        assert_eq!(second_payload["truncated"], json!(false));
        assert!(second_payload.get("next_cursor").is_none());
    }

    #[test]
    fn handle_lexical_lookup_on_a_miss_says_so_and_attaches_edge_coverage() {
        let entity = entity_with_body("Unrelated", "nothing to see here", 1);
        let graph = store_with_entities(&[entity]);

        let mut args: HashMap<String, Value> = HashMap::new();
        args.insert("literal".to_string(), json!("fetchCodespaces"));
        let result = handle_lexical_lookup(&args, &graph, None).expect("handler succeeds");
        let payload = payload_of(&result);

        assert_eq!(payload["total_matching"], json!(0));
        assert_eq!(payload["hits"], json!([]));
        let caution = payload[DISCLOSURE_KEY]["caution"].as_str().unwrap();
        assert!(caution.contains("not proof"));
        assert!(
            payload
                .get(crate::edge_coverage::EDGE_COVERAGE_KEY)
                .is_some(),
            "{payload}"
        );
    }

    #[test]
    fn lexical_regression_all_501_matches_are_reachable() {
        let entities: Vec<_> = (0..501)
            .map(|i| entity_with_body(&format!("Caller{i}"), "crowdneedle", i))
            .collect();
        let graph = store_with_entities(&entities);
        let mut args = HashMap::from([
            ("literal".into(), json!("crowdneedle")),
            ("limit".into(), json!(100)),
        ]);
        let mut found = HashSet::new();
        for _ in 0..6 {
            let payload = payload_of(&handle_lexical_lookup(&args, &graph, None).unwrap());
            assert_eq!(payload["total_matching"], json!(501));
            for hit in payload["hits"].as_array().unwrap() {
                assert!(
                    found.insert(hit["entity_id"].as_str().unwrap().to_string()),
                    "duplicate hit"
                );
            }
            if let Some(cursor) = payload.get("next_cursor") {
                args = HashMap::from([
                    ("cursor".into(), cursor.clone()),
                    ("limit".into(), json!(100)),
                ]);
            } else {
                assert_eq!(payload["truncated"], json!(false));
                break;
            }
        }
        assert_eq!(found.len(), 501);
    }

    #[test]
    fn lexical_regression_punctuation_literal_is_searchable() {
        let entity = entity_with_body("arrow", "const next = value => value + 1", 0);
        let graph = store_with_entities(std::slice::from_ref(&entity));
        let args = HashMap::from([("literal".into(), json!("=>"))]);
        let payload = payload_of(&handle_lexical_lookup(&args, &graph, None).unwrap());
        assert_eq!(payload["total_matching"], json!(1));
        assert_eq!(payload["hits"][0]["entity_id"], json!(entity.id));
    }

    #[test]
    fn lexical_regression_kind_filter_does_not_starve_after_500_candidates() {
        let mut entities: Vec<_> = (0..501)
            .map(|i| entity_with_body(&format!("crowdneedle{i}"), "crowdneedle", i))
            .collect();
        let mut target = entity_with_body(
            "Target",
            &format!("{} crowdneedle", "filler ".repeat(1000)),
            0,
        );
        target.kind = EntityKind::Class;
        let id = target.id;
        entities.push(target);
        let graph = store_with_entities(&entities);
        let args = HashMap::from([
            ("literal".into(), json!("crowdneedle")),
            ("kind".into(), json!("class")),
        ]);
        let payload = payload_of(&handle_lexical_lookup(&args, &graph, None).unwrap());
        assert_eq!(payload["total_matching"], json!(1));
        assert_eq!(payload["hits"][0]["entity_id"], json!(id));
    }

    fn regression_first_cursor(graph: &kin_db::InMemoryGraph) -> String {
        let args = HashMap::from([
            ("literal".into(), json!("crowdneedle")),
            ("limit".into(), json!(1)),
        ]);
        payload_of(&handle_lexical_lookup(&args, graph, None).unwrap())["next_cursor"]
            .as_str()
            .unwrap()
            .to_string()
    }

    #[test]
    fn lexical_regression_cursor_rejects_changed_literal_or_kind() {
        let entities: Vec<_> = (0..3)
            .map(|i| entity_with_body(&format!("Caller{i}"), "crowdneedle otherneedle", i))
            .collect();
        let graph = store_with_entities(&entities);
        let cursor = regression_first_cursor(&graph);
        for (key, value) in [("literal", "otherneedle"), ("kind", "class")] {
            let args =
                HashMap::from([("cursor".into(), json!(cursor)), (key.into(), json!(value))]);
            assert!(
                handle_lexical_lookup(&args, &graph, None).is_err(),
                "{key} mismatch must refuse"
            );
        }
    }

    fn assert_changed_cursor_refuses(replacement: &str) {
        use kin_model::graph::EntityStore;
        let entities: Vec<_> = (0..3)
            .map(|i| entity_with_body(&format!("Caller{i}"), "crowdneedle", i))
            .collect();
        let graph = store_with_entities(&entities);
        let cursor = regression_first_cursor(&graph);
        if replacement == "edit" {
            let mut changed = entities[0].clone();
            changed.metadata.extra.insert(
                EMBEDDING_BODY_PREVIEW_KEY.into(),
                json!("crowdneedle changed"),
            );
            graph.upsert_entity(&changed).unwrap();
        } else {
            graph.remove_entity(&entities[0].id).unwrap();
            if replacement == "replace" {
                graph
                    .upsert_entity(&entity_with_body("Replacement", "crowdneedle", 0))
                    .unwrap();
            }
        }
        graph.flush_text_index().unwrap();
        let args = HashMap::from([("cursor".into(), json!(cursor))]);
        assert!(
            handle_lexical_lookup(&args, &graph, None).is_err(),
            "{replacement} must invalidate cursor"
        );
    }

    #[test]
    fn lexical_regression_cursor_rejects_deletion() {
        assert_changed_cursor_refuses("delete");
    }

    #[test]
    fn lexical_regression_cursor_rejects_same_count_replacement() {
        assert_changed_cursor_refuses("replace");
    }

    #[test]
    fn lexical_regression_cursor_rejects_same_id_content_edit() {
        assert_changed_cursor_refuses("edit");
    }

    #[test]
    fn lexical_regression_cursor_rejects_insertion() {
        use kin_model::graph::EntityStore;
        let entities: Vec<_> = (0..3)
            .map(|i| entity_with_body(&format!("Caller{i}"), "crowdneedle", i))
            .collect();
        let graph = store_with_entities(&entities);
        let cursor = regression_first_cursor(&graph);
        graph
            .upsert_entity(&entity_with_body("Inserted", "crowdneedle", 0))
            .unwrap();
        let args = HashMap::from([("cursor".into(), json!(cursor))]);
        assert!(handle_lexical_lookup(&args, &graph, None).is_err());
    }

    #[test]
    fn lexical_lookup_reads_dirty_fields_and_survives_checkpoint_without_an_index() {
        let _lock = super::super::tests::ENV_MUTEX
            .get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        use kin_model::graph::EntityStore;
        let mut entity = entity_with_body("Caller", "oldliteral", 0);
        let graph = store_with_entities(&[entity.clone()]);
        entity.metadata.extra.insert(
            EMBEDDING_BODY_PREVIEW_KEY.into(),
            json!("newliteral => result"),
        );
        graph.upsert_entity(&entity).unwrap();
        assert!(
            graph.text_search("newliteral", 10).unwrap().is_empty(),
            "fixture keeps the old committed index"
        );
        let args = HashMap::from([("literal".into(), json!("newliteral"))]);
        let current = payload_of(&handle_lexical_lookup(&args, &graph, None).unwrap());
        assert_eq!(current["total_matching"], json!(1));
        assert_eq!(current["hits"][0]["score"], Value::Null);
        assert_eq!(
            current[DISCLOSURE_KEY]["answered_by"],
            json!("stored_graph_fields")
        );
        let bytes = graph.to_snapshot().to_bytes().unwrap();
        let reopened = kin_db::InMemoryGraph::from_snapshot_without_text_index(
            kin_db::GraphSnapshot::from_bytes(&bytes).unwrap(),
        )
        .unwrap();
        assert!(reopened.text_search("newliteral", 10).unwrap().is_empty());
        let restored = payload_of(&handle_lexical_lookup(&args, &reopened, None).unwrap());
        assert_eq!(restored, current);
        let old_args = HashMap::from([("literal".into(), json!("oldliteral"))]);
        assert_eq!(
            payload_of(&handle_lexical_lookup(&old_args, &graph, None).unwrap())["total_matching"],
            json!(0)
        );
    }

    #[test]
    fn lexical_lookup_ignores_derived_index_quarantine() {
        use kin_model::graph::EntityStore;
        let entities = [
            entity_with_body("Caller", "crowdneedle", 0),
            entity_with_body("Callee", "other", 1),
        ];
        let graph = store_with_entities(&entities);
        graph
            .upsert_relations_batch(&[kin_model::Relation {
                id: kin_model::RelationId::new(),
                kind: kin_model::RelationKind::Calls,
                src: kin_model::GraphNodeId::Entity(entities[0].id),
                dst: kin_model::GraphNodeId::Entity(entities[1].id),
                confidence: 1.0,
                origin: kin_model::RelationOrigin::Parsed,
                created_in: None,
                import_source: None,
                evidence: vec![],
            }])
            .unwrap();
        assert!(graph
            .text_search("crowdneedle", 10)
            .unwrap_err()
            .to_string()
            .contains("quarantined"));
        let args = HashMap::from([("literal".into(), json!("crowdneedle"))]);
        let result = payload_of(&handle_lexical_lookup(&args, &graph, None).unwrap());
        assert_eq!(result["total_matching"], json!(1));
    }

    #[test]
    fn lexical_lookup_cursor_is_stable_across_canonical_metadata_and_reopen() {
        use kin_model::graph::EntityStore;
        let mut entities: Vec<_> = (0..3)
            .map(|i| entity_with_body(&format!("Caller{i}"), "crowdneedle", i))
            .collect();
        entities[0]
            .metadata
            .extra
            .insert("nested".into(), json!({"z": 1, "a": 2}));
        let graph = store_with_entities(&entities);
        let cursor = regression_first_cursor(&graph);
        let mut reordered = entities[0].clone();
        let mut keys: Vec<_> = entities[0].metadata.extra.keys().cloned().collect();
        keys.sort_by(|a, b| b.cmp(a));
        reordered.metadata.extra = keys
            .into_iter()
            .map(|key| {
                let value = entities[0].metadata.extra[&key].clone();
                (key, value)
            })
            .collect();
        graph.upsert_entity(&reordered).unwrap();
        let reopened =
            kin_db::InMemoryGraph::from_snapshot_without_text_index(graph.to_snapshot()).unwrap();
        let args = HashMap::from([("cursor".into(), json!(cursor))]);
        let result = payload_of(&handle_lexical_lookup(&args, &reopened, None).unwrap());
        assert_eq!(result["hits"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn lexical_lookup_validates_inputs_and_test_role() {
        let mut test_entity = entity_with_body("TestCase", "crowdneedle", 0);
        test_entity.role = EntityRole::Test;
        let graph = store_with_entities(&[
            test_entity.clone(),
            entity_with_body("Ordinary", "crowdneedle", 1),
        ]);
        for (key, value) in [
            ("literal", json!(false)),
            ("literal", json!(" ")),
            ("literal", json!("x".repeat(MAX_LITERAL_BYTES + 1))),
            ("kind", json!("nonsense")),
            ("kind", json!(true)),
            ("limit", json!(1.5)),
            ("limit", json!(-1)),
            ("cursor", json!(42)),
        ] {
            let mut args = HashMap::from([("literal".into(), json!("crowdneedle"))]);
            args.insert(key.into(), value);
            assert!(
                handle_lexical_lookup(&args, &graph, None).is_err(),
                "{key} must refuse"
            );
        }
        let args = HashMap::from([
            ("literal".into(), json!("crowdneedle")),
            ("kind".into(), json!("test")),
            ("limit".into(), json!(u64::MAX)),
        ]);
        let result = payload_of(&handle_lexical_lookup(&args, &graph, None).unwrap());
        assert_eq!(result["total_matching"], json!(1));
        assert_eq!(result["hits"][0]["entity_id"], json!(test_entity.id));
        let legacy = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(r#"{"l":"crowdneedle","k":null,"o":1,"t":2}"#);
        assert!(LexicalCursor::decode(&legacy).is_none());
    }

    #[test]
    fn lexical_lookup_budgeted_pages_keep_every_match_reachable() {
        for requested_limit in [20, 100] {
            let entities: Vec<_> = (0..30)
                .map(|i| {
                    entity_with_body(
                        &format!("{}Caller{i}", "long_name_".repeat(40)),
                        "crowdneedle",
                        i,
                    )
                })
                .collect();
            let graph = store_with_entities(&entities);
            let mut args = HashMap::from([
                ("literal".into(), json!("crowdneedle")),
                ("limit".into(), json!(requested_limit)),
            ]);
            let budget = crate::budget::ResponseBudget {
                max_chars: 4_000,
                ..Default::default()
            };
            let mut found = HashSet::new();
            let mut saw_cut = false;
            for _ in 0..30 {
                let mut payload = payload_of(&handle_lexical_lookup(&args, &graph, None).unwrap());
                let before = payload["hits"].as_array().unwrap().len();
                crate::budget::enforce(&mut payload, TOOL_NAME, &budget).expect("budgeted");
                let hits = payload["hits"].as_array().unwrap();
                saw_cut |= hits.len() < before;
                for hit in hits {
                    assert!(
                        found.insert(hit["entity_id"].as_str().unwrap().to_string()),
                        "duplicate match"
                    );
                }
                if let Some(cursor) = payload.get("next_cursor").and_then(Value::as_str) {
                    args = HashMap::from([
                        ("cursor".into(), json!(cursor)),
                        ("limit".into(), json!(requested_limit)),
                    ]);
                } else {
                    break;
                }
            }
            assert!(saw_cut, "fixture must force a row cut");
            assert_eq!(
                found.len(),
                30,
                "budget must retain first and final page continuation"
            );
        }
    }

    #[test]
    fn handle_lexical_lookup_requires_literal_or_cursor() {
        let args: HashMap<String, Value> = HashMap::new();
        let graph = kin_db::InMemoryGraph::new();
        let error = handle_lexical_lookup(&args, &graph, None)
            .expect_err("missing literal and cursor must refuse");
        assert!(format!("{error}").contains("literal"));
    }
}
