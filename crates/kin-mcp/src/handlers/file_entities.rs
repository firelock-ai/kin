// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! File-scoped entity enumeration (FIR-2546).
//!
//! "What is in this file" is the cheapest question the graph can answer and it
//! was the one no tool on the `agent-default` profile asked. An agent that
//! needed it had to read ids out of a `semantic_locate` response and hope the
//! ranking had returned them all, which it cannot promise: locate is a bounded
//! ranking, so a short list and a full list are the same response.
//!
//! This tool answers the enumeration directly from graph truth and certifies
//! what it left out. Three facts decide that certification and each is read
//! from the store rather than inferred:
//!
//! - the entities whose `file_origin` is this path ([`kin_model::EntityFilter`]),
//! - whether a language adapter parsed the file, and how completely
//!   ([`kin_model::layout::FileLayout::parse_completeness`]),
//! - whether the repository tree admits the path at all
//!   ([`kin_model::graph::EntityStore::artifact_id_at_path`]).
//!
//! Nothing here reads the filesystem. A path the graph does not track is a
//! refusal that names the gap, never an empty list: those two answers look
//! identical to a caller and only one of them means the file has no entities.
//!
//! ## Why the page is bounded by a cursor rather than a cap
//!
//! A silent cap is the defect this tool exists to remove wearing a different
//! costume. `take(40)` returns forty entities from a file holding two hundred
//! and says nothing, so the caller reads a complete-looking list. Every page
//! here carries `total_in_file`, and a page that does not hold the whole file
//! carries a `next_cursor` and reports `exact: false` through
//! [`crate::envelope::Completeness`], so a partial answer can never be read as
//! a whole one.

use std::collections::HashMap;

use base64::Engine as _;
use kin_model::graph::{EntityFilter, GraphStore};
use kin_model::layout::ParseCompleteness;
use kin_model::{entity::Entity, EntityKind, EntityRole, FilePathId, LanguageId, Visibility};
use serde::Serialize;

use crate::error::{McpError, Result};
use crate::handlers::common::{entity_presentation_end_line, entity_presentation_start_line};
use crate::types::ToolCallResult;

/// The tool's registered name, spelled once so the registry, the dispatcher,
/// the budget table and the negative registry cannot drift from each other.
pub const TOOL_NAME: &str = "list_file_entities";

/// Key under which this tool publishes what the graph knows about the file
/// itself, beside the entities it enumerated.
///
/// Read back by [`crate::envelope::Completeness`] and [`crate::negative`], which
/// project it into the response's one verdict. Publishing the raw observation
/// here and the verdict there is the same split `edge_coverage` already uses: a
/// reader who disagrees with the verdict can audit the evidence it was built
/// from.
pub const FILE_COVERAGE_KEY: &str = "file_coverage";

/// Entities returned per page when the caller names no `page_size`.
const DEFAULT_PAGE_SIZE: u64 = 200;

/// Ceiling on `page_size`. Above this a single response stops being something
/// an agent can read and becomes something the response budget has to cut,
/// which reintroduces the silent truncation this tool exists to remove.
const MAX_PAGE_SIZE: u64 = 1_000;

pub const LIST_FILE_ENTITIES_DESC: &str = "\
Enumerate every entity the graph holds for one repository-relative file, with a completeness \
you can act on. This is the enumeration surface: unlike `semantic_locate`, which ranks and \
therefore cannot say what it left out, this returns the whole set the graph owns for the path \
and reports whether that set is whole. Give it `path`, such as \"lib/express.js\". Each row \
carries the `id` every other tool here takes (`get_entity_source`, `get_context_pack`, \
`find_references`, `graph_neighborhood`), plus `name`, `kind`, `language`, `role`, \
`visibility`, `signature`, and the defining span as both lines and bytes. \
`file_coverage` says what the graph knows about the file itself: `parsed` is `full` when a \
language adapter parsed it completely, `partial` or `failed` when it did not, and `absent` \
when no adapter parsed it at all. Only a `full` parse licenses reading this list as the file's \
whole surface, and `_kin.completeness` and `negative.safe_to_conclude_absent` are computed \
from that fact rather than from store-wide health. A path the graph does not track is refused \
by name instead of answered with an empty list, because those two answers are \
indistinguishable and only one of them means the file holds no entities. Large files page: \
`total_in_file` is the whole-file count on every page, and a page that does not hold all of \
them carries `next_cursor`, which you pass back as `cursor` for the next page.";

/// One entity as this tool serves it.
///
/// The byte span rides beside the line span rather than replacing it. Lines are
/// what an agent quotes to a human; bytes are what a splice or an exact
/// comparison needs, and recomputing them from lines requires the file, which is
/// the read this whole surface exists to avoid.
#[derive(Debug, Serialize)]
pub struct FileEntityRow {
    pub id: kin_model::EntityId,
    pub name: String,
    pub kind: EntityKind,
    pub language: LanguageId,
    pub role: EntityRole,
    pub visibility: Visibility,
    pub signature: String,
    pub start_line: Option<u32>,
    pub end_line: Option<u32>,
    pub start_byte: Option<usize>,
    pub end_byte: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub doc_summary: Option<String>,
}

impl From<Entity> for FileEntityRow {
    fn from(entity: Entity) -> Self {
        let start_line = entity_presentation_start_line(&entity);
        let end_line = entity_presentation_end_line(&entity);
        let (start_byte, end_byte) = entity
            .span
            .as_ref()
            .map(|span| (Some(span.start_byte), Some(span.end_byte)))
            .unwrap_or((None, None));
        Self {
            id: entity.id,
            name: entity.name,
            kind: entity.kind,
            language: entity.language,
            role: entity.role,
            visibility: entity.visibility,
            signature: entity.signature,
            start_line,
            end_line,
            start_byte,
            end_byte,
            doc_summary: entity.doc_summary,
        }
    }
}

/// How completely a language adapter parsed this file, in the one word the
/// verdict is computed from.
///
/// `Absent` is not `Failed`. A file nothing ever tried to parse and a file whose
/// parse failed both hold no entities, and only the second one is evidence about
/// the code; collapsing them is how "no entities" comes to read as "no exports".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParsedState {
    Full,
    Partial,
    Failed,
    Absent,
}

impl ParsedState {
    /// The wire word, matching [`ParseCompleteness::bucket`] for the three
    /// states that have a layout to read it from.
    pub fn wire(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Partial => "partial",
            Self::Failed => "failed",
            Self::Absent => "absent",
        }
    }

    /// Whether this state licenses reading the enumeration as the file's whole
    /// entity surface. Only a complete parse does.
    pub fn certifies_enumeration(self) -> bool {
        matches!(self, Self::Full)
    }
}

/// Entities scanned before the language-server reading gives up and reports
/// `unknown`.
///
/// The reading costs one relation read per entity and it decides nothing, so a
/// file large enough to make it expensive gets an honest `unknown` rather than a
/// query nobody asked for. `unknown` is a real answer here; the parse state is
/// what the verdict rests on.
const ENRICHMENT_SCAN_CAP: usize = 500;

/// Which tier of tracking the graph holds this file at.
///
/// Kin classifies every tracked file into exactly one of these
/// ([`kin_model::layout::TrackedFile`]), and the tier is what tells a caller
/// whether an empty enumeration is a defect or the ordinary answer. A lockfile
/// tracked as an opaque artifact holds no entities by design.
///
/// The four facets are mutually exclusive per file and the daemon enforces that
/// (`clear_incompatible_facets_in`), so the first hit in this order is the
/// file's tier rather than one of several.
fn tracking_tier<G: GraphStore>(store: &G, file_id: &FilePathId) -> Result<&'static str> {
    if store
        .get_file_layout(file_id)
        .map_err(McpError::graph)?
        .is_some()
    {
        return Ok("entity_source");
    }
    if store
        .get_shallow_file(file_id)
        .map_err(McpError::graph)?
        .is_some()
    {
        return Ok("shallow_syntax");
    }
    if store
        .get_structured_artifact(file_id)
        .map_err(McpError::graph)?
        .is_some()
    {
        return Ok("structured_artifact");
    }
    if store
        .get_opaque_artifact(file_id)
        .map_err(McpError::graph)?
        .is_some()
    {
        return Ok("opaque_artifact");
    }
    Ok("none")
}

/// Whether the graph holds language-server-derived edges for this file's
/// entities: the graph-truth reading of "enriched".
///
/// The daemon's own `lsp_enriched_files` marker is operational state its module
/// documents as something nothing answers a query from, so it is not read here.
/// [`kin_model::RelationOrigin::Lsp`] on an edge incident to one of the file's
/// entities is the durable fact, and it is the same test the daemon applies to
/// decide whether its own marker can be trusted.
///
/// Disclosure only. Enrichment adds edges between entities; it does not add
/// entities to a file, so it can never be the reason an enumeration is short.
fn language_server_edges<G: GraphStore>(store: &G, entities: &[Entity]) -> Result<&'static str> {
    if entities.is_empty() || entities.len() > ENRICHMENT_SCAN_CAP {
        return Ok("unknown");
    }
    for entity in entities {
        let relations = store
            .get_all_relations_for_entity(&entity.id)
            .map_err(McpError::graph)?;
        if relations
            .iter()
            .any(|relation| relation.origin == kin_model::RelationOrigin::Lsp)
        {
            return Ok("present");
        }
    }
    Ok("absent")
}

/// Where a page starts, and what the enumeration looked like when the cursor
/// that names it was minted.
///
/// `total` rides in the cursor so a later page can tell that the file changed
/// under the walk. Without it the second page of a file that gained or lost an
/// entity is served silently against a different list, and the caller assembles
/// pages that never described one state of the repository.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageCursor {
    pub path: String,
    pub offset: usize,
    pub total: usize,
}

impl PageCursor {
    /// Encode as one opaque URL-safe token. Opaque on purpose: a caller that
    /// parses and edits a cursor is constructing a page the graph never served.
    pub fn encode(&self) -> String {
        let raw = serde_json::json!({
            "p": self.path,
            "o": self.offset,
            "t": self.total,
        })
        .to_string();
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)
    }

    /// Decode a token, or `None` for anything this function did not mint.
    pub fn decode(token: &str) -> Option<Self> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(token.trim())
            .ok()?;
        let value: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
        Some(Self {
            path: value.get("p")?.as_str()?.to_string(),
            offset: value.get("o")?.as_u64()? as usize,
            total: value.get("t")?.as_u64()? as usize,
        })
    }
}

/// Normalize a caller's path to the spelling the graph stores.
///
/// Only the two rewrites that cannot change which file is meant: a `./` prefix
/// is dropped and backslashes become forward slashes, because a Windows client
/// spells the same tracked path with the other separator. No suffix matching and
/// no fuzzy fallback: a path that resolves by suffix resolves to whichever file
/// happened to end that way, and answering confidently about a file the caller
/// did not name is worse than refusing.
fn normalize_path(raw: &str) -> String {
    let swapped = raw.replace('\\', "/");
    let trimmed = swapped.trim();
    let mut path = trimmed;
    while let Some(rest) = path.strip_prefix("./") {
        path = rest;
    }
    path.to_string()
}

/// Sort key giving the enumeration one deterministic order.
///
/// Determinism is what makes offset paging correct: two pages of one stable
/// graph must partition the set, and a query whose order varies between calls
/// can repeat an entity on page two and drop another entirely. Byte position
/// first so the list reads down the file; name and id break ties for entities
/// the projection never placed, which sort last rather than at byte zero.
fn sort_key(entity: &Entity) -> (usize, String, String) {
    (
        entity
            .span
            .as_ref()
            .map(|span| span.start_byte)
            .unwrap_or(usize::MAX),
        entity.name.clone(),
        entity.id.0.to_string(),
    )
}

/// Enumerate the entities the graph holds for one file.
pub fn handle_list_file_entities<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let cursor = match args.get("cursor").and_then(serde_json::Value::as_str) {
        Some(token) if !token.trim().is_empty() => {
            Some(PageCursor::decode(token).ok_or_else(|| {
                McpError::InvalidParams(
                    "invalid cursor: pass back a `next_cursor` this tool returned, unedited, or \
                     omit `cursor` to start a fresh enumeration"
                        .to_string(),
                )
            })?)
        }
        _ => None,
    };

    // The cursor carries the path it was minted for, so a caller that pages one
    // file with another file's cursor is refused rather than served a window
    // into a list it never asked for.
    let raw_path = match (
        args.get("path").and_then(serde_json::Value::as_str),
        cursor.as_ref(),
    ) {
        (Some(path), Some(cursor)) if normalize_path(path) != cursor.path => {
            return Err(McpError::InvalidParams(format!(
                "cursor was minted for {:?} but `path` names {:?}; page one file at a time",
                cursor.path,
                normalize_path(path)
            )));
        }
        (Some(path), _) => path.to_string(),
        (None, Some(cursor)) => cursor.path.clone(),
        (None, None) => {
            return Err(McpError::InvalidParams(
                "missing required parameter: path (a repository-relative path such as \
                 \"lib/express.js\")"
                    .to_string(),
            ))
        }
    };

    let path = normalize_path(&raw_path);
    if path.is_empty() {
        return Err(McpError::InvalidParams(
            "invalid parameter: path must not be empty; name a repository-relative path such as \
             \"lib/express.js\""
                .to_string(),
        ));
    }
    // The same rule the projection and the transaction stage path apply, so a
    // path this tool accepts is a path the rest of Kin accepts. An absolute
    // path, a `..` escape, or a Kin/Git control component is refused by name
    // here rather than turned into an exact-match miss that reads as "this file
    // has no entities".
    let repo_path = kin_model::RepoPath::from_utf8(path.clone()).map_err(|error| {
        McpError::InvalidParams(format!(
            "invalid parameter: path {path:?} is not a usable repository path: {error}"
        ))
    })?;
    kin_core::validate_source_paths([&repo_path]).map_err(|error| {
        McpError::InvalidParams(format!(
            "invalid parameter: path {path:?} is not an admissible repository source path: \
             {error}. Name a repository-relative path such as \"lib/express.js\", with no leading \
             slash, no \"..\", and no Kin or Git control component"
        ))
    })?;

    let page_size = args
        .get("page_size")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(DEFAULT_PAGE_SIZE)
        .clamp(1, MAX_PAGE_SIZE) as usize;

    let file_id = FilePathId::new(path.clone());
    let mut entities = store
        .query_entities(&EntityFilter {
            file_path: Some(file_id.clone()),
            ..Default::default()
        })
        .map_err(McpError::graph)?;
    entities.sort_by_key(sort_key);
    let total_in_file = entities.len();

    let layout = store.get_file_layout(&file_id).map_err(McpError::graph)?;
    let parsed = match layout.as_ref().map(|layout| &layout.parse_completeness) {
        Some(ParseCompleteness::Full) => ParsedState::Full,
        Some(ParseCompleteness::Partial(_)) => ParsedState::Partial,
        Some(ParseCompleteness::Failed(_)) => ParsedState::Failed,
        None => ParsedState::Absent,
    };
    let parse_detail = match layout.as_ref().map(|layout| &layout.parse_completeness) {
        Some(ParseCompleteness::Partial(reason)) | Some(ParseCompleteness::Failed(reason)) => {
            Some(reason.clone())
        }
        _ => None,
    };
    // The layout's own entity-region count, published beside the enumeration
    // rather than folded into it. Two independent readings of one file: if the
    // CST recorded regions for entities the entity index does not return, the
    // enumeration is short and this is the number that says so.
    let layout_entity_regions = layout.as_ref().map(|layout| {
        layout
            .regions
            .iter()
            .filter(|region| matches!(region, kin_model::layout::SourceRegion::EntityRef { .. }))
            .count()
    });

    let tier = tracking_tier(store, &file_id)?;
    // Admission identity, resolved through the repository tree rather than
    // through a path-keyed facet. This is the ordering `kin-context` documents:
    // a path the tree does not admit is a graph gap, and answering it from
    // whatever enrichment still carries that path is how a stale facet comes to
    // stand in for a file the repository no longer has.
    let tracked_in_graph = store.artifact_id_at_path(&repo_path).is_some();

    // A path with no admitted identity, no facet at any tier, and no entities is
    // a path this graph has never seen. Answering it with an empty array
    // publishes "this file has no entities" about a file Kin cannot see, which
    // is the exact confusion this tool was filed to end, so it fails loudly and
    // names the gap instead.
    if !tracked_in_graph && tier == "none" && total_in_file == 0 {
        return Err(McpError::Context(format!(
            "graph gap: {path:?} is not tracked by this graph at any tier, so Kin cannot say what \
             entities it holds. This is not a claim that the file has no entities. Check the path \
             spelling against `kin_artifact_list`, or run a reconcile if the file is new."
        )));
    }

    let enriched = language_server_edges(store, &entities)?;

    let offset = cursor.as_ref().map(|cursor| cursor.offset).unwrap_or(0);
    // A cursor minted against a different-sized enumeration is describing a file
    // that changed under the walk. The rows are still served, because withholding
    // real graph truth teaches nothing, but the shift is named so the assembled
    // pages are never read as one consistent snapshot.
    let enumeration_shifted = cursor
        .as_ref()
        .is_some_and(|cursor| cursor.total != total_in_file);
    let window: Vec<FileEntityRow> = entities
        .into_iter()
        .skip(offset)
        .take(page_size)
        .map(FileEntityRow::from)
        .collect();
    let returned = window.len();
    let reached = offset.saturating_add(returned);
    let next_cursor = (reached < total_in_file).then(|| {
        PageCursor {
            path: path.clone(),
            offset: reached,
            total: total_in_file,
        }
        .encode()
    });
    // Whether THIS response holds the file's whole entity set. A last page is
    // not a whole answer: it holds the tail, and a caller reading `exact` off it
    // would be reading a claim about the pages it does not have.
    let whole_file_in_response = offset == 0 && next_cursor.is_none();

    let payload = serde_json::json!({
        "path": path,
        "entities": window,
        "returned": returned,
        "total_in_file": total_in_file,
        "page_size": page_size,
        "offset": offset,
        "next_cursor": next_cursor,
        // The same flag `kin_artifact_list` and `semantic_search` publish, in
        // the same sense: this response does not hold everything it counted.
        "truncated": next_cursor.is_some() || offset > 0,
        "enumeration_shifted": enumeration_shifted,
        FILE_COVERAGE_KEY: {
            "path": path,
            "tracked_in_graph": tracked_in_graph,
            "tier": tier,
            "parsed": parsed.wire(),
            "parse_detail": parse_detail,
            "layout_entity_regions": layout_entity_regions,
            // Whether the graph holds language-server-derived edges for this
            // file's entities. Disclosure: enrichment adds edges between
            // entities and never adds entities to a file, so it cannot be the
            // reason an enumeration is short.
            "enriched": enriched,
            // Deliberately not a per-file number, and named so a reader cannot
            // mistake it for one. No store API reports whether one file's
            // entities are embedded, and this enumeration reads the entity
            // index rather than the vector index, so embedding coverage is
            // disclosure here and never a decider. `_kin.completeness` carries
            // the store-grain reading beside it, labelled as store-grain.
            "embedded": "not_measured_per_file",
            "whole_file_in_response": whole_file_in_response,
            "certifies_enumeration": parsed.certifies_enumeration()
                && whole_file_in_response
                && !enumeration_shifted,
        },
    });

    Ok(ToolCallResult::text(
        serde_json::to_string_pretty(&payload).map_err(McpError::Json)?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_path_drops_dot_slash_and_swaps_separators() {
        assert_eq!(normalize_path("lib/express.js"), "lib/express.js");
        assert_eq!(normalize_path("./lib/express.js"), "lib/express.js");
        assert_eq!(normalize_path(".././lib/express.js"), ".././lib/express.js");
        assert_eq!(normalize_path("lib\\express.js"), "lib/express.js");
        assert_eq!(normalize_path("  lib/express.js  "), "lib/express.js");
    }

    #[test]
    fn cursor_round_trips_and_rejects_foreign_tokens() {
        let cursor = PageCursor {
            path: "lib/express.js".to_string(),
            offset: 200,
            total: 431,
        };
        let token = cursor.encode();
        assert_eq!(PageCursor::decode(&token), Some(cursor));
        assert_eq!(PageCursor::decode("not-a-cursor"), None);
        assert_eq!(PageCursor::decode(""), None);
    }

    #[test]
    fn only_a_full_parse_certifies_an_enumeration() {
        assert!(ParsedState::Full.certifies_enumeration());
        assert!(!ParsedState::Partial.certifies_enumeration());
        assert!(!ParsedState::Failed.certifies_enumeration());
        assert!(!ParsedState::Absent.certifies_enumeration());
    }
}
