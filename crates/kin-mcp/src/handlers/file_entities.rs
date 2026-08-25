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
when no adapter parsed it at all. When `absent` is because no adapter claims the file's type \
at all -- Kin admits such a file, hashes it and stores a preview, and extracts nothing -- \
`content_opaque` is true and `opaque_reason` names the extension, so a file that produced \
zero entities by design is never read as one whose parse failed. Only a `full` parse licenses reading this list as the file's \
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

/// Why a file the graph admitted holds no entities, when the reason is its TYPE
/// rather than anything about its content. `None` when the file's type is not
/// the reason.
///
/// Kin admits every file it is given. One whose extension no language adapter
/// claims is content-addressed, previewed and stored as an opaque artifact, and
/// it then reports `parsed: absent` in exactly the words a file whose adapter
/// fell over reports. Those are opposite facts, and only the second is evidence
/// about the code. A reader who cannot separate them reads "seven markdown files
/// admitted, zero entities" as a parser defect and files it as one, which is the
/// honesty failure this names rather than a coverage failure this fixes.
///
/// The registry decides, not the tier. A file an adapter parsed can never reach
/// this, because a parsed file's extension is one the registry claims by
/// definition, so the two conditions agree wherever they overlap.
///
/// The adapter registry IS the supported set, and its own
/// [`supported_languages_with_extensions`](kin_parser::languages::AdapterRegistry::supported_languages_with_extensions)
/// documents that anything reporting Kin's supported languages must read it
/// rather than keep a second list, because two lists of one fact can only come
/// to disagree. So this asks the registry. It is a path-string check against a
/// static table and reads no file, and it goes quiet on its own the day an
/// adapter claims the extension.
fn opaque_reason(path: &str, tier: &str) -> Option<String> {
    // Two tiers, because the store reaches this state by two routes and only one
    // of them was visible from reading the ingest code. A converted repository
    // serves `docs/notes.md` as `tracked_in_graph: true, tier: "none"`: the
    // repository tree admits the path and no facet was ever written for it. The
    // `opaque_artifact` row the ingest path builds is the other route. Gating on
    // that row alone made this disclosure a no-op on exactly the store it exists
    // for, which the acceptance fixture caught and the unit fixtures could not,
    // because they build the row by hand.
    //
    // Every other tier is excluded because something DID read the file.
    // `entity_source` means an adapter parsed it, so a `.py` file holding
    // nothing is an empty file rather than an unreadable one, and
    // `structured_artifact` means Kin understood the file structurally, which is
    // the opposite of opaque even though it yields no entities.
    if !matches!(tier, "opaque_artifact" | "none") {
        return None;
    }
    let Some(extension) = std::path::Path::new(path)
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase)
    else {
        return Some("no_adapter_for_path".to_string());
    };
    let claimed = kin_parser::languages::AdapterRegistry::new()
        .supported_languages_with_extensions()
        .into_iter()
        .any(|(_, extensions)| {
            extensions
                .iter()
                .any(|claimed| claimed.eq_ignore_ascii_case(&extension))
        });
    // An adapter does claim this extension, so whatever made the file opaque, it
    // was not its type. Naming the type would be a guess dressed as a cause.
    if claimed {
        return None;
    }
    Some(format!("no_adapter_for_extension:{extension}"))
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
    let opaque_reason = opaque_reason(&path, tier);
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
            // Whether this file holds no entities because its TYPE is one no
            // language adapter claims, as opposed to a parse that was attempted
            // and fell short. `parsed: absent` alone cannot separate those, and
            // reading the first as the second is how an admitted-and-unclaimed
            // file gets filed as a parser defect. Always present, so "checked
            // and no" is distinguishable from "not reported".
            "content_opaque": opaque_reason.is_some(),
            // The cause, naming the extension nothing claims. Null when
            // `content_opaque` is false.
            "opaque_reason": opaque_reason,
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

    use kin_db::InMemoryGraph;
    use kin_model::graph::EntityStore;
    use kin_model::layout::{FileLayout, ImportSection, SourceRegion};
    use kin_model::{ArtifactId, LocatedEntry, RepoPath, TransactionDelta, TreeDelta, TreeEntry};
    use kin_model::{
        EntityId, EntityMetadata, FingerprintAlgorithm, Hash256, SemanticFingerprint, SourceSpan,
    };

    const FILE: &str = "lib/express.js";

    fn entity_at(name: &str, file: &str, start_byte: usize) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::JavaScript,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                equivalence_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(file)),
            span: Some(SourceSpan {
                file: FilePathId::new(file),
                start_byte,
                end_byte: start_byte + 40,
                start_line: start_byte as u32 / 10,
                start_col: 0,
                end_line: start_byte as u32 / 10 + 2,
                end_col: 0,
            }),
            signature: format!("function {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn layout_for(file: &str, completeness: ParseCompleteness, regions: usize) -> FileLayout {
        FileLayout {
            file_id: FilePathId::new(file),
            parse_completeness: completeness,
            imports: ImportSection {
                byte_range: 0..0,
                items: Vec::new(),
            },
            regions: (0..regions)
                .map(|index| SourceRegion::EntityRef {
                    entity_id: EntityId::new(),
                    byte_range: index..index + 1,
                })
                .collect(),
        }
    }

    /// Admit one path into the graph's repository tree through the real tree
    /// transaction, which is what a layout or artifact facet requires.
    fn admit(store: &InMemoryGraph, path: &str) -> ArtifactId {
        let repo_path = RepoPath::from_utf8(path.to_string()).expect("valid test path");
        if let Some(artifact_id) = store.artifact_id_at_path(&repo_path) {
            return artifact_id;
        }
        let artifact_id = ArtifactId::new();
        store
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: Vec::new(),
                relation_deltas: Vec::new(),
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id,
                    new: LocatedEntry::new(
                        repo_path,
                        TreeEntry::blob(Hash256::from_bytes([7; 32]), false),
                    ),
                }],
                admission_policy_delta: None,
                external_reference_deltas: Vec::new(),
            })
            .expect("test admission goes through the repository tree transaction");
        artifact_id
    }

    /// A store holding `count` entities in [`FILE`], plus one entity in another
    /// file so every "not in the list" assertion has a live control: the graph
    /// can see that entity, and this tool still must not report it.
    fn store_with(count: usize, parse: Option<ParseCompleteness>) -> InMemoryGraph {
        let store = InMemoryGraph::new();
        admit(&store, FILE);
        admit(&store, "lib/router.js");
        for index in 0..count {
            store
                .upsert_entity(&entity_at(&format!("export{index}"), FILE, index * 100))
                .unwrap();
        }
        store
            .upsert_entity(&entity_at("elsewhere", "lib/router.js", 0))
            .unwrap();
        if let Some(parse) = parse {
            store
                .upsert_file_layout(&layout_for(FILE, parse, count))
                .unwrap();
        }
        store
    }

    fn call(
        store: &InMemoryGraph,
        args: &[(&str, serde_json::Value)],
    ) -> Result<serde_json::Value> {
        let args: HashMap<String, serde_json::Value> = args
            .iter()
            .map(|(key, value)| (key.to_string(), value.clone()))
            .collect();
        let result = handle_list_file_entities(&args, store)?;
        let crate::types::ContentBlock::Text { text } = &result.content[0];
        Ok(serde_json::from_str(text).expect("payload is JSON"))
    }

    fn names(payload: &serde_json::Value) -> Vec<String> {
        payload["entities"]
            .as_array()
            .expect("entities array")
            .iter()
            .map(|row| row["name"].as_str().expect("name").to_string())
            .collect()
    }

    /// A daemon envelope whose STRUCTURAL substrate is clean: the only state in
    /// which this tool's absence could be certified at all, so a refusal under
    /// it is a refusal this tool's own gate produced rather than one it
    /// inherited.
    fn structural_authoritative_envelope() -> crate::envelope::Envelope {
        let mut envelope = crate::envelope::Envelope::daemon();
        envelope.graph_state.initialized = Some(true);
        envelope.graph_state.loaded = Some(true);
        envelope.graph_state.entity_count = Some(42);
        envelope.graph_as_of = Some(serde_json::json!("change:deadbeef"));
        envelope
    }

    /// Put `path` in the store as an opaque artifact: admitted, hashed, and
    /// holding no entities because nothing ever tried to extract any.
    fn admit_opaque(store: &InMemoryGraph, path: &str) {
        admit(store, path);
        store
            .upsert_opaque_artifact(&kin_model::layout::OpaqueArtifact {
                file_id: FilePathId::new(path),
                content_hash: Hash256::from_bytes([3; 32]),
                mime_type: Some("text/md".to_string()),
                text_preview: None,
            })
            .unwrap();
    }

    /// A file whose type no adapter claims says so, and a file an adapter read
    /// says nothing of the kind.
    ///
    /// Kin admits every file it is given. Seven markdown files went into a graph,
    /// produced zero entities, and every surface reported that the way it reports
    /// a parse that failed. Those are opposite facts and only one is evidence
    /// about the code, so a reader with no way to tell them apart files the first
    /// as a parser defect.
    ///
    /// Three fixtures, and the second and third are the ones that make this able
    /// to fail. A flag hardcoded true fails on the Python file; a flag derived
    /// from "this file has zero entities" fails on the EMPTY Python file, which
    /// an adapter read perfectly well and which correctly holds nothing.
    #[test]
    fn a_file_no_adapter_claims_discloses_its_type_and_a_parsed_file_does_not() {
        let store = InMemoryGraph::new();
        admit_opaque(&store, "README.md");
        admit(&store, "src/thing.py");
        store
            .upsert_entity(&entity_at("thing", "src/thing.py", 0))
            .unwrap();
        store
            .upsert_file_layout(&layout_for("src/thing.py", ParseCompleteness::Full, 1))
            .unwrap();
        admit(&store, "src/empty.py");
        store
            .upsert_file_layout(&layout_for("src/empty.py", ParseCompleteness::Full, 0))
            .unwrap();
        // The shape a converted repository actually serves, which is not the one
        // the ingest code reads like it produces: the repository tree admits the
        // path and no facet was ever written, so the tier is `none` rather than
        // `opaque_artifact`. Gating on the artifact row alone made this
        // disclosure a no-op on every real store, and only the acceptance
        // fixture could see it, because these fixtures build the row by hand.
        admit(&store, "NOTES.md");
        // Its control, and the reason the tier cannot decide this on its own: a
        // Python file in the same no-facet state has an adapter that claims it,
        // so nothing about its TYPE explains an empty enumeration.
        admit(&store, "src/unparsed.py");

        for path in ["README.md", "NOTES.md"] {
            let payload = call(&store, &[("path", serde_json::json!(path))]).unwrap();
            assert_eq!(
                payload[FILE_COVERAGE_KEY]["content_opaque"],
                serde_json::json!(true),
                "{path}: {payload}"
            );
            assert_eq!(
                payload[FILE_COVERAGE_KEY]["opaque_reason"],
                serde_json::json!("no_adapter_for_extension:md"),
                "{path} names the extension nothing claims: {payload}"
            );
        }

        for path in ["src/thing.py", "src/empty.py", "src/unparsed.py"] {
            let payload = call(&store, &[("path", serde_json::json!(path))]).unwrap();
            assert_eq!(
                payload[FILE_COVERAGE_KEY]["content_opaque"],
                serde_json::json!(false),
                "{path} has an adapter that claims it, whatever its tier: {payload}"
            );
            assert_eq!(
                payload[FILE_COVERAGE_KEY]["opaque_reason"],
                serde_json::Value::Null,
                "{path} has no opaque cause to name: {payload}"
            );
        }
        assert_eq!(
            call(&store, &[("path", serde_json::json!("src/empty.py"))]).unwrap()["total_in_file"],
            serde_json::json!(0),
            "and the empty control really is empty, or it proves nothing"
        );
    }

    /// The reason is computed from the adapter registry rather than written down
    /// here, so it names whatever extension it was actually given.
    ///
    /// A hardcoded `md` passes every assertion above. This is what fails it.
    #[test]
    fn the_opaque_reason_names_the_extension_it_was_given() {
        let store = InMemoryGraph::new();
        admit_opaque(&store, "docs/diagram.png");
        let payload = call(&store, &[("path", serde_json::json!("docs/diagram.png"))]).unwrap();
        assert_eq!(
            payload[FILE_COVERAGE_KEY]["opaque_reason"],
            serde_json::json!("no_adapter_for_extension:png"),
            "{payload}"
        );
    }

    /// The envelope's limit word carries the cause, so the one verdict a reader
    /// acts on says why rather than only that.
    ///
    /// `file_parsed_absent` is true of a file nothing tried to parse and of a
    /// file whose adapter fell over, and a reader acting on it cannot tell which
    /// they have.
    #[test]
    fn the_limit_word_names_the_cause_when_the_answer_carries_one() {
        let store = InMemoryGraph::new();
        admit_opaque(&store, "README.md");
        let limits = finalized_limits(&store, "README.md");
        assert!(
            limits.contains("file_content_opaque_no_adapter_for_extension:md"),
            "the limit names the cause: {limits}"
        );
        assert!(
            !limits.contains("file_parsed_absent"),
            "and does not also state the symptom it replaces: {limits}"
        );

        // The control: a file an adapter tried and failed on keeps the generic
        // word, because its type is not the reason and naming one would be a
        // guess dressed as a cause.
        let failed = InMemoryGraph::new();
        admit(&failed, FILE);
        failed
            .upsert_file_layout(&layout_for(
                FILE,
                ParseCompleteness::Failed("syntax error".into()),
                0,
            ))
            .unwrap();
        let limits = finalized_limits(&failed, FILE);
        assert!(
            limits.contains("file_parsed_"),
            "a failed parse keeps the parse word: {limits}"
        );
        assert!(
            !limits.contains("content_opaque"),
            "and never borrows the opaque cause: {limits}"
        );
    }

    /// `_kin.completeness.limits` as the wire carries it, through the same
    /// finalize the server runs.
    fn finalized_limits(store: &InMemoryGraph, path: &str) -> String {
        let args = HashMap::from([("path".to_string(), serde_json::json!(path))]);
        let finalized = crate::finalize_with_envelope(
            handle_list_file_entities(&args, store).expect("the tool answers"),
            structural_authoritative_envelope(),
            TOOL_NAME,
        );
        let crate::types::ContentBlock::Text { text } = &finalized.content[0];
        let response: serde_json::Value = serde_json::from_str(text).expect("payload is JSON");
        response[crate::ENVELOPE_KEY]["completeness"]["limits"]
            .as_array()
            .unwrap_or_else(|| panic!("the envelope reports limits: {response}"))
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect::<Vec<_>>()
            .join(",")
    }

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

    /// The ticket's own case: a file with N entities enumerates exactly N, and a
    /// name that is not in it is absent.
    ///
    /// The control is `elsewhere`, a real entity this store holds in another
    /// file. Without it, "absent" would be satisfied by a tool that returns
    /// nothing at all, and the fabricated name would prove only that the graph
    /// does not invent rows.
    #[test]
    fn enumerates_exactly_the_file_and_nothing_else() {
        let store = store_with(5, Some(ParseCompleteness::Full));
        let payload = call(&store, &[("path", serde_json::json!(FILE))]).unwrap();

        assert_eq!(payload["total_in_file"], serde_json::json!(5));
        assert_eq!(payload["returned"], serde_json::json!(5));
        let names = names(&payload);
        for index in 0..5 {
            assert!(
                names.contains(&format!("export{index}")),
                "export{index} missing from {names:?}"
            );
        }
        assert!(
            !names.contains(&"elsewhere".to_string()),
            "an entity in another file leaked into {names:?}"
        );
        assert!(
            !names.contains(&"neverDefinedAnywhere".to_string()),
            "a fabricated name appeared in {names:?}"
        );
        assert_eq!(
            payload[FILE_COVERAGE_KEY]["certifies_enumeration"],
            serde_json::json!(true)
        );
        assert_eq!(payload["next_cursor"], serde_json::Value::Null);
    }

    /// A leading `./` is the one path spelling a caller reliably types that the
    /// graph never stores, so it must resolve rather than read as a miss.
    #[test]
    fn a_dot_slash_path_resolves_to_the_same_file() {
        let store = store_with(3, Some(ParseCompleteness::Full));
        let payload = call(&store, &[("path", serde_json::json!("./lib/express.js"))]).unwrap();
        assert_eq!(payload["total_in_file"], serde_json::json!(3));
        assert_eq!(payload["path"], serde_json::json!(FILE));
    }

    /// The refusal the ticket asks for. A path this graph has never seen must
    /// not come back as `entities: []`, because that response says "this file
    /// holds no entities" about a file Kin cannot see.
    #[test]
    fn an_unknown_path_refuses_rather_than_returning_an_empty_list() {
        let store = InMemoryGraph::new();
        let error = call(&store, &[("path", serde_json::json!("lib/nonexistent.js"))])
            .expect_err("an untracked path must refuse");
        let message = error.to_string();
        assert!(
            message.contains("graph gap"),
            "refusal must name the gap; got {message}"
        );
        assert!(
            message.contains("not a claim that the file has no entities"),
            "refusal must deny the absence reading; got {message}"
        );

        // Control: the identical call on a store that holds the file answers,
        // so the refusal is about this path rather than about the tool.
        let seeded = store_with(2, Some(ParseCompleteness::Full));
        let payload = call(&seeded, &[("path", serde_json::json!(FILE))]).unwrap();
        assert_eq!(payload["total_in_file"], serde_json::json!(2));
    }

    /// A path with no admitted identity that DOES carry a layout is a tracked
    /// file, so it answers rather than refusing. This is what stops the refusal
    /// above from firing on every legitimately empty source file.
    #[test]
    fn a_parsed_but_empty_file_answers_empty_instead_of_refusing() {
        let store = InMemoryGraph::new();
        admit(&store, FILE);
        store
            .upsert_file_layout(&layout_for(FILE, ParseCompleteness::Full, 0))
            .unwrap();
        let payload = call(&store, &[("path", serde_json::json!(FILE))]).unwrap();
        assert_eq!(payload["total_in_file"], serde_json::json!(0));
        assert_eq!(
            payload[FILE_COVERAGE_KEY]["parsed"],
            serde_json::json!("full")
        );
        assert_eq!(
            payload[FILE_COVERAGE_KEY]["tier"],
            serde_json::json!("entity_source")
        );
    }

    /// Parse state decides certification, and each state is distinguishable.
    /// A file the extractor never parsed and a file it parsed completely both
    /// return rows; only one of them may be read as the file's whole surface.
    #[test]
    fn parse_state_decides_whether_the_enumeration_is_certified() {
        for (parse, expected, certified) in [
            (Some(ParseCompleteness::Full), "full", true),
            (
                Some(ParseCompleteness::Partial("2 parse error range(s)".into())),
                "partial",
                false,
            ),
            (
                Some(ParseCompleteness::Failed("last known good".into())),
                "failed",
                false,
            ),
            (None, "absent", false),
        ] {
            let store = store_with(4, parse);
            let payload = call(&store, &[("path", serde_json::json!(FILE))]).unwrap();
            assert_eq!(
                payload[FILE_COVERAGE_KEY]["parsed"],
                serde_json::json!(expected)
            );
            assert_eq!(
                payload[FILE_COVERAGE_KEY]["certifies_enumeration"],
                serde_json::json!(certified),
                "parse state {expected} certified the wrong way"
            );
            // Rows are served either way. Withholding real graph truth because
            // it cannot be certified teaches an agent nothing and costs it the
            // answer it can still act on.
            assert_eq!(payload["total_in_file"], serde_json::json!(4));
        }
    }

    /// Pagination walks the whole set with no duplicates and no silent cap.
    #[test]
    fn pagination_covers_the_whole_set_without_duplicates() {
        let store = store_with(7, Some(ParseCompleteness::Full));
        let mut seen: Vec<String> = Vec::new();
        let mut pages = 0;
        let mut cursor: Option<String> = None;

        loop {
            let mut args = vec![("page_size", serde_json::json!(3))];
            match &cursor {
                Some(token) => args.push(("cursor", serde_json::json!(token))),
                None => args.push(("path", serde_json::json!(FILE))),
            }
            let payload = call(&store, &args).unwrap();
            pages += 1;
            assert_eq!(
                payload["total_in_file"],
                serde_json::json!(7),
                "every page must report the whole-file count"
            );
            seen.extend(names(&payload));
            match payload["next_cursor"].as_str() {
                Some(token) => cursor = Some(token.to_string()),
                None => break,
            }
            assert!(pages < 10, "cursor walk did not terminate");
        }

        assert_eq!(pages, 3, "7 entities at page_size 3 is three pages");
        assert_eq!(seen.len(), 7, "walk returned {} rows, want 7", seen.len());
        let unique: std::collections::BTreeSet<&String> = seen.iter().collect();
        assert_eq!(unique.len(), 7, "walk repeated a row: {seen:?}");
        for index in 0..7 {
            assert!(
                seen.contains(&format!("export{index}")),
                "export{index} was never returned across {pages} pages"
            );
        }
    }

    /// A page is not a file. The first page of three carries every entity it
    /// returned and still may not be read as the whole set.
    #[test]
    fn a_partial_page_is_not_certified() {
        let store = store_with(7, Some(ParseCompleteness::Full));
        let payload = call(
            &store,
            &[
                ("path", serde_json::json!(FILE)),
                ("page_size", serde_json::json!(3)),
            ],
        )
        .unwrap();
        assert_eq!(payload["returned"], serde_json::json!(3));
        assert_eq!(payload["total_in_file"], serde_json::json!(7));
        assert_eq!(payload["truncated"], serde_json::json!(true));
        assert_eq!(
            payload[FILE_COVERAGE_KEY]["whole_file_in_response"],
            serde_json::json!(false)
        );
        assert_eq!(
            payload[FILE_COVERAGE_KEY]["certifies_enumeration"],
            serde_json::json!(false),
            "a page of a file must not certify the file"
        );
    }

    /// A cursor minted before the file changed is served, and the shift is named
    /// rather than paged over in silence.
    #[test]
    fn a_cursor_from_a_changed_file_reports_the_shift() {
        let store = store_with(7, Some(ParseCompleteness::Full));
        let stale = PageCursor {
            path: FILE.to_string(),
            offset: 3,
            total: 99,
        }
        .encode();
        let payload = call(&store, &[("cursor", serde_json::json!(stale))]).unwrap();
        assert_eq!(payload["enumeration_shifted"], serde_json::json!(true));
        assert_eq!(
            payload[FILE_COVERAGE_KEY]["certifies_enumeration"],
            serde_json::json!(false)
        );

        // Control: the matching cursor pages cleanly and claims no shift.
        let fresh = PageCursor {
            path: FILE.to_string(),
            offset: 3,
            total: 7,
        }
        .encode();
        let clean = call(&store, &[("cursor", serde_json::json!(fresh))]).unwrap();
        assert_eq!(clean["enumeration_shifted"], serde_json::json!(false));
    }

    /// A cursor names its file, so paging one file with another's cursor is a
    /// refusal rather than a window into a list nobody asked for.
    #[test]
    fn a_cursor_for_another_file_is_refused() {
        let store = store_with(7, Some(ParseCompleteness::Full));
        let token = PageCursor {
            path: "lib/router.js".to_string(),
            offset: 0,
            total: 1,
        }
        .encode();
        let error = call(
            &store,
            &[
                ("path", serde_json::json!(FILE)),
                ("cursor", serde_json::json!(token)),
            ],
        )
        .expect_err("mismatched cursor must refuse");
        assert!(
            error.to_string().contains("page one file at a time"),
            "got {error}"
        );
    }

    /// An absolute path or a `..` escape is refused by name. Without this it
    /// becomes an exact-match miss, which reads as "this file has no entities".
    #[test]
    fn an_inadmissible_path_is_refused_by_name() {
        let store = store_with(3, Some(ParseCompleteness::Full));
        for bad in ["/etc/passwd", "../outside.js", ""] {
            let error = call(&store, &[("path", serde_json::json!(bad))])
                .expect_err("an inadmissible path must refuse");
            let message = error.to_string();
            assert!(
                message.contains("invalid parameter"),
                "{bad:?} refused without naming the parameter: {message}"
            );
        }
        // Control: the admissible path still answers, so the guard rejects bad
        // paths rather than every path.
        let payload = call(&store, &[("path", serde_json::json!(FILE))]).unwrap();
        assert_eq!(payload["total_in_file"], serde_json::json!(3));
    }

    /// The verdict an agent reads. An empty enumeration on a fully parsed file
    /// is a certifiable absence; the same empty enumeration on a file no adapter
    /// parsed is not, and the reason names the parse rather than store health.
    #[test]
    fn absence_is_certified_only_when_the_file_was_parsed() {
        let envelope = structural_authoritative_envelope();

        let parsed = InMemoryGraph::new();
        admit(&parsed, FILE);
        parsed
            .upsert_file_layout(&layout_for(FILE, ParseCompleteness::Full, 0))
            .unwrap();
        let payload = call(&parsed, &[("path", serde_json::json!(FILE))]).unwrap();
        let negative = crate::negative::negative_for(TOOL_NAME, &payload, &envelope, &[])
            .expect("an empty enumeration must carry a negative");
        assert_eq!(
            negative["safe_to_conclude_absent"],
            serde_json::json!(true),
            "a fully parsed empty file is a certifiable absence: {negative}"
        );
        assert_eq!(negative["kind"], serde_json::json!("no_file_entities"));

        let unparsed = InMemoryGraph::new();
        admit(&unparsed, FILE);
        unparsed
            .upsert_opaque_artifact(&kin_model::layout::OpaqueArtifact {
                file_id: FilePathId::new(FILE),
                content_hash: Hash256::from_bytes([0; 32]),
                mime_type: None,
                text_preview: None,
            })
            .unwrap();
        let payload = call(&unparsed, &[("path", serde_json::json!(FILE))]).unwrap();
        let negative = crate::negative::negative_for(TOOL_NAME, &payload, &envelope, &[])
            .expect("an empty enumeration must carry a negative");
        assert_eq!(
            negative["safe_to_conclude_absent"],
            serde_json::json!(false),
            "an unparsed file must never certify an absence: {negative}"
        );
        assert!(
            negative["trust_reason"]
                .as_str()
                .unwrap_or_default()
                .contains("file_not_parsed"),
            "the reason must name the parse, not store health: {negative}"
        );
    }

    /// The negative registry keys this tool's spec on a `const` used as a match
    /// pattern, and a `const` pattern that ever degrades to a fresh binding
    /// matches EVERY tool from that arm onward and hands them all this spec.
    ///
    /// The assertions below are chosen so they CAN fail. A tool whose arm sits
    /// earlier in the match is shadowed by its own arm and would keep its spec
    /// under the bug, so proving anything with one is proving nothing: the two
    /// probes here are a tool whose arm comes AFTER this one, and a tool with no
    /// spec at all, which is the case a catch-all binding turns from `None` into
    /// a confident file-enumeration negative about a response that has no file
    /// in it.
    #[test]
    fn the_file_spec_does_not_swallow_other_tools() {
        let envelope = structural_authoritative_envelope();

        let empty_flow = serde_json::json!({ "chain": [], "total_steps": 0 });
        let negative =
            crate::negative::negative_for("trace_data_flow", &empty_flow, &envelope, &[])
                .expect("trace_data_flow keeps its own negative");
        assert_eq!(
            negative["kind"],
            serde_json::json!("no_flow"),
            "the file-enumeration spec captured a tool declared after it: {negative}"
        );

        assert!(
            crate::negative::negative_for(
                "kin_work_create",
                &serde_json::json!({ "entities": [] }),
                &envelope,
                &[],
            )
            .is_none(),
            "a tool with no negative spec must synthesize no negative"
        );

        // Positive control: this tool still gets its own kind, so the two
        // assertions above are about scoping rather than about a spec that
        // never matches anything.
        let store = InMemoryGraph::new();
        admit(&store, FILE);
        store
            .upsert_file_layout(&layout_for(FILE, ParseCompleteness::Full, 0))
            .unwrap();
        let payload = call(&store, &[("path", serde_json::json!(FILE))]).unwrap();
        let mine = crate::negative::negative_for(TOOL_NAME, &payload, &envelope, &[])
            .expect("the file enumeration carries its own negative");
        assert_eq!(mine["kind"], serde_json::json!("no_file_entities"));
    }

    /// The completeness signal a caller reads instead of the row count. A page
    /// of a file reports its counts as a floor and names why.
    #[test]
    fn completeness_reports_a_page_as_a_floor() {
        let envelope = structural_authoritative_envelope();
        let store = store_with(7, Some(ParseCompleteness::Full));

        let whole = call(&store, &[("path", serde_json::json!(FILE))]).unwrap();
        let annotated = crate::envelope::finalize(
            ToolCallResult::text(serde_json::to_string(&whole).unwrap()),
            envelope.clone(),
            TOOL_NAME,
        );
        let crate::types::ContentBlock::Text { text } = &annotated.content[0];
        let value: serde_json::Value = serde_json::from_str(text).unwrap();
        let counted = &value["_kin"]["completeness"]["counted"];
        assert_eq!(counted["unit"], serde_json::json!("entities_in_file"));
        assert_eq!(counted["reported"], serde_json::json!(7));
        assert_eq!(counted["exact"], serde_json::json!(true));
        assert_eq!(
            value["_kin"]["completeness"]["classes"]["file_parsed"],
            serde_json::json!("present")
        );

        let page = call(
            &store,
            &[
                ("path", serde_json::json!(FILE)),
                ("page_size", serde_json::json!(3)),
            ],
        )
        .unwrap();
        let annotated = crate::envelope::finalize(
            ToolCallResult::text(serde_json::to_string(&page).unwrap()),
            envelope.clone(),
            TOOL_NAME,
        );
        let crate::types::ContentBlock::Text { text } = &annotated.content[0];
        let value: serde_json::Value = serde_json::from_str(text).unwrap();
        let counted = &value["_kin"]["completeness"]["counted"];
        assert_eq!(counted["reported"], serde_json::json!(7));
        assert_eq!(counted["returned"], serde_json::json!(3));
        assert_eq!(counted["exact"], serde_json::json!(false));
        assert_eq!(counted["floor_reason"], serde_json::json!("page_bounded"));
    }
}
