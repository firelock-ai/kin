// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;

use super::repository_authority::RequestRepositoryAuthority;
use kin_model::entity::EntityKind;
use kin_model::graph::{EntityFilter, GraphStore};
use kin_model::relation::RelationKind;
use serde::{Deserialize, Deserializer, Serialize};

use crate::error::{McpError, Result};
use crate::session::SessionRegistry;
use crate::types::ToolCallResult;

use super::common::*;

pub const SEMANTIC_SEARCH_DESC: &str = "\
Find code declarations in the semantic graph by name, kind, or language. Kin has \
already parsed the repository into entities — functions, methods, classes, structs, \
traits, enums, interfaces, types, and constants — so this matches real declarations, \
not raw string occurrences the way a grep would. Reach for it as your first step \
whenever you need to locate \"the thing called X\" or \"every Y of kind class in \
language rust\": it answers in one call and hands back the exact file path, line \
range, signature, and stable entity ID for each match. Those IDs are the currency for \
every other tool here (get_entity_source, get_context_pack, find_references, \
trace_data_flow, …), so a single search gives you everything you need to drill in \
without re-locating the symbol. Returns a ranked list (compact by default: \
id/name/kind/language/file_path/line range/signature; set compact=false to also get \
the doc summary) plus the total match count so you know whether results were \
truncated. Prefer it over text search when you care about declarations and want \
precise, navigable anchors rather than a pile of line hits. \
On an empty result the response carries an additive `negative` object: its \
`safe_to_conclude_absent` flag says whether the absence is authoritative \
(daemon-owned graph, complete embedding coverage, no degraded signals) or merely \
\"not indexed yet\" — check it before treating \"none found\" as ground truth.";

pub fn handle_semantic_search<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let (query, limit, filter) = build_semantic_search_request(args)?;
    let compact = get_optional_bool(args, "compact", true);

    let entities = store.query_entities(&filter).map_err(McpError::graph)?;
    let total_matches = entities.len();

    let json = if compact {
        let limited: Vec<_> = entities
            .into_iter()
            .take(limit)
            .map(CompactSearchResult::from)
            .collect();
        serde_json::to_string_pretty(&CompactSearchResponse {
            query,
            limit,
            total_matches,
            truncated: total_matches > limited.len(),
            results: limited,
        })
        .map_err(McpError::Json)?
    } else {
        let limited: Vec<_> = entities
            .into_iter()
            .take(limit)
            .map(SemanticSearchResult::from)
            .collect();
        serde_json::to_string_pretty(&SemanticSearchResponse {
            query,
            limit,
            total_matches,
            truncated: total_matches > limited.len(),
            results: limited,
        })
        .map_err(McpError::Json)?
    };

    Ok(ToolCallResult::text(json))
}

pub const SEMANTIC_LOCATE_DESC: &str = "\
Rank the code most relevant to a natural-language query. This is the tool to reach for \
when you are looking for \"where is the code that does X\" and you only have a \
description of the behavior, not an exact symbol name. Unlike semantic_search (which \
matches declarations by name/kind/language and ignores the query for ranking), \
semantic_locate ranks by query relevance and returns act-on-able hits: entity_id, file, \
line span, kind, score, and a bounded inline snippet. Set granularity to \"entity\" \
(default) for ranked declarations or \"file\" to roll results up to the most relevant \
files. Two pipelines can answer. By default a stock daemon serves the legacy \
single-vector cosine ranking (the `compat-v0` profile); the full fused retrieval \
pipeline `kin locate` serves — vector similarity, lexical search, and graph-structure \
signals fused with role-aware ranking, exact-name promotion, and (when its model is \
available) cross-encoder reranking — is opt-in per call with `pipeline: \"fused\"` or by \
running the daemon under KIN_PROFILE=accuracy-v1. The `routing` field reports which \
pipeline actually answered: `cosine-v0` for the single-vector default, `fused-v1` for \
the fused pipeline (also selectable per call with `pipeline: \"fused\"`). Every hit also \
carries an additive `match_evidence` object explaining why it ranked — the ranker that \
produced it, the score source, whether the query matched the entity name, and the \
ranking signals that applied — derived from graph-owned retrieval data, never a \
working-tree read. Pass an optional `queries` array of additional query variants to fan \
out: `query` plus each variant are retrieved independently and their rankings RRF-fused \
into one deduped result, with each hit's `match_evidence.matched_variants` naming the \
variants that surfaced it (diverse variants — identifiers, behavior, subsystem — recover \
more than any single phrasing); multi-query fusion always uses the fused pipeline. Both \
pipelines report semantic_coverage — the fraction of the graph \
that has embeddings indexed; the fused arm additionally reports a `degradations` array \
naming any retrieval capability that could not fully run (empty vector index, reranker \
model not cached, …), so a thin result set is attributable instead of silent. Requires \
the Kin daemon: retrieval runs against the daemon's live graph, so this tool returns an \
error in offline/no-daemon mode. On an empty result the additive `negative` object's \
`safe_to_conclude_absent` flag distinguishes an authoritative \"no match\" from \"not \
yet embedded\". A NON-empty result needs the opposite check, because retrieval always \
returns its best candidates: each hit carries `match_kind` (`name` when a query token is \
that entity's name, else `semantic` or `text_fallback`), and the response carries \
`all_fallback: true` when NOT ONE returned entity was named by the query. Asking for a \
symbol that does not exist yields a full, confident-looking page with `all_fallback` set \
— treat that as \"this symbol was not found\" rather than as the answer.";

/// Offline/generic dispatch arm for `semantic_locate`.
///
/// Real vector-ranked retrieval requires the daemon's concrete graph and HNSW
/// index (`embedding_status` and vector search are not part of the generic
/// `GraphStore` trait). In product mode the daemon's `/mcp/tools/call` route
/// special-cases this tool before falling through to the generic dispatcher, so
/// this handler is only reached in offline/no-daemon runs — where it returns a
/// clear, actionable error instead of silently degrading to a metadata filter.
pub fn handle_semantic_locate<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    _store: &G,
) -> Result<ToolCallResult> {
    // Validate the contract args up front so callers get precise feedback even
    // when no daemon is present.
    let _query = get_string_param(args, "query")?;
    if let Some(granularity) = get_optional_string_param(args, "granularity") {
        if granularity != "file" && granularity != "entity" {
            return Err(McpError::InvalidParams(format!(
                "invalid granularity '{granularity}': expected \"file\" or \"entity\""
            )));
        }
    }
    Ok(ToolCallResult::error(
        "semantic_locate requires the Kin daemon for vector search: ranked retrieval runs \
         against the daemon's live graph and HNSW index, which is unavailable in \
         offline/no-daemon mode. Start the repo daemon and retry."
            .to_string(),
    ))
}

pub const GET_ENTITY_DESC: &str = "\
Look up one entity by its ID and return its full metadata: kind, language, file path, \
line range, signature, visibility, role, and any doc summary — but not the source \
body. Use it when you already hold an entity ID (typically from semantic_search or a \
graph traversal) and want the authoritative facts about that declaration without \
pulling in its implementation. It is the lightweight counterpart to get_entity_source: \
reach for get_entity when you only need to confirm what/where a symbol is, and \
get_entity_source when you actually need to read the code.";

pub fn handle_get_entity<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
    repository_authority: Option<&RequestRepositoryAuthority>,
) -> Result<ToolCallResult> {
    let id_str = get_string_param(args, "entity_id")?;
    let entity_id = parse_entity_id(&id_str)?;

    match store.get_entity(&entity_id).map_err(McpError::graph)? {
        Some(entity) => {
            let value = entity_response_json(store, &entity, repository_authority)?;
            let json = serde_json::to_string_pretty(&value).map_err(McpError::Json)?;
            Ok(ToolCallResult::text(json))
        }
        None => Ok(ToolCallResult::error(format!(
            "Entity not found: {}",
            id_str
        ))),
    }
}

pub const GET_ENTITY_SOURCE_DESC: &str = "\
Return the exact implementation body of one entity by ID, served from graph-owned \
truth, along with its metadata (name, kind, language, file path, line range, \
signature). This is how you read the actual code for a declaration once \
semantic_search (or any traversal) has handed you its ID — no need to open the file \
and hunt for line numbers yourself. It returns just the focal entity's body, so it is \
the most economical way to inspect a single function/method/class; when you also need \
the surrounding callers, callees, and imports, use get_context_pack or trace_data_flow \
instead so you don't have to call this repeatedly.";

pub const GET_ENTITY_BODY_DESC: &str = "\
Alias for get_entity_source — same behavior and return shape. Provided so that whichever \
name comes naturally (\"source\" or \"body\") resolves to the same tool. Returns the exact \
implementation body of one entity by ID plus its metadata; prefer get_context_pack or \
trace_data_flow when you also need the entity's neighborhood rather than just its body.";

pub fn handle_get_entity_source<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
    repository_authority: Option<&RequestRepositoryAuthority>,
) -> Result<ToolCallResult> {
    let id_str = get_string_param(args, "entity_id")?;
    let entity_id = parse_entity_id(&id_str)?;

    match store.get_entity(&entity_id).map_err(McpError::graph)? {
        Some(entity) => {
            let exact_source = read_entity_source_excerpt_detailed(
                store,
                &entity,
                10_000,
                1_000_000,
                repository_authority,
                EntitySourceScope::WorkspaceHead,
            )?
            .ok_or_else(|| McpError::Context("entity source body unavailable".into()))?;
            let source = LAST_READ_SOURCE.with(|f| f.get());
            let mut value = serde_json::json!({
                "id": entity.id,
                "name": entity.name,
                "kind": entity.kind,
                "language": entity.language,
                "file_path": entity.file_origin.as_ref().map(|p| p.to_string()),
                "read_path": entity_read_path(&entity),
                "start_line": entity_presentation_start_line(&entity),
                "end_line": entity_presentation_end_line(&entity),
                "signature": entity.signature,
                "body": exact_source.body,
                "source": source,
            });
            if let Some(map) = value.as_object_mut() {
                map.extend(source_provenance_fields(&exact_source));
            }
            let json = serde_json::to_string_pretty(&value).map_err(McpError::Json)?;
            Ok(ToolCallResult::text(json))
        }
        None => Ok(ToolCallResult::error(format!(
            "Entity not found: {}",
            id_str
        ))),
    }
}

pub const GET_ENTITY_SOURCES_DESC: &str = "\
Return the source bodies for many entities in one budgeted call — the batch form of \
get_entity_source. Hand it a list of entity IDs (up to 50, in priority order) and it \
returns each entity's metadata plus its implementation body. Reach for it once \
semantic_search, find_references, or a graph traversal has handed you a set of IDs you \
want to read together: one call replaces the N separate get_entity_source round-trips \
(and N response envelopes) that would otherwise burn your tool-call budget. Bodies are \
filled in the order you list the IDs until the shared token_budget is reached; entities \
past that point come back signature-only with omitted=true and reason=\"budget\", and \
the envelope's truncated flag tells you to raise the budget or split the list. Pass \
compact=true for signature-only rows when you only need to confirm shape, and \
max_lines_per_body / max_bytes_per_body to bound each body. One bad ID never fails the \
batch — an unresolved ID returns its own row with reason=\"not_found\" or \"no_source\". \
Prefer get_context_pack when you need one entity plus its neighborhood rather than a \
flat set of bodies.";

/// Upper bound on IDs per `get_entity_sources` call. Smaller than
/// `bulk_check_references`' 200 because each row can carry a full source body,
/// not just a reference count — 50 keeps a worst-case response bounded even
/// before the token budget clamps it.
pub const MAX_BULK_SOURCE_ENTITIES: usize = 50;

/// One resolved entity's source facts, projected into a path-independent shape:
/// the generic graph store and the daemon graph both build this before the batch
/// envelope is assembled, so the response row is identical across serving paths.
///
/// Each row is individually coherent; the BATCH is not one instant. Authority is
/// sampled per entity, so a 50-row response can straddle workspace generations and
/// two rows may describe different ones. No row is wrong, but nothing here
/// promises they share a moment, which is why each row carries its own provenance
/// rather than the envelope carrying one stamp for all of them. A caller that
/// needs a single consistent snapshot across many entities must compare the
/// per-row `workspace_generation` values rather than assume they agree.
#[derive(Debug, Clone)]
pub struct EntitySourceRow {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub language: String,
    pub file_path: String,
    pub start_line: u32,
    pub end_line: u32,
    pub signature: String,
    pub body: String,
    /// This row's source provenance and span coherence, rendered by the shared
    /// [`source_provenance_fields`] seam, or empty when the serving path had none
    /// to offer.
    ///
    /// A batch row needs this more than a single read does, not less. This tool
    /// returns up to 50 full bodies and exists so an agent can restate source it
    /// is about to overwrite, so "these bytes are uncommitted" and "this span was
    /// never proven to describe them" are exactly the facts it must not have to
    /// guess.
    pub provenance: serde_json::Map<String, serde_json::Value>,
}

/// Per-ID outcome for the batched source tool. Mirrors the single tool's
/// found / not-found / no-source taxonomy so one bad ID degrades to a single
/// omitted row instead of failing the whole batch.
#[derive(Debug, Clone)]
pub enum ResolvedEntitySource {
    /// The entity resolved and its source body was read from graph truth.
    Found(EntitySourceRow),
    /// The ID did not resolve (invalid, stale, or not a UUID). Non-retryable.
    NotFound { id: String, message: String },
    /// The ID resolved but no source body could be served.
    NoSource { id: String, message: String },
}

/// Parsed, defaulted `get_entity_sources` options shared by both serving paths.
#[derive(Debug, Clone)]
pub struct BatchSourceOptions {
    /// Token budget shared across all bodies. `None` = unbounded.
    pub token_budget: Option<usize>,
    /// Emit signature-only rows (no bodies) for every entity when true.
    pub compact: bool,
    pub max_lines_per_body: usize,
    pub max_bytes_per_body: usize,
}

/// Parse and validate the shared `get_entity_sources` arguments. Enforces the
/// 1..=[`MAX_BULK_SOURCE_ENTITIES`] bound up front so both the generic and the
/// daemon path reject the same malformed requests identically.
pub fn parse_batch_source_args(
    args: &HashMap<String, serde_json::Value>,
) -> Result<(Vec<String>, BatchSourceOptions)> {
    let entity_ids = get_optional_string_array(args, "entity_ids").ok_or_else(|| {
        McpError::InvalidParams(
            "missing required parameter: entity_ids (array of entity UUIDs)".into(),
        )
    })?;
    if entity_ids.is_empty() {
        return Err(McpError::InvalidParams(
            "entity_ids must contain at least one UUID".into(),
        ));
    }
    if entity_ids.len() > MAX_BULK_SOURCE_ENTITIES {
        return Err(McpError::InvalidParams(format!(
            "entity_ids contains {} entries; maximum is {}",
            entity_ids.len(),
            MAX_BULK_SOURCE_ENTITIES
        )));
    }
    // A blank entry is a caller bug, not a query. It matches no uuid, so
    // resolution falls through to ranked name selection, and ranking an empty
    // query returns whichever entity sorts first: the row would carry an
    // arbitrary entity's body under the caller's empty id. Refuse the batch
    // rather than answer one of its rows with something nobody asked for.
    if let Some(index) = entity_ids.iter().position(|id| id.trim().is_empty()) {
        return Err(McpError::InvalidParams(format!(
            "entity_ids[{index}] is empty; every entry must be an entity uuid or its exact name"
        )));
    }
    // `token_budget` stays optional (None = unbounded); the others default to
    // the single-tool body bounds so an unclamped batch matches get_entity_source.
    let token_budget = args
        .get("token_budget")
        .and_then(serde_json::Value::as_u64)
        .map(|value| value as usize);
    let compact = get_optional_bool(args, "compact", false);
    let max_lines_per_body =
        get_optional_u64(args, "max_lines_per_body", DEFAULT_SOURCE_MAX_LINES as u64) as usize;
    let max_bytes_per_body =
        get_optional_u64(args, "max_bytes_per_body", DEFAULT_SOURCE_MAX_BYTES as u64) as usize;
    Ok((
        entity_ids,
        BatchSourceOptions {
            token_budget,
            compact,
            max_lines_per_body,
            max_bytes_per_body,
        },
    ))
}

/// Render one resolved-and-found row. A present `body` yields a full-body row;
/// `None` yields a signature-only row. `omitted`/`reason` follow the batch
/// contract: `omitted` is true (with a `reason`) exactly when a body the caller
/// asked for is absent — never for a compact row, where signatures are the
/// contract and the envelope-level `compact` flag is the signal.
fn source_row_json(
    row: &EntitySourceRow,
    body: Option<&str>,
    omitted: bool,
    reason: Option<&str>,
) -> serde_json::Value {
    let mut value = serde_json::json!({
        "id": row.id,
        "name": row.name,
        "kind": row.kind,
        "language": row.language,
        "file_path": row.file_path,
        "start_line": row.start_line,
        "end_line": row.end_line,
        "signature": row.signature,
        "omitted": omitted,
    });
    // Provenance rides with the body, and only with the body: a signature-only or
    // budget-omitted row served no bytes, so it has no byte provenance to describe
    // and stamping one would invite reading it as though it did.
    if let Some(body) = body {
        value["body"] = serde_json::json!(body);
        if let Some(object) = value.as_object_mut() {
            object.extend(row.provenance.clone());
        }
    }
    if let Some(reason) = reason {
        value["reason"] = serde_json::json!(reason);
    }
    value
}

/// Assemble the batch envelope from ordered per-ID resolutions, applying the
/// per-body clamp and the shared token budget.
///
/// Budget mechanics are first-come-first-served: bodies are emitted in request
/// order until the running token estimate would exceed `token_budget`; from that
/// point every remaining resolved body is omitted (signature-only) with
/// `reason = "budget"`, so `truncated` tells the caller to raise the budget or
/// page. `compact` suppresses every body up front with no budget accounting. One
/// row is always emitted per requested ID. `returned` counts the IDs that
/// resolved to a real sourced entity, so `total_requested - returned` is the
/// number of not-found / no-source IDs.
pub fn assemble_entity_sources_response(
    resolved: Vec<ResolvedEntitySource>,
    opts: &BatchSourceOptions,
) -> ToolCallResult {
    let total_requested = resolved.len();
    let mut returned = 0usize;
    let mut truncated = false;
    let mut budget_used = 0usize;
    let mut budget_exhausted = false;
    let mut results = Vec::with_capacity(total_requested);

    for outcome in resolved {
        match outcome {
            ResolvedEntitySource::Found(row) => {
                returned += 1;
                if opts.compact {
                    results.push(source_row_json(&row, None, false, None));
                    continue;
                }
                let body =
                    clamp_source_body(&row.body, opts.max_lines_per_body, opts.max_bytes_per_body);
                if budget_exhausted {
                    truncated = true;
                    results.push(source_row_json(&row, None, true, Some("budget")));
                    continue;
                }
                match opts.token_budget {
                    Some(budget) => {
                        let body_tokens = kin_context::estimate_tokens(&body);
                        if budget_used + body_tokens <= budget {
                            budget_used += body_tokens;
                            results.push(source_row_json(&row, Some(body.as_str()), false, None));
                        } else {
                            budget_exhausted = true;
                            truncated = true;
                            results.push(source_row_json(&row, None, true, Some("budget")));
                        }
                    }
                    None => results.push(source_row_json(&row, Some(body.as_str()), false, None)),
                }
            }
            ResolvedEntitySource::NotFound { id, message } => {
                results.push(serde_json::json!({
                    "id": id,
                    "omitted": true,
                    "reason": "not_found",
                    "message": message,
                }));
            }
            ResolvedEntitySource::NoSource { id, message } => {
                results.push(serde_json::json!({
                    "id": id,
                    "omitted": true,
                    "reason": "no_source",
                    "message": message,
                }));
            }
        }
    }

    let envelope = serde_json::json!({
        "total_requested": total_requested,
        "returned": returned,
        "truncated": truncated,
        "compact": opts.compact,
        "results": results,
    });
    match serde_json::to_string_pretty(&envelope) {
        Ok(json) => ToolCallResult::text(json),
        Err(error) => ToolCallResult::error(error.to_string()),
    }
}

/// Resolve one ID to a [`ResolvedEntitySource`] via the generic graph store,
/// mirroring the single-tool `handle_get_entity_source` body read. Never returns
/// `Err`: a per-ID failure becomes a `NotFound` / `NoSource` row so one bad ID
/// cannot fail the batch. Field formatting matches the daemon path's
/// `GraphSourceRecord` (debug-formatted kind, `to_string` language, raw
/// file path) so the row shape is identical whichever path resolved it.
fn resolve_entity_source_generic<G: GraphStore>(
    held: &HeldSourceAuthority<'_, G>,
    id: &str,
) -> ResolvedEntitySource {
    let store = held.store();
    let entity_id = match parse_entity_id(id) {
        Ok(entity_id) => entity_id,
        Err(_) => {
            return ResolvedEntitySource::NotFound {
                id: id.to_string(),
                message: format!("invalid entity_id (not a UUID): {id}"),
            };
        }
    };
    match store.get_entity(&entity_id) {
        Ok(Some(entity)) => {
            match read_entity_source_excerpt_detailed_held(
                held,
                &entity,
                DEFAULT_SOURCE_MAX_LINES,
                DEFAULT_SOURCE_MAX_BYTES,
                EntitySourceScope::WorkspaceHead,
            ) {
                Ok(Some(source)) => ResolvedEntitySource::Found(EntitySourceRow {
                    id: entity.id.to_string(),
                    name: entity.name.clone(),
                    kind: format!("{:?}", entity.kind),
                    language: entity.language.to_string(),
                    file_path: entity
                        .file_origin
                        .as_ref()
                        .map(|path| path.0.clone())
                        .unwrap_or_default(),
                    start_line: entity_presentation_start_line(&entity).unwrap_or(0),
                    end_line: entity_presentation_end_line(&entity).unwrap_or(0),
                    signature: entity.signature.clone(),
                    provenance: source_provenance_fields(&source),
                    body: source.body,
                }),
                Ok(None) => ResolvedEntitySource::NoSource {
                    id: entity.id.to_string(),
                    message: "entity source body unavailable".to_string(),
                },
                Err(error) => ResolvedEntitySource::NoSource {
                    id: entity.id.to_string(),
                    message: error.to_string(),
                },
            }
        }
        Ok(None) => ResolvedEntitySource::NotFound {
            id: id.to_string(),
            message: format!("Entity not found: {id}"),
        },
        Err(error) => ResolvedEntitySource::NoSource {
            id: id.to_string(),
            message: format!("graph read failed: {error}"),
        },
    }
}

/// Batched `get_entity_source`: resolve every requested ID against the generic
/// graph store and assemble the budgeted envelope. This is the offline/no-daemon
/// dispatch arm; in product mode the daemon special-cases the tool against its
/// concrete graph before falling through here, exactly as it does for the single
/// tool.
pub fn handle_get_entity_sources<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
    repository_authority: Option<&RequestRepositoryAuthority>,
) -> Result<ToolCallResult> {
    let (entity_ids, opts) = parse_batch_source_args(args)?;
    // A batch is one request: it holds authority once for every id it resolves.
    let held = HeldSourceAuthority::new(store, repository_authority);
    let resolved = entity_ids
        .iter()
        .map(|id| resolve_entity_source_generic(&held, id))
        .collect();
    Ok(assemble_entity_sources_response(resolved, &opts))
}

pub const GET_CONTEXT_PACK_DESC: &str = "\
Assemble a focused, ready-to-read context bundle around one entity, fitted to a token \
budget. Starting from a focal entity ID, Kin walks the relation graph to gather the \
nearby code you'd actually need to understand or change it — the focal body plus its \
direct dependencies (signatures), and optionally transitive deps, linked tests, \
contracts, work items, and annotations — and returns it all in a single structured \
response with the token accounting included. Reach for it when a question is about a \
unit of code in context (\"what does X do and what does it touch?\") rather than a single \
isolated body. Its value is that it replaces an open-ended chain of \
get_entity_source / find_references calls — which burns round-trips and easily blows \
your context window — with one budgeted call that stays within the limit you set. \
`focal_entity.body` in the response IS the focal entity's exact source text, so this one \
call already answers \"show me the code\": no follow-up read is needed, and it is the body \
to edit and stage back. If get_entity_source is available to you it is cheaper for a raw \
body alone; if you need to follow an actual call chain step by step, use trace_data_flow.";

pub fn handle_get_context_pack<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
    sessions: &SessionRegistry,
    repository_authority: Option<&RequestRepositoryAuthority>,
) -> Result<ToolCallResult> {
    use kin_context::{build_context_pack_with_traffic, ContextOptions};
    use kin_model::context::TokenBudget;

    let id_str = get_string_param(args, "entity_id")?;
    let entity_id = parse_entity_id(&id_str)?;
    let token_budget_val = get_optional_u64(args, "token_budget", 16000) as usize;
    let depth = get_optional_u64(args, "depth", 2) as u32;
    let include_traffic = get_optional_bool(args, "include_traffic", true);
    let compact = get_optional_bool(args, "compact", false);

    let budget = match token_budget_val {
        0..=8000 => TokenBudget::Small8k,
        8001..=16000 => TokenBudget::Medium16k,
        16001..=32000 => TokenBudget::Large32k,
        n => TokenBudget::Custom(n),
    };

    let opts = ContextOptions {
        budget,
        max_depth: depth,
        include_traffic,
        ..ContextOptions::default()
    };

    // Gather nearby intents for traffic awareness.
    let nearby_intents = if include_traffic {
        sessions.get_traffic_near_entity(&entity_id)
    } else {
        vec![]
    };

    let pack = build_context_pack_with_traffic(store, &entity_id, &opts, &nearby_intents)
        .map_err(|e| McpError::Context(e.to_string()))?;

    // Build structured response JSON. The pack still has to have projected a
    // focal entry for the focal entity to be worth serializing, but the body
    // comes from graph truth rather than from that entry.
    let focal_entry = pack.focal_entities.first();
    let focal_entity = store.get_entity(&entity_id).map_err(McpError::graph)?;

    // One held authority for the whole pack. A pack projects the focal entity
    // and then a body per dependency it carries, so deriving authority per
    // projection multiplies a full recovery by the pack's size.
    let held = HeldSourceAuthority::new(store, repository_authority);

    let focal_json = if let (Some(_), Some(entity)) = (focal_entry, &focal_entity) {
        focal_context_json_held(&held, entity, compact)?
    } else {
        serde_json::json!(null)
    };

    let project_dep = |entry: &kin_model::context::ContextEntry| -> Result<serde_json::Value> {
        // Look up the entity for structured fields.
        if let Some(e) = store
            .get_entity(&entry.entity_id)
            .map_err(McpError::graph)?
        {
            let mut obj = serde_json::json!({
                "id": e.id,
                "name": e.name,
                "kind": e.kind,
                "signature": e.signature,
                "file_path": e.file_origin.as_ref().map(|p| p.to_string()),
                "read_path": entity_read_path(&e),
                "start_line": entity_presentation_start_line(&e),
                "end_line": entity_presentation_end_line(&e),
            });
            if !compact {
                obj["projection"] = serde_json::json!(format!("{:?}", entry.projection_level));
                // A dependency whose file the current workspace does not contain
                // is still a dependency graph truth asserts, so it stays in the
                // pack and says why it has no body. Dropping it would shrink a
                // structural answer silently, and failing here would lose the
                // whole pack over one entity that history explains.
                let (body, absent_reason) = match read_entity_source_excerpt_detailed_held(
                    &held,
                    &e,
                    MCP_SOURCE_MAX_LINES,
                    MCP_SOURCE_MAX_CHARS,
                    EntitySourceScope::WorkspaceHead,
                ) {
                    Ok(body) => (body, None),
                    Err(error) if is_absent_at_generation(&error) => {
                        (None, Some(error.to_string()))
                    }
                    Err(error) => return Err(error),
                };
                let source = LAST_READ_SOURCE.with(|f| f.get());
                obj["source"] = serde_json::json!(source);
                // Same rule as the focal body: a dependency's `body` is the
                // graph-owned projection or null. The pack's own `entry.content`
                // is a token-accounting stub, and serving it here would hand an
                // agent signature text shaped like an implementation.
                match body {
                    Some(source) => {
                        obj["body"] = serde_json::json!(source.body);
                        if let Some(map) = obj.as_object_mut() {
                            map.extend(source_provenance_fields(&source));
                        }
                    }
                    None => {
                        obj["body"] = serde_json::Value::Null;
                        obj["body_unavailable"] = serde_json::json!(
                            absent_reason.unwrap_or_else(|| entity_body_gap_reason(&e))
                        );
                    }
                }
            }
            Ok(obj)
        } else {
            Ok(serde_json::json!({
                "id": entry.entity_id.to_string(),
                "content": entry.content,
            }))
        }
    };

    let dependencies: Vec<_> = pack
        .dependency_signatures
        .iter()
        .map(&project_dep)
        .collect::<Result<Vec<_>>>()?;
    let transitive: Vec<_> = pack
        .transitive_deps
        .iter()
        .map(&project_dep)
        .collect::<Result<Vec<_>>>()?;

    let mut result = serde_json::json!({
        "focal_entity": focal_json,
        "dependencies": dependencies,
        "token_budget": budget.max_tokens(),
        "tokens_used": pack.actual_tokens,
    });

    if !compact {
        if !transitive.is_empty() {
            result["transitive_deps"] = serde_json::json!(transitive);
        }
        let tests: Vec<_> = pack
            .tests
            .iter()
            .map(&project_dep)
            .collect::<Result<Vec<_>>>()?;
        if !tests.is_empty() {
            result["tests"] = serde_json::json!(tests);
        }
        let contracts: Vec<_> = pack
            .contracts
            .iter()
            .map(&project_dep)
            .collect::<Result<Vec<_>>>()?;
        if !contracts.is_empty() {
            result["contracts"] = serde_json::json!(contracts);
        }
        if !pack.work_items.is_empty() {
            result["work_items"] =
                serde_json::to_value(&pack.work_items).map_err(McpError::Json)?;
        }
        if !pack.annotations.is_empty() {
            result["annotations"] =
                serde_json::to_value(&pack.annotations).map_err(McpError::Json)?;
        }
    }

    if include_traffic && !pack.traffic.is_empty() {
        result["nearby_traffic"] = serde_json::to_value(&pack.traffic).map_err(McpError::Json)?;
    }

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

pub const TRACE_COMPUTATION_DESC: &str = "\
Get a focal entity together with its data- and control-flow neighborhood — its body \
plus callers, callees, and imports — in a single structured response within a token \
budget. You can address the focal either by entity_id or by exact name (query), so you \
don't have to resolve the symbol first. Reach for it on \"how does this computation \
work / where does this value come from / what does this end up calling\" questions, \
where the answer lives across several connected entities rather than in one body. Its \
value is consolidation: instead of looping get_entity_source over each step of a trace \
— which exhausts your context and round-trips — one call returns everything needed to \
reason about the flow step by step. By default the focal comes back as a full body and \
its dependencies as signatures (the shape best suited to trace reasoning); set \
compact=true for signature-only entries everywhere when you just need the structure. \
When you specifically want the ordered call chain itself (not a flat neighborhood), \
trace_data_flow walks the relations directionally and inlines each step.";

/// Convenience wrapper over `get_context_pack`: resolves the focal entity from
/// either `entity_id` or an exact-name `query`, applies trace-friendly defaults
/// (full focal body, signature-only deps), and returns the focal neighborhood in
/// one call so callers don't loop `get_entity_source` over each step of a trace.
pub fn handle_trace_computation<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
    sessions: &SessionRegistry,
    repository_authority: Option<&RequestRepositoryAuthority>,
) -> Result<ToolCallResult> {
    let mut merged: HashMap<String, serde_json::Value> = args.clone();

    if !merged.contains_key("entity_id") {
        if let Some(query) = get_optional_string_param(args, "query") {
            let target = select_best_reference_target(store, &query).map_err(McpError::graph)?;
            let Some(entity) = target else {
                return Ok(ToolCallResult::error(format!(
                    "trace_computation: no entity matches query '{}'",
                    query
                )));
            };
            merged.insert(
                "entity_id".into(),
                serde_json::Value::String(entity.id.to_string()),
            );
        } else {
            return Err(McpError::InvalidParams(
                "trace_computation requires either entity_id or query".into(),
            ));
        }
    }

    merged.entry("depth".into()).or_insert(serde_json::json!(3));
    merged
        .entry("token_budget".into())
        .or_insert(serde_json::json!(8000));
    merged
        .entry("compact".into())
        .or_insert(serde_json::json!(false));

    handle_get_context_pack(&merged, store, sessions, repository_authority)
}

pub const FIND_REFERENCES_DESC: &str = "\
Find who depends on an entity — its direct upstream callers, importers, and references. \
Give it an entity_id or an exact symbol name (it resolves the best-matching canonical \
definition) and it returns one row per upstream site with the relation kind, file path, \
line, and signature. Use it to answer \"who calls / imports / uses this?\" before you \
change or remove something, to gauge blast radius, or to navigate from a definition out \
to its usages. Filter with relation_kinds (calls, imports, references) when you only \
care about one kind of edge; it defaults to all three. When you need this answer for \
many entities at once (e.g. classifying a whole set as used vs. unused), don't loop \
this call per entity — bulk_check_references does the batch in one shot. \
When no references come back, the additive `negative` object's `safe_to_conclude_absent` \
flag says whether \"nothing depends on this\" is authoritative (daemon-owned graph, \
complete coverage, no degraded signals) or merely \"not indexed yet\" — consult it \
before treating the entity as safe to delete. An entity_id or name that resolves to nothing \
carries the same object, naming the resolution miss rather than reporting an empty result.";

fn normalize_cross_repo_repo_id(raw: Option<&str>) -> std::result::Result<String, String> {
    raw.map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            "KIN_REPO_ID is missing or blank; cross-repo authority cannot bind this graph to a repository"
                .to_string()
        })
}

/// Cross-repository binding for a caller that has no daemon-owned authority.
///
/// The standalone MCP server resolves this from the process environment once,
/// at its entry boundary. Holding the resolved values rather than re-reading
/// `KIN_REPO_ID` and `KIN_DAEMON_URL` mid-request means one request cannot see
/// two different bindings, and means a test can name a binding by argument
/// instead of writing the process-global table that every thread in the binary
/// shares.
#[derive(Clone, Debug)]
pub struct AmbientCrossRepoBinding {
    repo_id: std::result::Result<String, String>,
    daemon_url: Option<String>,
}

impl AmbientCrossRepoBinding {
    /// Bind to an explicitly named repository and spine endpoint.
    pub fn new(repo_id: Option<&str>, daemon_url: Option<&str>) -> Self {
        Self {
            repo_id: normalize_cross_repo_repo_id(repo_id),
            daemon_url: daemon_url
                .map(str::trim)
                .filter(|value| !value.is_empty())
                .map(str::to_owned),
        }
    }

    /// Resolve the binding from the process environment.
    pub fn from_env() -> Self {
        let repo_id = match std::env::var("KIN_REPO_ID") {
            Ok(value) => normalize_cross_repo_repo_id(Some(&value)),
            Err(std::env::VarError::NotPresent) => normalize_cross_repo_repo_id(None),
            Err(std::env::VarError::NotUnicode(_)) => Err(
                "KIN_REPO_ID is not valid Unicode; cross-repo authority cannot bind this graph to a repository"
                    .to_string(),
            ),
        };
        Self {
            repo_id,
            daemon_url: std::env::var("KIN_DAEMON_URL")
                .ok()
                .map(|value| value.trim().to_owned())
                .filter(|value| !value.is_empty()),
        }
    }
}

/// Daemon-owned cross-repository authority for `find_references`.
///
/// The daemon constructs this from its resolved repository identity and its
/// in-process spine. Neither value comes from MCP request arguments or ambient
/// process configuration, so a caller cannot redirect the authority query.
#[derive(Clone, Copy)]
pub struct FindReferencesAuthority<'a> {
    pub repo_id: &'a str,
    /// Exact root of the concrete live/session graph serving this request.
    pub graph_root: &'a str,
    pub spine: Option<&'a dyn kin_spine::SpineBackend>,
}

enum FindReferencesAuthoritySource<'a> {
    Ambient(AmbientCrossRepoBinding),
    Daemon(FindReferencesAuthority<'a>),
}

fn spine_reference_rows(
    repo_id: &str,
    target_id: &kin_model::EntityId,
    response: &kin_spine::SpineXrefResponse,
) -> Vec<ReferenceRow> {
    let mut rows = Vec::new();
    for edge in &response.edges {
        if edge.dst_repo != repo_id || edge.dst_entity != *target_id || edge.src_repo == repo_id {
            continue;
        }

        let source = response
            .entities
            .iter()
            .find(|entity| entity.repo_id == edge.src_repo && entity.entity_id == edge.src_entity);
        let name = source
            .map(|entity| entity.name.clone())
            .unwrap_or_else(|| edge.src_entity.to_string());
        let file_path = source
            .and_then(|entity| entity.file_path.as_deref())
            .map(|path| format!("[{}] {path}", edge.src_repo))
            .unwrap_or_else(|| format!("[{}] {}", edge.src_repo, edge.src_entity));

        rows.push(ReferenceRow {
            // The source ID belongs to another repo's graph authority. Returning
            // it as a local drill-through ID would resolve against the wrong
            // graph, so the repo-qualified path remains the navigation anchor.
            entity_id: None,
            name,
            kind: source.map(|entity| format!("{:?}", entity.kind)),
            file_path: Some(file_path),
            start_line: None,
            // A federated xref carries no site span from the other repo's graph.
            reference_lines: Vec::new(),
            signature: source.map(|entity| entity.signature.clone()),
            snippet: None,
            // CrossRepoEdge proves a dependency but does not retain whether
            // the source relation was Calls/Imports/References.
            relation_kinds: Vec::new(),
        });
    }

    rows
}

fn reference_filter_covers_unknown_subtypes(relation_kinds: &[RelationKind]) -> bool {
    let defaults = default_reference_kinds();
    relation_kinds.len() == defaults.len()
        && defaults.iter().all(|kind| relation_kinds.contains(kind))
}

fn reference_row_json(row: ReferenceRow) -> serde_json::Value {
    serde_json::json!({
        "entity_id": row.entity_id,
        "name": row.name,
        "kind": row.kind,
        "file_path": row.file_path,
        // `start_line` locates the CALLER's definition; `reference_lines` locates
        // the usages inside it. Both are graph facts and both are 1-based, so an
        // agent never has to count forward from a definition to find a call site.
        "start_line": row.start_line,
        "reference_lines": row.reference_lines,
        "signature": row.signature,
        "snippet": row.snippet,
        "relation_kinds": row
            .relation_kinds
            .into_iter()
            .map(relation_kind_name)
            .collect::<Vec<_>>(),
    })
}

fn daemon_spine_xref(
    authority: FindReferencesAuthority<'_>,
    target_id: &kin_model::EntityId,
) -> std::result::Result<(String, kin_spine::SpineQuery<kin_spine::SpineXrefResponse>), String> {
    let repo_id = normalize_cross_repo_repo_id(Some(authority.repo_id))?;
    let query = match authority.spine {
        Some(spine) => {
            let body = spine.cross_repo_xref_response(&repo_id, target_id);
            if body.authority_root_matches(&repo_id, authority.graph_root) {
                kin_spine::SpineQuery::Found(body)
            } else {
                kin_spine::SpineQuery::Unavailable(format!(
                    "spine root mismatch for repository {repo_id}: live/session graph root {} is not the registered spine root",
                    authority.graph_root
                ))
            }
        }
        None => kin_spine::SpineQuery::NotConfigured,
    };
    Ok((repo_id, query))
}

/// What `find_references` answers when the name it was given resolves to
/// nothing.
///
/// Public because a caller that has already ruled the name out from the name
/// index answers with this rather than a second wording: `negative.rs` keys the
/// `focal_not_resolved` envelope off the text, so two producers drifting apart
/// would silently drop the qualifier from one of them.
pub const FIND_REFERENCES_FOCAL_MISS: &str = "Entity not found";

pub async fn handle_find_references<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
    repository_authority: Option<&RequestRepositoryAuthority>,
) -> Result<ToolCallResult> {
    handle_find_references_with_authority_source(
        args,
        store,
        FindReferencesAuthoritySource::Ambient(AmbientCrossRepoBinding::from_env()),
        repository_authority,
    )
    .await
}

/// Serve `find_references` from an explicitly named ambient binding.
///
/// Same behavior as [`handle_find_references`], with the repository id and
/// spine endpoint supplied rather than read from the process environment. A
/// test covering the ambient path names its binding here instead of writing
/// `KIN_REPO_ID` and `KIN_DAEMON_URL`, which are process-global and, under
/// `cargo test`, visible to every other test in the binary.
pub async fn handle_find_references_with_ambient_binding<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
    binding: AmbientCrossRepoBinding,
    repository_authority: Option<&RequestRepositoryAuthority>,
) -> Result<ToolCallResult> {
    handle_find_references_with_authority_source(
        args,
        store,
        FindReferencesAuthoritySource::Ambient(binding),
        repository_authority,
    )
    .await
}

/// Serve `find_references` from daemon-owned repository and spine authority.
///
/// This avoids an HTTP loop back into the same daemon and, more importantly,
/// prevents `KIN_REPO_ID`, `KIN_DAEMON_URL`, or request fields from changing
/// which repository graph the answer is bound to.
pub async fn handle_find_references_with_authority<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
    authority: FindReferencesAuthority<'_>,
    repository_authority: Option<&RequestRepositoryAuthority>,
) -> Result<ToolCallResult> {
    handle_find_references_with_authority_source(
        args,
        store,
        FindReferencesAuthoritySource::Daemon(authority),
        repository_authority,
    )
    .await
}

async fn handle_find_references_with_authority_source<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
    authority_source: FindReferencesAuthoritySource<'_>,
    repository_authority: Option<&RequestRepositoryAuthority>,
) -> Result<ToolCallResult> {
    let relation_kinds = if let Some(raw_kinds) = get_optional_string_array(args, "relation_kinds")
    {
        if raw_kinds.is_empty() {
            default_reference_kinds()
        } else {
            raw_kinds
                .iter()
                .map(|kind| {
                    parse_reference_kind(kind).ok_or_else(|| {
                        McpError::InvalidParams(format!(
                            "unsupported relation kind '{}': use calls, imports, or references",
                            kind
                        ))
                    })
                })
                .collect::<Result<Vec<_>>>()?
        }
    } else {
        default_reference_kinds()
    };

    let target = if let Some(entity_id_str) = get_optional_string_param(args, "entity_id") {
        let entity_id = parse_entity_id(&entity_id_str)?;
        store.get_entity(&entity_id).map_err(McpError::graph)?
    } else if let Some(query) = get_optional_string_param(args, "query") {
        select_best_reference_target(store, &query).map_err(McpError::graph)?
    } else {
        return Err(McpError::InvalidParams(
            "missing required parameter: entity_id or query".into(),
        ));
    };

    let Some(target) = target else {
        return Ok(ToolCallResult::error(FIND_REFERENCES_FOCAL_MISS));
    };

    let mut rows =
        collect_graph_reference_rows(store, &target.id, &relation_kinds, repository_authority)?;
    // ── Federated Xrefs via Spine ─────────────────────────────────────
    let cross_repo_query = match authority_source {
        FindReferencesAuthoritySource::Ambient(binding) => match binding.repo_id {
            Ok(repo_id) => {
                let query = match binding.daemon_url.as_deref() {
                    Some(daemon_url) => fetch_spine_xref_at(daemon_url, &repo_id, &target.id).await,
                    None => kin_spine::SpineQuery::NotConfigured,
                };
                Ok((repo_id, query))
            }
            Err(reason) => Err(reason),
        },
        FindReferencesAuthoritySource::Daemon(authority) => {
            daemon_spine_xref(authority, &target.id)
        }
    };
    let cross_repo = match cross_repo_query {
        Err(reason) => {
            tracing::warn!(reason = %reason, "cross-repo repository binding unavailable for references enrichment");
            serde_json::json!({
                "status": "unavailable",
                "reason": reason,
            })
        }
        Ok((repo_id, query)) => match query {
            kin_spine::SpineQuery::Found(body) => {
                let federated_rows = spine_reference_rows(&repo_id, &target.id, &body);
                let relation_subtype_complete =
                    reference_filter_covers_unknown_subtypes(&relation_kinds)
                        || federated_rows.is_empty();
                let reference_count = if relation_subtype_complete {
                    rows.extend(federated_rows.iter().cloned());
                    federated_rows.len()
                } else {
                    0
                };
                let federated_references = federated_rows
                    .into_iter()
                    .map(reference_row_json)
                    .collect::<Vec<_>>();
                let authority_complete = body.authority_complete_for(&repo_id, &target.id);
                serde_json::json!({
                    "status": "available",
                    "payload_version": body.version(),
                    "reference_count": reference_count,
                    "federated_reference_count": federated_references.len(),
                    "federated_references": federated_references,
                    "relation_subtype_complete": relation_subtype_complete,
                    "authority_complete": authority_complete,
                    "authority_anchor": body.authority_anchor,
                    "authority_revision": body.authority_revision,
                    "authority_roots": body.authority_roots,
                })
            }
            // Spine configured but unreachable: surface as a warning rather than
            // silently dropping cross-repo references (which would read as "none").
            kin_spine::SpineQuery::Unavailable(reason) => {
                tracing::warn!(reason = %reason, "cross-repo spine unavailable for references enrichment");
                serde_json::json!({
                    "status": "unavailable",
                    "reason": reason,
                })
            }
            // Local-only (no spine configured): quiet — cross-repo refs don't apply.
            kin_spine::SpineQuery::NotConfigured => serde_json::json!({
                "status": "not_configured",
            }),
        },
    };

    rows.sort_by(|left, right| {
        left.file_path
            .cmp(&right.file_path)
            .then_with(|| left.name.cmp(&right.name))
    });

    // `entity_id` remains the local drill-through keystone. Federated rows use
    // repo-qualified paths and carry no local entity id.
    let references = rows.into_iter().map(reference_row_json).collect::<Vec<_>>();

    let result = serde_json::json!({
        "focal_entity": {
            "id": target.id,
            "name": target.name,
            "kind": target.kind,
            "file_path": target.file_origin.as_ref().map(|p| p.to_string()),
            "signature": target.signature,
        },
        "relation_kinds": relation_kinds
            .iter()
            .copied()
            .map(relation_kind_name)
            .collect::<Vec<_>>(),
        "total_upstream": references.len(),
        "references": references,
        "cross_repo": cross_repo,
    });

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

/// Batched reachability check: classify many entities in a single call.
///
/// Returns one row per requested entity_id with `has_references`, `reference_count`,
/// and (in non-compact mode) the matching relation kinds and entity metadata.
/// Unknown entities or authority gaps carry `has_references: null` and
/// `verdict_complete: false`; they are never counted as unreferenced. A numeric
/// total is emitted only with `reference_count_complete: true`; otherwise
/// `known_reference_count` is the explicit lower bound and `reference_count`
/// is null.
/// Designed for reachability / dead-code / count-callers workloads where calling
/// `find_references` per entity blows up token budgets.
pub const BULK_CHECK_REFERENCES_DESC: &str = "\
Classify many entities for reachability in one call. Pass up to 200 entity IDs and get \
back one row each: whether incoming relations of the requested kind exist \
(has_references) and how many (reference_count); set compact=false to also include \
name, kind, file path, and the matched relation kinds. Reach for it whenever the \
question is \"of these N entities, which have callers / which are unused?\" — \
reachability sweeps, dead-code candidate filtering, or counting callers across a set. \
Its value is that it collapses what would otherwise be N separate find_references calls \
(and N round-trips, plus the token cost of N full reference listings) into a single \
batched classification. Choose relation_kind to scope the check to Calls, Imports, \
References, or Any (the union, default). For a single entity where you want the actual \
list of callers, find_references is the right tool; for finding dead code from a search \
concept rather than a known ID set, find_dead_code_seeded combines the search and the \
classification. Each `has_references:false` row is qualified by the response's additive \
`negative` object — consult `safe_to_conclude_absent` before treating a false verdict as \
\"safe to delete\". Unknown entities, stale authority, and unclassified federated relation \
subtypes return `has_references:null` with `verdict_complete:false`, never a false verdict. \
When total count authority is incomplete, `reference_count` is null and \
`known_reference_count` is only a lower bound.";

pub fn handle_bulk_check_references<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    handle_bulk_check_references_with_authority_source(args, store, None)
}

/// Serve the batched reachability tool from the same exact daemon graph/spine
/// authority as `find_references`.
pub fn handle_bulk_check_references_with_authority<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
    authority: FindReferencesAuthority<'_>,
) -> Result<ToolCallResult> {
    handle_bulk_check_references_with_authority_source(args, store, Some(authority))
}

fn handle_bulk_check_references_with_authority_source<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
    authority: Option<FindReferencesAuthority<'_>>,
) -> Result<ToolCallResult> {
    const MAX_BULK_ENTITIES: usize = 200;

    let entity_ids_raw = get_optional_string_array(args, "entity_ids").ok_or_else(|| {
        McpError::InvalidParams(
            "missing required parameter: entity_ids (array of entity UUIDs)".into(),
        )
    })?;
    if entity_ids_raw.is_empty() {
        return Err(McpError::InvalidParams(
            "entity_ids must contain at least one UUID".into(),
        ));
    }
    if entity_ids_raw.len() > MAX_BULK_ENTITIES {
        return Err(McpError::InvalidParams(format!(
            "entity_ids contains {} entries; maximum is {}",
            entity_ids_raw.len(),
            MAX_BULK_ENTITIES
        )));
    }

    let relation_kinds = parse_bulk_relation_kind(
        get_optional_string_param(args, "relation_kind")
            .as_deref()
            .unwrap_or("Any"),
    )?;
    let compact = get_optional_bool(args, "compact", true);

    let allowed: std::collections::HashSet<RelationKind> = relation_kinds.iter().copied().collect();
    let relation_subtype_complete = reference_filter_covers_unknown_subtypes(&relation_kinds);
    let mut results = Vec::with_capacity(entity_ids_raw.len());
    let mut cross_repo_checked = 0usize;
    let mut cross_repo_authority_complete = true;
    let mut cross_repo_revision = None;
    let mut cross_repo_roots = serde_json::Map::new();
    let mut cross_repo_watermark_initialized = false;
    let mut cross_repo_watermark_complete = true;
    let mut cross_repo_unavailable = None;
    let mut federated_reference_count = 0usize;
    let mut saw_unknown_federated_subtype = false;

    for raw_id in &entity_ids_raw {
        let entity_id = match parse_entity_id(raw_id) {
            Ok(id) => id,
            Err(_) => {
                let mut row = serde_json::json!({
                    "entity_id": raw_id,
                    "error": "invalid entity_id (not a UUID)",
                    "has_references": null,
                    "reference_count": null,
                    "known_reference_count": null,
                    "reference_count_complete": false,
                    "verdict_complete": false,
                });
                if !compact {
                    row["federated_reference_count"] = serde_json::Value::Null;
                }
                results.push(row);
                continue;
            }
        };

        let entity = store.get_entity(&entity_id).map_err(McpError::graph)?;
        let Some(entity) = entity else {
            let mut row = serde_json::json!({
                "entity_id": raw_id,
                "error": "entity not found",
                "has_references": null,
                "reference_count": null,
                "known_reference_count": null,
                "reference_count_complete": false,
                "verdict_complete": false,
            });
            if !compact {
                row["name"] = serde_json::Value::Null;
                row["kind"] = serde_json::Value::Null;
                row["file_path"] = serde_json::Value::Null;
                row["matched_kinds"] = serde_json::json!([]);
                row["federated_reference_count"] = serde_json::Value::Null;
            }
            results.push(row);
            continue;
        };

        let mut reference_count = 0usize;
        let mut matched_kinds: Vec<RelationKind> = Vec::new();
        for rel in store
            .get_all_relations_for_entity(&entity_id)
            .map_err(McpError::graph)?
        {
            let Some(src_entity_id) = rel.src.as_entity() else {
                continue;
            };
            if rel.dst != kin_model::relation::GraphNodeId::Entity(entity_id) {
                continue;
            }
            if !allowed.contains(&rel.kind) {
                continue;
            }
            if src_entity_id == entity_id {
                continue;
            }
            reference_count += 1;
            if !matched_kinds.contains(&rel.kind) {
                matched_kinds.push(rel.kind);
            }
        }

        let mut entity_federated_reference_count = 0usize;
        // Local-only execution may prove a positive, but it has no authority
        // to classify a zero or numeric count as the cross-repo total.
        let mut entity_cross_repo_authority_complete = false;
        if let Some(authority) = authority {
            match daemon_spine_xref(authority, &entity_id) {
                Ok((repo_id, kin_spine::SpineQuery::Found(body))) => {
                    cross_repo_checked += 1;
                    entity_cross_repo_authority_complete =
                        body.authority_complete_for(&repo_id, &entity_id);
                    cross_repo_authority_complete &= entity_cross_repo_authority_complete;
                    let body_roots = body
                        .authority_roots
                        .iter()
                        .map(|(repo, root)| (repo.clone(), serde_json::Value::String(root.clone())))
                        .collect::<serde_json::Map<_, _>>();
                    if !cross_repo_watermark_initialized {
                        cross_repo_revision = body.authority_revision.clone();
                        cross_repo_roots = body_roots;
                        cross_repo_watermark_initialized = true;
                    } else if body.authority_revision != cross_repo_revision
                        || body_roots != cross_repo_roots
                    {
                        // A topology mutation raced this batch. Known positives
                        // remain useful, but no false row spans one atomic
                        // authority watermark, so the batch cannot certify
                        // absence.
                        cross_repo_authority_complete = false;
                        cross_repo_watermark_complete = false;
                    }
                    entity_federated_reference_count = body
                        .edges
                        .iter()
                        .filter(|edge| {
                            edge.dst_repo == repo_id
                                && edge.dst_entity == entity_id
                                && edge.src_repo != repo_id
                        })
                        .count();
                    federated_reference_count += entity_federated_reference_count;
                    if relation_subtype_complete && entity_federated_reference_count > 0 {
                        reference_count += entity_federated_reference_count;
                    }
                }
                Ok((_, kin_spine::SpineQuery::Unavailable(reason))) => {
                    cross_repo_unavailable.get_or_insert(reason);
                    cross_repo_authority_complete = false;
                }
                Ok((_, kin_spine::SpineQuery::NotConfigured)) => {
                    cross_repo_unavailable
                        .get_or_insert_with(|| "cross-repo spine is not configured".to_string());
                    cross_repo_authority_complete = false;
                }
                Err(reason) => {
                    cross_repo_unavailable.get_or_insert(reason);
                    cross_repo_authority_complete = false;
                }
            }
        }

        let known_positive = reference_count > 0;
        let federated_count_incomplete =
            !relation_subtype_complete && entity_federated_reference_count > 0;
        saw_unknown_federated_subtype |= federated_count_incomplete;
        let federated_subtype_unknown = federated_count_incomplete && !known_positive;
        let reference_count_complete =
            entity_cross_repo_authority_complete && !federated_count_incomplete;
        let has_references = if known_positive {
            Some(true)
        } else if reference_count_complete {
            Some(false)
        } else {
            None
        };
        let verdict_complete = has_references.is_some();
        let reported_reference_count = reference_count_complete.then_some(reference_count);
        let verdict_reason = if federated_subtype_unknown {
            Some("federated relation subtype unavailable")
        } else if !entity_cross_repo_authority_complete && !known_positive {
            Some("cross-repo authority incomplete")
        } else {
            None
        };

        if compact {
            let mut row = serde_json::json!({
                "entity_id": entity_id,
                "has_references": has_references,
                "reference_count": reported_reference_count,
                "known_reference_count": reference_count,
                "reference_count_complete": reference_count_complete,
                "federated_reference_count": entity_federated_reference_count,
                "verdict_complete": verdict_complete,
            });
            if let Some(reason) = verdict_reason {
                row["verdict_reason"] = serde_json::json!(reason);
            }
            results.push(row);
        } else {
            matched_kinds.sort_by_key(|kind| relation_kind_rank(kind));
            let mut row = serde_json::json!({
                "entity_id": entity_id,
                "name": entity.name,
                "kind": format!("{:?}", entity.kind),
                "file_path": entity.file_origin.as_ref().map(|p| p.to_string()),
                "has_references": has_references,
                "reference_count": reported_reference_count,
                "known_reference_count": reference_count,
                "reference_count_complete": reference_count_complete,
                "federated_reference_count": entity_federated_reference_count,
                "verdict_complete": verdict_complete,
                "matched_kinds": matched_kinds
                    .into_iter()
                    .map(relation_kind_name)
                    .collect::<Vec<_>>(),
            });
            if let Some(reason) = verdict_reason {
                row["verdict_reason"] = serde_json::json!(reason);
            }
            results.push(row);
        }
    }

    // If the topology watermark changed between rows, every negative row in
    // this batch becomes inconclusive. Preserve known positives, but never
    // leave a boolean `false` that spans two authority revisions.
    if !cross_repo_watermark_complete {
        for row in &mut results {
            if row
                .get("has_references")
                .and_then(serde_json::Value::as_bool)
                == Some(false)
            {
                row["has_references"] = serde_json::Value::Null;
                row["verdict_complete"] = serde_json::json!(false);
                row["verdict_reason"] =
                    serde_json::json!("cross-repo authority changed during batch");
            }
            if row.get("error").is_none() {
                row["reference_count"] = serde_json::Value::Null;
                row["reference_count_complete"] = serde_json::json!(false);
            }
        }
    }

    let total_checked = entity_ids_raw.len();
    let classified_count = results
        .iter()
        .filter(|row| {
            row.get("has_references")
                .is_some_and(serde_json::Value::is_boolean)
        })
        .count();
    let error_count = results
        .iter()
        .filter(|row| row.get("error").is_some())
        .count();
    let with_references = results
        .iter()
        .filter(|row| {
            row.get("has_references")
                .and_then(serde_json::Value::as_bool)
                == Some(true)
        })
        .count();
    let without_references = results
        .iter()
        .filter(|row| {
            row.get("has_references")
                .and_then(serde_json::Value::as_bool)
                == Some(false)
        })
        .count();
    let incomplete_verdict_count = total_checked
        .saturating_sub(classified_count)
        .saturating_sub(error_count);
    let verdicts_complete =
        classified_count == total_checked && error_count == 0 && cross_repo_watermark_complete;
    let relation_subtype_verdicts_complete =
        relation_subtype_complete || !saw_unknown_federated_subtype;
    let mut result = serde_json::json!({
        "total_checked": total_checked,
        "classified_count": classified_count,
        "error_count": error_count,
        "incomplete_verdict_count": incomplete_verdict_count,
        "with_references": with_references,
        "without_references": without_references,
        "relation_kinds": relation_kinds
            .iter()
            .copied()
            .map(relation_kind_name)
            .collect::<Vec<_>>(),
        "compact": compact,
        "results": results,
    });

    if authority.is_some() {
        result["cross_repo"] = if let Some(reason) = cross_repo_unavailable {
            serde_json::json!({
                "status": "unavailable",
                "reason": reason,
                "checked_entities": cross_repo_checked,
                "relation_subtype_complete": false,
            })
        } else {
            serde_json::json!({
                "status": "available",
                "checked_entities": cross_repo_checked,
                "authority_complete": cross_repo_authority_complete && verdicts_complete,
                "authority_revision": cross_repo_revision,
                "authority_roots": cross_repo_roots,
                "federated_reference_count": federated_reference_count,
                "relation_subtype_complete": relation_subtype_verdicts_complete,
                "verdicts_complete": verdicts_complete,
            })
        };
    }

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

fn parse_bulk_relation_kind(value: &str) -> Result<Vec<RelationKind>> {
    match value.to_ascii_lowercase().as_str() {
        "any" | "all" => Ok(default_reference_kinds()),
        "calls" | "call" => Ok(vec![RelationKind::Calls]),
        "imports" | "import" => Ok(vec![RelationKind::Imports]),
        "references" | "reference" | "refs" => Ok(vec![RelationKind::References]),
        other => Err(McpError::InvalidParams(format!(
            "unsupported relation_kind '{}': use Calls, Imports, References, or Any",
            other
        ))),
    }
}

pub const EXPLORE_CODEBASE_DESC: &str = "\
Explore a codebase in one shot, choosing the lens that fits the question. With \
strategy='overview' you get a map of the repository — entity counts broken down by \
kind and language, plus the top public declarations — ideal for orienting yourself in \
an unfamiliar repo. With strategy='search' (the default) you get the best-matching \
entities for your query each wrapped in its own focused context pack. With \
strategy='trace' you get a matched entity followed out along an ordered call chain, \
with real source bodies and the constants it imports inlined. The whole point is to \
answer broad, open-ended questions (\"how is auth structured?\", \"walk me through the \
request path\") in a single budgeted request instead of a long back-and-forth of \
semantic_search → get_entity_source → find_references. Use it to start exploration; \
once you've identified a specific entity, the targeted tools (get_entity_source, \
get_context_pack, find_references, trace_data_flow) let you go deeper precisely.";

pub fn handle_explore_codebase<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
    repository_authority: Option<&RequestRepositoryAuthority>,
) -> Result<ToolCallResult> {
    use kin_context::{build_context_pack, estimate_tokens, ContextOptions};
    use kin_model::context::TokenBudget;

    // One held authority for the whole exploration: the trace rendering below
    // reads a body per chain step and per constant it finds.
    let held = HeldSourceAuthority::new(store, repository_authority);

    let query = get_string_param(args, "query")?;
    let strategy = args
        .get("strategy")
        .and_then(|v| v.as_str())
        .unwrap_or("search");
    let token_budget = get_optional_u64(args, "token_budget", 8000) as usize;

    let mut output = String::new();
    let mut tokens_used: usize = 0;

    match strategy {
        "overview" => {
            // Get all entities and summarize by kind/language.
            let all_entities = store
                .query_entities(&EntityFilter::default())
                .map_err(McpError::graph)?;

            let total = all_entities.len();
            let mut by_kind: HashMap<String, usize> = HashMap::new();
            let mut by_lang: HashMap<String, usize> = HashMap::new();

            for e in &all_entities {
                *by_kind.entry(format!("{:?}", e.kind)).or_default() += 1;
                *by_lang.entry(e.language.to_string()).or_default() += 1;
            }

            output.push_str(&format!("# Codebase Overview ({} entities)\n\n", total));

            output.push_str("## By Kind\n");
            let mut kinds: Vec<_> = by_kind.into_iter().collect();
            kinds.sort_by(|a, b| b.1.cmp(&a.1));
            for (kind, count) in &kinds {
                output.push_str(&format!("  {}: {}\n", kind, count));
            }

            output.push_str("\n## By Language\n");
            let mut langs: Vec<_> = by_lang.into_iter().collect();
            langs.sort_by(|a, b| b.1.cmp(&a.1));
            for (lang, count) in &langs {
                output.push_str(&format!("  {}: {}\n", lang, count));
            }

            // Top declarations (public functions, classes, traits) up to budget.
            output.push_str("\n## Top Declarations\n");
            let mut top_decls: Vec<_> = all_entities
                .iter()
                .filter(|e| {
                    e.visibility == kin_model::entity::Visibility::Public
                        && matches!(
                            e.kind,
                            EntityKind::Function
                                | EntityKind::Class
                                | EntityKind::TraitDef
                                | EntityKind::Interface
                                | EntityKind::Module
                                | EntityKind::EnumDef
                        )
                })
                .collect();
            top_decls.sort_by(|a, b| a.name.cmp(&b.name));

            for decl in &top_decls {
                let line = format!(
                    "  {:?} {} ({}){}\n",
                    decl.kind,
                    decl.name,
                    decl.language,
                    decl.file_origin
                        .as_ref()
                        .map(|p| format!(" — {}", p))
                        .unwrap_or_default(),
                );
                let line_tokens = estimate_tokens(&line);
                if tokens_used + line_tokens > token_budget {
                    output.push_str(&format!(
                        "  ... ({} more declarations truncated)\n",
                        top_decls.len() - tokens_used
                    ));
                    break;
                }
                tokens_used += line_tokens;
                output.push_str(&line);
            }

            // Also filter by query if it's not just a broad request.
            if !query.is_empty() && query != "*" {
                let filter = EntityFilter {
                    name_pattern: Some(query.clone()),
                    ..Default::default()
                };
                let matched = store.query_entities(&filter).map_err(McpError::graph)?;
                if !matched.is_empty() {
                    output.push_str(&format!(
                        "\n## Matching '{}' ({} results)\n",
                        query,
                        matched.len()
                    ));
                    for e in matched.iter().take(20) {
                        let line =
                            format!("  {} {:?} {} — {}\n", e.id, e.kind, e.name, e.signature,);
                        let line_tokens = estimate_tokens(&line);
                        if tokens_used + line_tokens > token_budget {
                            break;
                        }
                        tokens_used += line_tokens;
                        output.push_str(&line);
                    }
                }
            }
        }
        "trace" => {
            let trace_query = parse_trace_query(&query);
            let filter = EntityFilter {
                name_pattern: Some(trace_query.symbol.clone()),
                ..Default::default()
            };
            let matches = store.query_entities(&filter).map_err(McpError::graph)?;

            if let Some(focal) =
                select_best_reference_target(store, &trace_query.symbol).map_err(McpError::graph)?
            {
                output.push_str(&format!(
                    "# Trace: {} ({:?}, {})\n",
                    focal.name, focal.kind, focal.language
                ));
                output.push_str(&format!("  Signature: {}\n", focal.signature));
                if let Some(ref fp) = focal.file_origin {
                    output.push_str(&format!("  File: {}\n", fp));
                }
                if let Some(ref span) = focal.span {
                    let (start_line, end_line) = presentation_span_lines(span);
                    output.push_str(&format!("  Lines: {start_line}–{end_line}\n"));
                }

                let chain = collect_primary_trace_chain(store, &focal, 12)?;

                if !chain.is_empty() {
                    output.push_str("\n## Ordered Call Chain\n");
                    tokens_used = estimate_tokens(&output);

                    for (index, step) in chain.iter().enumerate() {
                        if !push_with_budget(
                            &mut output,
                            &mut tokens_used,
                            token_budget,
                            &format!("\n{}. {} ({:?})\n", index + 1, step.name, step.kind),
                        ) {
                            output.push_str("  ... (truncated)\n");
                            break;
                        }

                        if let Some(read_path) = entity_read_path(step) {
                            if !push_with_budget(
                                &mut output,
                                &mut tokens_used,
                                token_budget,
                                &format!("   File: {read_path}\n"),
                            ) {
                                output.push_str("  ... (truncated)\n");
                                break;
                            }
                        }
                        if let Some(span) = step.span.as_ref() {
                            let (start_line, end_line) = presentation_span_lines(span);
                            if !push_with_budget(
                                &mut output,
                                &mut tokens_used,
                                token_budget,
                                &format!("   Lines: {start_line}–{end_line}\n"),
                            ) {
                                output.push_str("  ... (truncated)\n");
                                break;
                            }
                        }

                        let outgoing_calls =
                            outgoing_related_entities(store, &step.id, &[RelationKind::Calls])?;
                        let step_body = trace_body_held(&held, step)?;
                        let constants = trace_constants_for_step(store, step, &step_body)?;

                        if !push_with_budget(
                            &mut output,
                            &mut tokens_used,
                            token_budget,
                            "   Body:\n",
                        ) || !push_indented_body(
                            &mut output,
                            &mut tokens_used,
                            token_budget,
                            &step_body,
                        ) {
                            output.push_str("       ... [truncated]\n");
                            break;
                        }

                        if let Some(next_step) = chain.get(index + 1) {
                            if !push_with_budget(
                                &mut output,
                                &mut tokens_used,
                                token_budget,
                                &format!("   Next call: {}\n", next_step.name),
                            ) {
                                output.push_str("  ... (truncated)\n");
                                break;
                            }
                        } else if outgoing_calls.is_empty()
                            && !push_with_budget(
                                &mut output,
                                &mut tokens_used,
                                token_budget,
                                "   Next call: none\n",
                            )
                        {
                            output.push_str("  ... (truncated)\n");
                            break;
                        }

                        if !constants.is_empty() {
                            if !push_with_budget(
                                &mut output,
                                &mut tokens_used,
                                token_budget,
                                "   Imported constants:\n",
                            ) {
                                output.push_str("  ... (truncated)\n");
                                break;
                            }
                            for constant in &constants {
                                if !push_with_budget(
                                    &mut output,
                                    &mut tokens_used,
                                    token_budget,
                                    &format!("     - {} ({:?})\n", constant.name, constant.kind),
                                ) {
                                    output.push_str("  ... (truncated)\n");
                                    break;
                                }
                                let constant_body = trace_body_held(&held, constant)?;
                                if !push_indented_body(
                                    &mut output,
                                    &mut tokens_used,
                                    token_budget,
                                    &constant_body,
                                ) {
                                    output.push_str("       ... [truncated]\n");
                                    break;
                                }
                            }
                        }
                    }
                }

                if let Some(input_literal) = trace_query.input_literal {
                    if let Some(evaluation) =
                        evaluate_trace_chain_held(&held, &chain, input_literal)?
                    {
                        if push_with_budget(
                            &mut output,
                            &mut tokens_used,
                            token_budget,
                            "\n## Evaluation Walkthrough\n",
                        ) {
                            let _ = push_with_budget(
                                &mut output,
                                &mut tokens_used,
                                token_budget,
                                &format!("  Input: {input_literal}\n"),
                            );
                            for (index, step) in evaluation.iter().enumerate() {
                                if !push_with_budget(
                                    &mut output,
                                    &mut tokens_used,
                                    token_budget,
                                    &format!(
                                        "  {}. {}({}) = {} [{}]\n",
                                        index + 1,
                                        step.name,
                                        input_literal,
                                        step.value,
                                        step.detail
                                    ),
                                ) {
                                    output.push_str("  ... (truncated)\n");
                                    break;
                                }
                            }
                            let final_value =
                                evaluation.last().map(|step| step.value).unwrap_or_default();
                            let _ = push_with_budget(
                                &mut output,
                                &mut tokens_used,
                                token_budget,
                                &format!("  Final result: {final_value}\n"),
                            );
                        }
                    }
                }

                let mut similar_candidates = matches;
                if similar_candidates.len() <= 1 {
                    if let Some(broader_query) = broaden_trace_query(&trace_query.symbol) {
                        let broader_matches = store
                            .query_entities(&EntityFilter {
                                name_pattern: Some(broader_query),
                                ..Default::default()
                            })
                            .map_err(McpError::graph)?;
                        for entity in broader_matches {
                            if !similar_candidates.iter().any(|known| known.id == entity.id) {
                                similar_candidates.push(entity);
                            }
                        }
                    }
                }

                let similar = similar_candidates
                    .into_iter()
                    .filter(|entity| entity.id != focal.id)
                    .collect::<Vec<_>>();

                if !similar.is_empty() {
                    let header = "\n## Similar Matches\n";
                    if push_with_budget(&mut output, &mut tokens_used, token_budget, header) {
                        for entity in similar {
                            let line = format!(
                                "  - {} ({:?}){}\n",
                                entity.name,
                                entity.kind,
                                entity_read_path(&entity)
                                    .map(|path| format!(" — {path}"))
                                    .unwrap_or_default(),
                            );
                            if !push_with_budget(&mut output, &mut tokens_used, token_budget, &line)
                            {
                                output.push_str("  ... (truncated)\n");
                                break;
                            }
                        }
                    }
                }
            } else {
                output.push_str(&format!("No entities found matching '{}'\n", query));
            }
        }
        _ => {
            // "search" strategy: find top 3 matches, build context packs.
            let filter = EntityFilter {
                name_pattern: Some(query.clone()),
                ..Default::default()
            };
            let entities = store.query_entities(&filter).map_err(McpError::graph)?;

            if entities.is_empty() {
                output.push_str(&format!("No entities found matching '{}'\n", query));
            } else {
                let top_n = entities.into_iter().take(3).collect::<Vec<_>>();
                let per_entity_budget = token_budget / top_n.len();

                output.push_str(&format!(
                    "# Search: '{}' ({} results shown)\n\n",
                    query,
                    top_n.len()
                ));

                for entity in &top_n {
                    let budget = match per_entity_budget {
                        0..=8000 => TokenBudget::Small8k,
                        8001..=16000 => TokenBudget::Medium16k,
                        _ => TokenBudget::Large32k,
                    };
                    let opts = ContextOptions {
                        budget,
                        max_depth: 1,
                        include_traffic: false,
                        ..ContextOptions::default()
                    };

                    output.push_str(&format!(
                        "## {} ({:?}, {})\n",
                        entity.name, entity.kind, entity.language
                    ));
                    output.push_str(&format!("  ID: {}\n", entity.id));
                    output.push_str(&format!("  Signature: {}\n", entity.signature));
                    if let Some(ref fp) = entity.file_origin {
                        output.push_str(&format!("  File: {}\n", fp));
                    }
                    if let Some(ref span) = entity.span {
                        let (start_line, end_line) = presentation_span_lines(span);
                        output.push_str(&format!("  Lines: {start_line}–{end_line}\n"));
                    }

                    match build_context_pack(store, &entity.id, &opts) {
                        Ok(pack) => {
                            if !pack.dependency_signatures.is_empty() {
                                output.push_str("  Dependencies:\n");
                                for dep in &pack.dependency_signatures {
                                    let line = format!("    {}\n", dep.content.trim());
                                    let line_tokens = estimate_tokens(&line);
                                    if tokens_used + line_tokens > token_budget {
                                        output.push_str("    ... (truncated)\n");
                                        break;
                                    }
                                    tokens_used += line_tokens;
                                    output.push_str(&line);
                                }
                            }
                        }
                        Err(_) => {
                            output.push_str("  (context pack unavailable)\n");
                        }
                    }
                    output.push('\n');
                }
            }
        }
    }

    tokens_used = estimate_tokens(&output);

    let result = serde_json::json!({
        "strategy": strategy,
        "query": query,
        "tokens_used": tokens_used,
        "token_budget": token_budget,
        "content": output,
    });

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

pub const DEAD_CODE_DESC: &str = "\
List dead or unreachable code straight from the semantic graph. With no filters it \
returns entities that have no incoming relations at all — nothing calls, imports, or \
references them — across the whole repo, up to `limit`. Pass `files` to narrow the \
scan to specific file paths and return only the dead functions, methods, and classes \
declared there, ignoring within-file references so genuinely-unused declarations stand \
out. Reach for it when you want to find removable code, audit a module for orphaned \
definitions, or check whether a particular file still has live entry points. Because \
reachability is read directly off the graph's relation edges, you get the answer in one \
call without manually cross-referencing every symbol. When you'd rather start from a \
search concept than scan files — \"which of the entities matching X are dead?\" — \
find_dead_code_seeded combines the search and the dead-classification in one step. \
The response carries an additive `negative` object whose `safe_to_conclude_absent` flag \
says whether \"nothing dead found\" is authoritative or limited by index freshness — \
check it before concluding everything is reachable.";

pub fn handle_dead_code<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let limit = get_optional_u64(args, "limit", 50) as usize;
    let files = get_optional_string_array(args, "files").unwrap_or_default();

    if !files.is_empty() {
        let mut dead = Vec::new();
        let incoming_kinds = [
            RelationKind::Calls,
            RelationKind::Imports,
            RelationKind::References,
        ];

        for file in files {
            let mut entities = store
                .query_entities(&EntityFilter {
                    kinds: Some(vec![
                        EntityKind::Function,
                        EntityKind::Method,
                        EntityKind::Class,
                    ]),
                    languages: None,
                    name_pattern: None,
                    file_path: Some(kin_model::ids::FilePathId::new(file)),
                    roles: None,
                })
                .map_err(McpError::graph)?;

            entities.sort_by(|a, b| {
                let a_line = a
                    .span
                    .as_ref()
                    .map(|span| span.start_line)
                    .unwrap_or(u32::MAX);
                let b_line = b
                    .span
                    .as_ref()
                    .map(|span| span.start_line)
                    .unwrap_or(u32::MAX);
                a_line
                    .cmp(&b_line)
                    .then_with(|| a.name.cmp(&b.name))
                    .then_with(|| a.id.to_string().cmp(&b.id.to_string()))
            });

            for entity in entities {
                let is_live = store
                    .has_incoming_relation_kinds(&entity.id, &incoming_kinds, true)
                    .map_err(McpError::graph)?;
                if !is_live {
                    dead.push(entity);
                    if dead.len() >= limit {
                        let json = serde_json::to_string_pretty(&dead).map_err(McpError::Json)?;
                        return Ok(ToolCallResult::text(json));
                    }
                }
            }
        }

        let json = serde_json::to_string_pretty(&dead).map_err(McpError::Json)?;
        return Ok(ToolCallResult::text(json));
    }

    let dead = store.find_dead_code().map_err(McpError::graph)?;
    let limited: Vec<_> = dead.into_iter().take(limit).collect();

    let json = serde_json::to_string_pretty(&limited).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

pub const FIND_DEAD_CODE_SEEDED_DESC: &str = "\
Find dead code starting from a search concept, in a single call. Give it a query (a \
concept or partial name) and it searches the graph for the top-N matching entities, \
counts each one's incoming references, and returns them ranked dead-first — each row \
annotated with reference_count and a boolean `dead` flag, plus name, kind, file, and \
signature. Reach for it when you suspect a feature/area is unused and want to confirm \
which of its declarations are actually orphaned, without first knowing their IDs. Its \
value is that it fuses three steps — semantic_search, then a reference count per match, \
then the dead filter — into one response, so you don't loop find_references over every \
candidate and exhaust your round-trips on a large repo. Use dead_code instead when you \
want a whole-repo or file-scoped sweep rather than a concept-seeded one, and \
bulk_check_references when you already hold the exact set of entity IDs to classify.";

/// Seeded find-dead-code primitive: `semantic_search(query)` + per-candidate
/// reference counting + dead-filter, returned as one structured response, so
/// callers don't loop `semantic_search` → `find_references` per entity.
///
/// This generic-`GraphStore` implementation uses substring matching against
/// `query_entities` (matching the MCP `semantic_search` shape). In product
/// mode the daemon may special-case this tool to use the concrete-graph
/// vector path for true semantic ranking — both share the same response
/// shape and dead-classification logic.
pub fn handle_find_dead_code_seeded<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    const DEFAULT_LIMIT: usize = 20;
    const MAX_LIMIT: usize = 200;

    let query = get_string_param(args, "query")?;
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Err(McpError::InvalidParams(
            "query must be a non-empty string".into(),
        ));
    }
    let limit =
        (get_optional_u64(args, "limit", DEFAULT_LIMIT as u64) as usize).clamp(1, MAX_LIMIT);

    let filter = kin_model::graph::EntityFilter {
        name_pattern: Some(trimmed.to_string()),
        ..Default::default()
    };
    let entities = store.query_entities(&filter).map_err(McpError::graph)?;

    let reference_kinds = [
        RelationKind::Calls,
        RelationKind::Imports,
        RelationKind::References,
    ];
    let allowed: std::collections::HashSet<RelationKind> =
        reference_kinds.iter().copied().collect();

    let mut candidates: Vec<serde_json::Value> = Vec::new();
    let mut seen: std::collections::HashSet<kin_model::EntityId> = std::collections::HashSet::new();

    for entity in entities.into_iter().take(limit) {
        if !seen.insert(entity.id) {
            continue;
        }
        let mut reference_count = 0usize;
        for rel in store
            .get_all_relations_for_entity(&entity.id)
            .map_err(McpError::graph)?
        {
            let Some(src_entity_id) = rel.src.as_entity() else {
                continue;
            };
            if rel.dst != kin_model::relation::GraphNodeId::Entity(entity.id) {
                continue;
            }
            if !allowed.contains(&rel.kind) {
                continue;
            }
            if src_entity_id == entity.id {
                continue;
            }
            reference_count += 1;
        }
        let dead = reference_count == 0;
        candidates.push(serde_json::json!({
            "id": entity.id.to_string(),
            "name": entity.name,
            "kind": format!("{:?}", entity.kind),
            "file": entity.file_origin.as_ref().map(|p| p.to_string()),
            "signature": (!entity.signature.is_empty()).then_some(entity.signature),
            "reference_count": reference_count,
            "dead": dead,
        }));
    }

    candidates.sort_by(|a, b| {
        let a_count = a["reference_count"].as_u64().unwrap_or(0);
        let b_count = b["reference_count"].as_u64().unwrap_or(0);
        let a_name = a["name"].as_str().unwrap_or("");
        let b_name = b["name"].as_str().unwrap_or("");
        let a_id = a["id"].as_str().unwrap_or("");
        let b_id = b["id"].as_str().unwrap_or("");
        a_count
            .cmp(&b_count)
            .then_with(|| a_name.cmp(b_name))
            .then_with(|| a_id.cmp(b_id))
    });

    let total_searched = candidates.len();
    let result = serde_json::json!({
        "query": trimmed,
        "total_searched": total_searched,
        "candidates": candidates,
    });

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

pub const TRACE_DATA_FLOW_DESC: &str = "\
Walk the actual call/data-flow chain rooted at a focal entity and return it as an \
ordered list of steps in one call. Unlike trace_computation (which returns a flat \
neighborhood), this follows Calls/Imports/References edges directionally from the \
focal: direction='calls' walks outward to callees, 'callers' walks inward to callers, \
'both' merges them — recursing to depth N with a per-step fan-out cap, and inlining \
each step's body (in product mode, served from graph source records). Address the focal \
by entity_id or by exact name. Reach for it when you need to follow a path \"what does \
this call, and what do those call?\" or \"trace this value back to its source\" and want \
the chain in traversal order, not a bag of neighbors. Its value is that the whole walk \
happens substrate-side and comes back as one structured response, so you don't loop \
get_entity_source per hop and exhaust your tool-call budget. Tune depth and \
limit_per_step to control breadth; results flag when they were truncated. \
When the chain comes back empty, the additive `negative` object's `safe_to_conclude_absent` \
flag says whether \"no flow from here\" is authoritative or merely \"not indexed yet\", and its \
`subject` scopes the absence to the direction that was walked, so an empty 'callers' result is \
never read as \"this calls nothing\". A focal name the graph holds more than once, and a method \
whose incoming calls may not have been linked, each downgrade that flag rather than certifying \
absence. A focal that resolves to no entity at all carries the same object, naming the \
resolution miss rather than reporting an empty chain.";

/// Trace the actual call/data-flow chain rooted at a focal entity.
///
/// Walks Calls/Imports/References relations from the focal in the requested
/// direction, recurses to depth N, and returns the chain as a structured
/// response, so callers don't loop `get_entity_source` per step. The
/// generic-`GraphStore` implementation here produces the chain without inlined
/// source bodies; the daemon special-cases this tool against the concrete graph
/// to also inline source records — both share this same chain-construction logic.
pub fn handle_trace_data_flow<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    const DEFAULT_DEPTH: u64 = 3;
    const MAX_DEPTH: u64 = 8;
    const DEFAULT_LIMIT_PER_STEP: u64 = 5;
    const MAX_LIMIT_PER_STEP: u64 = 25;
    const MAX_TOTAL_STEPS: usize = 200;

    let focal = get_string_param(args, "focal")?;
    let trimmed = focal.trim();
    if trimmed.is_empty() {
        return Err(McpError::InvalidParams(
            "focal must be a non-empty string".into(),
        ));
    }
    let depth = get_optional_u64(args, "depth", DEFAULT_DEPTH).clamp(1, MAX_DEPTH) as usize;
    let limit_per_step = get_optional_u64(args, "limit_per_step", DEFAULT_LIMIT_PER_STEP)
        .clamp(1, MAX_LIMIT_PER_STEP) as usize;
    let direction = match get_optional_string_param(args, "direction") {
        Some(value) => match value.trim().to_lowercase().as_str() {
            "calls" | "callee" | "callees" | "out" | "outgoing" => "calls",
            "callers" | "caller" | "in" | "incoming" => "callers",
            "both" | "all" | "" => "both",
            other => {
                return Err(McpError::InvalidParams(format!(
                    "invalid direction '{other}': expected calls, callers, or both"
                )));
            }
        },
        None => "both",
    };

    // Resolve focal: UUID first, then exact-name lookup via the ranking path.
    let focal_id = uuid::Uuid::parse_str(trimmed).ok();
    let focal_entity = if let Some(uuid) = focal_id {
        store
            .get_entity(&kin_model::ids::EntityId(uuid))
            .map_err(McpError::graph)?
    } else {
        select_best_reference_target(store, trimmed).map_err(McpError::graph)?
    };
    let Some(focal_entity) = focal_entity else {
        return Ok(ToolCallResult::error(format!(
            "trace_data_flow: no entity matches focal '{}'",
            trimmed
        )));
    };
    let same_name_candidates = same_name_entity_count(store, &focal_entity.name)?;

    let reference_kinds = [
        RelationKind::Calls,
        RelationKind::Imports,
        RelationKind::References,
    ];
    let allowed: std::collections::HashSet<RelationKind> =
        reference_kinds.iter().copied().collect();

    let want_callees = matches!(direction, "calls" | "both");
    let want_callers = matches!(direction, "callers" | "both");

    let mut chain: Vec<serde_json::Value> = Vec::new();
    let mut visited: std::collections::HashSet<kin_model::ids::EntityId> =
        std::collections::HashSet::new();
    visited.insert(focal_entity.id);
    let mut truncated = false;

    let mut frontier: Vec<(usize, kin_model::ids::EntityId, usize)> = vec![(0, focal_entity.id, 0)];

    while !frontier.is_empty() {
        let mut next_frontier: Vec<(usize, kin_model::ids::EntityId, usize)> = Vec::new();
        for (parent_step, parent_id, parent_depth) in frontier.drain(..) {
            if parent_depth >= depth {
                continue;
            }
            let relations = store
                .get_all_relations_for_entity(&parent_id)
                .map_err(McpError::graph)?;
            // Independent per-direction budgets so `direction=both` doesn't
            // starve one side when relations are emitted in either order.
            let mut callee_count = 0usize;
            let mut caller_count = 0usize;
            for rel in &relations {
                if !allowed.contains(&rel.kind) {
                    continue;
                }
                let src_entity = rel.src.as_entity();
                let dst_entity = match rel.dst {
                    kin_model::relation::GraphNodeId::Entity(id) => Some(id),
                    _ => None,
                };
                let (next_id, role) = if want_callees
                    && src_entity == Some(parent_id)
                    && dst_entity.is_some()
                    && dst_entity != Some(parent_id)
                {
                    (dst_entity.unwrap(), "callee")
                } else if want_callers
                    && dst_entity == Some(parent_id)
                    && src_entity.is_some()
                    && src_entity != Some(parent_id)
                {
                    (src_entity.unwrap(), "caller")
                } else {
                    continue;
                };

                if role == "callee" && callee_count >= limit_per_step {
                    truncated = true;
                    continue;
                }
                if role == "caller" && caller_count >= limit_per_step {
                    truncated = true;
                    continue;
                }

                if !visited.insert(next_id) {
                    continue;
                }
                if role == "callee" {
                    callee_count += 1;
                } else {
                    caller_count += 1;
                }
                if chain.len() >= MAX_TOTAL_STEPS {
                    truncated = true;
                    break;
                }
                let next_entity = match store.get_entity(&next_id).map_err(McpError::graph)? {
                    Some(entity) => entity,
                    None => continue,
                };
                let next_depth = parent_depth + 1;
                let step_index = chain.len() + 1;
                chain.push(serde_json::json!({
                    "step": step_index,
                    "role": role,
                    "relation_kind": format!("{:?}", rel.kind),
                    "parent_step": parent_step,
                    "depth": next_depth,
                    "entity_id": next_entity.id.to_string(),
                    "entity_name": next_entity.name,
                    "entity_kind": format!("{:?}", next_entity.kind),
                    "entity_file": next_entity.file_origin.as_ref().map(|p| p.to_string()),
                    "signature": (!next_entity.signature.is_empty()).then_some(next_entity.signature),
                }));
                if next_depth < depth {
                    next_frontier.push((step_index, next_id, next_depth));
                }
            }
            if chain.len() >= MAX_TOTAL_STEPS {
                truncated = true;
                break;
            }
        }
        if chain.len() >= MAX_TOTAL_STEPS {
            truncated = true;
            break;
        }
        frontier = next_frontier;
    }

    let total_steps = chain.len();
    let result = serde_json::json!({
        "focal_id": focal_entity.id.to_string(),
        "focal_name": focal_entity.name,
        "focal_kind": format!("{:?}", focal_entity.kind),
        "focal_file": focal_entity.file_origin.as_ref().map(|p| p.to_string()),
        "direction": direction,
        "depth": depth,
        "chain": chain,
        "total_steps": total_steps,
        "truncated": truncated,
        "focal_resolution": {
            "addressed_by": if focal_id.is_some() { "entity_id" } else { "name" },
            "same_name_candidates": same_name_candidates,
        },
    });

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

/// How many entities carry `name` exactly, the focal included.
///
/// A name the graph holds more than once is the cfg-twin shape: two arms of the
/// same declaration are admitted as distinct entities, and a call the extractor
/// cannot attribute to one of them lands on neither. The walk follows a single
/// candidate, so an empty chain says nothing about the others. Only the handler
/// can see how many there were, and the qualifier that reads this treats an
/// unreported count as unknown rather than as one.
///
/// Never reports zero: the focal was resolved from this store, so it is its own
/// first candidate whatever the pattern query matched.
fn same_name_entity_count<G: GraphStore>(store: &G, name: &str) -> Result<usize> {
    let filter = EntityFilter {
        name_pattern: Some(name.to_string()),
        ..Default::default()
    };
    let matched = store.query_entities(&filter).map_err(McpError::graph)?;
    Ok(matched
        .iter()
        .filter(|entity| entity.name == name)
        .count()
        .max(1))
}

pub const GRAPH_NEIGHBORHOOD_DESC: &str = "\
Get the dependency neighborhood of an entity — both what it depends on and what depends \
on it — as a compact graph. Starting from an entity ID, Kin traverses the semantic \
relations (calls, imports, implements, …) out to the depth you specify and returns the \
reachable entities as lightweight summaries (id, name, kind, file, signature) plus the \
edges connecting them, along with total counts and a truncation flag. Traversal follows \
edges in both directions by default: direction='out' walks only what the focal depends \
on, 'in' walks only what depends on the focal (its dependents — this is the blast-radius \
direction), and 'both' merges them. Every returned edge carries the direction it was \
traversed in, so dependencies and dependents are never conflated. Reach for it when you \
want the structural shape around a symbol — its blast radius and its supports — rather \
than full source bodies: impact-scoping a change, understanding coupling, or mapping how \
a module hangs together. It returns summaries rather than code precisely so the \
neighborhood stays within token budgets even at depth; when you then want to read a \
specific neighbor's implementation, follow up with get_entity_source, and when you want \
a directional ordered chain with bodies inlined, use trace_data_flow. \
When no neighbors come back, the additive `negative` object's `safe_to_conclude_absent` \
flag says whether that absence is authoritative or merely \"not indexed yet\", and its \
`subject` scopes the absence to the side that was walked, so an empty 'in' result is never \
read as \"no dependencies\". A focal that is not in the graph is reported as that gap \
rather than as an isolated entity.";

/// Traverse the neighborhood around a focal entity in the requested direction.
///
/// Walks the relation table with [`GraphStore::get_all_relations_for_entity`],
/// which returns an entity's outgoing *and* incoming edges from two separate
/// adjacency indexes at the same cost. This deliberately does not use
/// `get_dependency_neighborhood`: that traversal is fed only the outgoing index,
/// so it returns what the focal depends on and never what depends on it. This
/// tool has always described itself as answering both, which meant an agent
/// asking for blast radius was handed the focal's dependencies and told they
/// were its dependents — the one error a caller cannot detect from the output.
/// Direction is now traversed as described and tagged per edge.
pub fn handle_graph_neighborhood<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    // Bidirectional traversal widens the frontier: a hot callee's incoming edge
    // set is unbounded in a way its outgoing set is not, so the walk is capped
    // and reports the cap through `truncated` rather than returning a partial
    // neighborhood that looks complete.
    const MAX_VISITED_ENTITIES: usize = 2_000;

    let id_str = get_string_param(args, "entity_id")?;
    let entity_id = parse_entity_id(&id_str)?;
    let depth = get_optional_u64(args, "depth", 2) as u32;
    let limit = get_optional_u64(args, "limit", 30) as usize;
    let direction = match get_optional_string_param(args, "direction") {
        Some(value) => match value.trim().to_lowercase().as_str() {
            "out" | "outgoing" | "dependencies" | "depends_on" | "calls" => "out",
            "in" | "incoming" | "dependents" | "callers" | "impact" => "in",
            "both" | "all" | "" => "both",
            other => {
                return Err(McpError::InvalidParams(format!(
                    "invalid direction '{other}': expected out, in, or both"
                )));
            }
        },
        None => "both",
    };
    let want_outgoing = matches!(direction, "out" | "both");
    let want_incoming = matches!(direction, "in" | "both");

    let mut visited: std::collections::HashSet<kin_model::ids::EntityId> =
        std::collections::HashSet::new();
    let mut entities: Vec<serde_json::Value> = Vec::new();
    let mut relations: Vec<serde_json::Value> = Vec::new();
    let mut seen_relations: std::collections::HashSet<kin_model::ids::RelationId> =
        std::collections::HashSet::new();
    let mut truncated = false;

    // The focal itself is part of its own neighborhood, matching what the
    // previous traversal returned so counts stay comparable across the change.
    if let Some(focal) = store.get_entity(&entity_id).map_err(McpError::graph)? {
        visited.insert(entity_id);
        entities.push(compact_entity_summary(&focal));
    }

    let mut frontier: Vec<(kin_model::ids::EntityId, u32)> = vec![(entity_id, 0)];
    while !frontier.is_empty() && !truncated {
        let mut next_frontier: Vec<(kin_model::ids::EntityId, u32)> = Vec::new();
        for (current, current_depth) in frontier.drain(..) {
            if current_depth >= depth {
                continue;
            }
            let edges = store
                .get_all_relations_for_entity(&current)
                .map_err(McpError::graph)?;
            for rel in &edges {
                let src_entity = rel.src.as_entity();
                let dst_entity = rel.dst.as_entity();
                // Classify by which endpoint is the node being expanded, so the
                // tag names the direction actually traversed rather than a
                // direction assumed from the focal.
                let (neighbor, edge_direction) = if want_outgoing
                    && src_entity == Some(current)
                    && dst_entity.is_some_and(|id| id != current)
                {
                    (dst_entity.unwrap(), "outgoing")
                } else if want_incoming
                    && dst_entity == Some(current)
                    && src_entity.is_some_and(|id| id != current)
                {
                    (src_entity.unwrap(), "incoming")
                } else {
                    continue;
                };

                // An edge is reachable from both endpoints; emit it once.
                if seen_relations.insert(rel.id) {
                    relations.push(serde_json::json!({
                        "src": rel.src,
                        "dst": rel.dst,
                        "kind": format!("{:?}", rel.kind),
                        "direction": edge_direction,
                        "from": current.to_string(),
                    }));
                }

                if !visited.insert(neighbor) {
                    continue;
                }
                if visited.len() > MAX_VISITED_ENTITIES {
                    truncated = true;
                    break;
                }
                if let Some(entity) = store.get_entity(&neighbor).map_err(McpError::graph)? {
                    entities.push(compact_entity_summary(&entity));
                }
                next_frontier.push((neighbor, current_depth + 1));
            }
            if truncated {
                break;
            }
        }
        frontier = next_frontier;
    }

    let total_entities = entities.len();
    let total_relations = relations.len();

    // Return compact entity summaries (name, kind, file, id) instead of full
    // entity objects to keep response sizes bounded.
    entities.truncate(limit);
    // Cap relations to match the entity limit to avoid unbounded output.
    relations.truncate(limit * 3);

    let result = serde_json::json!({
        "focal_id": entity_id.to_string(),
        "direction": direction,
        "depth": depth,
        "entity_count": total_entities,
        "relation_count": total_relations,
        "truncated": truncated || total_entities > limit,
        "entities": entities,
        "relations": relations,
    });

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

/// The lightweight per-entity row the neighborhood returns in place of a full
/// entity object, so a deep walk stays within an agent's token budget.
fn compact_entity_summary(entity: &kin_model::Entity) -> serde_json::Value {
    serde_json::json!({
        "id": entity.id,
        "name": entity.name,
        "kind": format!("{:?}", entity.kind),
        "file_path": entity.file_origin.as_ref().map(|p| p.to_string()),
        "signature": entity.signature,
    })
}

pub const GRAPH_STATUS_SCHEMA: &str = "kin.graph-status.v1";

fn deserialize_graph_status_schema<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let schema = String::deserialize(deserializer)?;
    if schema != GRAPH_STATUS_SCHEMA {
        return Err(serde::de::Error::custom(format!(
            "unsupported graph status schema '{schema}', expected '{GRAPH_STATUS_SCHEMA}'"
        )));
    }
    Ok(schema)
}

fn deserialize_graph_status_unattested<'de, D>(
    deserializer: D,
) -> std::result::Result<bool, D::Error>
where
    D: Deserializer<'de>,
{
    let completion_attested = bool::deserialize(deserializer)?;
    if completion_attested {
        return Err(serde::de::Error::custom(
            "kin.graph-status.v1 does not carry an enrichment-completion attestation",
        ));
    }
    Ok(false)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GraphStatusView {
    DaemonSelectedGraph,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GraphStatusScope {
    Head,
    TemporalSession,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GraphStatusEmbeddingSource {
    SelectedGraph,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum GraphStatusAuthority {
    RepoDaemon,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GraphStatusSampling {
    /// The daemon held embedding-work serialization while it sampled every
    /// counter, then revalidated the selected graph's mutation epoch and scope
    /// authority before publishing the report.
    PointInTimeSelectedGraph,
}

/// Readiness observations for the one daemon query graph selected for an MCP
/// call.
///
/// The schema, view, and scope are load-bearing. In particular, HEAD and a
/// temporal session graph are both daemon-owned but are not interchangeable.
/// Unknown fields require a new schema version instead of silently changing
/// what an existing consumer believes it measured.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct GraphStatusReport {
    pub schema: String,
    pub view: GraphStatusView,
    pub scope: GraphStatusScope,
    pub authority: GraphStatusAuthority,
    pub sampling: GraphStatusSampling,
    /// Process-local optimistic graph-authority epoch revalidated after every
    /// counter was captured. This is an observation fence, not a durable
    /// repository generation and not stable across daemon restarts.
    pub authority_epoch: u64,
    pub entity_count: usize,
    pub relation_count: usize,
    pub embedding_source: GraphStatusEmbeddingSource,
    pub embeddings_indexed: usize,
    pub embeddings_pending: usize,
    pub embeddings_total: usize,
    /// Observed counts do not attest that every eligible source was enriched.
    pub completion_attested: bool,
    /// The stdio server's standard response envelope. Direct daemon calls omit
    /// it; stdio adds a report-derived envelope that is validated against these
    /// same selected-graph observations. No unscoped `/health` graph metadata
    /// is allowed into this schema.
    #[serde(default, rename = "_kin", skip_serializing_if = "Option::is_none")]
    pub response_envelope: Option<crate::envelope::Envelope>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GraphStatusReportWire {
    #[serde(deserialize_with = "deserialize_graph_status_schema")]
    schema: String,
    view: GraphStatusView,
    scope: GraphStatusScope,
    authority: GraphStatusAuthority,
    sampling: GraphStatusSampling,
    authority_epoch: u64,
    entity_count: usize,
    relation_count: usize,
    embedding_source: GraphStatusEmbeddingSource,
    embeddings_indexed: usize,
    embeddings_pending: usize,
    embeddings_total: usize,
    #[serde(deserialize_with = "deserialize_graph_status_unattested")]
    completion_attested: bool,
    #[serde(default, rename = "_kin")]
    response_envelope: Option<crate::envelope::Envelope>,
}

impl<'de> Deserialize<'de> for GraphStatusReport {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = GraphStatusReportWire::deserialize(deserializer)?;
        let report = Self {
            schema: wire.schema,
            view: wire.view,
            scope: wire.scope,
            authority: wire.authority,
            sampling: wire.sampling,
            authority_epoch: wire.authority_epoch,
            entity_count: wire.entity_count,
            relation_count: wire.relation_count,
            embedding_source: wire.embedding_source,
            embeddings_indexed: wire.embeddings_indexed,
            embeddings_pending: wire.embeddings_pending,
            embeddings_total: wire.embeddings_total,
            completion_attested: wire.completion_attested,
            response_envelope: wire.response_envelope,
        };
        report.validate().map_err(serde::de::Error::custom)?;
        Ok(report)
    }
}

impl GraphStatusReport {
    fn validate(&self) -> std::result::Result<(), String> {
        if self.embeddings_indexed > self.embeddings_total {
            return Err(format!(
                "embeddings_indexed ({}) exceeds embeddings_total ({})",
                self.embeddings_indexed, self.embeddings_total
            ));
        }
        let uncovered = self
            .embeddings_total
            .saturating_sub(self.embeddings_indexed);
        if self.embeddings_pending < uncovered {
            return Err(format!(
                "embeddings_pending ({}) is below the uncovered embedding count ({uncovered})",
                self.embeddings_pending
            ));
        }
        if let Some(envelope) = &self.response_envelope {
            self.validate_response_envelope(envelope)?;
        }
        Ok(())
    }

    fn validate_response_envelope(
        &self,
        envelope: &crate::envelope::Envelope,
    ) -> std::result::Result<(), String> {
        use crate::envelope::{Runtime, ENVELOPE_VERSION};

        if envelope.envelope_version != ENVELOPE_VERSION {
            return Err(format!(
                "_kin envelope version {} does not match {ENVELOPE_VERSION}",
                envelope.envelope_version
            ));
        }
        if envelope.runtime != Runtime::RepoDaemon {
            return Err("_kin runtime is not repo-daemon".to_string());
        }
        if envelope.graph_as_of.is_some() {
            return Err(
                "_kin graph_as_of is not selected-graph identity and must be absent".to_string(),
            );
        }
        let entity_count = u64::try_from(self.entity_count)
            .map_err(|_| "entity_count does not fit the response envelope".to_string())?;
        if envelope.graph_state.entity_count != Some(entity_count)
            || envelope.graph_state.reconciliation_status.is_some()
            || envelope.graph_state.loaded.is_some()
            || envelope.graph_state.initialized.is_some()
        {
            return Err("_kin graph_state is not the exact selected-graph observation".to_string());
        }
        if envelope.degraded.daemon_unreachable.is_some()
            || envelope.degraded.embed_worker_failed.is_some()
            || envelope.degraded.mass_deletion_blocked.is_some()
            || envelope.degraded.offline_fallback.is_some()
        {
            return Err(
                "_kin carries unscoped daemon health alongside selected-graph status".to_string(),
            );
        }
        let coverage = envelope.semantic_coverage.as_ref().ok_or_else(|| {
            "_kin semantic_coverage is missing from selected-graph status".to_string()
        })?;
        let indexed = u64::try_from(self.embeddings_indexed)
            .map_err(|_| "embeddings_indexed does not fit the response envelope".to_string())?;
        let pending = u64::try_from(self.embeddings_pending)
            .map_err(|_| "embeddings_pending does not fit the response envelope".to_string())?;
        let total = u64::try_from(self.embeddings_total)
            .map_err(|_| "embeddings_total does not fit the response envelope".to_string())?;
        let complete = pending == 0 && indexed == total;
        if coverage.indexed != indexed
            || coverage.pending != pending
            || coverage.total != total
            || coverage.complete != complete
        {
            return Err("_kin semantic_coverage disagrees with selected-graph status".to_string());
        }
        if coverage.note.is_some() == complete {
            return Err(
                "_kin semantic_coverage.note must be present exactly when coverage is incomplete"
                    .to_string(),
            );
        }
        Ok(())
    }
}

pub const GRAPH_STATUS_DESC: &str = "\
Report the status of the semantic graph selected for this MCP call — live entity \
and relation counts, embedding-index coverage (embeddings_indexed / embeddings_total / \
embeddings_pending), and the schema, view, scope, and authority backing them. In product \
mode one repo-daemon response owns every field, including for an X-Kin-Session temporal \
scope, so durable repository counts cannot be mixed with a different live/session graph. \
Reach for it as a quick health/readiness check: confirm the selected graph is populated, \
check how much of its own retrieval universe has embeddings indexed, and verify the scope \
before relying on other tools. embedding_source is selected_graph; any pipeline-specific \
fallback coverage is reported by semantic_locate itself. sampling=point_in_time_selected_graph \
means the daemon held its normal embedding-work fence while reading internally synchronized \
coverage counters, then revalidated authority_epoch after capturing every counter; \
authority_epoch is process-local, not a durable repository generation. \
Enrichment completeness is not attested \
(completion_attested=false), so a populated graph is not by itself a complete one. This \
tool requires the Kin daemon; it does not invent an offline approximation.";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GraphStatusObservation {
    pub authority_epoch: u64,
    pub entity_count: usize,
    pub relation_count: usize,
    pub embeddings_indexed: usize,
    pub embeddings_pending: usize,
    pub embeddings_total: usize,
}

pub fn handle_daemon_graph_status_observation(
    scope: GraphStatusScope,
    observation: GraphStatusObservation,
) -> Result<ToolCallResult> {
    let report = GraphStatusReport {
        schema: GRAPH_STATUS_SCHEMA.to_string(),
        view: GraphStatusView::DaemonSelectedGraph,
        scope,
        authority: GraphStatusAuthority::RepoDaemon,
        sampling: GraphStatusSampling::PointInTimeSelectedGraph,
        authority_epoch: observation.authority_epoch,
        entity_count: observation.entity_count,
        relation_count: observation.relation_count,
        embedding_source: GraphStatusEmbeddingSource::SelectedGraph,
        embeddings_indexed: observation.embeddings_indexed,
        embeddings_pending: observation.embeddings_pending,
        embeddings_total: observation.embeddings_total,
        completion_attested: false,
        response_envelope: None,
    };
    report.validate().map_err(crate::McpError::Other)?;
    Ok(ToolCallResult::text(serde_json::to_string_pretty(&report)?))
}

/// Fail closed on the generic in-process dispatcher.
///
/// Product mode is special-cased by the daemon so it can identify the selected
/// scope and read the concrete embedding status. A bare [`GraphStore`] cannot
/// satisfy that contract.
pub fn handle_graph_status<G: GraphStore>(
    _args: &HashMap<String, serde_json::Value>,
    _store: &G,
) -> Result<ToolCallResult> {
    Ok(ToolCallResult::error(
        "kin_graph_status requires the Kin daemon: the generic in-process graph surface cannot \
         measure the exact embedding universe or identify HEAD versus a temporal session scope",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_db::InMemoryGraph;
    use kin_model::entity::{
        Entity, EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, SemanticFingerprint,
        Visibility,
    };
    use kin_model::graph::EntityStore as _;
    use kin_model::ids::{EntityId, FilePathId, Hash256, LanguageId, RelationId};
    use kin_model::relation::{GraphNodeId, Relation, RelationKind, RelationOrigin};
    use kin_spine::SpineBackend as _;

    fn make_entity(name: &str, file: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(file)),
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn make_relation(src: EntityId, dst: EntityId, kind: RelationKind) -> Relation {
        Relation {
            id: RelationId::new(),
            kind,
            src: GraphNodeId::Entity(src),
            dst: GraphNodeId::Entity(dst),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        }
    }

    fn graph_root(graph: &InMemoryGraph) -> String {
        graph
            .compute_root_hash()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn spine_entry(repo_id: &str, entity: &Entity) -> kin_spine::EntityEntry {
        kin_spine::EntityEntry {
            repo_id: repo_id.to_string(),
            entity_id: entity.id,
            name: entity.name.clone(),
            kind: entity.kind,
            signature: entity.signature.clone(),
            fingerprint: entity.fingerprint.clone(),
            file_path: entity.file_origin.as_ref().map(|path| path.0.clone()),
            role: Some(entity.role),
        }
    }

    fn structurally_ready_envelope() -> crate::Envelope {
        crate::Envelope::daemon().with_health(&serde_json::json!({
            "initialized": true,
            "graph_loaded": true,
            "graph_generation": 12,
        }))
    }

    fn parsed_response(result: &ToolCallResult) -> serde_json::Value {
        let crate::types::ContentBlock::Text { text } = result
            .content
            .first()
            .expect("expected at least one content block");
        serde_json::from_str(text).expect("response must be valid JSON")
    }

    fn found_source(id: &str, name: &str, body: &str) -> ResolvedEntitySource {
        ResolvedEntitySource::Found(EntitySourceRow {
            id: id.to_string(),
            name: name.to_string(),
            kind: "Function".to_string(),
            language: "rust".to_string(),
            file_path: format!("src/{name}.rs"),
            start_line: 1,
            end_line: 3,
            signature: format!("fn {name}()"),
            provenance: serde_json::Map::new(),
            body: body.to_string(),
        })
    }

    fn default_source_opts() -> BatchSourceOptions {
        BatchSourceOptions {
            token_budget: None,
            compact: false,
            max_lines_per_body: crate::handlers::common::DEFAULT_SOURCE_MAX_LINES,
            max_bytes_per_body: crate::handlers::common::DEFAULT_SOURCE_MAX_BYTES,
        }
    }

    #[test]
    fn cross_repo_binding_rejects_missing_or_blank_repo_id() {
        for raw in [None, Some(""), Some("   "), Some("\t\n")] {
            let reason = normalize_cross_repo_repo_id(raw).unwrap_err();
            assert!(reason.contains("KIN_REPO_ID is missing or blank"));
        }
        assert_eq!(
            normalize_cross_repo_repo_id(Some("  provider  ")).unwrap(),
            "provider"
        );
    }

    #[test]
    fn spine_xrefs_append_typed_external_callers() {
        let source = make_entity("run_task", "src/app.rs");
        let target = make_entity("do_work", "src/lib.rs");
        let response = kin_spine::SpineXrefResponse::new(
            vec![kin_spine::CrossRepoEdge {
                src_repo: "consumer".to_string(),
                src_entity: source.id,
                dst_repo: "provider".to_string(),
                dst_entity: target.id,
                confidence: 0.9,
            }],
            vec![kin_spine::EntityEntry {
                repo_id: "consumer".to_string(),
                entity_id: source.id,
                name: source.name.clone(),
                kind: source.kind,
                signature: source.signature.clone(),
                fingerprint: source.fingerprint.clone(),
                file_path: source.file_origin.as_ref().map(|path| path.0.clone()),
                role: Some(source.role),
            }],
        );
        let rows = spine_reference_rows("provider", &target.id, &response);

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].name, "run_task");
        assert_eq!(rows[0].kind.as_deref(), Some("Function"));
        assert_eq!(rows[0].file_path.as_deref(), Some("[consumer] src/app.rs"));
        assert_eq!(rows[0].signature.as_deref(), Some("fn run_task()"));
        assert!(rows[0].relation_kinds.is_empty());
    }

    #[test]
    fn spine_xrefs_respect_direction_and_keep_subtype_unknown() {
        let target = make_entity("do_work", "src/lib.rs");
        let other = EntityId::new();
        let outgoing_response = kin_spine::SpineXrefResponse::new(
            vec![kin_spine::CrossRepoEdge {
                src_repo: "provider".to_string(),
                src_entity: target.id,
                dst_repo: "consumer".to_string(),
                dst_entity: other,
                confidence: 0.9,
            }],
            Vec::new(),
        );
        let rows = spine_reference_rows("provider", &target.id, &outgoing_response);
        assert!(rows.is_empty());

        let source = make_entity("run_task", "src/app.rs");
        let incoming_response = kin_spine::SpineXrefResponse::new(
            vec![kin_spine::CrossRepoEdge {
                src_repo: "consumer".to_string(),
                src_entity: source.id,
                dst_repo: "provider".to_string(),
                dst_entity: target.id,
                confidence: 0.9,
            }],
            Vec::new(),
        );
        assert!(!incoming_response.authority_complete_for("provider", &target.id));

        let incoming = spine_reference_rows("provider", &target.id, &incoming_response);
        assert_eq!(incoming.len(), 1);
        assert!(incoming[0].relation_kinds.is_empty());
    }

    #[test]
    fn get_entity_sources_happy_batch_returns_all_bodies() {
        let resolved = vec![
            found_source("id-1", "one", "fn one() { 1 }"),
            found_source("id-2", "two", "fn two() { 2 }"),
        ];
        let env = parsed_response(&assemble_entity_sources_response(
            resolved,
            &default_source_opts(),
        ));
        assert_eq!(env["total_requested"], 2);
        assert_eq!(env["returned"], 2);
        assert_eq!(env["truncated"], false);
        assert_eq!(env["compact"], false);
        let rows = env["results"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["id"], "id-1");
        assert_eq!(rows[0]["body"], "fn one() { 1 }");
        assert_eq!(rows[0]["omitted"], false);
        assert!(rows[0].get("reason").is_none());
        assert_eq!(rows[1]["body"], "fn two() { 2 }");
    }

    #[test]
    fn get_entity_sources_isolates_bad_ids() {
        let resolved = vec![
            found_source("id-1", "one", "fn one() {}"),
            ResolvedEntitySource::NotFound {
                id: "id-2".into(),
                message: "no entity".into(),
            },
            ResolvedEntitySource::NoSource {
                id: "id-3".into(),
                message: "no body".into(),
            },
        ];
        let env = parsed_response(&assemble_entity_sources_response(
            resolved,
            &default_source_opts(),
        ));
        assert_eq!(env["total_requested"], 3);
        // Only the first ID resolved to a real sourced entity.
        assert_eq!(env["returned"], 1);
        let rows = env["results"].as_array().unwrap();
        assert_eq!(rows[0]["omitted"], false);
        assert_eq!(rows[1]["id"], "id-2");
        assert_eq!(rows[1]["omitted"], true);
        assert_eq!(rows[1]["reason"], "not_found");
        assert!(rows[1].get("body").is_none());
        assert_eq!(rows[2]["omitted"], true);
        assert_eq!(rows[2]["reason"], "no_source");
    }

    #[test]
    fn get_entity_sources_budget_truncates_in_request_order() {
        let b1 = "fn one() { 1 }";
        let b2 = "fn two() { 2 }";
        let b3 = "fn three() { 3 }";
        // A budget that fits the first two bodies but not the third.
        let budget = kin_context::estimate_tokens(b1) + kin_context::estimate_tokens(b2);
        let resolved = vec![
            found_source("id-1", "one", b1),
            found_source("id-2", "two", b2),
            found_source("id-3", "three", b3),
        ];
        let opts = BatchSourceOptions {
            token_budget: Some(budget),
            ..default_source_opts()
        };
        let env = parsed_response(&assemble_entity_sources_response(resolved, &opts));
        assert_eq!(env["truncated"], true);
        // All three resolved; the third is body-suppressed, not dropped.
        assert_eq!(env["returned"], 3);
        let rows = env["results"].as_array().unwrap();
        assert_eq!(rows[0]["body"], b1);
        assert!(rows[0].get("reason").is_none());
        assert_eq!(rows[1]["body"], b2);
        assert_eq!(rows[2]["omitted"], true);
        assert_eq!(rows[2]["reason"], "budget");
        assert!(rows[2].get("body").is_none());
        // The budget-omitted row still carries its signature for a follow-up read.
        assert_eq!(rows[2]["signature"], "fn three()");
    }

    #[test]
    fn get_entity_sources_compact_is_signature_only() {
        let resolved = vec![
            found_source("id-1", "one", "fn one() {}"),
            found_source("id-2", "two", "fn two() {}"),
        ];
        let opts = BatchSourceOptions {
            compact: true,
            ..default_source_opts()
        };
        let env = parsed_response(&assemble_entity_sources_response(resolved, &opts));
        assert_eq!(env["compact"], true);
        assert_eq!(env["returned"], 2);
        assert_eq!(env["truncated"], false);
        for row in env["results"].as_array().unwrap() {
            assert!(row.get("body").is_none(), "compact rows carry no body");
            assert_eq!(row["omitted"], false);
            assert!(row["signature"].as_str().unwrap().starts_with("fn "));
        }
    }

    #[test]
    fn get_entity_sources_applies_per_body_clamp() {
        let resolved = vec![found_source("id-1", "one", "line1\nline2\nline3\nline4\n")];
        let opts = BatchSourceOptions {
            max_lines_per_body: 2,
            ..default_source_opts()
        };
        let env = parsed_response(&assemble_entity_sources_response(resolved, &opts));
        assert_eq!(env["results"][0]["body"], "line1\nline2\n");
    }

    #[test]
    fn clamp_source_body_bounds_lines_and_bytes() {
        use crate::handlers::common::clamp_source_body;
        assert_eq!(clamp_source_body("a\nb\nc\n", 2, 1_000), "a\nb\n");
        assert_eq!(clamp_source_body("abcdef", 10, 3), "abc");
        // A 2-byte char is never split: capping at 1 byte drops it entirely.
        assert_eq!(clamp_source_body("é", 10, 1), "");
    }

    #[test]
    fn get_entity_sources_rejects_empty_and_oversized() {
        let store = InMemoryGraph::new();

        let missing = HashMap::new();
        assert!(matches!(
            handle_get_entity_sources(&missing, &store, None).unwrap_err(),
            McpError::InvalidParams(_)
        ));

        let mut empty_list = HashMap::new();
        empty_list.insert("entity_ids".to_string(), serde_json::json!([]));
        assert!(matches!(
            handle_get_entity_sources(&empty_list, &store, None).unwrap_err(),
            McpError::InvalidParams(_)
        ));

        // One past the bound of 50 is rejected before any graph access.
        let too_many: Vec<String> = (0..=MAX_BULK_SOURCE_ENTITIES)
            .map(|_| EntityId::new().to_string())
            .collect();
        assert_eq!(too_many.len(), 51);
        let mut over = HashMap::new();
        over.insert("entity_ids".to_string(), serde_json::json!(too_many));
        assert!(matches!(
            handle_get_entity_sources(&over, &store, None).unwrap_err(),
            McpError::InvalidParams(_)
        ));

        // Exactly 50 IDs is accepted; against an empty graph every ID is a
        // not-found row, but the batch itself succeeds.
        let at_bound: Vec<String> = (0..MAX_BULK_SOURCE_ENTITIES)
            .map(|_| EntityId::new().to_string())
            .collect();
        let mut ok = HashMap::new();
        ok.insert("entity_ids".to_string(), serde_json::json!(at_bound));
        let env = parsed_response(&handle_get_entity_sources(&ok, &store, None).unwrap());
        assert_eq!(env["total_requested"], 50);
        assert_eq!(env["returned"], 0);
        assert_eq!(env["results"][0]["reason"], "not_found");
    }

    #[test]
    fn bulk_check_references_compact_and_verbose_shapes() {
        let store = InMemoryGraph::new();
        let caller = make_entity("caller", "src/a.rs");
        let live = make_entity("live", "src/b.rs");
        let dead = make_entity("dead", "src/c.rs");
        let caller_id = caller.id;
        let live_id = live.id;
        let dead_id = dead.id;

        store.upsert_entity(&caller).unwrap();
        store.upsert_entity(&live).unwrap();
        store.upsert_entity(&dead).unwrap();

        store
            .upsert_relation(&make_relation(caller_id, live_id, RelationKind::Calls))
            .unwrap();
        store
            .upsert_relation(&make_relation(caller_id, live_id, RelationKind::Imports))
            .unwrap();

        let mut args = HashMap::new();
        args.insert(
            "entity_ids".to_string(),
            serde_json::json!([live_id.to_string(), dead_id.to_string()]),
        );
        args.insert("relation_kind".to_string(), serde_json::json!("Any"));

        let compact = handle_bulk_check_references(&args, &store).unwrap();
        let body = parsed_response(&compact);
        assert_eq!(body["total_checked"], 2);
        assert_eq!(body["classified_count"], 1);
        assert_eq!(body["error_count"], 0);
        assert_eq!(body["incomplete_verdict_count"], 1);
        assert_eq!(body["with_references"], 1);
        assert_eq!(body["without_references"], 0);
        assert_eq!(body["compact"], true);
        let rows = body["results"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        let live_row = rows
            .iter()
            .find(|r| r["entity_id"] == serde_json::json!(live_id))
            .unwrap();
        assert_eq!(live_row["has_references"], true);
        assert!(live_row["reference_count"].is_null());
        assert_eq!(live_row["known_reference_count"], 2);
        assert_eq!(live_row["reference_count_complete"], false);
        assert_eq!(live_row["verdict_complete"], true);
        assert!(
            live_row.get("name").is_none(),
            "compact mode must omit name"
        );
        let dead_row = rows
            .iter()
            .find(|r| r["entity_id"] == serde_json::json!(dead_id))
            .unwrap();
        assert!(
            dead_row["has_references"].is_null(),
            "a local-only zero is not a total reachability verdict"
        );
        assert!(dead_row["reference_count"].is_null());
        assert_eq!(dead_row["known_reference_count"], 0);
        assert_eq!(dead_row["reference_count_complete"], false);
        assert_eq!(dead_row["verdict_complete"], false);
        assert_eq!(
            dead_row["verdict_reason"],
            "cross-repo authority incomplete"
        );

        args.insert("compact".to_string(), serde_json::json!(false));
        let verbose = handle_bulk_check_references(&args, &store).unwrap();
        let vbody = parsed_response(&verbose);
        let vrows = vbody["results"].as_array().unwrap();
        let live_row = vrows
            .iter()
            .find(|r| r["entity_id"] == serde_json::json!(live_id))
            .unwrap();
        assert_eq!(live_row["name"], "live");
        assert_eq!(live_row["kind"], "Function");
        assert_eq!(live_row["file_path"], "src/b.rs");
        let matched = live_row["matched_kinds"].as_array().unwrap();
        assert!(matched.iter().any(|v| v == "calls"));
        assert!(matched.iter().any(|v| v == "imports"));
    }

    #[test]
    fn bulk_check_references_relation_kind_filter() {
        let store = InMemoryGraph::new();
        let caller = make_entity("caller", "src/a.rs");
        let target = make_entity("target", "src/b.rs");
        let caller_id = caller.id;
        let target_id = target.id;

        store.upsert_entity(&caller).unwrap();
        store.upsert_entity(&target).unwrap();
        store
            .upsert_relation(&make_relation(caller_id, target_id, RelationKind::Imports))
            .unwrap();

        let mut args = HashMap::new();
        args.insert(
            "entity_ids".to_string(),
            serde_json::json!([target_id.to_string()]),
        );

        // Asking for Calls only — Imports edge must NOT count.
        args.insert("relation_kind".to_string(), serde_json::json!("Calls"));
        let calls_resp = parsed_response(&handle_bulk_check_references(&args, &store).unwrap());
        assert_eq!(calls_resp["with_references"], 0);
        assert_eq!(calls_resp["without_references"], 0);
        assert!(calls_resp["results"][0]["has_references"].is_null());
        assert!(calls_resp["results"][0]["reference_count"].is_null());
        assert_eq!(calls_resp["results"][0]["known_reference_count"], 0);
        assert_eq!(calls_resp["results"][0]["reference_count_complete"], false);

        // Asking for Imports — should match.
        args.insert("relation_kind".to_string(), serde_json::json!("Imports"));
        let imports_resp = parsed_response(&handle_bulk_check_references(&args, &store).unwrap());
        assert_eq!(imports_resp["with_references"], 1);
        assert_eq!(imports_resp["results"][0]["has_references"], true);
        assert!(imports_resp["results"][0]["reference_count"].is_null());
        assert_eq!(imports_resp["results"][0]["known_reference_count"], 1);
        assert_eq!(
            imports_resp["results"][0]["reference_count_complete"],
            false
        );
    }

    #[test]
    fn bulk_check_references_rejects_empty_and_invalid() {
        let store = InMemoryGraph::new();

        let args = HashMap::new();
        let err = handle_bulk_check_references(&args, &store).unwrap_err();
        assert!(matches!(err, McpError::InvalidParams(_)));

        let mut empty = HashMap::new();
        empty.insert("entity_ids".to_string(), serde_json::json!([]));
        let err = handle_bulk_check_references(&empty, &store).unwrap_err();
        assert!(matches!(err, McpError::InvalidParams(_)));

        let mut bad = HashMap::new();
        bad.insert(
            "entity_ids".to_string(),
            serde_json::json!(["not-a-uuid", EntityId::new().to_string()]),
        );
        let resp = parsed_response(&handle_bulk_check_references(&bad, &store).unwrap());
        let rows = resp["results"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["error"], "invalid entity_id (not a UUID)");
        assert_eq!(rows[1]["error"], "entity not found");
        assert_eq!(resp["classified_count"], 0);
        assert_eq!(resp["error_count"], 2);
        assert_eq!(resp["incomplete_verdict_count"], 0);
        assert_eq!(resp["with_references"], 0);
        assert_eq!(resp["without_references"], 0);
        for row in rows {
            assert!(
                row["has_references"].is_null(),
                "an invalid or missing entity is not a false reachability verdict: {row}"
            );
            assert!(row["reference_count"].is_null());
            assert!(row["known_reference_count"].is_null());
            assert_eq!(row["reference_count_complete"], false);
            assert_eq!(row["verdict_complete"], false);
        }
    }

    #[tokio::test]
    async fn find_references_returns_only_graph_edges() {
        let store = InMemoryGraph::new();
        let caller = make_entity("caller", "src/a.rs");
        let target = make_entity("target", "src/b.rs");
        let caller_id = caller.id;
        let target_id = target.id;

        store.upsert_entity(&caller).unwrap();
        store.upsert_entity(&target).unwrap();
        store
            .upsert_relation(&make_relation(caller_id, target_id, RelationKind::Calls))
            .unwrap();

        let mut args = HashMap::new();
        args.insert(
            "entity_id".to_string(),
            serde_json::json!(target_id.to_string()),
        );

        let body = parsed_response(&handle_find_references(&args, &store, None).await.unwrap());
        assert_eq!(body["total_upstream"], 1);
        let refs = body["references"].as_array().unwrap();
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0]["name"], "caller");
        assert_eq!(refs[0]["file_path"], "src/a.rs");
        assert_eq!(refs[0]["kind"], "Function");
        // The keystone: each reference carries the caller's graph entity_id so an
        // agent can drill straight to its body with no name re-resolution.
        assert_eq!(refs[0]["entity_id"], caller_id.to_string());
        // `snippet` is always present in the shape (null here: the fixture has no
        // blob-backed body to project).
        assert!(refs[0].as_object().unwrap().contains_key("snippet"));
    }

    #[tokio::test]
    async fn find_references_reports_empty_graph_gap_without_backfill() {
        let store = InMemoryGraph::new();
        let target = make_entity("orphan", "src/orphan.rs");
        let target_id = target.id;
        store.upsert_entity(&target).unwrap();

        let mut args = HashMap::new();
        args.insert(
            "entity_id".to_string(),
            serde_json::json!(target_id.to_string()),
        );

        let body = parsed_response(&handle_find_references(&args, &store, None).await.unwrap());
        assert_eq!(body["total_upstream"], 0);
        assert!(body["references"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn daemon_find_references_requires_exact_live_graph_root() {
        let graph = InMemoryGraph::new();
        let target = make_entity("target", "src/lib.rs");
        graph.upsert_entity(&target).unwrap();
        let registered_root = graph_root(&graph);

        let spine = kin_spine::InMemorySpineBackend::new();
        spine.register_repo(
            "provider",
            vec![spine_entry("provider", &target)],
            &registered_root,
        );
        spine.refresh_cross_repo_edges("provider", &[], &[], &["provider".to_string()]);

        let args = HashMap::from([(
            "entity_id".to_string(),
            serde_json::json!(target.id.to_string()),
        )]);
        let matching = handle_find_references_with_authority(
            &args,
            &graph,
            FindReferencesAuthority {
                repo_id: "provider",
                graph_root: &registered_root,
                spine: Some(&spine),
            },
            None,
        )
        .await
        .unwrap();
        let matching = crate::finalize_with_envelope(
            matching,
            structurally_ready_envelope(),
            "find_references",
        );
        let matching = parsed_response(&matching);
        assert_eq!(matching["cross_repo"]["authority_complete"], true);
        assert_eq!(matching["negative"]["safe_to_conclude_absent"], true);

        graph
            .upsert_entity(&make_entity("session_only", "src/session.rs"))
            .unwrap();
        let live_root = graph_root(&graph);
        assert_ne!(live_root, registered_root);
        let mismatched = handle_find_references_with_authority(
            &args,
            &graph,
            FindReferencesAuthority {
                repo_id: "provider",
                graph_root: &live_root,
                spine: Some(&spine),
            },
            None,
        )
        .await
        .unwrap();
        let mismatched = crate::finalize_with_envelope(
            mismatched,
            structurally_ready_envelope(),
            "find_references",
        );
        let mismatched = parsed_response(&mismatched);
        assert_eq!(mismatched["cross_repo"]["status"], "unavailable");
        assert!(mismatched["cross_repo"]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("root mismatch")));
        assert_eq!(mismatched["negative"]["safe_to_conclude_absent"], false);
        assert!(mismatched["references"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn filtered_find_references_keeps_unknown_federated_subtype_advisory() {
        let graph = InMemoryGraph::new();
        let target = make_entity("target", "src/lib.rs");
        let source = make_entity("caller", "src/app.rs");
        graph.upsert_entity(&target).unwrap();
        let provider_root = graph_root(&graph);

        let spine = kin_spine::InMemorySpineBackend::new();
        spine.register_repo(
            "provider",
            vec![spine_entry("provider", &target)],
            &provider_root,
        );
        spine.register_repo(
            "consumer",
            vec![spine_entry("consumer", &source)],
            "consumer-root",
        );
        let repos = vec!["consumer".to_string(), "provider".to_string()];
        for repo in &repos {
            spine.refresh_cross_repo_edges(repo, &[], &[], &repos);
        }
        spine.add_cross_repo_edge(kin_spine::CrossRepoEdge {
            src_repo: "consumer".to_string(),
            src_entity: source.id,
            dst_repo: "provider".to_string(),
            dst_entity: target.id,
            confidence: 0.9,
        });

        let args = HashMap::from([
            (
                "entity_id".to_string(),
                serde_json::json!(target.id.to_string()),
            ),
            ("relation_kinds".to_string(), serde_json::json!(["calls"])),
        ]);
        let filtered = handle_find_references_with_authority(
            &args,
            &graph,
            FindReferencesAuthority {
                repo_id: "provider",
                graph_root: &provider_root,
                spine: Some(&spine),
            },
            None,
        )
        .await
        .unwrap();
        let filtered = crate::finalize_with_envelope(
            filtered,
            structurally_ready_envelope(),
            "find_references",
        );
        let filtered = parsed_response(&filtered);
        assert_eq!(filtered["total_upstream"], 0);
        assert!(filtered["references"].as_array().unwrap().is_empty());
        assert_eq!(filtered["cross_repo"]["federated_reference_count"], 1);
        assert_eq!(filtered["cross_repo"]["relation_subtype_complete"], false);
        assert_eq!(filtered["negative"]["safe_to_conclude_absent"], false);

        let default_args = HashMap::from([(
            "entity_id".to_string(),
            serde_json::json!(target.id.to_string()),
        )]);
        let unfiltered = parsed_response(
            &handle_find_references_with_authority(
                &default_args,
                &graph,
                FindReferencesAuthority {
                    repo_id: "provider",
                    graph_root: &provider_root,
                    spine: Some(&spine),
                },
                None,
            )
            .await
            .unwrap(),
        );
        assert_eq!(unfiltered["total_upstream"], 1);
        assert_eq!(unfiltered["references"][0]["name"], "caller");
    }

    #[tokio::test]
    async fn filtered_find_references_certifies_complete_federated_zero() {
        let graph = InMemoryGraph::new();
        let target = make_entity("target", "src/lib.rs");
        graph.upsert_entity(&target).unwrap();
        let provider_root = graph_root(&graph);

        let spine = kin_spine::InMemorySpineBackend::new();
        spine.register_repo(
            "provider",
            vec![spine_entry("provider", &target)],
            &provider_root,
        );
        spine.refresh_cross_repo_edges("provider", &[], &[], &["provider".to_string()]);

        let args = HashMap::from([
            (
                "entity_id".to_string(),
                serde_json::json!(target.id.to_string()),
            ),
            ("relation_kinds".to_string(), serde_json::json!(["calls"])),
        ]);
        let result = handle_find_references_with_authority(
            &args,
            &graph,
            FindReferencesAuthority {
                repo_id: "provider",
                graph_root: &provider_root,
                spine: Some(&spine),
            },
            None,
        )
        .await
        .unwrap();
        let result =
            crate::finalize_with_envelope(result, structurally_ready_envelope(), "find_references");
        let result = parsed_response(&result);

        assert!(result["references"].as_array().unwrap().is_empty());
        assert_eq!(result["cross_repo"]["authority_complete"], true);
        assert_eq!(
            result["cross_repo"]["relation_subtype_complete"], true,
            "a complete empty incoming edge set excludes every unknown subtype"
        );
        assert_eq!(result["negative"]["safe_to_conclude_absent"], true);
    }

    #[test]
    fn daemon_bulk_reachability_includes_complete_federated_edges() {
        let graph = InMemoryGraph::new();
        let target = make_entity("target", "src/lib.rs");
        let source = make_entity("caller", "src/app.rs");
        graph.upsert_entity(&target).unwrap();
        let provider_root = graph_root(&graph);

        let spine = kin_spine::InMemorySpineBackend::new();
        spine.register_repo(
            "provider",
            vec![spine_entry("provider", &target)],
            &provider_root,
        );
        spine.register_repo(
            "consumer",
            vec![spine_entry("consumer", &source)],
            "consumer-root",
        );
        let repos = vec!["consumer".to_string(), "provider".to_string()];
        for repo in &repos {
            spine.refresh_cross_repo_edges(repo, &[], &[], &repos);
        }
        spine.add_cross_repo_edge(kin_spine::CrossRepoEdge {
            src_repo: "consumer".to_string(),
            src_entity: source.id,
            dst_repo: "provider".to_string(),
            dst_entity: target.id,
            confidence: 0.9,
        });

        let mut args = HashMap::from([(
            "entity_ids".to_string(),
            serde_json::json!([target.id.to_string()]),
        )]);
        let authority = FindReferencesAuthority {
            repo_id: "provider",
            graph_root: &provider_root,
            spine: Some(&spine),
        };
        let any = handle_bulk_check_references_with_authority(&args, &graph, authority).unwrap();
        let any = crate::finalize_with_envelope(
            any,
            structurally_ready_envelope(),
            "bulk_check_references",
        );
        let any = parsed_response(&any);
        assert_eq!(any["results"][0]["has_references"], true);
        assert_eq!(any["results"][0]["reference_count"], 1);
        assert_eq!(any["results"][0]["known_reference_count"], 1);
        assert_eq!(any["results"][0]["reference_count_complete"], true);
        assert_eq!(any["results"][0]["federated_reference_count"], 1);
        assert_eq!(any["cross_repo"]["authority_complete"], true);
        assert_eq!(any["negative"]["safe_to_conclude_absent"], true);

        args.insert("relation_kind".to_string(), serde_json::json!("Calls"));
        let calls = handle_bulk_check_references_with_authority(&args, &graph, authority).unwrap();
        let calls = crate::finalize_with_envelope(
            calls,
            structurally_ready_envelope(),
            "bulk_check_references",
        );
        let calls = parsed_response(&calls);
        assert!(
            calls["results"][0]["has_references"].is_null(),
            "an untyped federated edge cannot be classified as Calls=false"
        );
        assert!(calls["results"][0]["reference_count"].is_null());
        assert_eq!(calls["results"][0]["known_reference_count"], 0);
        assert_eq!(calls["results"][0]["reference_count_complete"], false);
        assert_eq!(calls["results"][0]["federated_reference_count"], 1);
        assert_eq!(calls["results"][0]["verdict_complete"], false);
        assert_eq!(
            calls["results"][0]["verdict_reason"],
            "federated relation subtype unavailable"
        );
        assert_eq!(calls["classified_count"], 0);
        assert_eq!(calls["incomplete_verdict_count"], 1);
        assert_eq!(calls["without_references"], 0);
        assert_eq!(calls["cross_repo"]["relation_subtype_complete"], false);
        assert_eq!(calls["cross_repo"]["verdicts_complete"], false);
        assert_eq!(calls["negative"]["safe_to_conclude_absent"], false);
    }

    #[test]
    fn semantic_locate_requires_daemon_in_offline_mode() {
        let store = InMemoryGraph::new();
        let mut args = HashMap::new();
        args.insert(
            "query".to_string(),
            serde_json::json!("where is auth handled"),
        );

        let result = handle_semantic_locate(&args, &store).unwrap();
        assert_eq!(result.is_error, Some(true));
        let crate::types::ContentBlock::Text { text } = result.content.first().unwrap();
        assert!(
            text.contains("requires the Kin daemon"),
            "offline semantic_locate must explain the daemon requirement, got: {text}"
        );
    }

    #[test]
    fn semantic_locate_rejects_missing_query() {
        let store = InMemoryGraph::new();
        let args = HashMap::new();
        let err = handle_semantic_locate(&args, &store).unwrap_err();
        assert!(matches!(err, McpError::InvalidParams(_)));
    }

    #[test]
    fn semantic_locate_rejects_invalid_granularity() {
        let store = InMemoryGraph::new();
        let mut args = HashMap::new();
        args.insert("query".to_string(), serde_json::json!("q"));
        args.insert("granularity".to_string(), serde_json::json!("module"));
        let err = handle_semantic_locate(&args, &store).unwrap_err();
        assert!(matches!(err, McpError::InvalidParams(_)));
    }

    /// `caller -> focal -> callee`: the focal has exactly one dependent and one
    /// dependency, on opposite sides of the relation table.
    fn neighborhood_fixture() -> (InMemoryGraph, EntityId, EntityId, EntityId) {
        let store = InMemoryGraph::new();
        let caller = make_entity("caller", "src/caller.rs");
        let focal = make_entity("focal", "src/focal.rs");
        let callee = make_entity("callee", "src/callee.rs");
        let (caller_id, focal_id, callee_id) = (caller.id, focal.id, callee.id);
        store.upsert_entity(&caller).unwrap();
        store.upsert_entity(&focal).unwrap();
        store.upsert_entity(&callee).unwrap();
        store
            .upsert_relation(&make_relation(caller_id, focal_id, RelationKind::Calls))
            .unwrap();
        store
            .upsert_relation(&make_relation(focal_id, callee_id, RelationKind::Calls))
            .unwrap();
        (store, caller_id, focal_id, callee_id)
    }

    fn neighborhood_names(response: &serde_json::Value) -> Vec<String> {
        let mut names: Vec<String> = response["entities"]
            .as_array()
            .expect("entities must be an array")
            .iter()
            .map(|e| {
                e["name"]
                    .as_str()
                    .expect("name must be a string")
                    .to_string()
            })
            .collect();
        names.sort();
        names
    }

    fn neighborhood_response_in(
        store: &InMemoryGraph,
        focal: EntityId,
        direction: Option<&str>,
    ) -> serde_json::Value {
        let mut args = HashMap::new();
        args.insert(
            "entity_id".to_string(),
            serde_json::json!(focal.to_string()),
        );
        if let Some(direction) = direction {
            args.insert("direction".to_string(), serde_json::json!(direction));
        }
        parsed_response(&handle_graph_neighborhood(&args, store).unwrap())
    }

    /// The FIR-1595 regression. The tool has always described itself as
    /// returning "both what it depends on and what depends on it", but traversed
    /// the outgoing index alone, so `caller` — the only entity whose behavior a
    /// change to `focal` can break — was never in the answer. An agent asking
    /// this tool for blast radius got the focal's dependencies instead, with
    /// nothing in the output to reveal the substitution.
    #[test]
    fn graph_neighborhood_returns_dependents_not_only_dependencies() {
        let (store, _, focal_id, _) = neighborhood_fixture();
        let response = neighborhood_response_in(&store, focal_id, None);
        assert_eq!(response["direction"], "both");
        assert_eq!(
            neighborhood_names(&response),
            vec!["callee", "caller", "focal"],
            "the default neighborhood must carry the dependent as well as the dependency"
        );
        assert_eq!(response["entity_count"], 3);
        assert_eq!(response["relation_count"], 2);
        assert_eq!(response["truncated"], false);
    }

    /// Direction is not just a filter on a merged walk: asking for dependents
    /// alone must return the dependent alone.
    #[test]
    fn graph_neighborhood_direction_in_returns_only_dependents() {
        let (store, caller_id, focal_id, _) = neighborhood_fixture();
        let response = neighborhood_response_in(&store, focal_id, Some("in"));
        assert_eq!(response["direction"], "in");
        assert_eq!(neighborhood_names(&response), vec!["caller", "focal"]);
        let edges = response["relations"].as_array().unwrap();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0]["direction"], "incoming");
        assert_eq!(edges[0]["src"]["Entity"], serde_json::json!(caller_id));
        assert_eq!(edges[0]["dst"]["Entity"], serde_json::json!(focal_id));
    }

    /// The previous behavior stays reachable by name, so a caller that really
    /// wants dependencies can ask for them and know that is what it got.
    #[test]
    fn graph_neighborhood_direction_out_returns_only_dependencies() {
        let (store, _, focal_id, callee_id) = neighborhood_fixture();
        let response = neighborhood_response_in(&store, focal_id, Some("out"));
        assert_eq!(response["direction"], "out");
        assert_eq!(neighborhood_names(&response), vec!["callee", "focal"]);
        let edges = response["relations"].as_array().unwrap();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0]["direction"], "outgoing");
        assert_eq!(edges[0]["dst"]["Entity"], serde_json::json!(callee_id));
    }

    /// Direction aliases exist because agents phrase this as "callers" or
    /// "dependents" far more often than as "in".
    #[test]
    fn graph_neighborhood_accepts_direction_aliases() {
        let (store, _, focal_id, _) = neighborhood_fixture();
        for alias in ["in", "incoming", "dependents", "callers", "impact"] {
            let response = neighborhood_response_in(&store, focal_id, Some(alias));
            assert_eq!(response["direction"], "in", "alias {alias} must map to in");
        }
        for alias in ["out", "outgoing", "dependencies", "depends_on", "calls"] {
            let response = neighborhood_response_in(&store, focal_id, Some(alias));
            assert_eq!(
                response["direction"], "out",
                "alias {alias} must map to out"
            );
        }
    }

    #[test]
    fn graph_neighborhood_rejects_an_unknown_direction() {
        let (store, _, focal_id, _) = neighborhood_fixture();
        let mut args = HashMap::new();
        args.insert(
            "entity_id".to_string(),
            serde_json::json!(focal_id.to_string()),
        );
        args.insert("direction".to_string(), serde_json::json!("sideways"));
        let err = handle_graph_neighborhood(&args, &store).unwrap_err();
        assert!(matches!(err, McpError::InvalidParams(_)), "{err:?}");
    }

    /// Depth must walk dependents transitively, not just one hop back: the
    /// grandparent of a focal is inside its blast radius at depth 2.
    #[test]
    fn graph_neighborhood_walks_dependents_transitively() {
        let (store, caller_id, focal_id, _) = neighborhood_fixture();
        let grandparent = make_entity("grandparent", "src/grandparent.rs");
        let grandparent_id = grandparent.id;
        store.upsert_entity(&grandparent).unwrap();
        store
            .upsert_relation(&make_relation(
                grandparent_id,
                caller_id,
                RelationKind::Calls,
            ))
            .unwrap();

        let mut args = HashMap::new();
        args.insert(
            "entity_id".to_string(),
            serde_json::json!(focal_id.to_string()),
        );
        args.insert("direction".to_string(), serde_json::json!("in"));
        args.insert("depth".to_string(), serde_json::json!(2));
        let response = parsed_response(&handle_graph_neighborhood(&args, &store).unwrap());
        assert_eq!(
            neighborhood_names(&response),
            vec!["caller", "focal", "grandparent"]
        );
    }

    /// An edge reachable from both of its endpoints is still one edge. Walking
    /// both directions must not double-count the relation table.
    #[test]
    fn graph_neighborhood_emits_each_edge_once() {
        let (store, _, focal_id, callee_id) = neighborhood_fixture();
        // focal -> callee and callee -> focal: a cycle whose single pair of
        // edges is reachable from either side in `both` mode.
        store
            .upsert_relation(&make_relation(callee_id, focal_id, RelationKind::Calls))
            .unwrap();
        let response = neighborhood_response_in(&store, focal_id, Some("both"));
        let edges = response["relations"].as_array().unwrap();
        let mut ids: Vec<String> = edges
            .iter()
            .map(|e| format!("{}->{}", e["src"], e["dst"]))
            .collect();
        ids.sort();
        let unique: std::collections::HashSet<&String> = ids.iter().collect();
        assert_eq!(
            unique.len(),
            ids.len(),
            "each relation must appear once: {ids:?}"
        );
    }

    /// A focal with no edges at all still reports itself, and reports honestly
    /// that nothing else is there.
    #[test]
    fn graph_neighborhood_on_an_isolated_entity_reports_only_the_focal() {
        let store = InMemoryGraph::new();
        let lonely = make_entity("lonely", "src/lonely.rs");
        let lonely_id = lonely.id;
        store.upsert_entity(&lonely).unwrap();
        let response = neighborhood_response_in(&store, lonely_id, None);
        assert_eq!(neighborhood_names(&response), vec!["lonely"]);
        assert_eq!(response["relation_count"], 0);
        assert_eq!(response["truncated"], false);
    }

    /// The description promises that when no neighbors come back, the additive
    /// `negative` object says whether "isolated, no dependencies" is
    /// authoritative or merely "not indexed yet". The neighborhood always
    /// returns the focal itself, so that promise was keyed on a list that is
    /// never empty for an indexed entity and never arrived. Asserted end to end
    /// through the annotation chokepoint, and on a directional walk, because an
    /// empty `in` walk is evidence about dependents alone.
    #[test]
    fn graph_neighborhood_isolated_focal_carries_the_promised_negative() {
        let store = InMemoryGraph::new();
        let lonely = make_entity("lonely", "src/lonely.rs");
        let lonely_id = lonely.id;
        store.upsert_entity(&lonely).unwrap();
        let mut args = HashMap::new();
        args.insert(
            "entity_id".to_string(),
            serde_json::json!(lonely_id.to_string()),
        );
        args.insert("direction".to_string(), serde_json::json!("in"));
        let annotated = crate::finalize_with_envelope(
            handle_graph_neighborhood(&args, &store).unwrap(),
            structurally_ready_envelope(),
            "graph_neighborhood",
        );
        let response = parsed_response(&annotated);
        assert_eq!(response["negative"]["kind"], "no_neighbors");
        assert_eq!(response["negative"]["safe_to_conclude_absent"], true);
        assert!(
            response["negative"]["subject"]
                .as_str()
                .expect("the negative must carry a subject")
                .contains("dependents"),
            "an incoming-only walk must qualify dependents alone: {}",
            response["negative"]
        );
    }

    /// At depth 0 the frontier is dropped before a single edge is read, so the
    /// empty neighborhood describes the request and not the entity. The focal
    /// here has a dependent and a dependency, and neither is looked at.
    #[test]
    fn graph_neighborhood_at_depth_zero_does_not_certify_isolation() {
        let (store, _, focal_id, _) = neighborhood_fixture();
        let mut args = HashMap::new();
        args.insert(
            "entity_id".to_string(),
            serde_json::json!(focal_id.to_string()),
        );
        args.insert("depth".to_string(), serde_json::json!(0));
        let annotated = crate::finalize_with_envelope(
            handle_graph_neighborhood(&args, &store).unwrap(),
            structurally_ready_envelope(),
            "graph_neighborhood",
        );
        let response = parsed_response(&annotated);
        assert_eq!(response["relation_count"], 0);
        assert_eq!(response["negative"]["kind"], "no_traversal");
        assert_eq!(
            response["negative"]["safe_to_conclude_absent"], false,
            "an entity with both a caller and a callee must never be certified isolated: {}",
            response["negative"]
        );
    }

    /// The focal is added to the entity list only when the store actually holds
    /// it, so an id that was never upserted yields an empty neighborhood that
    /// says nothing about isolation. `entity_count` is the name that fact
    /// travels under from this handler to the guard that reads it, and only an
    /// end-to-end call pins the two together.
    #[test]
    fn graph_neighborhood_missing_focal_is_not_an_absence() {
        let (store, _, _, _) = neighborhood_fixture();
        let never_upserted = EntityId::new();
        let mut args = HashMap::new();
        args.insert(
            "entity_id".to_string(),
            serde_json::json!(never_upserted.to_string()),
        );
        let annotated = crate::finalize_with_envelope(
            handle_graph_neighborhood(&args, &store).unwrap(),
            structurally_ready_envelope(),
            "graph_neighborhood",
        );
        let response = parsed_response(&annotated);
        assert_eq!(response["entity_count"], 0);
        assert_eq!(response["negative"]["kind"], "focal_not_in_graph");
        assert_eq!(
            response["negative"]["safe_to_conclude_absent"], false,
            "an entity the walk never found must not be certified isolated: {}",
            response["negative"]
        );
    }

    /// `limit: 0` empties the emitted edge array of a neighborhood that really
    /// has neighbors. The pre-truncation total is the only thing that can tell
    /// a capped answer from an absence, and `relation_count` is the name it
    /// travels under from this handler to the guard that reads it.
    #[test]
    fn graph_neighborhood_truncated_to_zero_is_not_an_absence() {
        let (store, _, focal_id, _) = neighborhood_fixture();
        let mut args = HashMap::new();
        args.insert(
            "entity_id".to_string(),
            serde_json::json!(focal_id.to_string()),
        );
        args.insert("limit".to_string(), serde_json::json!(0));
        let annotated = crate::finalize_with_envelope(
            handle_graph_neighborhood(&args, &store).unwrap(),
            structurally_ready_envelope(),
            "graph_neighborhood",
        );
        let response = parsed_response(&annotated);
        assert!(
            response["relations"]
                .as_array()
                .expect("relations must be an array")
                .is_empty(),
            "the caller capped the array to nothing"
        );
        assert_eq!(
            response["relation_count"], 2,
            "the pre-truncation total still reports the two real edges"
        );
        assert!(
            response.get("negative").is_none(),
            "a truncated edge array is not an absence and must not be qualified as one: {response}"
        );
    }

    /// A graph that is initialized, loaded, and holds entities: the only state
    /// in which a structural absence is authoritative. Carries the entity count
    /// `structurally_ready_envelope` leaves unknown, because a resolution miss
    /// on a graph holding nothing is a fact about the graph, not the name.
    fn populated_ready_envelope() -> crate::Envelope {
        crate::Envelope::daemon().with_health(&serde_json::json!({
            "initialized": true,
            "graph_loaded": true,
            "graph_generation": 12,
            "graph_entity_count": 3,
        }))
    }

    /// Run `trace_data_flow` through the annotation chokepoint, so the payload
    /// key names the handler writes are pinned to the qualifier that reads them.
    fn traced_response(
        store: &InMemoryGraph,
        focal: &str,
        direction: &str,
        envelope: crate::Envelope,
    ) -> serde_json::Value {
        let mut args = HashMap::new();
        args.insert("focal".to_string(), serde_json::json!(focal));
        args.insert("direction".to_string(), serde_json::json!(direction));
        let annotated = crate::finalize_with_envelope(
            handle_trace_data_flow(&args, store).unwrap(),
            envelope,
            "trace_data_flow",
        );
        parsed_response(&annotated)
    }

    fn trust_reason(response: &serde_json::Value) -> String {
        response["negative"]["trust_reason"]
            .as_str()
            .unwrap_or_else(|| panic!("the negative must carry a trust_reason: {response}"))
            .to_string()
    }

    /// The authoritative side of the trace absence: a focal that is in the
    /// graph, carries a name nothing else shares, is not a method, and has no
    /// edges at all. That is a real absence, and the qualifier must still be
    /// willing to say so. A gate that never certifies anything is as useless
    /// as one that certifies everything.
    #[test]
    fn trace_data_flow_isolated_focal_is_authoritative_on_a_ready_graph() {
        let store = InMemoryGraph::new();
        let lonely = make_entity("lonely", "src/lonely.rs");
        store.upsert_entity(&lonely).unwrap();

        let response = traced_response(
            &store,
            &lonely.id.to_string(),
            "both",
            structurally_ready_envelope(),
        );
        assert_eq!(response["focal_name"], "lonely");
        assert_eq!(response["total_steps"], 0);
        assert_eq!(response["focal_resolution"]["same_name_candidates"], 1);
        assert_eq!(response["negative"]["kind"], "no_flow");
        assert_eq!(
            response["negative"]["safe_to_conclude_absent"], true,
            "a resolved, uniquely named, non-method focal with no edges on a loaded graph is a \
             real absence: {}",
            response["negative"]
        );
    }

    /// And the inconclusive side of the same walk. The in-process runtime is a
    /// fallback surface, so the identical empty chain must not be handed back
    /// as proof the entity is unused.
    #[test]
    fn trace_data_flow_isolated_focal_is_inconclusive_on_an_unattested_graph() {
        let store = InMemoryGraph::new();
        let lonely = make_entity("lonely", "src/lonely.rs");
        store.upsert_entity(&lonely).unwrap();

        let response = traced_response(
            &store,
            &lonely.id.to_string(),
            "both",
            crate::Envelope::offline(),
        );
        assert_eq!(response["negative"]["kind"], "no_flow");
        assert_eq!(
            response["negative"]["safe_to_conclude_absent"], false,
            "an unattested runtime cannot certify absence: {}",
            response["negative"]
        );
        assert!(trust_reason(&response).contains("offline_fallback"));
    }

    /// The reported shape: two cfg arms of one declaration are admitted as
    /// distinct entities, a call the extractor cannot attribute to a single
    /// candidate lands on neither, and the walk follows one twin. An empty
    /// chain there answers for both twins a question that was asked of one, so
    /// it must never be certified.
    #[test]
    fn trace_data_flow_same_named_twins_never_certify_absence() {
        let store = InMemoryGraph::new();
        let real = make_entity("process_embedding_queue", "src/engine/graph.rs");
        let stub = make_entity("process_embedding_queue", "src/engine/graph_stub.rs");
        store.upsert_entity(&real).unwrap();
        store.upsert_entity(&stub).unwrap();

        let response = traced_response(
            &store,
            &real.id.to_string(),
            "callers",
            structurally_ready_envelope(),
        );
        assert_eq!(response["total_steps"], 0);
        assert_eq!(response["focal_resolution"]["same_name_candidates"], 2);
        assert_eq!(
            response["negative"]["safe_to_conclude_absent"], false,
            "a name the graph holds twice cannot certify absence for either twin: {}",
            response["negative"]
        );
        assert!(trust_reason(&response).contains("focal_resolution_ambiguous"));
    }

    /// Receiver-method calls are linked by bare name while method entities are
    /// keyed by their qualified name, so a method's incoming call edges are
    /// frequently missing. `find_references` has always refused to certify that
    /// absence; the trace reads the same edges and now refuses too.
    #[test]
    fn trace_data_flow_method_focal_never_certifies_an_empty_callers_walk() {
        let store = InMemoryGraph::new();
        let mut method = make_entity("process_embedding_queue", "src/engine/graph.rs");
        method.kind = EntityKind::Method;
        store.upsert_entity(&method).unwrap();

        let response = traced_response(
            &store,
            &method.id.to_string(),
            "callers",
            structurally_ready_envelope(),
        );
        assert_eq!(
            response["negative"]["safe_to_conclude_absent"], false,
            "an empty callers walk on a method is not proof of disuse: {}",
            response["negative"]
        );
        assert!(trust_reason(&response).contains("method_call_resolution_incomplete"));
    }

    /// An empty walk is empty only on the side that was walked. This focal is
    /// genuinely called by another entity, so a merged claim would be false;
    /// the outgoing walk may say only that it calls nothing.
    #[test]
    fn trace_data_flow_absence_names_the_direction_that_was_walked() {
        let (store, _, _, callee_id) = neighborhood_fixture();

        let outgoing = traced_response(
            &store,
            &callee_id.to_string(),
            "calls",
            structurally_ready_envelope(),
        );
        assert_eq!(outgoing["total_steps"], 0);
        let subject = outgoing["negative"]["subject"]
            .as_str()
            .expect("the negative must carry a subject")
            .to_string();
        assert!(
            subject.contains("anything it calls") && !subject.contains("either direction"),
            "an outgoing-only walk must claim only what the focal calls: {subject}"
        );

        let incoming = traced_response(
            &store,
            &callee_id.to_string(),
            "callers",
            structurally_ready_envelope(),
        );
        assert_eq!(
            incoming["total_steps"], 2,
            "the focal really is called, transitively, which is what makes the merged claim false"
        );
    }

    /// The asymmetry an agent cannot see: every resolved answer from this tool
    /// carried the full negative while a name that resolved to nothing arrived
    /// as a bare message. The message still has to survive, because it is the
    /// only part a human reads.
    #[test]
    fn trace_data_flow_focal_miss_carries_the_negative_beside_its_message() {
        let store = InMemoryGraph::new();
        let mut args = HashMap::new();
        args.insert("focal".to_string(), serde_json::json!("absent_symbol"));
        let annotated = crate::finalize_with_envelope(
            handle_trace_data_flow(&args, &store).unwrap(),
            populated_ready_envelope(),
            "trace_data_flow",
        );
        let response = parsed_response(&annotated);

        assert!(
            response["message"]
                .as_str()
                .is_some_and(|message| message.contains("absent_symbol")),
            "the human-readable message must survive beside the qualifier: {response}"
        );
        assert!(
            response[crate::ENVELOPE_KEY].is_object(),
            "the envelope must ride along as it always did: {response}"
        );
        assert_eq!(response["negative"]["kind"], "focal_not_resolved");
        assert_eq!(response["negative"]["interpretation"], "name_not_resolved");
        assert_eq!(
            response["negative"]["safe_to_conclude_absent"], true,
            "a name no entity carries, on a loaded graph that holds entities, is a real answer: {}",
            response["negative"]
        );
    }

    /// The other half: a graph holding nothing at all answers every name the
    /// same way, so a miss there is a fact about the graph rather than about
    /// the symbol. This is the case that made a bare "not found" dangerous.
    #[test]
    fn trace_data_flow_focal_miss_on_an_empty_graph_is_not_authoritative() {
        let store = InMemoryGraph::new();
        let mut args = HashMap::new();
        args.insert("focal".to_string(), serde_json::json!("absent_symbol"));
        let empty_graph = crate::Envelope::daemon().with_health(&serde_json::json!({
            "initialized": true,
            "graph_loaded": true,
            "graph_entity_count": 0,
        }));
        let annotated = crate::finalize_with_envelope(
            handle_trace_data_flow(&args, &store).unwrap(),
            empty_graph,
            "trace_data_flow",
        );
        let response = parsed_response(&annotated);

        assert_eq!(
            response["negative"]["safe_to_conclude_absent"], false,
            "a graph with no entities cannot report that a name is absent from the code: {}",
            response["negative"]
        );
        assert!(trust_reason(&response).contains("graph_empty"));
    }

    /// `find_references` answered its own miss the same bare way, and gets the
    /// same qualifier from the same chokepoint.
    #[tokio::test]
    async fn find_references_entity_miss_carries_the_negative_beside_its_message() {
        let store = InMemoryGraph::new();
        let mut args = HashMap::new();
        args.insert(
            "entity_id".to_string(),
            serde_json::json!(EntityId::new().to_string()),
        );
        let annotated = crate::finalize_with_envelope(
            handle_find_references(&args, &store, None).await.unwrap(),
            populated_ready_envelope(),
            "find_references",
        );
        let response = parsed_response(&annotated);

        assert_eq!(response["message"], "Entity not found");
        assert!(response[crate::ENVELOPE_KEY].is_object());
        assert_eq!(response["negative"]["kind"], "focal_not_resolved");
        assert_eq!(
            response["negative"]["safe_to_conclude_absent"], true,
            "an id no entity carries, on a loaded graph that holds entities, is a real answer: {}",
            response["negative"]
        );
    }

    /// And its inconclusive side, so neither tool can certify a miss off a
    /// fallback surface.
    #[tokio::test]
    async fn find_references_entity_miss_is_inconclusive_on_an_unattested_graph() {
        let store = InMemoryGraph::new();
        let mut args = HashMap::new();
        args.insert(
            "entity_id".to_string(),
            serde_json::json!(EntityId::new().to_string()),
        );
        let annotated = crate::finalize_with_envelope(
            handle_find_references(&args, &store, None).await.unwrap(),
            crate::Envelope::offline(),
            "find_references",
        );
        let response = parsed_response(&annotated);

        assert_eq!(response["message"], "Entity not found");
        assert_eq!(response["negative"]["safe_to_conclude_absent"], false);
        assert!(trust_reason(&response).contains("offline_fallback"));
    }

    /// The declared tool schema must offer the parameter the handler honors,
    /// and the description must claim the direction the traversal delivers.
    #[test]
    fn graph_neighborhood_schema_and_description_match_the_behavior() {
        let tools = crate::tools::tool_definitions();
        let tool = tools
            .tools
            .iter()
            .find(|t| t.name == "graph_neighborhood")
            .expect("graph_neighborhood must be registered");
        assert!(
            tool.input_schema["properties"]["direction"].is_object(),
            "the direction parameter must be declared: {}",
            tool.input_schema
        );
        assert!(
            tool.description.contains("both directions"),
            "the description must state that traversal is bidirectional"
        );
    }

    /// This file may not quietly go back to the outgoing-only traversal:
    /// `get_dependency_neighborhood` is fed only the outgoing index in kin-db,
    /// which is what made this tool answer dependencies when it was asked for
    /// dependents. The scan reads this one file, so it guards the handler that
    /// regressed rather than every call site in the crate.
    #[test]
    fn graph_neighborhood_does_not_use_the_outgoing_only_traversal() {
        // Split so this guard's own source line is not a match for itself.
        let needle = concat!(".get_dependency_", "neighborhood(");
        let source = include_str!("entities.rs");
        let call_site = source.lines().find(|line| line.contains(needle));
        assert!(
            call_site.is_none(),
            "outgoing-only neighborhood traversal reintroduced: {call_site:?}"
        );
    }

    #[test]
    fn daemon_graph_status_measures_one_selected_graph() {
        let graph = InMemoryGraph::new();
        let caller = make_entity("caller", "src/caller.rs");
        let callee = make_entity("callee", "src/callee.rs");
        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&callee).unwrap();
        graph
            .upsert_relation(&make_relation(caller.id, callee.id, RelationKind::Calls))
            .unwrap();
        let embeddings = graph.embedding_status();
        let observation = GraphStatusObservation {
            authority_epoch: 42,
            entity_count: graph.entity_count(),
            relation_count: graph.relation_count(),
            embeddings_indexed: embeddings.indexed,
            embeddings_pending: embeddings.pending,
            embeddings_total: embeddings.total,
        };
        let result =
            handle_daemon_graph_status_observation(GraphStatusScope::TemporalSession, observation)
                .unwrap();
        let report: GraphStatusReport = serde_json::from_value(parsed_response(&result)).unwrap();

        assert_eq!(report.schema, GRAPH_STATUS_SCHEMA);
        assert_eq!(report.view, GraphStatusView::DaemonSelectedGraph);
        assert_eq!(report.scope, GraphStatusScope::TemporalSession);
        assert_eq!(report.authority, GraphStatusAuthority::RepoDaemon);
        assert_eq!(
            report.sampling,
            GraphStatusSampling::PointInTimeSelectedGraph
        );
        assert_eq!(report.authority_epoch, 42);
        assert_eq!(report.entity_count, observation.entity_count);
        assert_eq!(report.relation_count, observation.relation_count);
        assert_eq!(
            report.embedding_source,
            GraphStatusEmbeddingSource::SelectedGraph
        );
        assert_eq!(report.embeddings_indexed, embeddings.indexed);
        assert_eq!(report.embeddings_pending, embeddings.pending);
        assert_eq!(report.embeddings_total, embeddings.total);
        assert!(!report.completion_attested);
        assert!(report.response_envelope.is_none());
    }

    #[test]
    fn daemon_graph_status_rejects_an_impossible_observation_before_serializing() {
        let error = handle_daemon_graph_status_observation(
            GraphStatusScope::Head,
            GraphStatusObservation {
                authority_epoch: 42,
                entity_count: 2,
                relation_count: 1,
                embeddings_indexed: 3,
                embeddings_pending: 0,
                embeddings_total: 2,
            },
        )
        .expect_err("the direct daemon boundary must reject impossible coverage");
        assert!(
            error
                .to_string()
                .contains("embeddings_indexed (3) exceeds embeddings_total (2)"),
            "{error}"
        );
    }

    #[test]
    fn generic_graph_status_refuses_an_unmeasured_offline_approximation() {
        let result = handle_graph_status(&HashMap::new(), &InMemoryGraph::new()).unwrap();
        assert_eq!(result.is_error, Some(true));
        let crate::types::ContentBlock::Text { text } = &result.content[0];
        assert!(text.contains("requires the Kin daemon"), "{text}");
    }
}
