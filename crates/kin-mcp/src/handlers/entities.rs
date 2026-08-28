// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;

use super::repository_authority::RequestRepositoryAuthority;
use kin_index::RelationResolution;
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
(daemon-owned graph, initialized and loaded, holding entities, no degraded signals) \
or merely \"not indexed yet\" — check it before treating \"none found\" as ground \
truth. This filter reads the entity index rather than the vector index, so its \
absence is gated on the graph being complete, not on embedding coverage. An empty \
answer also carries `edge_coverage`, naming the languages the filter's own scope \
spans and how many entities it holds with the name pattern removed. Nothing measures \
a coverage class for those languages yet, so an empty answer is never certified: a \
miss cannot separate a declaration the repository lacks from one the extractor never \
admitted as an entity, and a file the graph has not admitted reads the same way. \
Where a sharper reason applies it leads instead, naming a scope the index never \
populated, a language this build wires no adapter for, or the narrowing filter that \
removed every candidate the name did match.";

pub fn handle_semantic_search<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let (query, limit, filter) = build_semantic_search_request(args)?;
    let compact = get_optional_bool(args, "compact", true);

    let entities = store.query_entities(&filter).map_err(McpError::graph)?;
    let total_matches = entities.len();

    let mut payload = if compact {
        let limited: Vec<_> = entities
            .into_iter()
            .take(limit)
            .map(CompactSearchResult::from)
            .collect();
        serde_json::to_value(CompactSearchResponse {
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
        serde_json::to_value(SemanticSearchResponse {
            query,
            limit,
            total_matches,
            truncated: total_matches > limited.len(),
            results: limited,
        })
        .map_err(McpError::Json)?
    };

    // FIR-2430. An empty search is a claim about the region this filter selected,
    // and until this observation existed the claim was certified from daemon
    // health alone: `semantic_search(query: "utils", kind: "module")` on
    // expressjs/express reported `safe_to_conclude_absent: true` while
    // `lib/utils.js` sat in the tree holding nine entities, minutes after
    // `find_references` had refused to certify an absence on the same repository
    // because JavaScript has no reference enrichment in this build.
    //
    // The scope query is the same filter with the name pattern removed, so the
    // count is the coverage of the kind/language/role the caller asked about
    // rather than of the name they asked for. Paid only on the empty path, which
    // is the only answer whose trust depends on it.
    if total_matches == 0 {
        let scope = kin_model::graph::EntityFilter {
            name_pattern: None,
            ..filter.clone()
        };
        let scoped = store.query_entities(&scope).map_err(McpError::graph)?;
        let mut observation = crate::edge_coverage::observe_absence_scope(
            &crate::edge_coverage::languages_of(&scoped),
            Some(scoped.len()),
        );

        // FIR-2452. The scope above removes the name and keeps the narrowing
        // filters, so it cannot see an answer that the narrowing filters emptied.
        // That is the answer the stranger run got: `query: "request", kind:
        // "method"` on psf/requests returned zero and certified the absence,
        // because the scope held every method in the repository and Python is a
        // language this build enriches, so every gate read healthy. Asking the
        // name's own side is what separates the two: the store's pattern index
        // returns its exact-name and token hits and returns EARLY on any hit
        // without reaching its substring fallback, and the kind predicate then
        // removed every candidate it had returned.
        //
        // Paid only when a narrowing filter was actually applied and only on the
        // empty path. With no narrowing filter this query IS the name query, its
        // count is the zero already in hand, and running it again would buy
        // nothing.
        let narrowed_by = narrowing_filters_of(&filter);
        if !narrowed_by.is_empty() {
            let name_only = kin_model::graph::EntityFilter {
                kinds: None,
                languages: None,
                roles: None,
                ..filter.clone()
            };
            let candidates = store.query_entities(&name_only).map_err(McpError::graph)?;
            crate::edge_coverage::attach_name_filter_scope(
                &mut observation,
                &narrowed_by,
                candidates.len(),
            );
        }

        payload[crate::edge_coverage::EDGE_COVERAGE_KEY] = observation;
    }

    let json = serde_json::to_string_pretty(&payload).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

/// The narrowing filters a search request applied beside its name pattern, named
/// as the caller asked for them.
///
/// These are the filters that can empty an answer the name pattern did not, so
/// naming them is what lets an absence verdict say which one removed the
/// candidates instead of reporting an unattributed miss. `role` is listed
/// separately from `kind` because `kind: "test"` resolves to a role filter with
/// no kind filter at all, so reporting it as a kind would name a predicate the
/// query never applied.
fn narrowing_filters_of(filter: &kin_model::graph::EntityFilter) -> Vec<&'static str> {
    let mut applied = Vec::new();
    if filter.kinds.is_some() {
        applied.push("kind");
    }
    if filter.languages.is_some() {
        applied.push("language");
    }
    if filter.roles.is_some() {
        applied.push("role");
    }
    applied
}

pub const SEMANTIC_LOCATE_DESC: &str = "\
Rank the code most relevant to a natural-language query. This is the tool to reach for \
when you are looking for \"where is the code that does X\" and you only have a \
description of the behavior, not an exact symbol name. Unlike semantic_search (which \
matches declarations by name/kind/language and ignores the query for ranking), \
semantic_locate ranks by query relevance and returns act-on-able hits: entity_id, file, \
line span, kind, score, and a bounded inline source excerpt. Each hit carries that text \
ONCE: read it from `body` on the fused pipeline (the default) and from `snippet` on the \
cosine pipeline, and read `routing` if you need to know which answered. Set \
granularity to \"entity\" \
(default) for ranked declarations or \"file\" to roll results up to the most relevant \
files. Two pipelines can answer. The default on every profile is the full fused \
retrieval pipeline `kin locate` serves: vector similarity, lexical search, and \
graph-structure signals fused with role-aware ranking and exact-name promotion. The \
legacy single-vector cosine ranking stays reachable per call with \
`pipeline: \"cosine\"` for A/B comparison. The `routing` field reports which pipeline \
actually answered: `fused-v1` for the fused default, `cosine-v0` for the per-call \
legacy arm. Every hit also \
carries an additive `match_evidence` object explaining why it ranked — the ranker that \
produced it, the score source, whether the query matched the entity name, and the \
ranking signals that applied — derived from graph-owned retrieval data, never a \
working-tree read. Pass an optional `queries` array of additional query variants to fan \
out: `query` plus each variant are retrieved independently and their rankings RRF-fused \
into one deduped result. The fan-out is echoed once under `queries` and each hit's \
`matched_variant_indexes` gives the positions in that list of the variants \
that surfaced it (diverse variants, meaning identifiers, behavior and subsystem, recover \
more than any single phrasing); multi-query fusion always uses the fused pipeline. Both \
pipelines report semantic_coverage as one counter object (indexed, total, pending, \
complete), the same shape `_kin.semantic_coverage` carries, and both report a `degradations` array \
naming any retrieval capability that could not fully run (empty vector index, reranker \
model not cached, …), so a thin result set is attributable instead of silent. Ranking \
demotes test-role entities, and at several stages excludes them, unless the query text \
itself reads as being about tests; pass `include_tests: true` to rank them alongside \
source. When the default withholds test paths the response says how many under \
`semantic_coverage.graph_bodies.withheld_test_paths` and records a `graph_role_filter` \
degradation, and `complete` is never true over a population that filter narrowed. Requires \
the Kin daemon: retrieval runs against the daemon's live graph, so this tool returns an \
error in offline/no-daemon mode. On an empty result the additive `negative` object's \
`safe_to_conclude_absent` flag distinguishes an authoritative \"no match\" from \"not \
yet embedded\". A NON-empty result needs the opposite check, because retrieval always \
returns its best candidates: each hit carries `match_kind` (`name` when a query token is \
that entity's name, else `semantic` or `text_fallback`), and an entity-granularity response carries \
`all_fallback: true` when NOT ONE returned entity was named by the query. Asking for a \
symbol that does not exist yields a full, confident-looking page with `all_fallback` set \
— treat that as \"this symbol was not found\" rather than as the answer. Every hit also \
states which id space it belongs to, because the retrieval index spans two and their ids \
look alike. `id_space: \"entity\"` means the hit carries an `entity_id` that resolves in \
the graph, so get_entity_source, get_context_pack, graph_neighborhood, and find_references \
all take it. `id_space: \"artifact\"` means the hit is an artifact-level embedding — a \
tracked file the parsers produced no entities for — so it carries `artifact_path` and NO \
`entity_id`, and those tools will refuse it; read it with kin_artifact_read instead. Do \
not synthesize an entity id from an artifact hit's path. The response attempts to bound its own size \
(max_chars, default 45000 serialized characters, ceiling 60000): it is compact by default, meaning no per-signal `match_evidence` breakdown unless you \
ask with explain=true or compact=false, and under pressure an entity-granularity response first \
sheds its secondary per-file symbol roll-up. File granularity preserves those symbols because they \
are primary answer detail. It then sheds inline snippets, and only then withholds hits from the end \
of the page. Any cut is reported \
in `degradations` and in `_kin.response`, which carries the budget applied and what the response \
measured before it. Primary rows are withheld only when `next_cursor` can be rebased so every row \
stays reachable. A cursorless final page keeps its primary rows instead; if those rows alone exceed \
the ceiling, the response ships over budget with `response_over_budget` disclosure rather than \
silently losing unrecoverable answers, and a size-limited client may still refuse it.";

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

/// Certified dependents a pack will recover into its `dependents` group beyond
/// the rows its own section already carried.
///
/// The group's membership must not depend on how much token budget was left,
/// which is the whole point of recovering them, but a focal with hundreds of
/// callers must not turn a budgeted pack into an unbudgeted one either. Past
/// this the count is still exact: `certified_dependents` reports what the
/// reference authority proved and `dependents_withheld` reports what did not
/// fit, so a caller reading a short group knows to ask `find_references` for
/// the rest rather than reading the group as the whole set.
const CERTIFIED_DEPENDENTS_MAX: usize = 24;

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
your context window — with one budgeted call. `token_budget` bounds the content the pack \
selects, and it cannot bound the envelope that content travels in, so read `tokens_used`, \
which measures the serialized response this call returns, as what the call costs you. \
`focal_entity.body` in the response IS the focal entity's exact source text, so this one \
call already answers \"show me the code\": no follow-up read is needed, and it is the body \
to edit and stage back, in compact mode too, which drops the dependency bodies and \
projection levels but never the focal body. The two directions are separate groups, because they answer opposite questions: \
`dependencies` is what the focal needs to run, and `dependents` is what breaks if you \
change it. Every row also says why it is there: `relation: \"dependency_edge\"` is an \
edge leaving the focal, `relation: \"dependent_edge\"` is an edge arriving at it, and \
`relation: \"same_file_neighbor\"` means the focal had no dependency edge in either \
direction, so the row is a neighbour sharing the focal's file rather than anything the \
focal depends on. That last one is the usual shape for a class whose only edges are \
containment, and those rows sort after the real edges. A row carrying \
`bidirectional: true` is joined to the focal BOTH ways; it is grouped by the arriving \
edge because that is the one that decides whether changing the focal breaks it. \
`dependents` is assembled by the same collector `find_references` uses, on the same \
graph, so the two tools cannot answer differently about one entity: a caller that tool \
returns is in this group, and a bare-name receiver guess it declines to certify is in \
neither. `dependency_selection` names which selection filled the dependency list, how \
many rows each group returned, how many dependents the reference authority certified, \
how many were withheld to stay inside the pack's budget, and, for the fallback, how many \
same-file candidates there were and how many were dropped to fit. Read `edge_coverage` \
and the response's `negative` verdict before acting on an EMPTY `dependents`: a graph \
that does not link this language's calls across files returns the same `[]` for a symbol \
with twenty callers as for one with none. \
If get_entity_source is available to you it is cheaper for a raw \
body alone; if you need to follow an actual call chain step by step, use trace_data_flow.";

pub fn handle_get_context_pack<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
    sessions: &SessionRegistry,
    repository_authority: Option<&RequestRepositoryAuthority>,
) -> Result<ToolCallResult> {
    use kin_context::{
        build_context_pack_with_traffic_and_provenance, ContextOptions, DependencyRelation,
    };
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

    let (pack, selection) =
        build_context_pack_with_traffic_and_provenance(store, &entity_id, &opts, &nearby_intents)
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
        focal_context_json_held(&held, entity)?
    } else {
        serde_json::json!(null)
    };

    // `relation` is what keeps a same-file neighbour from reading as a
    // dependency. The builder tags the fallback inside `entry.content`, which
    // this handler does not serialize, so without the selection travelling
    // alongside the pack the two are indistinguishable on the wire. Rows in the
    // sections that are not dependencies (transitive, tests, contracts) pass
    // `None` and carry no relation at all.
    let project_dep = |entry: &kin_model::context::ContextEntry,
                       relation: Option<DependencyRelation>|
     -> Result<serde_json::Value> {
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
            if let Some(relation) = relation {
                obj["relation"] = serde_json::json!(relation.as_str());
            }
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
            let mut obj = serde_json::json!({
                "id": entry.entity_id.to_string(),
                "content": entry.content,
            });
            if let Some(relation) = relation {
                obj["relation"] = serde_json::json!(relation.as_str());
            }
            Ok(obj)
        }
    };

    // Membership of the `dependents` group is decided by the edge authority
    // `find_references` reads, on the same store, in the same request. The two
    // surfaces answer the same question about the same entity, so a pack that
    // decided it independently could disagree with the tool beside it, and it
    // did: on expressjs/express `res.sendFile` packed `dependents: []` while
    // `find_references` on that id returned `res.download`, which calls it.
    //
    // This is the same call `handle_find_references` makes, not a second
    // implementation of it. Everything that decides what counts as a reference
    // -- the allowed edge classes, the self-edge exclusion, composition over
    // proven overrides, and dropping a caller the workspace no longer contains
    // -- is that function's, so the two cannot drift apart by being edited
    // separately.
    let reference_kinds = default_reference_kinds();
    let reference_rows =
        collect_graph_reference_rows(store, &entity_id, &reference_kinds, repository_authority)?;
    // Observed before the partition, because a candidate row still witnesses the
    // edge class it arrived on. Same rule as the reference tool's, so the
    // coverage the pack publishes is the coverage that tool would publish.
    let witnessed = match &focal_entity {
        Some(entity) => answer_witnessed_classes(store, entity, &reference_rows),
        None => Vec::new(),
    };
    // FIR-1552 again, in the direction that matters here: a row matched on a
    // bare receiver name with nothing at the site proving the destination is a
    // candidate, not a caller. `find_references` withholds it from its count,
    // so a pack that promoted it to a dependent would be certifying what the
    // reference surface declined to.
    let mut certified_rows: Vec<ReferenceRow> = reference_rows
        .into_iter()
        .filter(|row| !row.receiver_name_guess)
        .collect();
    certified_rows.sort_by(|left, right| {
        left.file_path
            .cmp(&right.file_path)
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.entity_id.cmp(&right.entity_id))
    });
    let certified_ids: Vec<kin_model::ids::EntityId> = certified_rows
        .iter()
        .filter_map(|row| row.entity_id.as_deref())
        .filter_map(|id| parse_entity_id(id).ok())
        .collect();
    let certified: std::collections::HashSet<kin_model::ids::EntityId> =
        certified_ids.iter().copied().collect();
    // What the graph can structurally answer over the classes the group was
    // built from. An empty `dependents` is only evidence about the code when
    // this says the focal's language links those classes across files, and
    // nothing else in a pack reports it.
    let edge_coverage = match &focal_entity {
        Some(entity) => crate::edge_coverage::observe_cross_file_reference_coverage_witnessed(
            store,
            entity,
            &reference_kinds,
            &witnessed,
        ),
        None => serde_json::Value::Null,
    };
    // Whether a caller could have reached this focal through a call the linker
    // recorded no edge for (FIR-2775), read exactly as `find_references` reads
    // it and published under the same key.
    //
    // A pack's `dependents` group is built by the same collector over the same
    // edges, so it inherits the same gap and has to report it the same way. The
    // method gate beside this one is shared for precisely that reason: gating a
    // shared gap on the tool name alone was how two surfaces over one graph came
    // to answer opposite things about one entity, the tool that refused to
    // certify and the tool that published `[]` reading the identical incomplete
    // call graph. Adding a new gap to one surface and not the other would
    // rebuild that disagreement from scratch.
    let caller_arrival = match &focal_entity {
        Some(entity) => crate::caller_arrival::observe_caller_arrival(store, entity).to_json(),
        None => serde_json::Value::Null,
    };

    // The dependency section carries both directions, so it is served as two
    // groups named for what they are. Serving it as one list called
    // `dependencies` reported a focal's callers as things the focal depends on,
    // which is the opposite claim and the one an agent acts on when it decides
    // what it may safely change. The builder has already ordered the section so
    // real dependencies precede dependents and fallback neighbours, and that
    // order survives the partition.
    let mut dependencies: Vec<serde_json::Value> = Vec::new();
    let mut dependents: Vec<serde_json::Value> = Vec::new();
    let mut packed: std::collections::HashSet<kin_model::ids::EntityId> =
        std::collections::HashSet::new();
    for entry in &pack.dependency_signatures {
        let packed_relation = selection.relation_for(&entry.entity_id);
        // The union, never the intersection. A certified caller is a dependent
        // whatever the pack's own section made of it, and an arriving edge of a
        // class the reference surface does not read -- `UsesType`, `Implements`,
        // `Extends` -- is still a dependent the pack can see and that surface
        // cannot. Taking either one alone would drop real blast radius.
        let relation = if certified.contains(&entry.entity_id) {
            DependencyRelation::DependentEdge
        } else {
            packed_relation
        };
        let mut row = project_dep(entry, Some(relation))?;
        match relation {
            DependencyRelation::DependentEdge => {
                // Nothing is lost when a pair is joined both ways. The pack used
                // to resolve that by calling the neighbour a dependency, which
                // on a JavaScript object literal spends a weak leaving
                // `References` edge to erase a real arriving `Calls` -- and
                // every sibling method has that shape, so a focal lost its whole
                // caller set at once. The group is decided by the arriving edge
                // and the other direction is stated on the row.
                if packed_relation == DependencyRelation::DependencyEdge {
                    row["bidirectional"] = serde_json::json!(true);
                }
                packed.insert(entry.entity_id);
                dependents.push(row);
            }
            DependencyRelation::DependencyEdge | DependencyRelation::SameFileNeighbor => {
                dependencies.push(row)
            }
        }
    }
    // A certified caller the pack's own section never reached -- shed by the
    // builder's token budget, or missed by its subgraph walk -- is exactly the
    // shape this defect had. Recovering it here is what makes the group's
    // membership a property of the answer rather than of how much budget was
    // left, and the recovered rows carry the same shape as the projected ones so
    // a reader cannot tell which path produced them.
    let mut dependents_withheld = 0usize;
    for id in &certified_ids {
        if packed.contains(id) {
            continue;
        }
        if dependents.len() >= CERTIFIED_DEPENDENTS_MAX {
            dependents_withheld += 1;
            continue;
        }
        let entry = kin_model::context::ContextEntry {
            entity_id: *id,
            projection_level: kin_model::context::ProjectionLevel::SignatureOnly,
            content: String::new(),
        };
        dependents.push(project_dep(
            &entry,
            Some(DependencyRelation::DependentEdge),
        )?);
        packed.insert(*id);
    }
    let transitive: Vec<_> = pack
        .transitive_deps
        .iter()
        .map(|entry| project_dep(entry, None))
        .collect::<Result<Vec<_>>>()?;

    // The cap and the fallback are both invisible in the rows themselves: six
    // neighbours out of twenty-four look exactly like six dependencies. This
    // says which selection ran and what it dropped, in every mode, because a
    // caller deciding whether to ask again needs it most when the answer is
    // small.
    let returned = dependencies.len();
    let dependents_returned = dependents.len();
    let mut result = serde_json::json!({
        "focal_entity": focal_json,
        "dependencies": dependencies,
        // Always present, empty included. "no dependents" and "this build does
        // not report dependents" are different answers, and a group that
        // appears only when populated cannot tell them apart. What separates
        // them now is `edge_coverage` and the response's `negative` verdict:
        // an empty group on a graph that demonstrably links this language's
        // edges across files is an answer, and an empty group on one that does
        // not is a gap, and both used to serialize as `[]`.
        "dependents": dependents,
        "dependency_selection": {
            "source": selection.source().as_str(),
            "returned": returned,
            "dependents_returned": dependents_returned,
            // What the reference authority certified, stated beside what the
            // group returned so the two can be compared. They differ when the
            // pack sees an arriving edge of a class that authority does not
            // read, and when the cap below withholds one.
            "certified_dependents": certified_ids.len(),
            // The cap's own number, and only the cap's. The top-level
            // `dependents_withheld` counts every cause together, because a
            // caller asking "how many rows am I not seeing" wants one answer;
            // this one stays because a caller already reading it must not have
            // its meaning changed underneath it.
            "dependents_withheld": dependents_withheld,
            "same_file_candidates": selection.same_file_candidates(),
            "same_file_dropped": selection.same_file_dropped(),
        },
        // The substrate behind the `dependents` group, so an empty group is
        // read against what this graph can structurally answer for the focal's
        // language rather than as a bare fact. Computed by the same observer
        // `find_references` uses, from the same witnesses.
        crate::edge_coverage::EDGE_COVERAGE_KEY: edge_coverage,
        crate::caller_arrival::CALLER_ARRIVAL_KEY: caller_arrival,
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
            .map(|entry| project_dep(entry, None))
            .collect::<Result<Vec<_>>>()?;
        if !tests.is_empty() {
            result["tests"] = serde_json::json!(tests);
        }
        let contracts: Vec<_> = pack
            .contracts
            .iter()
            .map(|entry| project_dep(entry, None))
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

    // What the pack's own token budget refused, in the map the response budget
    // already publishes its cuts to.
    //
    // Two budgets cut this answer and only one of them was ever visible. The
    // token budget runs first, inside the builder, and a dependency section it
    // trimmed from twelve rows to six serialized exactly like a focal with six:
    // `returned: 6` beside six rows, and nothing anywhere saying a row had been
    // a candidate. That is the reading kin#1062 removed from the list case and
    // kin#1068 from the impact case, arriving here through the earlier budget.
    //
    // One map, keyed by the group, with the cause named on each entry: a caller
    // raises `token_budget` for these and `max_chars` for the response budget's,
    // and being told the wrong lever costs a round trip that cannot help.
    let recovered = |id: &kin_model::ids::EntityId| packed.contains(id);
    let mut budget_groups: Vec<&str> = vec![
        kin_context::group::DEPENDENCIES,
        kin_context::group::DEPENDENTS,
    ];
    if !compact {
        // A section `compact` never serves cannot be misread as an empty one,
        // because dropping it is the documented shape of that mode. A section
        // this mode does serve is absent only when it holds nothing, which is
        // exactly the reading a budget cut must not produce.
        budget_groups.extend([
            kin_context::group::TRANSITIVE_DEPS,
            kin_context::group::TESTS,
            kin_context::group::CONTRACTS,
            kin_context::group::WORK_ITEMS,
            kin_context::group::ANNOTATIONS,
        ]);
    }
    for group in budget_groups {
        let elided = selection.budget_elided_unrecovered(group, recovered);
        if elided == 0 {
            continue;
        }
        let kept = result
            .get(group)
            .and_then(serde_json::Value::as_array)
            .map_or(0, Vec::len);
        // The scalar beside the map, written here so the response budget's own
        // later cut of the same list adds to it rather than replacing it.
        result[format!("{group}_withheld")] = serde_json::json!(elided);
        crate::budget::record_elision_for(
            &mut result,
            group,
            kept,
            elided,
            crate::budget::ELISION_REASON_TOKEN_BUDGET,
        );
    }
    // The certified-dependents cap is the third cutter on this payload, and it
    // was disclosed only as a nested counter inside `dependency_selection`,
    // which is the sibling-counter shape that saved nobody in the stranger
    // session kin#1062 was filed from. It carries its own reason because no
    // budget parameter recovers it.
    if dependents_withheld > 0 {
        let kept = result
            .get("dependents")
            .and_then(serde_json::Value::as_array)
            .map_or(0, Vec::len);
        let prior = result
            .get("dependents_withheld")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0) as usize;
        result["dependents_withheld"] = serde_json::json!(prior + dependents_withheld);
        crate::budget::record_elision_for(
            &mut result,
            "dependents",
            kept,
            dependents_withheld,
            crate::budget::ELISION_REASON_DEPENDENTS_CAP,
        );
    }

    let json = serialize_with_measured_tokens(&mut result)?;
    Ok(ToolCallResult::text(json))
}

/// Passes allowed to settle `tokens_used` against the bytes carrying it.
///
/// The estimator counts a number as one token however many digits it has, so
/// writing the measurement back changes the count only when the payload's own
/// structure changes, which it does not. One correcting pass and one
/// confirming pass are what this actually takes; the rest is headroom.
const MEASURED_TOKEN_PASSES: usize = 4;

/// Serialize the pack, reporting what the bytes it returns actually cost.
///
/// `tokens_used` is the number a caller subtracts from its own context budget
/// before deciding what to ask for next, and it was the planner's estimate:
/// the cost of the signature stubs admission considered, not of the bodies,
/// provenance, and JSON structure this handler goes on to serve. A caller that
/// trusted it spent more than it was told, on every call, and the gap grew with
/// the pack because bodies are the part the estimate omits.
///
/// Measuring is self-referential, since the count is a field of the object
/// being counted. Writing the count back and re-measuring settles that: the
/// estimator treats a number as one token whatever its width, so the second
/// pass confirms the first rather than chasing it.
///
/// What this counts is the tool's own serialized payload. The `_kin` envelope
/// is attached after the handler returns and is not visible from here, so it
/// remains outside the number, which is a bounded and constant understatement
/// rather than the unbounded one this replaces.
fn serialize_with_measured_tokens(result: &mut serde_json::Value) -> Result<String> {
    let mut json = serde_json::to_string_pretty(result).map_err(McpError::Json)?;
    for _ in 0..MEASURED_TOKEN_PASSES {
        let measured = serde_json::json!(kin_context::estimate_tokens(&json));
        if result["tokens_used"] == measured {
            break;
        }
        result["tokens_used"] = measured;
        json = serde_json::to_string_pretty(result).map_err(McpError::Json)?;
    }
    Ok(json)
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
compact=true to drop the dependency bodies when you just need the structure, which \
leaves the focal body in place. \
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
Find who depends on an entity: its direct upstream callers, importers, and references. \
Give it an entity_id or an exact symbol name (it resolves the best-matching canonical \
definition) and it returns ONE ROW PER REFERENCING ENTITY, with that caller's entity id, \
name, kind, file path, its own definition line (start_line), and every line inside it \
that references the focal (reference_lines). Two callers in one file are two rows, and \
`total_upstream` is the number of referencing entities, the same unit `kin refs` prints. \
The `counts` object states the unit outright and adds `files` and `reference_sites`, so \
a count is never read against the wrong unit. `reference_sites` is null when some row's \
sites could not be located, with `known_reference_sites` the lower bound and each such \
row naming why under `reference_lines_absent_reason`. Rows omit the caller's body by \
default to keep the response small; pass include_snippets=true for the signature and a \
bounded body excerpt, or drill to any row's entity_id with get_entity_source. \
Use it to answer \"who calls / imports / uses this?\" before you \
change or remove something, to gauge blast radius, or to navigate from a definition out \
to its usages. Filter with relation_kinds (calls, imports, references) when you only \
care about one kind of edge; it defaults to all three. When you need this answer for \
many entities at once (e.g. classifying a whole set as used vs. unused), don't loop \
this call per entity, because bulk_check_references does the batch in one shot. \
When no references come back, the additive `negative` object's `safe_to_conclude_absent` \
flag says whether \"nothing depends on this\" is authoritative (daemon-owned graph, \
complete coverage, no degraded signals) or merely \"not indexed yet\" — consult it \
before treating the entity as safe to delete. An entity_id or name that resolves to nothing \
carries the same object, naming the resolution miss rather than reporting an empty result. \
Every row carries `resolution`: `type_resolved` (the destination is proven by a local \
binding, a declared import, or a resolved dispatch class), `import_scoped` (the target \
module was known and the symbol selected inside it), or `name_only` (a bare same-name \
match across the repo, with nothing at the reference site proving it). A `name_only` row \
is a candidate, not a fact; do not count it as use, and do not conclude something is \
unused from the absence of anything but `name_only` rows without confirming. \
`name_only` rows are held out of `total_upstream` and travel in `candidates`, and \
`unconfirmed_candidates` beside the headline says how many were held, so a \
`total_upstream` of 0 with `unconfirmed_candidates` above 0 means this answer is holding \
rows it could not confirm and the zero may not be read alone. \
`_kin.verdict` is the one verdict for the whole response and outranks every count in it. \
The response bounds its own size (max_chars, default 45000 serialized characters, ceiling \
60000): a symbol \
with hundreds of call sites sheds its inline snippets before it withholds any row, and any cut \
is reported in `degradations` and in `_kin.response` with the size the response had before the \
budget, so a short answer is never mistaken for a complete one.";

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
            // A federated xref carries no site span from the other repo's graph,
            // and says so rather than leaving an unexplained empty list.
            reference_lines: Vec::new(),
            reference_lines_absent: Some(ReferenceLinesAbsent::FederatedXref),
            signature: source.map(|entity| entity.signature.clone()),
            snippet: None,
            // CrossRepoEdge proves a dependency but does not retain whether
            // the source relation was Calls/Imports/References.
            relation_kinds: Vec::new(),
            // The resolving edge lives in the other repository's graph, so how
            // it was resolved is not knowable here. Absent, not guessed. For
            // the same reason it is not a receiver-name guess: nothing in this
            // payload could show that it was.
            resolution: None,
            receiver_name_guess: false,
            // No local entity, so no role. Defaulting this to `Source` would
            // report every federated caller as product code on no evidence.
            role: None,
            // A federated xref reaches the focal directly in the other
            // repository's graph; nothing here is composed over an override.
            via_override_of: None,
        });
    }

    rows
}

fn reference_filter_covers_unknown_subtypes(relation_kinds: &[RelationKind]) -> bool {
    let defaults = default_reference_kinds();
    relation_kinds.len() == defaults.len()
        && defaults.iter().all(|kind| relation_kinds.contains(kind))
}

/// The reference classes this answer itself proves the graph holds across files.
///
/// A returned row IS a resolved edge, so a row whose caller sits in a different
/// file from the focal and carries the focal's language is exactly the witness
/// the language scan in [`crate::edge_coverage`] goes looking for. Handing it
/// over spares that scan on the healthy path, which matters now that an
/// observation is taken on every answer rather than only on empty ones.
///
/// The language check is not optional. The scan is scoped to the focal's
/// language because extraction gaps are per-language, so a caller written in
/// another language proves nothing about whether THIS language's edges resolve,
/// and a witness taken from one would let a well-linked language lend coverage
/// to a language whose edges were never produced.
///
/// A row this cannot confirm contributes nothing and the scan runs, so the
/// failure direction is a scan that was not needed rather than a class reported
/// present on evidence that did not support it.
fn answer_witnessed_classes<G: GraphStore>(
    store: &G,
    focal: &kin_model::entity::Entity,
    rows: &[ReferenceRow],
) -> Vec<RelationKind> {
    let focal_file = focal.file_origin.as_ref().map(|path| path.0.clone());
    let mut witnessed: Vec<RelationKind> = Vec::new();
    for row in rows {
        if row
            .relation_kinds
            .iter()
            .all(|kind| witnessed.contains(kind))
        {
            continue;
        }
        let Some(file_path) = row.file_path.as_ref() else {
            continue;
        };
        if focal_file.as_ref() == Some(file_path) {
            continue;
        }
        let Some(entity_id) = row
            .entity_id
            .as_deref()
            .and_then(|id| parse_entity_id(id).ok())
        else {
            continue;
        };
        let Ok(Some(caller)) = store.get_entity(&entity_id) else {
            continue;
        };
        if caller.language != focal.language {
            continue;
        }
        for kind in &row.relation_kinds {
            if !witnessed.contains(kind) {
                witnessed.push(*kind);
            }
        }
    }
    witnessed
}

/// What a reference answer counted, stated rather than left to be inferred.
///
/// `total_upstream` is a bare number, and a reader who does not know its unit
/// cannot tell an under-count from a small repository. It counted distinct FILES
/// until FIR-2398, which is how eleven callers across two files were served as
/// "2" beside two flags that read complete.
///
/// The site total follows the rule `bulk_check_references` already uses: a
/// number is emitted only when it is complete, and the lower bound is named as a
/// bound otherwise. A row whose site lines the graph does not carry makes the
/// site total a floor, never a fact.
///
/// `reference_sites_complete` is about the rows that came back: it says every
/// returned reference could be located at a line. Whether the row SET itself is
/// complete is the `negative` object's question for an empty answer and
/// `edge_coverage`'s for the classes the query read; this field does not restate
/// either, and on an empty answer it describes an empty set.
fn reference_counts(rows: &[ReferenceRow], receiver_name_candidates: usize) -> serde_json::Value {
    let known_reference_sites: usize = rows.iter().map(|row| row.reference_lines.len()).sum();
    let reference_sites_complete = rows.iter().all(|row| !row.reference_lines.is_empty());
    let files = rows
        .iter()
        .filter_map(|row| row.file_path.as_deref())
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    serde_json::json!({
        "counted": "referencing_entities",
        "referencing_entities": rows.len(),
        "files": files,
        "reference_sites": reference_sites_complete.then_some(known_reference_sites),
        "known_reference_sites": known_reference_sites,
        "reference_sites_complete": reference_sites_complete,
        // Rows held out of every number above, carried in `candidates`. Stated
        // here so a reader who looks only at `counts` still learns the answer
        // withheld something (FIR-1552).
        "receiver_name_candidates": receiver_name_candidates,
    })
}

/// Component and reason a withheld-candidate disclosure is filed under, matched
/// to the pair `trace_data_flow` already files its `name_only` hops under so one
/// vocabulary covers both surfaces.
const CALL_RESOLUTION_COMPONENT: &str = "call_resolution";
const RECEIVER_NAME_CANDIDATES_REASON: &str = "receiver_name_candidates";

/// Declare the candidates this answer held out of its headline.
///
/// Withholding them is what makes the count honest, and saying nothing about it
/// would make the count look whole instead. A reported degradation is the one
/// disclosure the absence gate already consumes: `negative` reads the payload's
/// own `degradations` and refuses to certify an absence beside one, so an answer
/// that resolved nothing and withheld twenty candidates cannot come back as
/// `safe_to_conclude_absent: true`.
fn disclose_withheld_candidates(result: &mut serde_json::Value) {
    let withheld = result["candidates"].as_array().map_or(0, Vec::len);
    if withheld == 0 {
        return;
    }
    let resolved = result["total_upstream"].as_u64().unwrap_or(0);
    let disclosure = serde_json::json!({
        "component": CALL_RESOLUTION_COMPONENT,
        "reason": RECEIVER_NAME_CANDIDATES_REASON,
        "detail": format!(
            "{withheld} same-name candidate(s) were held out of the {resolved} counted here, \
             because a bare-name match does not prove its destination"
        ),
        "remediation":
            "read `candidates` for the rows withheld, and confirm each at its reference site \
             before treating it as a caller",
    });
    match result
        .get_mut("degradations")
        .and_then(serde_json::Value::as_array_mut)
    {
        Some(existing) => existing.push(disclosure),
        None => result["degradations"] = serde_json::Value::Array(vec![disclosure]),
    }
}

/// Project one reference row.
///
/// `include_snippets` adds the caller's bounded body and signature. They are off
/// by default because the row count is now the caller count rather than the file
/// count, and each body runs to [`RETRIEVAL_SNIPPET_MAX_CHARS`]: the case that
/// motivated the row change went from two rows to eleven, so bodies scale with
/// callers where they used to scale with files. The identifying fields an agent
/// navigates by (entity id, name, kind, file, caller line, site lines, relation
/// kinds, resolution) are always present, and `entity_id` still drills straight
/// to the body on demand.
fn reference_row_json(row: ReferenceRow, include_snippets: bool) -> serde_json::Value {
    let mut value = serde_json::json!({
        "entity_id": row.entity_id,
        "name": row.name,
        "kind": row.kind,
        // How the graph classifies this CALLER: `source`, `test`, `vendored`,
        // and so on. Thirty test callers and thirty production callers are
        // different facts about blast radius, and this is the field that
        // separates them without a per-row `get_entity` round-trip. Null for a
        // federated row, which has no local entity to carry one.
        "role": row.role,
        "file_path": row.file_path,
        // `start_line` locates the CALLER's definition; `reference_lines` locates
        // the usages inside it. Both are graph facts and both are 1-based, so an
        // agent never has to count forward from a definition to find a call site.
        "start_line": row.start_line,
        "reference_lines": row.reference_lines,
        "reference_line_count": row.reference_lines.len(),
        // Why `reference_lines` is empty, when it is: `no_evidence_span` (the
        // parser recorded the edge without a position), `span_outside_caller_file`
        // (the spans it recorded name another file), or `federated_xref` (the
        // edge lives in another repository's graph). Null when site lines came
        // back, so an empty list is never an unexplained silence.
        "reference_lines_absent_reason": row
            .reference_lines_absent
            .map(ReferenceLinesAbsent::as_str),
        "relation_kinds": row
            .relation_kinds
            .into_iter()
            .map(relation_kind_name)
            .collect::<Vec<_>>(),
        // How strongly this reference was resolved. Normally `type_resolved`,
        // `import_scoped`, or `name_only`; `name_only` is a same-name match with
        // nothing at the call site proving the destination, so it is a candidate
        // rather than a fact. Absent only for a federated row, whose edge lives
        // in another repository's graph.
        //
        // A row composed over a proven override reports
        // `via_override_of=<base>` instead. It is a reference and it counts, but
        // it is not the same fact as a direct call: the caller provably calls
        // the BASE, and the focal provably overrides that base. A reader
        // separating direct callers from dispatch-reachable ones needs to see
        // which, and one undifferentiated `type_resolved` would hide it.
        "resolution": match (&row.via_override_of, row.resolution) {
            (Some(base), _) => Some(format!("via_override_of={base}")),
            (None, resolution) => resolution.map(|r| r.as_str().to_string()),
        },
        // The base named on its own, so a consumer filters on it without
        // parsing the label.
        "via_override_of": row.via_override_of,
    });
    if include_snippets {
        value["signature"] = serde_json::json!(row.signature);
        value["snippet"] = serde_json::json!(row.snippet);
    }
    value
}

/// Machine-readable codes a spine unavailability can carry, each the name of one
/// computed condition. A reason is prefixed with its code so a consumer reports
/// the condition that actually held instead of collapsing every spine gap into
/// one label.
///
/// [`SPINE_REPO_UNREGISTERED`] and [`SPINE_ROOT_STALE`] were one message until
/// FIR-2353. A repository with no spine registration at all reported "spine root
/// mismatch", which reads as a topology misconfiguration and was quoted back as
/// the cause of a miss that had nothing to do with another repository.
pub const SPINE_REPO_UNREGISTERED: &str = "spine_repo_unregistered";
/// The spine holds a root for this repository, but the live graph has advanced
/// past it: stale cross-repo authority rather than a mismatched one.
pub const SPINE_ROOT_STALE: &str = "spine_root_stale";

/// Split a spine unavailability reason into its code and human detail, or
/// `None` for a reason that carries no recognized code (a binding failure, say,
/// whose message is not one of the conditions computed here).
///
/// Only the known codes are stripped. Treating any colon-prefixed word as a code
/// would promote the first word of an arbitrary error message into a machine
/// label, which is the kind of guess this module exists to avoid.
fn split_spine_unavailable_reason(reason: &str) -> (Option<&'static str>, &str) {
    for code in [SPINE_REPO_UNREGISTERED, SPINE_ROOT_STALE] {
        if let Some(detail) = reason
            .strip_prefix(code)
            .and_then(|rest| rest.strip_prefix(": "))
        {
            return (Some(code), detail);
        }
    }
    (None, reason)
}

/// The cross-repo object for a spine that could not answer, carrying the code of
/// the condition that held beside its human detail.
fn cross_repo_unavailable_json(reason: &str) -> serde_json::Value {
    let (code, detail) = split_spine_unavailable_reason(reason);
    let mut value = serde_json::json!({
        "status": "unavailable",
        "reason": detail,
    });
    if let Some(code) = code {
        value["code"] = serde_json::json!(code);
    }
    value
}

fn daemon_spine_xref(
    authority: FindReferencesAuthority<'_>,
    target_id: &kin_model::EntityId,
) -> std::result::Result<(String, kin_spine::SpineQuery<kin_spine::SpineXrefResponse>), String> {
    let repo_id = normalize_cross_repo_repo_id(Some(authority.repo_id))?;
    let query = match authority.spine {
        Some(spine) => {
            let body = spine.cross_repo_xref_response(&repo_id, target_id);
            match body.authority_root_state(&repo_id, authority.graph_root) {
                kin_spine::AuthorityRootState::Matches => kin_spine::SpineQuery::Found(body),
                // The spine registered this repository at the graph it was
                // initialized from, and graph truth has moved since. Its
                // topology is stale, which bears on references from OTHER
                // repositories and says nothing about the local graph that just
                // answered.
                kin_spine::AuthorityRootState::Stale { registered } => {
                    kin_spine::SpineQuery::Unavailable(format!(
                        "{SPINE_ROOT_STALE}: spine root mismatch for repository {repo_id}: \
                         live/session graph root {} has advanced past the registered spine root \
                         {registered}, so cross-repo authority is stale for other repositories \
                         and says nothing about references inside this one",
                        authority.graph_root
                    ))
                }
                // No registration at all, which is the ordinary state of a
                // single-repo install rather than a mismatch of any kind.
                kin_spine::AuthorityRootState::Unregistered => {
                    kin_spine::SpineQuery::Unavailable(format!(
                        "{SPINE_REPO_UNREGISTERED}: repository {repo_id} has no registered spine \
                         root, so cross-repo authority cannot answer for it; this is the ordinary \
                         single-repo state and says nothing about references inside this repository"
                    ))
                }
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
    let include_snippets = get_optional_bool(args, "include_snippets", false);
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

    let addressed_by_name = get_optional_string_param(args, "entity_id").is_none();
    // Kept for the resolution accounting below. The count that answers "how
    // ambiguous was what I typed" can only be taken against the caller's own
    // string, and the resolver consumes it and hands back a winner.
    let resolution_query = get_optional_string_param(args, "query");
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
            cross_repo_unavailable_json(&reason)
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
                    .map(|row| reference_row_json(row, include_snippets))
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
                cross_repo_unavailable_json(&reason)
            }
            // Local-only (no spine configured): quiet — cross-repo refs don't apply.
            kin_spine::SpineQuery::NotConfigured => serde_json::json!({
                "status": "not_configured",
            }),
        },
    };

    // Same order as the shared CLI collector, entity id included: rows come off
    // a hash map, and several callers can share a file and a name, so without
    // the last key the order of two such rows is whatever the map iterated.
    rows.sort_by(|left, right| {
        left.file_path
            .cmp(&right.file_path)
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.entity_id.cmp(&right.entity_id))
    });

    // Read off the rows before they are projected, where the caller's entity id
    // is still addressable. Every row witnesses its own edge classes, candidate
    // or not: a `name_only` edge is still an edge of that class, and reading
    // only the resolved rows here would report a class absent on a graph
    // holding it.
    let witnessed = answer_witnessed_classes(store, &target, &rows);

    // FIR-1552. A `name_only` row was matched on a bare name with nothing at the
    // reference site proving the destination. Counting one beside a proven
    // caller is how `find_references(HTTPAdapter.send)` on psf/requests answered
    // `total_upstream: 33` for a method `git grep` finds two call sites for,
    // with all 33 rows carrying `resolution: "name_only"` so the per-row marker
    // could not separate the two true rows from the 31 invented ones. The
    // headline counts what resolved; candidates travel in their own array under
    // their own count and are never added to it.
    let (rows, candidate_rows): (Vec<ReferenceRow>, Vec<ReferenceRow>) =
        rows.into_iter().partition(|row| !row.receiver_name_guess);

    // What this answer counted, computed before the rows are projected. One row
    // is one referencing entity, so `referencing_entities` is the row count and
    // `files` is what the pre-FIR-2398 `total_upstream` was reporting.
    let counts = reference_counts(&rows, candidate_rows.len());

    // `entity_id` remains the local drill-through keystone. Federated rows use
    // repo-qualified paths and carry no local entity id.
    let references = rows
        .into_iter()
        .map(|row| reference_row_json(row, include_snippets))
        .collect::<Vec<_>>();
    let candidates = candidate_rows
        .into_iter()
        .map(|row| reference_row_json(row, include_snippets))
        .collect::<Vec<_>>();

    // What the graph can structurally answer over the edge classes this query
    // reads. A reference list is only evidence about the code when the graph
    // demonstrably holds cross-file edges of those classes for the focal's
    // language, and nothing else in this payload reports that.
    //
    // Observed on EVERY answer, empty or not (FIR-2357 item 1). The reasoning
    // that limited it to empty answers is the defect: an answer that returned
    // rows proved the classes those rows came through, and proved nothing about
    // the class a caller it missed would have come through. `normalize_title`
    // came back with one intra-file caller for a symbol five call sites reached,
    // and an unqualified `1` is the answer an agent cannot tell from a complete
    // one. The witnesses the rows already carry keep the healthy path from
    // paying a language scan for a fact it is holding.
    let edge_coverage = crate::edge_coverage::observe_cross_file_reference_coverage_witnessed(
        store,
        &target,
        &relation_kinds,
        &witnessed,
    );

    let mut result = serde_json::json!({
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
        // One referencing entity per unit, which is what `kin refs` prints as
        // "referenced by N entities". It counted distinct FILES until FIR-2398.
        // `counts.counted` names the unit in the payload so no reader has to
        // infer it, and `counts.reference_sites` carries the finer number when
        // every row could be located.
        "total_upstream": references.len(),
        // FIR-2463. The headline may not be readable alone when the same
        // response is holding evidence that contradicts it. `HTTPAdapter.send`
        // on psf/requests answered `total_upstream: 0` while carrying its one
        // real caller, `Session.send` at `sessions.py:784`, in `candidates`: a
        // reader of the number deletes working code and a reader of the array
        // keeps it, off one response. This is the same withheld count
        // `counts.receiver_name_candidates` and
        // `_kin.completeness.counted.withheld_candidates` publish, from the same
        // partition, placed where a reader of the headline cannot miss it rather
        // than as a fourth accounting of it. Emitted at zero as well, because a
        // field that appears only when it is nonzero is one no reader learns to
        // look for.
        "unconfirmed_candidates": candidates.len(),
        "counts": counts,
        "references": references,
        // Same row shape as `references`, held apart because these are not
        // references: each is a same-name match whose destination nothing at the
        // reference site proves. Read them to widen a search by hand; never add
        // them to `total_upstream`.
        "candidates": candidates,
        "cross_repo": cross_repo,
    });
    result[crate::edge_coverage::EDGE_COVERAGE_KEY] = edge_coverage;
    // Whether a caller could have reached this focal through a call site the
    // linker recorded no edge for (FIR-2775). `edge_coverage` above answers
    // whether the graph holds the CLASS of edge this query reads; this answers
    // whether the files that can reach this focal had their own call sites
    // accounted for. A graph can pass the first and fail the second, and that is
    // the state in which an empty reference list came back certified for a
    // function a test calls.
    //
    // Published on every answer rather than only on empty ones, for the reason
    // stated above `edge_coverage`: an answer that returned rows proved nothing
    // about the caller it missed. The gate in `crate::negative` reads it back
    // from here so the verdict and the evidence a reader audits it against are
    // the same object.
    result[crate::caller_arrival::CALLER_ARRIVAL_KEY] =
        crate::caller_arrival::observe_caller_arrival(store, &target).to_json();
    disclose_withheld_candidates(&mut result);

    // Say that a bare name was resolved, and to how many candidates.
    //
    // A repository holding both `Database.resolve` and `LinkGraph.resolve`
    // answered `find_references(query: "resolve")` with one of them and its
    // reference list, and nothing in the response said the other existed. The
    // answer was right, and a rename driven by it on a colliding name is a
    // rename driven by an unannounced guess. `trace_data_flow` already reports
    // this as `focal_resolution`; the shape is copied deliberately so the two
    // tools answer the same question with the same key.
    //
    // The count has to be taken against what the CALLER addressed, not against
    // what the resolver returned. Taking it against the winner's own name made
    // it structurally unable to count on any language that qualifies a method:
    // `find_references(query: "dispatch_request")` on pallets/flask resolved
    // `Flask.dispatch_request` and reported one candidate, while the graph held
    // `View.dispatch_request` and `MethodView.dispatch_request` beside it and
    // `semantic_search` for the same string returned six. An ambiguity counter
    // pinned at one is worse than no counter: a reader who checks it is handed
    // an explicit assurance that there was nothing to disambiguate (FIR-2475).
    let resolution = focal_resolution_for(
        store,
        &target,
        if addressed_by_name {
            resolution_query.as_deref()
        } else {
            None
        },
    )?;
    let same_name_candidates = resolution["same_name_candidates"].as_u64().unwrap_or(1);
    result["focal_resolution"] = resolution;
    if addressed_by_name && same_name_candidates > 1 {
        let entry = serde_json::json!({
            "component": "focal_resolution",
            "reason": "ambiguous_name",
            "detail": format!(
                "{same_name_candidates} entities match the name '{}' that was queried, and this \
                 answer describes the one reported as focal_entity. Address it by entity_id, \
                 from focal_resolution.other_candidates, to pin the choice.",
                resolution_query.as_deref().unwrap_or(target.name.as_str())
            ),
        });
        match result
            .get_mut("degradations")
            .and_then(serde_json::Value::as_array_mut)
        {
            Some(existing) => existing.push(entry),
            None => result["degradations"] = serde_json::Value::Array(vec![entry]),
        }
    }

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
    let mut batch_languages: Vec<kin_model::ids::LanguageId> = Vec::new();

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

        if !batch_languages.contains(&entity.language) {
            batch_languages.push(entity.language);
        }

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

    // Every `has_references: false` row in this batch is read off the same
    // cross-file edge classes a single reference query reads, so the batch
    // publishes the same observation. It covers each language the resolved
    // entities span, and the weakest of them governs.
    result[crate::edge_coverage::EDGE_COVERAGE_KEY] =
        crate::edge_coverage::observe_cross_file_reference_coverage_for_languages(
            store,
            &batch_languages,
            &relation_kinds,
        );

    if authority.is_some() {
        result["cross_repo"] = if let Some(reason) = cross_repo_unavailable {
            let mut unavailable = cross_repo_unavailable_json(&reason);
            unavailable["checked_entities"] = serde_json::json!(cross_repo_checked);
            unavailable["relation_subtype_complete"] = serde_json::json!(false);
            unavailable
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
declared there. `files` narrows WHICH entities are classified, never the evidence they \
are classified on: a declaration its own file calls is live in both modes, so the \
answer means the same thing whether or not you passed `files`. \
Reach for it when you want to find removable code, audit a module for orphaned \
definitions, or check whether a particular file still has live entry points. Because \
reachability is read directly off the graph's relation edges, you get the answer in one \
call without manually cross-referencing every symbol. When you'd rather start from a \
search concept than scan files — \"which of the entities matching X are dead?\" — \
find_dead_code_seeded combines the search and the dead-classification in one step. \
A runtime entry point (a `main`) is never listed: it is called by the runtime rather than \
by any edge, so no inbound edge was ever owed. \
Only a PROVEN inbound edge counts as life. An edge the linker chose by matching a bare \
name across the repository is a candidate, not evidence, so it does not keep an entity \
off this list; that makes the list longer rather than shorter, which is why you must \
read coverage before acting on it. \
The response carries an additive `negative` object whose `safe_to_conclude_absent` flag \
says whether \"nothing dead found\" is authoritative or limited by index freshness — \
check it before concluding everything is reachable. Absence is only as good as the \
graph's reference-edge coverage: read that from `kin graph status` before deleting \
anything this reports.";

pub fn handle_dead_code<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let limit = get_optional_u64(args, "limit", 50) as usize;
    let files = get_optional_string_array(args, "files").unwrap_or_default();
    // One reference-kind list for both scopes. Passing `files` chooses which
    // entities are classified; it must not change what "dead" means, or the two
    // modes answer different questions under one tool name.
    let incoming_kinds = default_reference_kinds();

    if !files.is_empty() {
        let mut dead = Vec::new();

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
                // Same rule as the whole-repo scope below, read off the same
                // edges `find_references` reads. This branch used to exclude
                // within-file callers, which answers "unused OUTSIDE this file"
                // — a different question that the undifferentiated row shape
                // cannot report. On a graph holding no cross-file edge it named
                // every entity in the file, callers and all.
                if kin_core::entry_points::is_conventional_entry_point(&entity) {
                    continue;
                }
                if has_incoming_reference_edge(store, &entity.id, &incoming_kinds)? {
                    continue;
                }
                dead.push(entity);
                if dead.len() >= limit {
                    let json = serde_json::to_string_pretty(&dead).map_err(McpError::Json)?;
                    return Ok(ToolCallResult::text(json));
                }
            }
        }

        let json = serde_json::to_string_pretty(&dead).map_err(McpError::Json)?;
        return Ok(ToolCallResult::text(json));
    }

    // The candidate generator asks only whether an inbound edge crosses a FILE
    // boundary, so an entity whose only caller sits beside it in the same file
    // arrives here as a candidate while `find_references` reports that caller.
    // This tool's own contract is "no incoming relations at all", so it keeps
    // only the candidates that have none, read through the same reference kinds
    // `find_references` defaults to. An entry point is referenced by the runtime
    // rather than by an edge, so it is not a candidate either.
    let mut dead = Vec::new();
    for entity in store.find_dead_code().map_err(McpError::graph)? {
        if dead.len() >= limit {
            break;
        }
        if kin_core::entry_points::is_conventional_entry_point(&entity) {
            continue;
        }
        if has_incoming_reference_edge(store, &entity.id, &incoming_kinds)? {
            continue;
        }
        dead.push(entity);
    }

    let json = serde_json::to_string_pretty(&dead).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

/// Whether any other entity references this one, by the same rule `kin refs`,
/// `bulk_check_references` and `find_references` apply: an inbound edge of a
/// reference kind, from an entity that is not this one.
///
/// A self-recursive function references nothing but itself, so its own edge
/// never makes it reachable.
///
/// Only a proven edge counts. A `name_only` edge was chosen by matching a bare
/// name across the whole repository, so it is a candidate for where a call went
/// rather than evidence that this destination is used, and counting one as life
/// is exactly what made `Session.request` appear to call
/// `RequestsCookieJar.update`. Discarding it lengthens the delete list rather
/// than shortening it, so every surface that prints the list states its own
/// reference-edge coverage beside it.
fn has_incoming_reference_edge<G: GraphStore>(
    store: &G,
    entity_id: &kin_model::EntityId,
    kinds: &[RelationKind],
) -> Result<bool> {
    for relation in store
        .get_all_relations_for_entity(entity_id)
        .map_err(McpError::graph)?
    {
        let Some(source) = relation.src.as_entity() else {
            continue;
        };
        if relation.dst != kin_model::GraphNodeId::Entity(*entity_id)
            || !kinds.contains(&relation.kind)
            || source == *entity_id
            || !RelationResolution::of(&relation).is_proven()
        {
            continue;
        }
        return Ok(true);
    }
    Ok(false)
}

pub const FIND_DEAD_CODE_SEEDED_DESC: &str = "\
Find dead code starting from a search concept, in a single call. Give it a query (a \
concept or partial name) and it searches the graph for the top-N matching entities, \
counts each one's incoming references, and returns them ranked dead-first — each row \
annotated with reference_count, proven_reference_count and a boolean `dead` flag, plus \
name, kind, file, and signature. `dead` is decided on the PROVEN count, the same rule \
dead_code applies, so a row can carry references and still be dead: the difference \
between the two counts is the edges the linker chose by matching a bare name across \
the repository, which prove nothing about this destination. Reach for it when you suspect a feature/area is unused and want to confirm \
which of its declarations are actually orphaned, without first knowing their IDs. Its \
value is that it fuses three steps — semantic_search, then a reference count per match, \
then the dead filter — into one response, so you don't loop find_references over every \
candidate and exhaust your round-trips on a large repo. Use dead_code instead when you \
want a whole-repo or file-scoped sweep rather than a concept-seeded one, and \
bulk_check_references when you already hold the exact set of entity IDs to classify. \
When the seed matches nothing the response carries an additive `negative` object beside \
an `edge_coverage` naming the languages the graph holds. Nothing measures a coverage \
class for them yet, so that absence is never certified: a seed that matched no \
declaration cannot separate a symbol the repository lacks from one the extractor never \
admitted. A language this build wires no language-server adapter for is named as the \
sharper reason where it applies.";

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
        let mut proven_reference_count = 0usize;
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
            if RelationResolution::of(&rel).is_proven() {
                proven_reference_count += 1;
            }
        }
        // Decided on proven edges, the same rule `dead_code` and the CLI scan
        // apply. A raw count here would make one entity dead on one surface and
        // live on another, and the row carries both counts so a reader can see
        // which edges were discarded rather than infer it.
        let dead = proven_reference_count == 0;
        candidates.push(serde_json::json!({
            "id": entity.id.to_string(),
            "name": entity.name,
            "kind": format!("{:?}", entity.kind),
            "file": entity.file_origin.as_ref().map(|p| p.to_string()),
            "signature": (!entity.signature.is_empty()).then_some(entity.signature),
            "reference_count": reference_count,
            "proven_reference_count": proven_reference_count,
            "dead": dead,
        }));
    }

    // Dead first, and `dead` keys on the proven count, so the proven count is
    // what orders the page.
    candidates.sort_by(|a, b| {
        let a_proven = a["proven_reference_count"].as_u64().unwrap_or(0);
        let b_proven = b["proven_reference_count"].as_u64().unwrap_or(0);
        let a_count = a["reference_count"].as_u64().unwrap_or(0);
        let b_count = b["reference_count"].as_u64().unwrap_or(0);
        let a_name = a["name"].as_str().unwrap_or("");
        let b_name = b["name"].as_str().unwrap_or("");
        let a_id = a["id"].as_str().unwrap_or("");
        let b_id = b["id"].as_str().unwrap_or("");
        a_proven
            .cmp(&b_proven)
            .then_with(|| a_count.cmp(&b_count))
            .then_with(|| a_name.cmp(b_name))
            .then_with(|| a_id.cmp(b_id))
    });

    let total_searched = candidates.len();
    let mut result = serde_json::json!({
        "query": trimmed,
        "total_searched": total_searched,
        "candidates": candidates,
    });

    // The seed match is the same name filter over the same entity index
    // `semantic_search` reads, so an empty seed carries the same observation and
    // answers to the same gate (FIR-2430). The scope is the whole graph because
    // the seed filter constrains nothing but the name.
    if total_searched == 0 {
        let scoped = store
            .query_entities(&kin_model::graph::EntityFilter::default())
            .map_err(McpError::graph)?;
        result[crate::edge_coverage::EDGE_COVERAGE_KEY] =
            crate::edge_coverage::observe_absence_scope(
                &crate::edge_coverage::languages_of(&scoped),
                Some(scoped.len()),
            );
    }

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

pub const TRACE_DATA_FLOW_DESC: &str = "\
A CALL-CHAIN WALKER, despite the name: it walks entity-to-entity edges and returns them \
as an ordered list of steps in one call. It does NOT follow a value. If your question is \
\"where does this parameter end up\" or \"what actually reads this field\", start with \
semantic_locate on the behavior at the far end, because the graph has no node for a value \
and this walker will trace control flow past the branch the data went down. \
Walk the call chain rooted at a focal entity and return it as an \
ordered list of steps in one call. Unlike trace_computation (which returns a flat \
neighborhood), this follows Calls/Imports/References edges directionally from the \
focal: direction='calls' walks outward to callees, 'callers' walks inward to callers, \
'both' merges them — recursing to depth N with a per-step fan-out cap, and inlining \
each step's body (in product mode, served from graph source records). Address the focal \
by entity_id or by exact name. Reach for it when you need to follow a path \"what does \
this call, and what do those call?\" and want the chain in traversal order, not a bag of \
neighbors. The unit is the entity, not the value: it walks Calls/Imports/References edges \
between functions, classes and modules, so a parameter or a variable is followed only as \
far as the function that receives it, and never through an assignment, a field or a \
return. It cannot trace a value back to its source. Its value is that the whole walk \
happens substrate-side and comes back as one structured response, so you don't loop \
get_entity_source per hop and exhaust your tool-call budget. Ask for the chain's SHAPE with \
include_body=false (names, kinds, roles, spans, edges, no source) — that is the cheap call, and \
the one to reach for unless you mean to read the code. The response bounds its own size \
(max_response_chars, default 45000, ceiling 60000) and cuts bodies before edges, so it is never \
refused for being too large; any cut is reported in `degradations` with the numbers. A budget \
that cut the chain never empties it: at least one step survives and `elisions.chain` names what \
was kept, what was withheld, and why, so an empty `chain` always means the walk reached nothing. Tune depth and limit_per_step to control \
breadth: the per-step cap keeps the most relevant neighbors (located over file-less, source over \
test, Calls over Imports over References, the expanded node's own file first) rather than \
whatever order the relation table returned, and any node whose fan-out was cut carries \
`fanout_truncated` with `fanout_dropped`, listed together under `clipped_steps`, so you can \
re-query exactly that node with a wider limit_per_step. That cap is where a narrow walk \
loses answers: on a fifteen-callee function a five-wide cap discards ten neighbors, and it \
ranks them by proximity, which no question is an input to. Pass `target` with the symbol \
you are trying to reach and every neighbor from which it is still reachable sorts ahead of \
every neighbor that is not, BEFORE the cap cuts. Without a target, read \
`spine_clipped_steps`: when it is above zero the walk continued beneath a node whose \
fan-out was already cut, so this chain is one route among several and a hop it does not \
contain was never looked for. Do not read such a chain as evidence that X never reaches Y. Every step reports the same keys, \
including `reference_lines` for the 1-based syntax sites that introduced the hop and \
`reference_lines_absent_reason` when the parser recorded no usable site. For a `callee` step \
those lines live in its parent's file; for a `caller` step they live in the step's own \
`entity_file`. A symbol the graph owns no file for carries explicit nulls plus `external: true` \
rather than a shorter record, and one symbol never appears both located and file-less in one response. \
When the chain comes back empty, the additive `negative` object's `safe_to_conclude_absent` \
flag says whether \"no flow from here\" is authoritative or merely \"not indexed yet\", and its \
`subject` scopes the absence to the direction that was walked, so an empty 'callers' result is \
never read as \"this calls nothing\". A focal name the graph holds more than once, and a method \
whose incoming calls may not have been linked, each downgrade that flag rather than certifying \
absence. A focal that resolves to no entity at all carries the same object, naming the \
resolution miss rather than reporting an empty chain. \
Each step carries `resolution` for the edge that reached it: `type_resolved`, \
`import_scoped`, or `name_only`. A chain is only as trustworthy as its weakest hop, so a \
`name_only` step means the flow it claims may not exist at all. \
The walk ends at two boundaries rather than crossing them, and says which on the step that \
stopped it. A symbol this repository does not define is a leaf carrying \
`terminal: \"external_reference\"`: there is no next hop, and walking one turns a shared \
stdlib name into a hub that joins unrelated code into the chain. An edge that merely states \
a type is a leaf carrying `terminal: \"type_annotation\"`, because two entities that annotate \
with the same class share no data; pass include_type_edges=true to walk through those when \
the type is one this repository defines, which is a real flow for a field or a return. \
`terminal_external_steps` and `terminal_annotation_steps` count them, kept apart because only \
the second is recoverable by a parameter. Neither sets `truncated`: a boundary means the chain \
ends there, not that you received less of one that exists. \
Every other node the walk did not continue through also says why, in the same field. \
`terminal: \"leaf\"` means the walk read that node's relations, the graph held no further \
edge of the walked classes, and the coverage classes the answer rests on were observed \
present, so the chain ends there. `terminal: \"bound_reached\"` means the node's relations \
were never read, because the requested depth or a work budget stopped the walk first; raise \
`depth` to open it. `terminal: \"coverage_gap\"` means the read was empty on a language whose \
deciding coverage classes were absent or unmeasured, so the walk cannot tell a missing hop \
from a graph that never held one; `edge_coverage` on the response names the classes and \
`_kin.completeness` carries the same reading. The last two DO set `truncated`, and \
`terminal_leaf_steps`, `terminal_bound_steps` and `terminal_coverage_gap_steps` count them. \
`focal_terminal` says the same thing about the focal, which has no row in `chain`, so an \
empty chain still states why it is empty. Read `truncated: false` as a claim only when no \
step carries one of those two: it now means the walk received every hop the graph could \
offer, rather than only that no cap fired.";

/// One node of a trace walk, carrying the file and directory its fan-out is
/// scored against.
///
/// Relevance is measured against the node being EXPANDED rather than the focal:
/// at depth 3 the focal's directory says nothing about which of a distant node's
/// callees continue the chain.
struct TraceFrontierNode {
    /// Step index of this node; `0` is the focal.
    step: usize,
    id: kin_model::ids::EntityId,
    depth: usize,
    file: Option<String>,
    /// The same file in graph identity form, for checking relation evidence
    /// against the referencing entity without rebuilding it from display text.
    file_origin: Option<kin_model::ids::FilePathId>,
    dir: Option<String>,
}

impl TraceFrontierNode {
    fn at(step: usize, depth: usize, entity: &kin_model::entity::Entity) -> Self {
        Self {
            step,
            id: entity.id,
            depth,
            file: entity.file_origin.as_ref().map(|path| path.0.clone()),
            file_origin: entity.file_origin.clone(),
            dir: kin_ranking::entity_ranking::entity_directory(entity),
        }
    }

    fn rooted(entity: &kin_model::entity::Entity) -> Self {
        Self::at(0, 0, entity)
    }
}

/// One neighbor a node offers, before the per-step cap decides whether it is
/// kept.
struct TraceFanoutCandidate {
    entity: kin_model::entity::Entity,
    role: &'static str,
    relation_kind: RelationKind,
    confidence: f32,
    /// Where the in-repo graph ends, when this candidate sits on the boundary.
    crossing: Option<kin_index::TraceCrossing>,
    /// Call edges into this candidate, and how many were the operand of a
    /// `raise`. Counted rather than folded into a bool, for the reason the CLI
    /// arm's sibling field records: a fold made the answer depend on which edge
    /// happened to arrive first, and on a real store that left the flag false
    /// for every exception class it was written to demote.
    call_edges: usize,
    raise_call_edges: usize,
    /// Classification of the edge this candidate is currently described by.
    /// It moves with `relation_kind` and `confidence` when a stronger edge to
    /// the same neighbor replaces them, so the step reports what the edge it
    /// names actually proved.
    resolution: RelationResolution,
    /// Whether a named target is still reachable from this candidate inside the
    /// requested depth. False for every candidate when no target was named, so
    /// an untargeted walk orders exactly as it did before this existed.
    reaches_target: bool,
    /// Call/reference sites accumulated across every edge that reaches this
    /// step, independent of which edge supplies the displayed relation kind.
    reference_lines: Vec<u32>,
    /// Evidence spans naming a file other than the caller's. This distinguishes
    /// unusable evidence from an edge whose parser recorded no span at all.
    reference_spans_outside_caller_file: usize,
}

impl TraceFanoutCandidate {
    /// Whether this candidate is only ever thrown, never called for its value.
    ///
    /// Only parse-authored call edges vote. An LSP call-hierarchy edge cannot
    /// see a `raise`, so its silence is not a claim that the call was ordinary,
    /// and counting it made this answer `false` for every candidate on any
    /// repository with a language server installed.
    fn is_raise_target(&self) -> bool {
        self.call_edges > 0 && self.raise_call_edges == self.call_edges
    }

    fn normalize_reference_lines(&mut self) {
        self.reference_lines.sort_unstable();
        self.reference_lines.dedup();
    }

    fn reference_lines_absent_reason(&self) -> Option<&'static str> {
        if !self.reference_lines.is_empty() {
            None
        } else if self.reference_spans_outside_caller_file > 0 {
            Some(ReferenceLinesAbsent::SpanOutsideCallerFile.as_str())
        } else {
            Some(ReferenceLinesAbsent::NoEvidenceSpan.as_str())
        }
    }
}

/// Entities from which `target` is reachable, walking the requested direction
/// backwards and bounded by the same depth as the chain.
///
/// The depth bound is the walk's whole depth rather than the remaining depth at
/// each candidate, which makes the set a superset in that direction: preferring
/// a neighbor that might reach the target costs a cap slot, while missing one
/// costs the answer.
fn trace_reach_set_toward<G: GraphStore>(
    store: &G,
    target: &kin_model::entity::Entity,
    direction: &str,
    depth: usize,
    allowed: &std::collections::HashSet<RelationKind>,
) -> Result<std::collections::HashSet<kin_model::ids::EntityId>> {
    let want_callees = direction == "calls" || direction == "both";
    let want_callers = direction == "callers" || direction == "both";
    let mut seen: std::collections::HashSet<kin_model::ids::EntityId> =
        std::collections::HashSet::new();
    seen.insert(target.id);
    let mut frontier = vec![target.id];
    for _ in 0..depth {
        let mut next = Vec::new();
        for node in frontier.drain(..) {
            let relations = store
                .get_all_relations_for_entity(&node)
                .map_err(McpError::graph)?;
            for rel in &relations {
                if !allowed.contains(&rel.kind) {
                    continue;
                }
                let src = rel.src.as_entity();
                let dst = match rel.dst {
                    kin_model::GraphNodeId::Entity(id) => Some(id),
                    _ => None,
                };
                // One step back along whichever sense the forward walk takes: a
                // `calls` chain reaches the target through outgoing edges, so
                // whoever reaches it is on the incoming side.
                let prior = if want_callees && dst == Some(node) {
                    src
                } else if want_callers && src == Some(node) {
                    dst
                } else {
                    None
                };
                let Some(prior) = prior else { continue };
                if prior != node && seen.insert(prior) {
                    next.push(prior);
                }
            }
        }
        if next.is_empty() {
            break;
        }
        frontier = next;
    }
    Ok(seen)
}

/// Apply the per-step cap to one side of a node's ranked fan-out.
///
/// Returns how many candidates were dropped, and how many of those lived
/// outside the expanding node's own file. The keep rule is
/// [`kin_ranking::entity_ranking::fanout_cap_keeps`], the same one the CLI
/// walker calls, because two copies of a cap can only ever disagree in a way
/// that reads as a passing run on both sides.
fn apply_trace_fanout_cap(
    candidates: &mut Vec<TraceFanoutCandidate>,
    node_file: Option<&str>,
    limit: usize,
) -> (usize, usize) {
    let locality: Vec<kin_ranking::entity_ranking::FanoutLocality> = candidates
        .iter()
        .map(|candidate| match candidate.entity.file_origin.as_ref() {
            None => kin_ranking::entity_ranking::FanoutLocality::Unlocated,
            Some(file) if node_file == Some(file.0.as_str()) => {
                kin_ranking::entity_ranking::FanoutLocality::SameFile
            }
            Some(_) => kin_ranking::entity_ranking::FanoutLocality::OtherFile,
        })
        .collect();
    let keep = kin_ranking::entity_ranking::fanout_cap_keeps(&locality, limit);
    if keep.len() == candidates.len() {
        return (0, 0);
    }
    let kept: std::collections::HashSet<usize> = keep.iter().copied().collect();
    let dropped_crossing = (0..candidates.len())
        .filter(|index| {
            !kept.contains(index)
                && locality[*index] == kin_ranking::entity_ranking::FanoutLocality::OtherFile
        })
        .count();
    let dropped = candidates.len() - keep.len();
    let mut taken: Vec<TraceFanoutCandidate> = Vec::with_capacity(keep.len());
    for (index, candidate) in std::mem::take(candidates).into_iter().enumerate() {
        if kept.contains(&index) {
            taken.push(candidate);
        }
    }
    *candidates = taken;
    (dropped, dropped_crossing)
}

/// Order one side of a node's fan-out by relevance, most relevant first, with
/// name and id tiebreaks so the same store returns the same chain every run.
fn sort_trace_candidates(candidates: &mut [TraceFanoutCandidate], node: &TraceFrontierNode) {
    candidates.sort_by(|left, right| {
        // The question first, when there is one. Every proximity term below is
        // a guess about what the caller meant; reachability toward a named
        // target is the one term that knows.
        if left.reaches_target != right.reaches_target {
            return right.reaches_target.cmp(&left.reaches_target);
        }
        let left_score = trace_fanout_score(
            &left.entity,
            left.relation_kind,
            node.file.as_deref(),
            node.dir.as_deref(),
            left.confidence,
            left.is_raise_target(),
        );
        let right_score = trace_fanout_score(
            &right.entity,
            right.relation_kind,
            node.file.as_deref(),
            node.dir.as_deref(),
            right.confidence,
            right.is_raise_target(),
        );
        right_score
            .cmp(&left_score)
            .then_with(|| left.entity.name.cmp(&right.entity.name))
            .then_with(|| left.entity.id.0.cmp(&right.entity.id.0))
    });
}

/// The one record shape every entity in a trace is reported in: the same keys
/// whether the graph owns a location for the symbol or holds it only as a
/// reference target, with explicit nulls and an `external` marker instead of a
/// shorter object.
///
/// This arm serves no bodies — it answers from a generic graph store with no
/// repository authority to project source through — so `body` is null on every
/// record here and `bodies_included` on the response says so.
fn trace_entity_value(
    entity: &kin_model::entity::Entity,
    crossing: Option<&kin_index::TraceCrossing>,
) -> serde_json::Value {
    let (start_line, end_line) = match entity.span.as_ref() {
        Some(span) => {
            let (start, end) = presentation_span_lines(span);
            (Some(start), Some(end))
        }
        None => (None, None),
    };
    serde_json::json!({
        "entity_id": entity.id.to_string(),
        "entity_name": entity.name.clone(),
        "entity_kind": format!("{:?}", entity.kind),
        "entity_role": format!("{:?}", entity.role).to_lowercase(),
        "entity_file": entity.file_origin.as_ref().map(|path| path.to_string()),
        "external": trace_entity_is_external(entity),
        "start_line": start_line,
        "end_line": end_line,
        "signature": (!entity.signature.is_empty()).then(|| entity.signature.clone()),
        "body": serde_json::Value::Null,
        "span_coherence": serde_json::Value::Null,
        "crossing": crossing,
    })
}

/// One chain step: its edge, its depth, its entity record, and its own fan-out
/// truncation, flat so every step carries one key set.
fn trace_step_value(
    step: usize,
    role: &str,
    relation_kind: &str,
    resolution: &str,
    parent_step: usize,
    depth: usize,
    reference_lines: Vec<u32>,
    reference_lines_absent_reason: Option<&str>,
    entity: &kin_model::entity::Entity,
    terminal: Option<TraceTerminal>,
    crossing: Option<&kin_index::TraceCrossing>,
) -> serde_json::Value {
    let mut value = serde_json::json!({
        "step": step,
        "role": role,
        "relation_kind": relation_kind,
        // How the edge INTO this step was resolved. A chain is only as
        // trustworthy as its weakest hop, and a `name_only` hop means the flow
        // may not exist at all.
        "resolution": resolution,
        "parent_step": parent_step,
        "depth": depth,
        // The edge's 1-based source sites, not the entity definition line. A
        // callee's sites live in its parent file; a caller's sites live in its
        // own entity_file. The role plus parent_step identifies which.
        "reference_lines": reference_lines,
        // Explicit null when lines exist, and the same two reason strings
        // `find_references` uses when they do not.
        "reference_lines_absent_reason": reference_lines_absent_reason,
        "fanout_truncated": false,
        "fanout_dropped": 0,
        // Why the walk stopped here, or null for an ordinary step. Written on
        // every step rather than only on a terminal one: this array's keys are
        // uniform by contract, and a sometimes-absent key is the shape that
        // broke a consumer's parser twice.
        "terminal": terminal.map(TraceTerminal::as_str),
    });
    let record = trace_entity_value(entity, crossing);
    if let (Some(target), Some(source)) = (value.as_object_mut(), record.as_object()) {
        for (key, entry) in source {
            target.insert(key.clone(), entry.clone());
        }
    }
    value
}

/// Push one degradation onto the response, creating the array if this is the
/// first.
/// Mark the clips the chain continued beneath, and count them once at the top.
///
/// The distinction is the point of the field. A clip at the end of a branch
/// costs breadth a reader can see missing; a clip the walk went on beneath
/// hands back a route that reads like the route, while the neighbors it dropped
/// were never followed. Only the second makes "this chain does not contain X"
/// mean nothing at all. Mirrors `record_spine_clipping` on the CLI walker, and
/// the two are held together by `both_trace_walkers_report_spine_clipping`.
fn record_trace_spine_clipping(result: &mut serde_json::Value) {
    let parents: std::collections::HashSet<u64> = result["chain"]
        .as_array()
        .map(|chain| {
            chain
                .iter()
                .filter_map(|step| step["parent_step"].as_u64())
                .collect()
        })
        .unwrap_or_default();
    let mut spine_steps = 0usize;
    let mut spine_crossing = 0usize;
    let mut widest: Option<(String, u64, u64)> = None;
    if let Some(clips) = result["clipped_steps"].as_array_mut() {
        for clip in clips.iter_mut() {
            let on_spine = clip["step"]
                .as_u64()
                .is_some_and(|step| parents.contains(&step));
            clip["continued_below"] = serde_json::Value::Bool(on_spine);
            if !on_spine {
                continue;
            }
            spine_steps += 1;
            spine_crossing += clip["dropped_crossing_file"].as_u64().unwrap_or(0) as usize;
            let dropped = clip["dropped_callees"].as_u64().unwrap_or(0)
                + clip["dropped_callers"].as_u64().unwrap_or(0);
            if widest.as_ref().is_none_or(|(_, most, _)| dropped > *most) {
                widest = Some((
                    clip["entity_name"].as_str().unwrap_or_default().to_string(),
                    dropped,
                    clip["limit_per_step"].as_u64().unwrap_or(0),
                ));
            }
        }
    }
    if spine_steps == 0 {
        return;
    }
    result["spine_clipped_steps"] = serde_json::Value::from(spine_steps);
    if spine_crossing > 0 {
        result["spine_dropped_crossing_file"] = serde_json::Value::from(spine_crossing);
    }
    let Some((name, dropped, limit)) = widest else {
        return;
    };
    let crossing = if spine_crossing > 0 {
        format!(", {spine_crossing} of which lived outside the file of the node that offered them")
    } else {
        String::new()
    };
    append_trace_degradation(
        result,
        serde_json::json!({
            "component": "fanout_cap",
            "reason": "spine_clipped",
            "detail": format!(
                "the walk continued beneath {spine_steps} node(s) whose fan-out limit_per_step \
                 {limit} had already cut, dropping neighbors that were never followed{crossing}; \
                 the widest was '{name}', which offered {dropped} more than the cap kept. This \
                 chain is one route among the ones the cap left, so a hop it does not contain \
                 was not looked for and its absence proves nothing"
            ),
            "remediation": format!(
                "name the symbol you are looking for as `target` so the cap ranks toward it, or \
                 re-query '{name}' with limit_per_step above {limit}"
            ),
        }),
    );
}

fn append_trace_degradation(result: &mut serde_json::Value, disclosure: serde_json::Value) {
    match result
        .get_mut("degradations")
        .and_then(serde_json::Value::as_array_mut)
    {
        Some(existing) => existing.push(disclosure),
        None => result["degradations"] = serde_json::Value::Array(vec![disclosure]),
    }
}

/// Narrow this arm's chain to fit, and report how many steps went.
///
/// The rule itself lives in [`crate::budget::narrow_fanout_to_fit`], written
/// once and shared with the CLI arm the daemon route serves, because a budget
/// rule that differed by whether a daemon was up is the two-surface divergence
/// class this codebase keeps paying for. All this wrapper does is read the two
/// keys off a JSON step and install the result.
fn narrow_trace_fanout_to_fit(
    result: &mut serde_json::Value,
    discovered: &[serde_json::Value],
    target: usize,
    measure: fn(&serde_json::Value) -> usize,
) -> usize {
    let step_of = |value: &serde_json::Value| value["step"].as_u64().unwrap_or(0);
    let parent_of = |value: &serde_json::Value| value["parent_step"].as_u64();
    // The question this walk was given, so the branch that answers it is not
    // offered up as "least relevant". Read off the result rather than passed in
    // because this is the same string the response echoes to the caller, and a
    // rule keyed on a second copy is a rule that can drift from the answer.
    let named = result
        .get("target_name")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string);
    let must_keep = |value: &serde_json::Value| {
        named.as_deref().is_some_and(|name| {
            value.get("entity_name").and_then(serde_json::Value::as_str) == Some(name)
        })
    };
    let narrowed = crate::budget::narrow_fanout_to_fit(
        discovered,
        &step_of,
        &parent_of,
        &must_keep,
        &mut |kept: &[serde_json::Value]| {
            result["chain"] = serde_json::Value::Array(kept.to_vec());
            result["total_steps"] = serde_json::Value::from(kept.len());
            measure(result) <= target
        },
    );
    match narrowed {
        Some(kept) => {
            let dropped = discovered.len() - kept.len();
            result["chain"] = serde_json::Value::Array(kept);
            result["total_steps"] = serde_json::Value::from(discovered.len() - dropped);
            dropped
        }
        None => {
            // Nothing narrow enough fits; hand the whole chain back and let the
            // suffix cut run, which always terminates.
            result["chain"] = serde_json::Value::Array(discovered.to_vec());
            result["total_steps"] = serde_json::Value::from(discovered.len());
            0
        }
    }
}

/// Bound this arm's payload, narrowing each node's fan-out before it will
/// amputate depth, and disclosing the cut.
///
/// This arm serves no bodies, so it has none to cut first: what it can shed is
/// steps. It still needs the bound, because 200 steps of identity, span, and
/// signature is a six-figure character count on their own, and a response the
/// client refuses is worse than a short one — the caller gets neither the chain
/// nor a way to ask for less.
///
/// A suffix is what makes the fallback cut safe: the chain is discovery-ordered,
/// so children always sit after their parents and removing the end never orphans
/// a surviving step's `parent_step`.
///
/// ## Why a suffix cut alone produced a wrong answer
///
/// The chain is discovery-ordered, which means breadth-first, which means the
/// tail is the DEEPEST steps. A suffix cut therefore spends the whole budget on
/// the shallow fan-out and amputates the far end of every chain, and the far end
/// is where a trace stops being a list of neighbours and becomes an answer.
///
/// Measured on a converted `psf/requests` by the rc0550 stranger, at the
/// documented cheap settings (`depth: 3`, `limit_per_step: 12`,
/// `include_body: false`): 67 of 117 steps dropped, and the survivors did not
/// include `_urllib3_request_context`, which is one hop past
/// `build_connection_pool_key_attributes` and is the function that folds
/// `verify` into the urllib3 pool key. Read alone the response said `verify`
/// reaches TLS at `cert_verify` and stopped, missing the half that governs
/// connection reuse. The stranger's words: "If I had trusted the Kin arm alone I
/// would have written a wrong answer." The edge was in the graph the whole time.
///
/// So the cut now narrows before it amputates. A node's fan-out was already
/// ordered by relevance ([`kin_ranking::entity_ranking::trace_fanout_score`]),
/// so its LAST child is the one it can most afford to lose; dropping that child
/// and its descendants keeps every remaining `parent_step` valid and costs the
/// chain its least-relevant branch instead of its deepest reach. Only when
/// nothing is left to narrow does the suffix cut run, so a pathological walk
/// still fits rather than being refused.
fn bound_trace_payload(result: &mut serde_json::Value, max_chars: usize) {
    fn measure(value: &serde_json::Value) -> usize {
        serde_json::to_string_pretty(value).map_or(usize::MAX, |json| json.len())
    }
    if measure(result) <= max_chars {
        return;
    }
    let target = max_chars.saturating_sub(TRACE_DISCLOSURE_RESERVE_CHARS);
    let discovered: Vec<serde_json::Value> =
        result["chain"].as_array().cloned().unwrap_or_default();
    let narrowed = narrow_trace_fanout_to_fit(result, &discovered, target, measure);
    let full: Vec<serde_json::Value> = result["chain"].as_array().cloned().unwrap_or_default();
    // Always written, zero included. A count that appears only when it fired
    // is the sometimes-absent key that broke a consumer's parser twice, and a
    // reader cannot tell "narrowed nothing" from "this build cannot narrow".
    result["fanout_narrowed"] = serde_json::Value::from(narrowed);
    if measure(result) <= target {
        result["total_steps"] = serde_json::Value::from(full.len());
        let omitted = discovered.len() - full.len();
        if omitted == 0 {
            return;
        }
        result["steps_omitted"] = serde_json::Value::from(omitted);
        crate::budget::record_elision(result, "chain", full.len(), omitted);
        result["truncated"] = serde_json::Value::Bool(true);
        // `steps_omitted` and not a reason of its own: the reason code names
        // the lever a caller raises, and that lever is `max_response_chars`
        // whichever way the cut was made. WHICH cut it was belongs in the
        // detail and in `fanout_narrowed` beside it.
        let disclosure = serde_json::json!({
            "component": "response_budget",
            "reason": "steps_omitted",
            "detail": format!(
                "the response exceeded its {max_chars}-character budget, so {omitted} steps were \
                 dropped as whole branches, least relevant first, rather than from the end of the \
                 chain; re-query a node with a smaller limit_per_step, or raise \
                 max_response_chars to receive them"
            ),
        });
        append_trace_degradation(result, disclosure);
        return;
    }

    // Bisected rather than popped one step at a time: the same answer, in a
    // handful of serializations instead of one per dropped step.
    //
    // The floor is one step, not zero. A walk that found 200 steps and returns
    // `"chain": []` is indistinguishable from a walk that found none, and the
    // caller has no second field that outranks the empty array. One step plus
    // the elision beside it says both what was reached and what was withheld.
    let floor = usize::from(!full.is_empty());
    let mut kept = floor;
    let mut low = floor;
    let mut high = full.len();
    while low <= high {
        let mid = (low + high) / 2;
        result["chain"] = serde_json::Value::Array(full[..mid].to_vec());
        result["total_steps"] = serde_json::Value::from(mid);
        if measure(result) <= target {
            kept = mid;
            low = mid + 1;
        } else if mid <= floor {
            break;
        } else {
            high = mid - 1;
        }
    }
    result["chain"] = serde_json::Value::Array(full[..kept].to_vec());
    result["total_steps"] = serde_json::Value::from(kept);

    let omitted = full.len() - kept;
    if omitted == 0 {
        return;
    }
    result["steps_omitted"] = serde_json::Value::from(omitted);
    // The same loss in the shape every budgeted list reports it in, so a caller
    // reads one key whether the tool cut a chain or a bucket of tests.
    crate::budget::record_elision(result, "chain", kept, omitted);
    // Dropped steps are edges the caller did not receive, which is what this flag
    // has always meant.
    result["truncated"] = serde_json::Value::Bool(true);
    // A clip naming a step the response no longer carries would send a caller
    // re-querying a node it cannot see.
    if let Some(clips) = result
        .get_mut("clipped_steps")
        .and_then(serde_json::Value::as_array_mut)
    {
        clips.retain(|clip| clip["step"].as_u64().unwrap_or(0) as usize <= kept);
    }
    let disclosure = serde_json::json!({
        "component": "response_budget",
        "reason": "steps_omitted",
        "detail": format!(
            "the response exceeded its {max_chars}-character budget, so {omitted} steps were \
             dropped from the end of the chain; this arm inlines no bodies, so steps are all it \
             can shed"
        ),
        "remediation": "narrow the walk with a smaller depth or limit_per_step, or raise \
                        max_response_chars if the caller's own result limit accepts a larger \
                        payload",
    });
    // Appended rather than assigned: another producer may already have disclosed
    // something about this same answer.
    match result
        .get_mut("degradations")
        .and_then(serde_json::Value::as_array_mut)
    {
        Some(existing) => existing.push(disclosure),
        None => result["degradations"] = serde_json::Value::Array(vec![disclosure]),
    }
}

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
    let include_type_edges = args
        .get("include_type_edges")
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false);
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

    // The kinds a data-flow claim actually rests on, and the ones the coverage
    // observation below is measured against.
    let reference_kinds = [
        RelationKind::Calls,
        RelationKind::Imports,
        RelationKind::References,
    ];
    // `UsesType` is walkable only in the sense that it can REACH a step:
    // admitted so an annotation target is a named leaf rather than a symbol the
    // walk silently never mentions, and so `include_type_edges` has an edge to
    // open. It is deliberately not in `reference_kinds`, because a graph
    // holding no annotation edges says nothing about whether this walk's
    // answer was whole.
    let allowed: std::collections::HashSet<RelationKind> = reference_kinds
        .iter()
        .copied()
        .chain(std::iter::once(RelationKind::UsesType))
        .collect();

    let want_callees = matches!(direction, "calls" | "both");
    let want_callers = matches!(direction, "callers" | "both");

    let mut chain: Vec<serde_json::Value> = Vec::new();
    let mut visited: std::collections::HashSet<kin_model::ids::EntityId> =
        std::collections::HashSet::new();
    visited.insert(focal_entity.id);
    // Which step already stands for a symbol NAME, so an import alias and the
    // function it aliases never arrive as two identities for one symbol. Seeded
    // with the focal only when the graph owns a file for it.
    let mut name_index: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    if focal_entity.file_origin.is_some() {
        name_index.insert(focal_entity.name.clone(), 0);
    }
    let mut external_identities_merged = 0usize;
    let mut clipped_steps: Vec<serde_json::Value> = Vec::new();
    let mut truncated = false;
    // What each node's expansion produced, keyed by step index (`0` is the
    // focal), and each step's language. Neither survives into the chain: a step
    // with no children looks the same whether its relations were read and held
    // nothing or were never read at all, and a coverage verdict borrowed from
    // the focal would cross an extraction boundary the chain crossed.
    let mut expansion: std::collections::HashMap<usize, TraceExpansion> =
        std::collections::HashMap::new();
    let mut step_language: std::collections::HashMap<usize, kin_model::ids::LanguageId> =
        std::collections::HashMap::new();

    // The question, resolved once and consulted per candidate. A target that
    // resolves to nothing is disclosed rather than fatal: the chain the caller
    // asked for is still the chain.
    let mut target_name: Option<String> = None;
    let mut target_unresolved: Option<String> = None;
    let mut reach_set: Option<std::collections::HashSet<kin_model::ids::EntityId>> = None;
    if let Some(target) = get_optional_string_param(args, "target")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
    {
        let resolved = match uuid::Uuid::parse_str(&target).ok() {
            Some(uuid) => store
                .get_entity(&kin_model::ids::EntityId(uuid))
                .map_err(McpError::graph)?,
            None => select_best_reference_target(store, &target).map_err(McpError::graph)?,
        };
        match resolved {
            Some(entity) => {
                reach_set = Some(trace_reach_set_toward(
                    store, &entity, direction, depth, &allowed,
                )?);
                target_name = Some(entity.name.clone());
            }
            None => target_unresolved = Some(target),
        }
    }

    // Frontier: (step, entity, depth, file, dir) — the expanded node's own
    // location travels with it, because relevance is scored against the node
    // being expanded rather than against the focal.
    let mut frontier: Vec<TraceFrontierNode> = vec![TraceFrontierNode::rooted(&focal_entity)];

    while !frontier.is_empty() {
        let mut next_frontier: Vec<TraceFrontierNode> = Vec::new();
        for node in frontier.drain(..) {
            if node.depth >= depth {
                continue;
            }
            let relations = store
                .get_all_relations_for_entity(&node.id)
                .map_err(McpError::graph)?;
            // Every neighbor is collected before any is kept: a per-step cap is
            // a choice between candidates, and a loop that admits as it reads
            // keeps whatever the relation table listed first.
            let mut candidates: Vec<TraceFanoutCandidate> = Vec::new();
            let mut candidate_index: std::collections::HashMap<
                (kin_model::ids::EntityId, &'static str),
                usize,
            > = std::collections::HashMap::new();
            // Counted before the visited filter and before the per-step cap: a
            // terminal answers whether the GRAPH held a next hop, not whether
            // this response admitted one.
            let mut admissible_neighbors = 0usize;
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
                    && src_entity == Some(node.id)
                    && dst_entity.is_some()
                    && dst_entity != Some(node.id)
                {
                    (dst_entity.unwrap(), "callee")
                } else if want_callers
                    && dst_entity == Some(node.id)
                    && src_entity.is_some()
                    && src_entity != Some(node.id)
                {
                    (src_entity.unwrap(), "caller")
                } else {
                    continue;
                };

                admissible_neighbors += 1;

                // Already in the chain by another edge: not a candidate, and not
                // a drop either.
                if visited.contains(&next_id) {
                    continue;
                }

                let candidate_at = match candidate_index.get(&(next_id, role)) {
                    Some(&existing) => {
                        let candidate: &mut TraceFanoutCandidate = &mut candidates[existing];
                        let stronger = trace_relation_rank(rel.kind)
                            > trace_relation_rank(candidate.relation_kind)
                            || (rel.kind == candidate.relation_kind
                                && rel.confidence > candidate.confidence);
                        if stronger {
                            candidate.relation_kind = rel.kind;
                            candidate.confidence = rel.confidence;
                            candidate.resolution = RelationResolution::of(rel);
                        }
                        // Accumulated across every edge, not moved with the
                        // strongest one; mirrors the CLI arm exactly.
                        candidate.call_edges +=
                            usize::from(kin_index::is_raise_classifiable_call_edge(rel));
                        candidate.raise_call_edges +=
                            usize::from(kin_index::is_raise_target_edge(rel));
                        if candidate
                            .crossing
                            .as_ref()
                            .is_none_or(|crossing| crossing.specifier.is_none())
                        {
                            if let Some(named) =
                                kin_index::trace_crossing_for(&candidate.entity, Some(rel))
                                    .filter(|crossing| crossing.specifier.is_some())
                            {
                                candidate.crossing = Some(named);
                            }
                        }
                        existing
                    }
                    None => {
                        let Some(entity) = store.get_entity(&next_id).map_err(McpError::graph)?
                        else {
                            continue;
                        };
                        candidate_index.insert((next_id, role), candidates.len());
                        let crossing = kin_index::trace_crossing_for(&entity, Some(rel));
                        let reaches_target =
                            reach_set.as_ref().is_some_and(|set| set.contains(&next_id));
                        candidates.push(TraceFanoutCandidate {
                            reaches_target,
                            call_edges: usize::from(kin_index::is_raise_classifiable_call_edge(
                                rel,
                            )),
                            raise_call_edges: usize::from(kin_index::is_raise_target_edge(rel)),
                            entity,
                            role,
                            relation_kind: rel.kind,
                            confidence: rel.confidence,
                            resolution: RelationResolution::of(rel),
                            crossing,
                            reference_lines: Vec::new(),
                            reference_spans_outside_caller_file: 0,
                        });
                        candidates.len() - 1
                    }
                };

                // The source site belongs to the referencing entity. An
                // outgoing step's caller is the parent node; an incoming
                // step's caller is the candidate itself. Keep every edge's
                // site even when another edge ranks stronger for display.
                //
                // Every REFERENCE edge, that is. `allowed` also carries
                // `UsesType` so an annotation target is a named leaf, and the
                // graph holds one beside the `Calls` edge for the same pair.
                // Its span is the annotation's target, which is the callee's
                // own definition rather than a site where the caller calls it,
                // so accumulating it published `[def_line, call_line]` on every
                // row with nothing to tell them apart. `reference_kinds` is
                // what the reference surface reads, so gating on it keeps the
                // two answers the same.
                if reference_kinds.contains(&rel.kind) {
                    let caller_file = if role == "callee" {
                        node.file_origin.as_ref()
                    } else {
                        candidates[candidate_at].entity.file_origin.as_ref()
                    };
                    let tally = relation_reference_lines(rel, caller_file);
                    candidates[candidate_at].reference_lines.extend(tally.lines);
                    candidates[candidate_at].reference_spans_outside_caller_file +=
                        tally.outside_caller_file;
                }
            }

            // This node's relations were read to the end, so what the graph held
            // for it is now a fact rather than a guess.
            expansion.insert(
                node.step,
                if admissible_neighbors > 0 {
                    TraceExpansion::HadEdges
                } else {
                    TraceExpansion::NoEdges
                },
            );

            // Independent per-direction budgets so `direction=both` doesn't
            // starve one side when relations are emitted in either order.
            let (mut callees, mut callers): (Vec<TraceFanoutCandidate>, Vec<TraceFanoutCandidate>) =
                candidates.into_iter().partition(|c| c.role == "callee");
            sort_trace_candidates(&mut callees, &node);
            sort_trace_candidates(&mut callers, &node);
            let (dropped_callees, crossing_callees) =
                apply_trace_fanout_cap(&mut callees, node.file.as_deref(), limit_per_step);
            let (dropped_callers, crossing_callers) =
                apply_trace_fanout_cap(&mut callers, node.file.as_deref(), limit_per_step);

            if dropped_callees + dropped_callers > 0 {
                truncated = true;
                let dropped = dropped_callees + dropped_callers;
                let (entity_id, entity_name) = if node.step == 0 {
                    (focal_entity.id.to_string(), focal_entity.name.clone())
                } else {
                    let step = &mut chain[node.step - 1];
                    step["fanout_truncated"] = serde_json::Value::Bool(true);
                    let already = step["fanout_dropped"].as_u64().unwrap_or(0);
                    step["fanout_dropped"] =
                        serde_json::Value::from(already.saturating_add(dropped as u64));
                    (
                        step["entity_id"].as_str().unwrap_or_default().to_string(),
                        step["entity_name"].as_str().unwrap_or_default().to_string(),
                    )
                };
                let mut clip = serde_json::json!({
                    "step": node.step,
                    "entity_id": entity_id,
                    "entity_name": entity_name,
                    "dropped_callees": dropped_callees,
                    "dropped_callers": dropped_callers,
                    "continued_below": false,
                    "limit_per_step": limit_per_step,
                });
                let crossing = crossing_callees + crossing_callers;
                if crossing > 0 {
                    clip["dropped_crossing_file"] = serde_json::Value::from(crossing);
                }
                clipped_steps.push(clip);
            }

            for mut candidate in callees.into_iter().chain(callers) {
                if chain.len() >= MAX_TOTAL_STEPS {
                    truncated = true;
                    break;
                }
                let candidate_external = trace_entity_is_external(&candidate.entity);
                if let Some(&existing) = name_index.get(candidate.entity.name.as_str()) {
                    let existing_external =
                        existing > 0 && chain[existing - 1]["external"].as_bool().unwrap_or(false);
                    if candidate_external {
                        visited.insert(candidate.entity.id);
                        external_identities_merged += 1;
                        continue;
                    }
                    if existing_external {
                        // Fill the placeholder in with the record the graph owns,
                        // rather than admitting one symbol under two identities.
                        let promoted_depth =
                            chain[existing - 1]["depth"].as_u64().unwrap_or(0) as usize;
                        // A promoted record is located by construction, so the
                        // external boundary no longer applies to it; the edge
                        // that reached it is unchanged, so the annotation one
                        // still does.
                        let promoted_terminal = trace_step_terminal(
                            &candidate.entity,
                            candidate.relation_kind,
                            include_type_edges,
                        );
                        let promoted = trace_step_value(
                            existing,
                            chain[existing - 1]["role"].as_str().unwrap_or("callee"),
                            chain[existing - 1]["relation_kind"]
                                .as_str()
                                .unwrap_or("Calls"),
                            chain[existing - 1]["resolution"]
                                .as_str()
                                .unwrap_or_else(|| RelationResolution::NameOnly.as_str()),
                            chain[existing - 1]["parent_step"].as_u64().unwrap_or(0) as usize,
                            promoted_depth,
                            chain[existing - 1]["reference_lines"]
                                .as_array()
                                .cloned()
                                .unwrap_or_default()
                                .into_iter()
                                .filter_map(|line| {
                                    line.as_u64().and_then(|line| u32::try_from(line).ok())
                                })
                                .collect(),
                            chain[existing - 1]["reference_lines_absent_reason"].as_str(),
                            &candidate.entity,
                            promoted_terminal,
                            candidate.crossing.as_ref(),
                        );
                        chain[existing - 1] = promoted;
                        // The record that replaced the placeholder brings its
                        // own language, and the coverage verdict this step is
                        // read against has to follow it.
                        step_language.insert(existing, candidate.entity.language);
                        visited.insert(candidate.entity.id);
                        external_identities_merged += 1;
                        if promoted_terminal.is_none() && promoted_depth < depth {
                            next_frontier.push(TraceFrontierNode::at(
                                existing,
                                promoted_depth,
                                &candidate.entity,
                            ));
                        }
                        continue;
                    }
                }
                if !visited.insert(candidate.entity.id) {
                    continue;
                }
                let next_depth = node.depth + 1;
                let step_index = chain.len() + 1;
                name_index
                    .entry(candidate.entity.name.clone())
                    .or_insert(step_index);
                // Decided before the step is pushed, because it decides both
                // what the step says and whether the node is expanded at all.
                let terminal = trace_step_terminal(
                    &candidate.entity,
                    candidate.relation_kind,
                    include_type_edges,
                );
                candidate.normalize_reference_lines();
                let reference_lines_absent_reason = candidate.reference_lines_absent_reason();
                chain.push(trace_step_value(
                    step_index,
                    candidate.role,
                    &format!("{:?}", candidate.relation_kind),
                    candidate.resolution.as_str(),
                    node.step,
                    next_depth,
                    candidate.reference_lines,
                    reference_lines_absent_reason,
                    &candidate.entity,
                    terminal,
                    candidate.crossing.as_ref(),
                ));
                step_language.insert(step_index, candidate.entity.language);
                if terminal.is_none() && next_depth < depth {
                    next_frontier.push(TraceFrontierNode::at(
                        step_index,
                        next_depth,
                        &candidate.entity,
                    ));
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
    // The walk expands exactly the reference kinds above, so a chain is only
    // evidence about the focal when the graph holds cross-file edges of those
    // kinds for its language. Observed on every walk rather than only on an
    // empty one (FIR-2357 item 1): a walk that returned three steps over a graph
    // holding no cross-file calls has stayed inside one file, and reporting that
    // as an unqualified chain is the same quiet partial the reference tool had.
    //
    // No witness is passed here, unlike `find_references`. A chain step records
    // the entity reached, not which class of edge reached it, and a witness
    // asserted for the wrong class is the one thing this observation must never
    // accept.
    let edge_coverage = crate::edge_coverage::observe_cross_file_reference_coverage(
        store,
        &focal_entity,
        &reference_kinds,
    );

    // Give every node the walk did not continue through a reason, in the same
    // vocabulary and by the same rule the daemon arm uses. A step with no
    // children arrived here indistinguishable from three different endings: the
    // code ends, a bound stopped the walk, or the graph could not have held the
    // next hop. Only the first is a complete answer.
    let mut certain: std::collections::HashMap<kin_model::ids::LanguageId, bool> =
        std::collections::HashMap::new();
    certain.insert(
        focal_entity.language,
        crate::edge_coverage::deciding_classes_observed_present(&edge_coverage),
    );
    let focal_terminal = trace_walk_terminal(
        expansion
            .get(&0)
            .copied()
            .unwrap_or(TraceExpansion::BoundStopped),
        certain
            .get(&focal_entity.language)
            .copied()
            .unwrap_or(false),
    );
    for step in chain.iter_mut() {
        // An external or annotation boundary was decided at the edge that
        // reached the node and is the stronger statement: there is nothing on
        // the other side to walk.
        if step["terminal"].as_str().is_some() {
            continue;
        }
        let step_number = step["step"].as_u64().unwrap_or(0) as usize;
        let outcome = expansion
            .get(&step_number)
            .copied()
            .unwrap_or(TraceExpansion::BoundStopped);
        // Only an empty read consults coverage, so a healthy chain pays one
        // language scan for the focal and none for its steps.
        let coverage_certain = if matches!(outcome, TraceExpansion::NoEdges) {
            let language = step_language
                .get(&step_number)
                .copied()
                .unwrap_or(focal_entity.language);
            match certain.get(&language) {
                Some(&known) => known,
                None => {
                    let observation =
                        crate::edge_coverage::observe_cross_file_reference_coverage_for_languages(
                            store,
                            &[language],
                            &reference_kinds,
                        );
                    let known =
                        crate::edge_coverage::deciding_classes_observed_present(&observation);
                    certain.insert(language, known);
                    known
                }
            }
        } else {
            false
        };
        step["terminal"] = match trace_walk_terminal(outcome, coverage_certain) {
            Some(terminal) => serde_json::Value::from(terminal.as_str()),
            None => serde_json::Value::Null,
        };
    }
    // A bound the caller can raise and a graph that could not have held the next
    // hop both mean the chain may be shorter than the code, which is what this
    // flag has always meant. Never cleared here: the walk's own ceilings set it
    // first and this pass must not overturn them.
    if focal_terminal.is_some_and(TraceTerminal::truncates)
        || chain.iter().any(|step| {
            step["terminal"]
                .as_str()
                .and_then(trace_terminal_named)
                .is_some_and(TraceTerminal::truncates)
        })
    {
        truncated = true;
    }

    let mut result = serde_json::json!({
        "focal_id": focal_entity.id.to_string(),
        "focal_name": focal_entity.name.clone(),
        "focal_kind": format!("{:?}", focal_entity.kind),
        "focal_file": focal_entity.file_origin.as_ref().map(|p| p.to_string()),
        "focal_entity": trace_entity_value(&focal_entity, None),
        "direction": direction,
        "depth": depth,
        "limit_per_step": limit_per_step,
        // This arm reads no bodies at all: it answers from a generic graph store,
        // with no repository authority to project source through. Stating it
        // keeps `include_body` from reading as honoured here.
        "bodies_included": false,
        // Echoed because it is the parameter a caller reading a
        // `type_annotation` terminal has to change, and a caller cannot
        // otherwise tell a walk that had no type edges from one that refused
        // them.
        "include_type_edges": include_type_edges,
        "chain": chain,
        "total_steps": total_steps,
        "truncated": truncated,
        "focal_resolution": {
            "addressed_by": if focal_id.is_some() { "entity_id" } else { "name" },
            "same_name_candidates": same_name_candidates,
        },
    });
    result[crate::edge_coverage::EDGE_COVERAGE_KEY] = edge_coverage;
    if let Some(name) = target_name {
        result["target_name"] = serde_json::Value::from(name);
    }
    if let Some(target) = target_unresolved {
        append_trace_degradation(
            &mut result,
            serde_json::json!({
                "component": "target_reachability",
                "reason": "target_not_resolved",
                "detail": format!(
                    "no entity matches target '{target}', so this walk ranked its fan-out by \
                     relevance alone and the question had no vote in what the cap kept"
                ),
                "remediation": "check the target's spelling, or find it first with semantic_locate",
            }),
        );
    }
    if !clipped_steps.is_empty() {
        result["clipped_steps"] = serde_json::Value::Array(clipped_steps);
    }
    if external_identities_merged > 0 {
        result["external_identities_merged"] = serde_json::Value::from(external_identities_merged);
    }
    let max_response_chars = trace_response_budget(
        args.get("max_response_chars")
            .and_then(serde_json::Value::as_u64)
            .map(|value| value as usize),
    );
    result["max_response_chars"] = serde_json::Value::from(max_response_chars);
    // Set before the bound so it is on every response, not only the cut ones.
    // The bounder returns at its first line when the payload already fits, and
    // a key that appears only after a cut cannot be read as a zero.
    result["fanout_narrowed"] = serde_json::Value::from(0);
    bound_trace_payload(&mut result, max_response_chars);
    // After the bound, because a clip is on the spine only if the walk beneath
    // it is in the response the caller receives.
    record_trace_spine_clipping(&mut result);
    // Counted from the chain rather than during the walk, so the numbers
    // describe the steps this payload carries after `bound_trace_payload` has
    // dropped whatever it drops. Kept apart rather than summed because only the
    // annotation half is recoverable: `include_type_edges` opens those leaves
    // and opens none of the external ones. Neither sets `truncated`, since a
    // boundary means the chain ends there rather than that the caller received
    // less of one that exists.
    let terminal_count = |class: TraceTerminal| {
        result["chain"]
            .as_array()
            .map(|chain| {
                chain
                    .iter()
                    .filter(|step| step["terminal"].as_str() == Some(class.as_str()))
                    .count()
            })
            .unwrap_or(0)
    };
    // Every count is taken before the first write, because the counter reads
    // `result` and a write would end its borrow of it.
    //
    // The three walk terminals are counted the same way and kept apart for the
    // same reason the two boundary ones are: a caller raises `depth` for a
    // bound, repairs enrichment for a gap, and believes a leaf.
    let counted: Vec<(&str, usize)> = [
        ("terminal_external_steps", TraceTerminal::ExternalReference),
        ("terminal_annotation_steps", TraceTerminal::TypeAnnotation),
        ("terminal_leaf_steps", TraceTerminal::Leaf),
        ("terminal_bound_steps", TraceTerminal::BoundReached),
        ("terminal_coverage_gap_steps", TraceTerminal::CoverageGap),
    ]
    .into_iter()
    .map(|(key, class)| (key, terminal_count(class)))
    .collect();
    for (key, total) in counted {
        if total > 0 {
            result[key] = serde_json::Value::from(total);
        }
    }
    // The chain carries no row for the focal, so an empty chain has nowhere
    // else to say why it is empty, and an empty chain is the answer whose trust
    // depends on that most.
    if let Some(focal_terminal) = focal_terminal {
        result["focal_terminal"] = serde_json::Value::from(focal_terminal.as_str());
    }

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
/// Rejected candidates a resolution will name before it stops listing them.
///
/// The count beside them is exact whatever this is, so a caller reading a short
/// list still knows how many it is choosing between. The cap exists because a
/// short query is a substring: `find_references(query: "get")` matches every
/// getter in the repository, and a resolution note is not the place to
/// enumerate them.
const RESOLUTION_CANDIDATES_LISTED_MAX: usize = 10;

/// How many entities the caller's QUERY could have meant, and which ones the
/// resolver did not pick.
///
/// This mirrors what `kin_ranking::select_best_entity` filters on, because the
/// number is only honest if it counts the set that resolver actually chose
/// among: the same `name_pattern` match, which is a case-insensitive substring
/// unless the caller wrote a wildcard, and the same exclusion of external
/// reference targets the repository does not define. A count taken with a
/// different rule than the choice it describes is a different question wearing
/// the same field name, which is the whole of FIR-2475.
fn query_resolution_candidates<G: GraphStore>(
    store: &G,
    query: &str,
    chosen: &kin_model::ids::EntityId,
) -> Result<(usize, Vec<serde_json::Value>)> {
    let filter = EntityFilter {
        name_pattern: Some(query.to_string()),
        ..Default::default()
    };
    let mut matched: Vec<_> = store
        .query_entities(&filter)
        .map_err(McpError::graph)?
        .into_iter()
        .filter(|entity| {
            entity.file_origin.is_some() || entity.role != kin_model::entity::EntityRole::External
        })
        .collect();
    // A total order, so two runs of one store list the same candidates. The rows
    // come off a query whose order is the store's, and several entities can
    // share a file and a name.
    matched.sort_by(|left, right| {
        left.file_origin
            .as_ref()
            .map(|path| path.0.as_str())
            .cmp(&right.file_origin.as_ref().map(|path| path.0.as_str()))
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.id.cmp(&right.id))
    });
    // A resolved focal proves at least one match, so a zero here would be the
    // count disagreeing with the answer it travels with rather than a fact.
    let count = matched.len().max(1);
    let others = matched
        .into_iter()
        .filter(|entity| entity.id != *chosen)
        .take(RESOLUTION_CANDIDATES_LISTED_MAX)
        .map(|entity| {
            serde_json::json!({
                "id": entity.id,
                "name": entity.name,
                "kind": entity.kind,
                "file_path": entity.file_origin.as_ref().map(|path| path.to_string()),
            })
        })
        .collect();
    Ok((count, others))
}

/// The `focal_resolution` block, for every surface that resolves a focal and
/// then answers about it.
///
/// Public and shared because `kin_mcp::negative`'s `focal_resolution_gap`
/// REFUSES any `find_references` absence whose payload does not carry a
/// `same_name_candidates`, and a missing block is the refusing arm rather than
/// an exemption. So a CLI surface routed through that gate has to publish this
/// block, and the only safe way for it to do that is to call the producer the
/// MCP handler calls. A second copy in `kin-cli` would let the two surfaces
/// count ambiguity by different rules and disagree about one store, which is
/// the drift FIR-2524 exists to end and would arrive by the door its own fix
/// left open. Same reasoning that made `IMPACT_REFERENCE_KINDS` public.
///
/// `query` is the name the CALLER addressed, and `None` means the focal was
/// pinned by id. Which one it is decides the counting rule, and FIR-2475 is what
/// happens when the count is taken against the winner's own name instead.
pub fn focal_resolution_for<G: GraphStore>(
    store: &G,
    target: &kin_model::Entity,
    query: Option<&str>,
) -> Result<serde_json::Value> {
    let (same_name_candidates, other_candidates, matched_by) = match query {
        Some(query) => {
            let (count, others) = query_resolution_candidates(store, query, &target.id)?;
            (count, others, "query_name_pattern")
        }
        // A pinned entity_id resolved nothing by name, so there is no query
        // ambiguity to report. What still applies is the twin question: a name
        // the graph holds twice (two cfg arms admitted as distinct entities)
        // means an edge the extractor could not attribute sits on neither.
        None => {
            let count = same_name_entity_count(store, &target.name)?;
            (count, Vec::new(), "exact_focal_name")
        }
    };
    Ok(serde_json::json!({
        "addressed_by": if query.is_some() { "name" } else { "entity_id" },
        "same_name_candidates": same_name_candidates,
        // Which rule produced the number. Without it the same field means two
        // different things depending on how the call was addressed, and a
        // reader cannot tell which answer they are holding.
        "matched": matched_by,
        // A count alone says the tool guessed and leaves no way to ask again.
        // These are addressable by id, bounded, and never include the winner.
        "other_candidates": other_candidates,
    }))
}

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
read as \"no dependencies\". A walk that expanded no edge also carries `edge_coverage` \
naming the focal's language. Nothing measures a coverage class for it yet, so an empty \
walk is never certified as isolation: an entity nothing reaches and one whose incoming \
edges were never linked read the same here. A build that wires no language-server \
adapter for that language is named as the sharper reason where it applies. A focal that is not in the graph is reported as that gap \
rather than as an isolated entity. Every edge also carries `resolution` \
(`type_resolved`, `import_scoped`, `name_only`) saying how strongly its destination was \
proven; a `name_only` edge was matched by bare name and is a candidate, not structure you \
can rely on.";

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
                        // A `name_only` edge was matched by name alone and is a
                        // candidate, not a fact. Neighborhoods are read as
                        // structure, so an unmarked guess spreads furthest here.
                        "resolution": RelationResolution::of(&rel).as_str(),
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

    let mut result = serde_json::json!({
        "focal_id": entity_id.to_string(),
        "direction": direction,
        "depth": depth,
        "entity_count": total_entities,
        "relation_count": total_relations,
        "truncated": truncated || total_entities > limit,
        "entities": entities,
        "relations": relations,
    });

    // A walk that expanded no edge is claiming the focal has no neighbors on the
    // side that was walked, and for an incoming walk that is the same claim
    // `find_references` makes. It answers to the same gate (FIR-2430), scoped to
    // the focal's own language. A focal that did not resolve names no language,
    // and the observation says so rather than guessing one, so the
    // focal-not-in-graph gap stays the limiting factor a reader is handed.
    if total_relations == 0 {
        let focal_languages = store
            .get_entity(&entity_id)
            .map_err(McpError::graph)?
            .map(|entity| vec![entity.language])
            .unwrap_or_default();
        result[crate::edge_coverage::EDGE_COVERAGE_KEY] =
            crate::edge_coverage::observe_absence_scope(&focal_languages, None);
    }

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
    /// The live sample could not be taken inside its bounded attempts, so every
    /// counter below replays the last settled observation of this same selected
    /// graph. `stale` says when that instant was and what blocked the live one.
    ///
    /// This exists because a status surface that answers only on a quiet system
    /// answers exactly when nobody needs it (FIR-2135). A reading labelled as of
    /// an earlier instant is an answer a caller can act on; a bare instruction
    /// to retry is not.
    LastSettledSelectedGraph,
}

/// What stopped the live sample, stated as the state that blocked it rather
/// than as advice the caller has no way to act on.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GraphStatusStaleReason {
    /// Embedding-work serialization stayed held across every attempt, which is
    /// what a store mid-embed looks like from the status path.
    EmbeddingCoverageChanging,
    /// The selected graph's authority epoch moved during every attempt, which is
    /// what a store under continuous reconcile churn looks like.
    SelectedGraphChanging,
}

/// The disclosure that makes a replayed reading honest.
///
/// Present exactly when `sampling` is [`GraphStatusSampling::LastSettledSelectedGraph`],
/// which [`GraphStatusReport::validate`] enforces in both directions: a stale
/// report that forgot its disclosure and a fresh report that carries one are
/// both rejected, so neither can ship as a silent relabelling of the other.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GraphStatusStaleness {
    /// The state that blocked the live sample.
    pub reason: GraphStatusStaleReason,
    /// How long before this response the replayed observation was taken.
    pub settled_age_ms: u64,
    /// The graph-authority epoch current when the live sample was abandoned,
    /// when one could be read at all. `authority_epoch` above is the replayed
    /// reading's own epoch, so a difference between the two is the change this
    /// report is disclosing rather than hiding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_authority_epoch: Option<u64>,
    /// How many bounded live attempts were spent before the replay.
    pub live_attempts: u32,
    /// One sentence naming what was tried, what blocked it, and what would
    /// change the outcome.
    pub note: String,
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
    /// Entities durable repository authority carried when the daemon last
    /// levelled this graph with authority (FIR-2421).
    ///
    /// Beside `entity_count` because that is where it is misread. The live
    /// count above is what the daemon can answer from right now, and a daemon
    /// admits host content into that graph continuously without recording any
    /// of it, so a populated `entity_count` says nothing about whether the work
    /// survives this process. The difference between the two is what a daemon
    /// exit would lose; `_kin.durability` states it as a sentence. Absent, not
    /// zero, when the daemon has never levelled with durable authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub durable_entity_count: Option<u64>,
    pub relation_count: usize,
    pub embedding_source: GraphStatusEmbeddingSource,
    pub embeddings_indexed: usize,
    pub embeddings_pending: usize,
    pub embeddings_total: usize,
    /// Vectors resident in the selected graph's index, INCLUDING any the graph
    /// no longer admits. `embeddings_total` is the size of the retrieval
    /// universe graph truth admits right now, so the two differ exactly by the
    /// index's accumulated staleness. Absent when this build or this graph has
    /// no vector index to measure, which is not the same as zero.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding_index_keys: Option<usize>,
    /// Indexed vectors graph truth does not admit: superseded entity revisions
    /// and retired entities whose vectors the sidecar carried forward. This is
    /// the counter that makes staleness legible beside a complete coverage
    /// figure. Retrieval ranks these keys and then drops them, which is what
    /// semantic_locate reports as its `vector_sidecar` degradation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding_keys_not_in_graph: Option<usize>,
    /// Observed counts do not attest that every eligible source was enriched.
    pub completion_attested: bool,
    /// Why every counter above is an earlier instant's, when it is (FIR-2135).
    /// Absent on a live point-in-time sample, which is the only shape where its
    /// absence is honest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stale: Option<GraphStatusStaleness>,
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
    #[serde(default)]
    durable_entity_count: Option<u64>,
    relation_count: usize,
    embedding_source: GraphStatusEmbeddingSource,
    embeddings_indexed: usize,
    embeddings_pending: usize,
    embeddings_total: usize,
    #[serde(default)]
    embedding_index_keys: Option<usize>,
    #[serde(default)]
    embedding_keys_not_in_graph: Option<usize>,
    #[serde(deserialize_with = "deserialize_graph_status_unattested")]
    completion_attested: bool,
    #[serde(default)]
    stale: Option<GraphStatusStaleness>,
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
            durable_entity_count: wire.durable_entity_count,
            relation_count: wire.relation_count,
            embedding_source: wire.embedding_source,
            embeddings_indexed: wire.embeddings_indexed,
            embeddings_pending: wire.embeddings_pending,
            embeddings_total: wire.embeddings_total,
            embedding_index_keys: wire.embedding_index_keys,
            embedding_keys_not_in_graph: wire.embedding_keys_not_in_graph,
            completion_attested: wire.completion_attested,
            stale: wire.stale,
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
        // The index cannot hold fewer vectors than the graph-admitted keys found
        // in it, and the staleness counter is a derivation of the two rather
        // than a third independent claim. Validating it here is what stops the
        // report from carrying a staleness figure that disagrees with its own
        // coverage.
        if let Some(index_keys) = self.embedding_index_keys {
            if index_keys < self.embeddings_indexed {
                return Err(format!(
                    "embedding_index_keys ({index_keys}) is below embeddings_indexed ({})",
                    self.embeddings_indexed
                ));
            }
            let expected = index_keys - self.embeddings_indexed;
            if self.embedding_keys_not_in_graph != Some(expected) {
                return Err(format!(
                    "embedding_keys_not_in_graph ({:?}) is not embedding_index_keys minus \
                     embeddings_indexed ({expected})",
                    self.embedding_keys_not_in_graph
                ));
            }
        } else if self.embedding_keys_not_in_graph.is_some() {
            return Err(
                "embedding_keys_not_in_graph was reported without the index population it is \
                 derived from"
                    .to_string(),
            );
        }
        // Both directions, because either one alone lets a relabelling ship
        // silently: a replayed reading that forgot to disclose itself reads as a
        // live sample, and a live sample carrying a disclosure reads as stale
        // when it is not.
        match (&self.sampling, &self.stale) {
            (GraphStatusSampling::LastSettledSelectedGraph, None) => {
                return Err(
                    "sampling is last_settled_selected_graph with no stale disclosure beside it"
                        .to_string(),
                );
            }
            (GraphStatusSampling::PointInTimeSelectedGraph, Some(_)) => {
                return Err(
                    "a point_in_time_selected_graph sample cannot carry a stale disclosure"
                        .to_string(),
                );
            }
            _ => {}
        }
        if let Some(stale) = &self.stale {
            if stale.note.trim().is_empty() {
                return Err("stale.note is empty, so the disclosure says nothing".to_string());
            }
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
            || envelope.degraded.workspace_mismatch.is_some()
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
before relying on other tools. That universe is what graph truth admits right now — the \
graph's entities, their head revisions, and its artifacts — so a graph holding no entities \
can still report complete coverage over its artifacts alone: read entity_count beside the \
coverage, never instead of it. Coverage completeness is also not index freshness. \
embedding_index_keys reports how many vectors the index actually holds and \
embedding_keys_not_in_graph how many of those graph truth no longer admits (superseded \
revisions, retired entities), so a fully stale index cannot read as a clean one behind \
pending=0. Retrieval ranks those keys and drops them, which is the same fact \
semantic_locate reports as its vector_sidecar degradation. Both counters are absent, not \
zero, when there is no index to measure. embedding_source is selected_graph; any \
pipeline-specific \
fallback coverage is reported by semantic_locate itself. sampling=point_in_time_selected_graph \
means the daemon held its normal embedding-work fence while reading internally synchronized \
coverage counters, then revalidated authority_epoch after capturing every counter; \
authority_epoch is process-local, not a durable repository generation. \
On a store mid-embed or under continuous reconcile the live sample can lose every bounded \
attempt, and rather than refuse, this tool then answers sampling=last_settled_selected_graph: \
the same counters as of the last settled reading of this same selected graph, with a `stale` \
block giving that reading's age in milliseconds, which state blocked the live sample, and the \
authority_epoch that was current when it was abandoned. Read those counters as of that \
earlier instant, not as of now. \
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
    /// Vectors resident in the selected graph's index, sampled under the same
    /// fence as the counters above. `None` when there is no index to measure.
    pub embedding_index_keys: Option<usize>,
    /// Entities durable repository authority carried when the daemon last
    /// levelled this graph with authority (FIR-2421). `None` when it never has,
    /// which is not zero.
    pub durable_entity_count: Option<u64>,
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
        durable_entity_count: observation.durable_entity_count,
        relation_count: observation.relation_count,
        embedding_source: GraphStatusEmbeddingSource::SelectedGraph,
        embeddings_indexed: observation.embeddings_indexed,
        embeddings_pending: observation.embeddings_pending,
        embeddings_total: observation.embeddings_total,
        embedding_index_keys: observation.embedding_index_keys,
        embedding_keys_not_in_graph: observation
            .embedding_index_keys
            .map(|keys| keys.saturating_sub(observation.embeddings_indexed)),
        completion_attested: false,
        stale: None,
        response_envelope: None,
    };
    report.validate().map_err(crate::McpError::Other)?;
    Ok(ToolCallResult::text(serde_json::to_string_pretty(&report)?))
}

/// Publish the last settled observation of this selected graph, labelled as of
/// the instant it was taken (FIR-2135).
///
/// Same counters, same validation, same schema as the live path; the one
/// difference is that `sampling` says the reading is replayed and `stale`
/// carries the age, the blocking state, and the epoch that was current when the
/// live sample was abandoned. The caller decides whether a reading that old is
/// usable, which is a decision a bare retry instruction takes away from it.
pub fn handle_daemon_graph_status_stale_observation(
    scope: GraphStatusScope,
    observation: GraphStatusObservation,
    staleness: GraphStatusStaleness,
) -> Result<ToolCallResult> {
    let report = GraphStatusReport {
        schema: GRAPH_STATUS_SCHEMA.to_string(),
        view: GraphStatusView::DaemonSelectedGraph,
        scope,
        authority: GraphStatusAuthority::RepoDaemon,
        sampling: GraphStatusSampling::LastSettledSelectedGraph,
        authority_epoch: observation.authority_epoch,
        entity_count: observation.entity_count,
        durable_entity_count: observation.durable_entity_count,
        relation_count: observation.relation_count,
        embedding_source: GraphStatusEmbeddingSource::SelectedGraph,
        embeddings_indexed: observation.embeddings_indexed,
        embeddings_pending: observation.embeddings_pending,
        embeddings_total: observation.embeddings_total,
        embedding_index_keys: observation.embedding_index_keys,
        embedding_keys_not_in_graph: observation
            .embedding_index_keys
            .map(|keys| keys.saturating_sub(observation.embeddings_indexed)),
        completion_attested: false,
        stale: Some(staleness),
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
    use kin_model::relation::{
        GraphNodeId, Relation, RelationEvidence, RelationKind, RelationOrigin,
    };
    use kin_spine::SpineBackend as _;

    /// A row as the wire carries it, so the field cannot be added to the struct
    /// and dropped by the serializer.
    ///
    /// The federated case is asserted beside it because
    /// [`kin_model::EntityRole`] defaults to `Source`: a row with no local
    /// entity must report null, never the default, or every cross-repo caller
    /// arrives labelled product code on no evidence.
    #[test]
    fn the_wire_row_carries_the_callers_role_and_a_federated_row_reports_null() {
        let local = super::reference_row_json(
            ReferenceRow {
                entity_id: Some("local".to_string()),
                name: "test_send".to_string(),
                kind: Some("Function".to_string()),
                file_path: Some("tests/test_requests.py".to_string()),
                start_line: Some(4),
                reference_lines: vec![7],
                reference_lines_absent: None,
                signature: None,
                snippet: None,
                relation_kinds: Vec::new(),
                resolution: None,
                via_override_of: None,
                receiver_name_guess: false,
                role: Some(EntityRole::Test),
            },
            false,
        );
        assert_eq!(local["role"], serde_json::json!("test"), "{local}");

        let federated = super::reference_row_json(
            ReferenceRow {
                entity_id: None,
                name: "consumer".to_string(),
                kind: None,
                file_path: Some("[other] src/app.py".to_string()),
                start_line: None,
                reference_lines: Vec::new(),
                reference_lines_absent: Some(ReferenceLinesAbsent::FederatedXref),
                signature: None,
                snippet: None,
                relation_kinds: Vec::new(),
                resolution: None,
                via_override_of: None,
                receiver_name_guess: false,
                role: None,
            },
            false,
        );
        assert_eq!(
            federated["role"],
            serde_json::Value::Null,
            "a row with no local entity has no role to report: {federated}"
        );
    }

    /// The description states the unit it walks and promises nothing finer.
    ///
    /// `trace_data_flow` walks entity-level Calls/Imports/References edges. There
    /// is no `FlowsTo` relation kind and no `Parameter` entity kind in the model,
    /// so "trace this value back to its source" was a promise the substrate
    /// cannot keep, and a reader who took it spent a tool call learning that
    /// (FIR-2603). The capability is a separate, much larger piece of work; this
    /// guard is only that the description stops claiming it.
    ///
    /// Strengthened for FIR-2781 part three, because what it pinned was a
    /// PHRASING and not the property. It banned one historical string, so a
    /// rewrite promising value tracing in any other words passed it; it asserted
    /// containment anywhere rather than position, so the call-chain-walker claim
    /// could move to the bottom or vanish while a later line kept the test
    /// green; and it said nothing about the routing to `semantic_locate`, so the
    /// stranger's actual recommendation could disappear silently. The text being
    /// present today is the weakest possible state of done, one rewrite from
    /// gone.
    #[test]
    fn the_trace_description_promises_entity_edges_and_never_value_tracing() {
        let description = TRACE_DATA_FLOW_DESC;
        assert!(
            description.contains("The unit is the entity, not the value"),
            "it must state the unit it does walk: {description}"
        );
        assert!(
            description.contains("Calls/Imports/References edges"),
            "naming the edge classes it follows: {description}"
        );
    }

    /// The opening sentence, which is the only part of a long description a
    /// hurried caller reads, and the reason this tool cost a stranger a wasted
    /// call: its NAME promises data flow and the substrate walks call chains.
    ///
    /// Pinned by POSITION rather than by containment. A rewrite that keeps the
    /// claim somewhere further down leaves the name unqualified exactly where it
    /// is read, which is the state FIR-2781 was filed about, so a containment
    /// check would stay green through the regression it exists to catch.
    #[test]
    fn the_trace_descriptions_first_sentence_says_what_it_actually_walks() {
        let opening = trace_description_opening_sentence();
        let lowered = opening.to_ascii_lowercase();
        assert!(
            lowered.contains("call-chain walker") || lowered.contains("call chain walker"),
            "the FIRST sentence must say plainly what this walks, because the tool's own name \
             says otherwise and the first sentence is what a hurried caller reads. Got: {opening}"
        );
    }

    /// The stranger's own recommendation, kept as a routable destination rather
    /// than as prose that happens to be true today.
    ///
    /// A description that denies doing value tracing and then leaves the caller
    /// nowhere to go has answered half the question. `semantic_locate` is the
    /// surface that did answer it, in one call, in the session that filed this,
    /// and it is a proper noun, so asserting it by name pins the routing rather
    /// than a phrasing of the routing.
    #[test]
    fn the_trace_description_routes_value_questions_to_semantic_locate() {
        let description = TRACE_DATA_FLOW_DESC;
        let opening: String = description.chars().take(600).collect();
        assert!(
            opening.contains("semantic_locate"),
            "a value-flow question must be routed somewhere, by name, in the opening block \
             rather than left for the caller to guess: {opening}"
        );
    }

    /// The negative, made property-shaped instead of banning one historical
    /// string.
    ///
    /// The trap this has to survive, and it caught me on the first attempt: the
    /// honest text DENIES value tracing in words that contain the promise as a
    /// substring. "It cannot trace a value back to its source" contains "trace a
    /// value". A bare substring sweep therefore fires on the correct text, and a
    /// guard that fails on correct text is a guard whoever meets it deletes.
    ///
    /// So the check is negation-aware: a promise pattern is a violation only
    /// where no negator precedes it. And the denial fixture is taken FROM THE
    /// REAL DESCRIPTION rather than invented, because that is exactly how the
    /// first attempt failed. I wrote a denial in my own words, it happened not to
    /// contain the pattern that fires, and the guard passed its control while
    /// failing the actual text. A fixture written by the same hand as the check
    /// cannot tell you what the producer really says.
    #[test]
    fn the_trace_description_never_promises_to_follow_a_value() {
        for promise in TRACE_VALUE_PROMISES {
            assert!(
                !promises_without_negation(TRACE_DATA_FLOW_DESC, promise),
                "the description promises value-level tracing the substrate cannot do \
                 ({promise:?}); there is no FlowsTo relation kind and no Parameter entity kind \
                 for it to walk"
            );
        }

        // Control one: the denials the real description already makes must pass,
        // quoted from it rather than paraphrased. Each of these CONTAINS a banned
        // pattern and is correct text.
        for denial in [
            "It does NOT follow a value.",
            "It cannot trace a value back to its source.",
            "The unit is the entity, not the value",
            "the graph has no node for a value",
        ] {
            assert!(
                TRACE_DATA_FLOW_DESC.contains(denial),
                "this control is quoted from the description and must still be in it, or the \
                 control has drifted from what it controls for: {denial:?}"
            );
            for promise in TRACE_VALUE_PROMISES {
                assert!(
                    !promises_without_negation(denial, promise),
                    "pattern {promise:?} fires on the honest denial {denial:?}, so it bans \
                     correct text and will be deleted by whoever trips it"
                );
            }
        }

        // Control two: each pattern must catch the promise it names, un-negated,
        // or the list is decoration that can never fail.
        for (promise, wording) in TRACE_VALUE_PROMISES
            .iter()
            .zip(TRACE_VALUE_PROMISE_EXAMPLES)
        {
            assert!(
                promises_without_negation(wording, promise),
                "pattern {promise:?} does not catch its own example {wording:?}, so it guards \
                 nothing"
            );
        }
    }

    /// Whether `text` states `promise` somewhere no negator precedes it.
    ///
    /// The window is the sixteen characters before the match, which holds every
    /// negator this text uses ("cannot ", "does NOT ", "never ", "no node for ",
    /// "not the value") without reaching back into a previous clause. Widening it
    /// would start swallowing negations that belong to a different sentence,
    /// which is the failure mode in the other direction: a guard that never
    /// fires because some earlier sentence said "not".
    fn promises_without_negation(text: &str, promise: &str) -> bool {
        let lowered = text.to_ascii_lowercase();
        let mut from = 0usize;
        while let Some(offset) = lowered[from..].find(promise) {
            let at = from + offset;
            let window_start = at.saturating_sub(16);
            let window = &lowered[window_start..at];
            let negated = ["not", "never", "cannot", "no ", "n't"]
                .iter()
                .any(|negator| window.contains(negator));
            if !negated {
                return true;
            }
            from = at + promise.len();
        }
        false
    }

    /// Shapes that only an actual promise of value-level tracing takes: a verb
    /// with the value as its OBJECT. Negation is handled by the matcher rather
    /// than by the patterns, so a denial using any of these words still passes.
    const TRACE_VALUE_PROMISES: &[&str] = &[
        "trace this value",
        "trace a value",
        "traces values",
        "trace the value back",
        "follows a value",
        "follows the value",
        "value-level trace",
        "where a value comes from",
    ];

    /// One real sentence per pattern, un-negated, so the list is proven able to
    /// catch what it claims to catch rather than assumed able.
    const TRACE_VALUE_PROMISE_EXAMPLES: &[&str] = &[
        "It can trace this value back to its source.",
        "Use it to trace a value through the program.",
        "It traces values across assignments.",
        "It will trace the value back to where it was assigned.",
        "It follows a value through fields and returns.",
        "It follows the value into every caller.",
        "A value-level trace of the parameter.",
        "It answers where a value comes from.",
    ];

    /// The first sentence of the trace description, by position.
    ///
    /// Split on the first sentence-ending period followed by a space. The
    /// opening carries a colon and a comma before that point and no
    /// abbreviation, so this boundary is the real one rather than a guess; the
    /// test above prints what it got, so a future rewrite that breaks the
    /// assumption says so rather than failing obscurely.
    fn trace_description_opening_sentence() -> String {
        let text = TRACE_DATA_FLOW_DESC.trim_start();
        match text.find(". ") {
            Some(end) => text[..=end].to_string(),
            None => text.to_string(),
        }
    }

    fn make_entity(name: &str, file: &str) -> Entity {
        make_entity_in(LanguageId::Rust, name, file)
    }

    /// A chain payload in the shape the generic-`GraphStore` arm builds, sized
    /// so the caller can force a cut.
    fn chain_payload(steps: usize, signature_chars: usize) -> serde_json::Value {
        chain_payload_padded(steps, signature_chars, 0)
    }

    /// The same payload with bulk the budget cannot trim, so a walk with an
    /// empty chain still reaches the bisect. Without it an empty-chain fixture
    /// is under budget, the bounder returns at its first line, and a test
    /// asserting what it did not do can never fail. That was measured: the
    /// unpadded version of the test below passed with the rule deliberately
    /// broken.
    fn chain_payload_padded(
        steps: usize,
        signature_chars: usize,
        pad_chars: usize,
    ) -> serde_json::Value {
        let chain: Vec<serde_json::Value> = (0..steps)
            .map(|index| {
                serde_json::json!({
                    "step": index + 1,
                    "parent_step": index,
                    "entity_id": format!("00000000-0000-0000-0000-{index:012}"),
                    "entity_name": format!("hop_{index}"),
                    "entity_kind": "Function",
                    "entity_file": format!("src/hop_{index}.rs"),
                    "relation": "Calls",
                    "signature": "s".repeat(signature_chars),
                })
            })
            .collect();
        serde_json::json!({
            "focal": "entry",
            "focal_body": "b".repeat(pad_chars),
            "total_steps": steps,
            "chain": chain,
        })
    }

    /// A walk that reached steps must never answer with an empty chain, because
    /// an empty chain is the shape that means the walk reached nothing and no
    /// counter beside it outranks that reading. One step survives and
    /// `elisions.chain` says what the budget took.
    #[test]
    fn a_budget_never_returns_an_empty_chain_for_a_walk_that_found_steps() {
        let mut payload = chain_payload(200, 400);
        bound_trace_payload(&mut payload, 2_000);
        let kept = payload["chain"].as_array().expect("chain survives").len();
        assert!(
            kept > 0,
            "the budget emptied a chain of 200 steps: {payload}"
        );
        let omitted = payload["steps_omitted"].as_u64().expect("a cut is counted") as usize;
        assert_eq!(kept + omitted, 200, "{payload}");
        assert_eq!(payload["total_steps"], serde_json::json!(kept), "{payload}");
        let elision = &payload["elisions"]["chain"];
        assert_eq!(elision["kept"], serde_json::json!(kept), "{payload}");
        assert_eq!(elision["elided"], serde_json::json!(omitted), "{payload}");
        assert_eq!(elision["total"], serde_json::json!(200), "{payload}");
        assert_eq!(
            elision["reason"],
            serde_json::json!(crate::budget::ELISION_REASON_BUDGET),
            "{payload}"
        );
        assert_eq!(payload["truncated"], serde_json::json!(true), "{payload}");
    }

    /// The direction that makes the rule mean something: a walk that reached
    /// nothing still answers with an empty chain and claims no elision.
    #[test]
    fn a_walk_that_reached_nothing_still_answers_with_an_empty_chain() {
        // Padded past the budget on purpose, so the bounder runs its bisect on an
        // empty chain rather than returning at its first line.
        let mut payload = chain_payload_padded(0, 0, 8_000);
        assert!(
            serde_json::to_string_pretty(&payload).unwrap().len() > 2_000,
            "the fixture must reach the bounder or this proves nothing"
        );
        bound_trace_payload(&mut payload, 2_000);
        assert_eq!(
            payload["chain"],
            serde_json::json!([]),
            "an empty walk must report itself: {payload}"
        );
        assert!(
            payload.get("elisions").is_none(),
            "nothing was withheld, so nothing may be claimed: {payload}"
        );
        assert!(payload.get("steps_omitted").is_none(), "{payload}");
    }

    fn make_entity_in(language: LanguageId, name: &str, file: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language,
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

    fn make_relation_with_site(
        src: EntityId,
        dst: EntityId,
        kind: RelationKind,
        file: &str,
        row: u32,
    ) -> Relation {
        let mut relation = make_relation(src, dst, kind);
        relation.evidence = vec![RelationEvidence {
            source_span: Some(kin_model::entity::SourceSpan {
                file: FilePathId::new(file),
                start_byte: 0,
                end_byte: 1,
                start_line: row,
                start_col: 0,
                end_line: row,
                end_col: 1,
            }),
            ..RelationEvidence::default()
        }];
        relation
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

    fn search_args(query: &str, kind: Option<&str>) -> HashMap<String, serde_json::Value> {
        let mut args = HashMap::new();
        args.insert("query".to_string(), serde_json::json!(query));
        if let Some(kind) = kind {
            args.insert("kind".to_string(), serde_json::json!(kind));
        }
        args
    }

    /// A daemon envelope reporting the graph initialized, loaded and populated:
    /// the state in which a structural absence is otherwise certifiable, so the
    /// verdicts below turn on the scope observation and nothing else.
    fn ready_daemon_envelope(entity_count: u64) -> crate::envelope::Envelope {
        crate::envelope::Envelope::daemon().with_health(&serde_json::json!({
            "graph_loaded": true,
            "initialized": true,
            "graph_entity_count": entity_count,
            "graph_generation": 1,
        }))
    }

    fn module_entity(language: LanguageId, name: &str, file: &str) -> Entity {
        let mut entity = make_entity_in(language, name, file);
        entity.kind = EntityKind::Module;
        entity
    }

    /// FIR-2430, end to end through the handler that built the bad answer.
    ///
    /// The store is shaped like expressjs/express as the stranger run found it:
    /// JavaScript, with a `Module` entity for one file and none for
    /// `lib/utils.js`, which still holds entities of other kinds. That is the
    /// state in which `semantic_search(query: "utils", kind: "module")` returned
    /// zero and stamped it `safe_to_conclude_absent: true`, `trust:
    /// "authoritative"`, minutes after `find_references` refused to certify an
    /// absence on the same repository because this build wires no
    /// language-server adapter for JavaScript.
    #[test]
    fn a_javascript_search_absence_names_an_unresolved_program_and_a_python_one_names_unmeasured_coverage(
    ) {
        // A Python developer's machine: pyright installed, no JavaScript server.
        // Stated rather than inherited, because the whole contrast below is
        // between a language something resolved and one nothing did, and a test
        // that read the developer's PATH would assert a different thing on
        // every host.
        let _host =
            crate::edge_coverage::test_support::scoped_language_servers(&[LanguageId::Python]);
        let store = InMemoryGraph::new();
        store
            .upsert_entity(&module_entity(
                LanguageId::JavaScript,
                "express",
                "lib/express.js",
            ))
            .unwrap();
        store
            .upsert_entity(&make_entity_in(
                LanguageId::JavaScript,
                "createETagGenerator",
                "lib/utils.js",
            ))
            .unwrap();

        // Positive control on the same call: a module that IS in the graph comes
        // back populated and carries no scope observation, because an answer
        // that returned a row proved the region can answer.
        let found = parsed_response(
            &handle_semantic_search(&search_args("express", Some("module")), &store).unwrap(),
        );
        assert_eq!(found["total_matches"], 1);
        assert!(
            found.get(crate::edge_coverage::EDGE_COVERAGE_KEY).is_none(),
            "a populated answer needs no scope observation: {found}"
        );

        // The reported call, verbatim. The region is populated (one module), so
        // what stops the certification is that nothing resolves the program
        // behind these declarations, which is exactly what the stranger's own
        // find_references had just said about the same repository.
        let empty = parsed_response(
            &handle_semantic_search(&search_args("utils", Some("module")), &store).unwrap(),
        );
        assert_eq!(empty["total_matches"], 0);
        let coverage = &empty[crate::edge_coverage::EDGE_COVERAGE_KEY];
        assert_eq!(coverage["language"], "JavaScript");
        assert_eq!(coverage["reference_enrichment"], "no_language_server");
        assert_eq!(
            coverage["scope_entities"], 1,
            "the kind-filtered absence states the coverage of that kind: {coverage}"
        );
        let negative = crate::negative::negative_for(
            "semantic_search",
            &empty,
            &ready_daemon_envelope(2),
            &[],
        )
        .expect("an empty search carries a negative");
        assert_eq!(negative["safe_to_conclude_absent"], false);
        assert_eq!(negative["trust"], "inconclusive");
        assert!(
            negative["trust_reason"]
                .as_str()
                .unwrap()
                .starts_with("entity_index_unresolved"),
            "{negative}"
        );

        // The other direction on the same code path, and what makes it a test
        // rather than a tautology: both arms refuse this zero and they refuse it
        // for different reasons, which is the discrimination the gate exists to
        // make. JavaScript's program is unresolved, so nothing could have linked
        // it; Python's resolves, and what stops the certification there is the
        // coverage class nothing measured (FIR-2496). Read the reasons, not the
        // flags: if the enrichment gate were removed, this arm's reason would
        // appear on the arm above.
        let python = InMemoryGraph::new();
        python
            .upsert_entity(&module_entity(LanguageId::Python, "utils", "app/utils.py"))
            .unwrap();
        python
            .upsert_entity(&make_entity_in(
                LanguageId::Python,
                "render_page",
                "app/views.py",
            ))
            .unwrap();
        let found = parsed_response(
            &handle_semantic_search(&search_args("utils", Some("module")), &python).unwrap(),
        );
        assert_eq!(
            found["total_matches"], 1,
            "control: the module the Python graph holds is findable, so the absence below \
             is a real absence rather than a broken filter"
        );

        let absent = parsed_response(
            &handle_semantic_search(&search_args("zzz_not_a_symbol", None), &python).unwrap(),
        );
        assert_eq!(absent["total_matches"], 0);
        let coverage = &absent[crate::edge_coverage::EDGE_COVERAGE_KEY];
        assert_eq!(coverage["language"], "Python");
        // pyright is installed on the host this test declares, which is what
        // entitles the Python arm below to certify at all.
        assert_eq!(coverage["reference_enrichment"], "available");
        assert_eq!(coverage["scope_entities"], 2);
        let negative = crate::negative::negative_for(
            "semantic_search",
            &absent,
            &ready_daemon_envelope(2),
            &[],
        )
        .expect("an empty search carries a negative");
        // The Python half clears the enrichment gate, and FIR-2464 is what earns
        // it: the host probe found a server for this language, so the
        // observation reports `available` rather than leaving the question open.
        // It still does not certify, because `observe_absence_scope` measures no
        // coverage class and the shipped v0.5.43 answer that did certify on this
        // exact shape was wrong twice in one session.
        assert_eq!(negative["safe_to_conclude_absent"], false);
        assert_eq!(negative["trust"], "inconclusive");
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(
            reason.contains("absence_coverage_unmeasured"),
            "a resolved program with no measured coverage names that: {negative}"
        );
        assert!(
            !reason.contains("entity_index_unresolved"),
            "the JavaScript reason must not appear on a language this host resolves: {negative}"
        );
    }

    /// The reported call from the v0.5.41 stranger run, end to end (FIR-2452).
    ///
    /// `semantic_search(query: "request", kind: "method")` on psf/requests
    /// answered zero and reported `safe_to_conclude_absent: true` with "safe to
    /// treat the target as genuinely absent/unused", about a name the graph
    /// resolves. Nothing that existed could see it: the store is Python, which
    /// this build enriches, the scope holds entities, and the tool traverses no
    /// edge, so every gate correctly read healthy. The name's own side is the
    /// only place the miss is visible.
    #[test]
    fn a_search_whose_kind_filter_removed_every_name_match_certifies_nothing() {
        let store = InMemoryGraph::new();
        // `requests.api.request` is a function, and it is what the name matches.
        store
            .upsert_entity(&make_entity_in(
                LanguageId::Python,
                "request",
                "requests/api.py",
            ))
            .unwrap();
        store
            .upsert_entity(&make_entity_in(
                LanguageId::Python,
                "render_page",
                "app/views.py",
            ))
            .unwrap();
        // A method the kind filter DOES select, so the region it narrows to is
        // populated and the older scope gate stays quiet. That is the case this
        // test is about: on psf/requests the scope held every method in the
        // repository, which is why nothing refused to certify.
        let mut method = make_entity_in(LanguageId::Python, "send", "requests/sessions.py");
        method.kind = EntityKind::Method;
        store.upsert_entity(&method).unwrap();

        let empty = parsed_response(
            &handle_semantic_search(&search_args("request", Some("method")), &store).unwrap(),
        );
        assert_eq!(empty["total_matches"], 0);
        let coverage = &empty[crate::edge_coverage::EDGE_COVERAGE_KEY];
        // Every signal the older gates read is healthy here, which is the point.
        assert_eq!(coverage["language"], "Python");
        assert_eq!(coverage["reference_enrichment"], "unknown");
        assert_eq!(
            coverage["scope_entities"], 1,
            "the region the kind filter selected is populated: {coverage}"
        );
        assert_eq!(
            coverage[crate::edge_coverage::NAME_FILTER_KEY]["candidates"],
            1,
            "the name matched a declaration on its own: {coverage}"
        );
        assert_eq!(
            coverage[crate::edge_coverage::NAME_FILTER_KEY]["narrowed_by"],
            serde_json::json!(["kind"])
        );

        let negative = crate::negative::negative_for(
            "semantic_search",
            &empty,
            &ready_daemon_envelope(2),
            &[],
        )
        .expect("an empty search carries a negative");
        assert_eq!(negative["safe_to_conclude_absent"], false);
        assert_eq!(negative["trust"], "inconclusive");
        assert!(
            negative["trust_reason"]
                .as_str()
                .unwrap()
                .starts_with("name_filter_narrowed_to_zero"),
            "{negative}"
        );

        // Control on the same store and the same kind filter: a name nothing
        // carries matches nothing on its own, so no filter removed anything and
        // this gate stays quiet. Without it the fix would be indistinguishable
        // from firing the name-filter reason on every kind-filtered answer.
        //
        // The zero is not certifiable either, since FIR-2496: this store's
        // observation measures no coverage class, so nothing separates a
        // declaration the repository lacks from one the extractor never
        // admitted. What separates the two cases is which reason leads, and that
        // is what this control now reads.
        let absent = parsed_response(
            &handle_semantic_search(&search_args("zzz_not_a_symbol", Some("method")), &store)
                .unwrap(),
        );
        assert_eq!(absent["total_matches"], 0);
        assert_eq!(
            absent[crate::edge_coverage::EDGE_COVERAGE_KEY][crate::edge_coverage::NAME_FILTER_KEY]
                ["candidates"],
            0
        );
        let negative = crate::negative::negative_for(
            "semantic_search",
            &absent,
            &ready_daemon_envelope(2),
            &[],
        )
        .expect("an empty search carries a negative");
        assert_eq!(
            negative["safe_to_conclude_absent"], false,
            "an unmeasured coverage class stops this zero too: {negative}"
        );
        let reason = negative["trust_reason"].as_str().unwrap();
        assert!(
            reason.starts_with("absence_coverage_unmeasured"),
            "a name that matched nothing is limited by the coverage nobody measured, not by a \
             filter that removed nothing: {negative}"
        );
        assert!(
            !reason.contains("name_filter_narrowed_to_zero"),
            "no candidate was removed here, so that gate must stay quiet: {negative}"
        );

        // And a query that applied no narrowing filter publishes no name-filter
        // observation at all, because that query IS the name query and counting
        // it twice would buy nothing.
        let unfiltered = parsed_response(
            &handle_semantic_search(&search_args("zzz_not_a_symbol", None), &store).unwrap(),
        );
        assert!(
            unfiltered[crate::edge_coverage::EDGE_COVERAGE_KEY]
                .get(crate::edge_coverage::NAME_FILTER_KEY)
                .is_none(),
            "no narrowing filter, no second count: {unfiltered}"
        );
    }

    /// A filter that selected a region the extractor never populated says
    /// nothing about the repository, whatever language it is over.
    #[test]
    fn a_search_filtered_into_an_unpopulated_region_certifies_nothing() {
        let store = InMemoryGraph::new();
        store
            .upsert_entity(&make_entity_in(
                LanguageId::Python,
                "render_page",
                "app/views.py",
            ))
            .unwrap();

        let empty = parsed_response(
            &handle_semantic_search(&search_args("utils", Some("module")), &store).unwrap(),
        );
        assert_eq!(
            empty[crate::edge_coverage::EDGE_COVERAGE_KEY]["scope_entities"],
            0,
            "this graph holds no module entity at all: {empty}"
        );
        let negative = crate::negative::negative_for(
            "semantic_search",
            &empty,
            &ready_daemon_envelope(1),
            &[],
        )
        .expect("an empty search carries a negative");
        assert_eq!(negative["safe_to_conclude_absent"], false);
        assert!(
            negative["trust_reason"]
                .as_str()
                .unwrap()
                .starts_with("absence_scope_empty"),
            "{negative}"
        );
    }

    /// The neighborhood publishes the same observation, and a focal that did not
    /// resolve names no language rather than borrowing one, so the
    /// focal-not-in-graph gap stays the limiting factor a reader is handed.
    #[test]
    fn an_empty_neighborhood_publishes_the_scope_it_walked() {
        // No language server at all, which is the container the v0.5.42
        // stranger run used.
        let _host = crate::edge_coverage::test_support::scoped_language_servers(&[]);
        let store = InMemoryGraph::new();
        let focal = make_entity_in(
            LanguageId::JavaScript,
            "createETagGenerator",
            "lib/utils.js",
        );
        let focal_id = focal.id;
        store.upsert_entity(&focal).unwrap();

        let mut args = HashMap::new();
        args.insert(
            "entity_id".to_string(),
            serde_json::json!(focal_id.to_string()),
        );
        args.insert("direction".to_string(), serde_json::json!("in"));
        let walked = parsed_response(&handle_graph_neighborhood(&args, &store).unwrap());
        assert_eq!(walked["relation_count"], 0);
        let coverage = &walked[crate::edge_coverage::EDGE_COVERAGE_KEY];
        assert_eq!(coverage["language"], "JavaScript");
        // `no_language_server` rather than `unsupported`: this build wires a
        // JavaScript adapter now, so what leaves the program unresolved is the
        // host, not the build. Both block certification, and the difference is
        // whether an operator can do anything about it.
        assert_eq!(coverage["reference_enrichment"], "no_language_server");
        assert!(
            coverage.get("scope_entities").is_none(),
            "a walk counts no region, so it publishes no count: {coverage}"
        );
        let negative = crate::negative::negative_for(
            "graph_neighborhood",
            &walked,
            &ready_daemon_envelope(1),
            &[],
        )
        .expect("an empty walk carries a negative");
        assert_eq!(negative["safe_to_conclude_absent"], false);

        let mut missing = HashMap::new();
        missing.insert(
            "entity_id".to_string(),
            serde_json::json!(EntityId::new().to_string()),
        );
        let unresolved = parsed_response(&handle_graph_neighborhood(&missing, &store).unwrap());
        assert_eq!(
            unresolved[crate::edge_coverage::EDGE_COVERAGE_KEY]["language"],
            "no resolved language"
        );
        let negative = crate::negative::negative_for(
            "graph_neighborhood",
            &unresolved,
            &ready_daemon_envelope(1),
            &[],
        )
        .expect("an unresolved focal carries a negative");
        assert!(
            negative["trust_reason"]
                .as_str()
                .unwrap()
                .starts_with("focal_not_in_graph"),
            "the focal miss stays the limiting factor: {negative}"
        );
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
        // Bodies are opt-in, so the default row carries neither the excerpt nor
        // the signature. `entity_id` above is what reaches the body.
        assert!(!refs[0].as_object().unwrap().contains_key("snippet"));
        assert!(!refs[0].as_object().unwrap().contains_key("signature"));

        args.insert("include_snippets".to_string(), serde_json::json!(true));
        let verbose = parsed_response(&handle_find_references(&args, &store, None).await.unwrap());
        let verbose_refs = verbose["references"].as_array().unwrap();
        // Present in the shape when asked for (null here: the fixture has no
        // blob-backed body to project).
        assert!(verbose_refs[0].as_object().unwrap().contains_key("snippet"));
        assert_eq!(verbose_refs[0]["signature"], "fn caller()");
    }

    /// FIR-2475. The ambiguity counter above cannot count ambiguity on any
    /// language that qualifies a method name, which is most of them.
    ///
    /// Measured on pallets/flask at d318b683 with npm `@kinlab/kin@0.5.42`:
    /// `find_references(query: "dispatch_request")` resolved
    /// `Flask.dispatch_request` and reported `same_name_candidates: 1`, while
    /// `semantic_search` for the same string in the same session returned
    /// `total_matches: 6`. Three of those are source-role methods whose
    /// unqualified name is exactly `dispatch_request`, in two files.
    ///
    /// Two bugs stack. The count is taken against the RESOLVED focal's qualified
    /// name rather than against the query the caller typed, and it is taken with
    /// exact string equality rather than the substring rule the resolver ranked
    /// with. So for a qualified-name language the answer is pinned at one
    /// whatever the caller asked, the `ambiguous_name` degradation can never
    /// fire, and a reader following FIR-2439's own advice gets an explicit
    /// assurance that there was nothing to disambiguate. The fixture above
    /// passes only because its two entities carry bare identical names.
    #[tokio::test]
    async fn find_references_counts_what_the_query_could_have_meant() {
        let store = InMemoryGraph::new();
        let app = make_entity_in(
            LanguageId::Python,
            "Flask.dispatch_request",
            "src/flask/app.py",
        );
        let base = make_entity_in(
            LanguageId::Python,
            "View.dispatch_request",
            "src/flask/views.py",
        );
        let derived = make_entity_in(
            LanguageId::Python,
            "MethodView.dispatch_request",
            "src/flask/views.py",
        );
        for entity in [&app, &base, &derived] {
            store.upsert_entity(entity).unwrap();
        }

        // The control. Three distinct entities really do answer to this query in
        // this store, so a response reporting one candidate is reporting a fact
        // the store contradicts rather than a small repository.
        let matched = store
            .query_entities(&kin_model::graph::EntityFilter {
                name_pattern: Some("dispatch_request".to_string()),
                ..Default::default()
            })
            .unwrap();
        assert_eq!(
            matched.len(),
            3,
            "control: the query must be genuinely ambiguous in this store, or this test \
             cannot fail"
        );

        let mut args = HashMap::new();
        args.insert("query".to_string(), serde_json::json!("dispatch_request"));
        let body = parsed_response(&handle_find_references(&args, &store, None).await.unwrap());

        assert_eq!(body["focal_resolution"]["addressed_by"], "name");
        assert_eq!(
            body["focal_resolution"]["same_name_candidates"], 3,
            "the count must answer what the QUERY could have meant, not how many \
             entities carry the winner's qualified name: {body}"
        );
        assert_eq!(
            body["focal_resolution"]["matched"], "query_name_pattern",
            "the response must name the rule it counted by, or the number is unreadable: {body}"
        );

        // A count alone tells an agent it guessed and leaves it no way to ask
        // again. The rejected candidates travel with it, addressable by id.
        let others = body["focal_resolution"]["other_candidates"]
            .as_array()
            .unwrap_or_else(|| {
                panic!("an ambiguous resolution must name what it did not pick: {body}")
            });
        assert_eq!(others.len(), 2, "two candidates were not chosen: {body}");
        let focal_id = body["focal_entity"]["id"].as_str().unwrap().to_string();
        for other in others {
            assert_ne!(
                other["id"].as_str().unwrap(),
                focal_id,
                "the chosen entity is not one of the rejected ones: {body}"
            );
            assert!(
                other["name"].is_string() && other["file_path"].is_string(),
                "a rejected candidate must be re-askable: {other}"
            );
        }

        let degradations = body["degradations"]
            .as_array()
            .unwrap_or_else(|| panic!("an ambiguous resolution must degrade: {body}"));
        assert!(
            degradations
                .iter()
                .any(|entry| entry["reason"] == "ambiguous_name"),
            "the ambiguity must be named: {body}"
        );

        // The verdict half of this is asserted where `negative_for` is callable
        // directly, in `negative::tests`. This handler returns its payload
        // before the envelope layer attaches one, so asserting it here would be
        // asserting on a key this call never produces.
    }

    /// The control for the case above, and the reason the field cannot simply be
    /// redefined as "everything the pattern matched". Addressing by entity_id
    /// resolves nothing by name, so there is no query ambiguity to report, and
    /// the count must stay the exact-name twin count that protects the cfg-twin
    /// shape rather than inheriting a substring's fan-out.
    #[tokio::test]
    async fn find_references_addressed_by_id_counts_exact_name_twins() {
        let store = InMemoryGraph::new();
        let app = make_entity_in(
            LanguageId::Python,
            "Flask.dispatch_request",
            "src/flask/app.py",
        );
        let base = make_entity_in(
            LanguageId::Python,
            "View.dispatch_request",
            "src/flask/views.py",
        );
        for entity in [&app, &base] {
            store.upsert_entity(entity).unwrap();
        }

        let mut args = HashMap::new();
        args.insert(
            "entity_id".to_string(),
            serde_json::json!(app.id.to_string()),
        );
        let body = parsed_response(&handle_find_references(&args, &store, None).await.unwrap());

        assert_eq!(body["focal_resolution"]["addressed_by"], "entity_id");
        assert_eq!(
            body["focal_resolution"]["same_name_candidates"], 1,
            "one entity carries this exact name, and the caller pinned it: {body}"
        );
        assert_eq!(
            body["focal_resolution"]["matched"], "exact_focal_name",
            "a pinned address must say it counted twins, not query matches: {body}"
        );
        assert!(
            body["degradations"]
                .as_array()
                .is_none_or(|entries| entries.iter().all(|e| e["reason"] != "ambiguous_name")),
            "a pinned address is not an ambiguous one: {body}"
        );
    }

    /// A bare name that matches several entities is resolved to one of them and
    /// says so.
    ///
    /// A repository holding both `Database.resolve` and `LinkGraph.resolve`
    /// answered `find_references(query: "resolve")` with one of them and its
    /// reference list, and nothing in the response mentioned that the other
    /// existed. The answer was correct; a rename driven by it on a colliding
    /// name is a rename driven by an unannounced guess.
    #[tokio::test]
    async fn find_references_reports_an_ambiguous_name_resolution() {
        let store = InMemoryGraph::new();
        let one = make_entity("resolve", "src/database.rs");
        let two = make_entity("resolve", "src/link_graph.rs");
        store.upsert_entity(&one).unwrap();
        store.upsert_entity(&two).unwrap();

        let mut args = HashMap::new();
        args.insert("query".to_string(), serde_json::json!("resolve"));
        let body = parsed_response(&handle_find_references(&args, &store, None).await.unwrap());

        assert_eq!(body["focal_resolution"]["addressed_by"], "name");
        assert_eq!(
            body["focal_resolution"]["same_name_candidates"], 2,
            "two entities carry this name and the response must say so: {body}"
        );
        let degradations = body["degradations"]
            .as_array()
            .unwrap_or_else(|| panic!("an ambiguous resolution must degrade: {body}"));
        assert!(
            degradations
                .iter()
                .any(|entry| entry["reason"] == "ambiguous_name"),
            "the ambiguity must be named, not left to focal_entity: {body}"
        );

        // Addressing the same entity by id is not ambiguous and must not
        // degrade: the caller already pinned the choice.
        let mut pinned = HashMap::new();
        pinned.insert(
            "entity_id".to_string(),
            serde_json::json!(one.id.to_string()),
        );
        let exact = parsed_response(&handle_find_references(&pinned, &store, None).await.unwrap());
        assert_eq!(exact["focal_resolution"]["addressed_by"], "entity_id");
        assert!(
            exact.get("degradations").is_none(),
            "pinning by id resolves nothing and must not degrade: {exact}"
        );
    }

    /// One row per REFERENCING ENTITY, and `total_upstream` counting those
    /// entities rather than the files they sit in.
    ///
    /// Rows were keyed on the caller's file path, so every caller in one file
    /// collapsed into a single row keeping the first caller's id and name, and
    /// `total_upstream` reported the number of distinct files. That is how
    /// FIR-2398's `to_dot`, with eleven callers across two files, was answered
    /// with "2" beside `authority_complete` and `relation_subtype_complete` both
    /// true. The tool's stated job is blast radius, so an agent renaming or
    /// deleting on that answer saw a fifth of the work.
    ///
    /// The fixture is deliberately lopsided: three callers in one file and one
    /// in another. A balanced fixture would let the file count and the caller
    /// count coincide, and the assertion could not fail.
    #[tokio::test]
    async fn find_references_reports_every_caller_not_one_row_per_file() {
        let store = InMemoryGraph::new();
        let target = make_entity("to_dot", "src/linkgraph.rs");
        store.upsert_entity(&target).unwrap();

        let shared_file_callers = ["draws_nodes", "draws_edges", "draws_dashed"]
            .map(|name| make_entity(name, "tests/test_linkgraph.rs"));
        let other_file_caller = make_entity("cmd_graph", "src/cli.rs");
        for caller in shared_file_callers.iter().chain([&other_file_caller]) {
            store.upsert_entity(caller).unwrap();
            store
                .upsert_relation(&make_relation(caller.id, target.id, RelationKind::Calls))
                .unwrap();
        }

        let args = HashMap::from([(
            "entity_id".to_string(),
            serde_json::json!(target.id.to_string()),
        )]);
        let body = parsed_response(&handle_find_references(&args, &store, None).await.unwrap());

        let refs = body["references"].as_array().unwrap();
        assert_eq!(
            refs.len(),
            4,
            "four callers are four rows, whatever files they share: {body:#}"
        );
        assert_eq!(
            body["total_upstream"], 4,
            "total_upstream counts referencing entities, not the 2 files: {body:#}"
        );

        // Every caller present by identity, so a row cannot stand in for the
        // callers it collapsed. Names are distinct here only to make a failure
        // readable; the ids are the assertion that matters.
        let returned_ids = refs
            .iter()
            .map(|row| row["entity_id"].as_str().unwrap().to_string())
            .collect::<std::collections::BTreeSet<_>>();
        for caller in shared_file_callers.iter().chain([&other_file_caller]) {
            assert!(
                returned_ids.contains(&caller.id.to_string()),
                "caller {} is missing from the answer: {body:#}",
                caller.name
            );
        }

        // The unit is named in the payload, and the file count is still
        // available beside it rather than being what `total_upstream` means.
        assert_eq!(body["counts"]["counted"], "referencing_entities");
        assert_eq!(body["counts"]["referencing_entities"], 4);
        assert_eq!(body["counts"]["files"], 2);
    }

    /// A returned reference with no site lines says why, and the answer says
    /// whether any site could be located at all.
    ///
    /// FIR-2357 item 3: an empty `reference_lines` on a row that DID come back
    /// is the quiet-partial failure in miniature. This was once what EVERY real
    /// answer looked like, because no ingest path populated
    /// `RelationEvidence::source_span`. The Python and JavaScript adapters now
    /// record their call sites (FIR-1825, measured per language by `kin-index`'s
    /// `relation_evidence_span_coverage`), so this is now the shape of a row
    /// from a language whose adapter does not, and saying so is still the
    /// difference between a caller that knows the sites are unavailable and one
    /// that reads `[]` as "no sites".
    #[tokio::test]
    async fn find_references_says_why_a_row_carries_no_site_lines() {
        let store = InMemoryGraph::new();
        let caller = make_entity("caller", "src/a.rs");
        let target = make_entity("target", "src/b.rs");
        store.upsert_entity(&caller).unwrap();
        store.upsert_entity(&target).unwrap();
        store
            .upsert_relation(&make_relation(caller.id, target.id, RelationKind::Calls))
            .unwrap();

        let args = HashMap::from([(
            "entity_id".to_string(),
            serde_json::json!(target.id.to_string()),
        )]);
        let body = parsed_response(&handle_find_references(&args, &store, None).await.unwrap());
        let row = &body["references"].as_array().unwrap()[0];

        assert_eq!(row["reference_lines"], serde_json::json!([]));
        assert_eq!(row["reference_line_count"], 0);
        assert_eq!(
            row["reference_lines_absent_reason"], "no_evidence_span",
            "an empty site list must name its cause, not stay silent: {body:#}"
        );
        // The row is still reported. Dropping a caller whose site the graph does
        // not carry would understate blast radius, which is the defect this
        // whole surface is being fixed for.
        assert_eq!(body["total_upstream"], 1);

        assert_eq!(
            body["counts"]["reference_sites"],
            serde_json::Value::Null,
            "a site total that cannot be completed is not emitted as a number: {body:#}"
        );
        assert_eq!(body["counts"]["known_reference_sites"], 0);
        assert_eq!(body["counts"]["reference_sites_complete"], false);
    }

    /// The completeness signal must be able to say "complete".
    ///
    /// FIR-2357 item 4 names the lazy regression directly: a fix that marks
    /// every answer uncertain is not a fix. This is the same surface as the test
    /// above with the one input changed that should flip the verdict, so a
    /// hardcoded `false` fails here and a hardcoded `true` fails there.
    #[tokio::test]
    async fn find_references_reports_complete_sites_when_the_graph_carries_spans() {
        let store = InMemoryGraph::new();
        let caller_file = FilePathId::new("src/a.rs");
        let caller = make_entity("caller", "src/a.rs");
        let target = make_entity("target", "src/b.rs");
        store.upsert_entity(&caller).unwrap();
        store.upsert_entity(&target).unwrap();

        // Two call sites inside one caller, graph rows 11 and 41, which the
        // agent-facing surface reports 1-based as 12 and 42.
        let site_span = |row: u32| kin_model::entity::SourceSpan {
            file: caller_file.clone(),
            start_byte: 0,
            end_byte: 1,
            start_line: row,
            start_col: 0,
            end_line: row,
            end_col: 1,
        };
        let mut relation = make_relation(caller.id, target.id, RelationKind::Calls);
        relation.evidence = vec![11, 41]
            .into_iter()
            .map(|row| RelationEvidence {
                source_span: Some(site_span(row)),
                ..RelationEvidence::default()
            })
            .collect();
        store.upsert_relation(&relation).unwrap();

        let args = HashMap::from([(
            "entity_id".to_string(),
            serde_json::json!(target.id.to_string()),
        )]);
        let body = parsed_response(&handle_find_references(&args, &store, None).await.unwrap());
        let row = &body["references"].as_array().unwrap()[0];

        assert_eq!(
            row["reference_lines"],
            serde_json::json!([12, 42]),
            "both sites, 1-based, ascending: {body:#}"
        );
        assert_eq!(row["reference_line_count"], 2);
        assert_eq!(
            row["reference_lines_absent_reason"],
            serde_json::Value::Null,
            "a row with sites has no absence to explain: {body:#}"
        );
        // One caller, two sites: the counts object distinguishes them, which is
        // the whole point of naming the unit.
        assert_eq!(body["total_upstream"], 1);
        assert_eq!(body["counts"]["referencing_entities"], 1);
        assert_eq!(body["counts"]["reference_sites"], 2);
        assert_eq!(body["counts"]["known_reference_sites"], 2);
        assert_eq!(body["counts"]["reference_sites_complete"], true);
    }

    /// A span the parser recorded against some other file is dropped, and the
    /// drop is declared rather than looking like a parser that recorded nothing.
    ///
    /// The two absences call for different follow-ups, so collapsing them into
    /// one empty list would hide which one held.
    #[tokio::test]
    async fn find_references_distinguishes_a_dropped_span_from_a_missing_one() {
        let store = InMemoryGraph::new();
        let caller = make_entity("caller", "src/a.rs");
        let target = make_entity("target", "src/b.rs");
        store.upsert_entity(&caller).unwrap();
        store.upsert_entity(&target).unwrap();

        let mut relation = make_relation(caller.id, target.id, RelationKind::Calls);
        relation.evidence = vec![RelationEvidence {
            source_span: Some(kin_model::entity::SourceSpan {
                file: FilePathId::new("src/somewhere_else.rs"),
                start_byte: 0,
                end_byte: 1,
                start_line: 7,
                start_col: 0,
                end_line: 7,
                end_col: 1,
            }),
            ..RelationEvidence::default()
        }];
        store.upsert_relation(&relation).unwrap();

        let args = HashMap::from([(
            "entity_id".to_string(),
            serde_json::json!(target.id.to_string()),
        )]);
        let body = parsed_response(&handle_find_references(&args, &store, None).await.unwrap());
        let row = &body["references"].as_array().unwrap()[0];

        assert_eq!(
            row["reference_lines"],
            serde_json::json!([]),
            "line 8 of another file is not a line of src/a.rs: {body:#}"
        );
        assert_eq!(
            row["reference_lines_absent_reason"], "span_outside_caller_file",
            "the reason must name the condition that held: {body:#}"
        );
    }

    /// A recursive edge is not an upstream caller, on either surface.
    ///
    /// The shared CLI collector has always excluded self edges, so counting them
    /// here would put `kin refs` and `find_references` one apart on every
    /// recursive function while both looked internally consistent.
    #[tokio::test]
    async fn find_references_excludes_a_self_edge() {
        let store = InMemoryGraph::new();
        let mut caller = make_entity("caller", "src/a.rs");
        // A role the graph did not default to, so the assertion below proves the
        // VALUE reached the wire and not merely the key (FIR-1940).
        caller.role = EntityRole::Test;
        let target = make_entity("recurse", "src/b.rs");
        store.upsert_entity(&caller).unwrap();
        store.upsert_entity(&target).unwrap();
        store
            .upsert_relation(&make_relation(target.id, target.id, RelationKind::Calls))
            .unwrap();
        store
            .upsert_relation(&make_relation(caller.id, target.id, RelationKind::Calls))
            .unwrap();

        let args = HashMap::from([(
            "entity_id".to_string(),
            serde_json::json!(target.id.to_string()),
        )]);
        let body = parsed_response(&handle_find_references(&args, &store, None).await.unwrap());

        assert_eq!(
            body["total_upstream"], 1,
            "the recursive edge is not a second caller: {body:#}"
        );
        assert_eq!(
            body["references"][0]["entity_id"],
            caller.id.to_string(),
            "the one row must be the external caller: {body:#}"
        );
        assert_eq!(
            body["references"][0]["role"],
            serde_json::json!("test"),
            "a local row carries the caller's own role through the whole handler: {body:#}"
        );
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

    /// The single-repo case FIR-2633 is really about, driven through the real
    /// producer rather than a hand-written payload.
    ///
    /// A store with no spine at all is the ordinary install, and every absent
    /// `find_references` on one used to come back qualified by a limit about
    /// other repositories. The producer's own word for the state is checked here
    /// too: a fixture that guessed it would prove the gate against a status
    /// nothing emits, which is how the sibling disclosure in this PR was a no-op
    /// on every real store until an acceptance fixture caught it.
    #[tokio::test]
    async fn an_install_with_no_spine_is_not_limited_by_cross_repo_authority() {
        let store = InMemoryGraph::new();
        let target = make_entity("orphan", "src/orphan.rs");
        store.upsert_entity(&target).unwrap();
        // An empty answer is evidence about the target only once the graph can
        // hold a cross-file reference at all.
        seed_cross_file_call_witness(&store);

        let live_root = graph_root(&store);
        let args = HashMap::from([(
            "entity_id".to_string(),
            serde_json::json!(target.id.to_string()),
        )]);
        // The daemon authority with no spine backend, which is what a repository
        // that has an id and no cross-repo topology actually is. The ambient
        // path with no `KIN_REPO_ID` at all reports a different state, and that
        // one is deliberately untouched here.
        let response = parsed_response(&crate::finalize_with_envelope(
            handle_find_references_with_authority(
                &args,
                &store,
                FindReferencesAuthority {
                    repo_id: "nk",
                    graph_root: &live_root,
                    spine: None,
                },
                None,
            )
            .await
            .unwrap(),
            structurally_ready_envelope(),
            "find_references",
        ));

        assert!(
            response["references"].as_array().unwrap().is_empty(),
            "the absence path is the one under test: {response:#}"
        );
        assert_eq!(
            response["cross_repo"]["status"], "not_configured",
            "the producer's own word for a store with no spine: {}",
            response["cross_repo"]
        );
        let trust_reason = response["negative"]["trust_reason"]
            .as_str()
            .unwrap_or_default();
        assert!(
            !trust_reason.contains("cross_repo"),
            "a spine that does not exist limited nothing: {trust_reason}"
        );
        let notes = response["negative"]["notes"]
            .as_array()
            .unwrap_or_else(|| panic!("the state is still reported: {}", response["negative"]));
        assert!(
            notes.iter().any(|note| note
                .as_str()
                .is_some_and(|note| note.starts_with("cross_repo_not_configured"))),
            "in the channel that limits nothing: {notes:?}"
        );
    }

    #[tokio::test]
    async fn daemon_find_references_requires_exact_live_graph_root() {
        let graph = InMemoryGraph::new();
        let target = make_entity("target", "src/lib.rs");
        graph.upsert_entity(&target).unwrap();
        // The graph has to be able to hold a cross-file reference before an empty
        // one is evidence about the target rather than about the graph.
        seed_cross_file_call_witness(&graph);
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
        // A registered root the live graph has advanced past is stale authority,
        // and the code says which condition held rather than leaving every spine
        // gap wearing one label.
        assert_eq!(mismatched["cross_repo"]["code"], SPINE_ROOT_STALE);
        assert!(mismatched["negative"]["trust_reason"]
            .as_str()
            .is_some_and(|reason| reason.starts_with(SPINE_ROOT_STALE)));
        assert_eq!(mismatched["negative"]["safe_to_conclude_absent"], false);
        assert!(mismatched["references"].as_array().unwrap().is_empty());
    }

    /// FIR-2353, second observation: a single-repo install whose repository the
    /// spine never registered reported "spine root mismatch" as the reason a
    /// local miss could not be trusted. Nothing had mismatched and nothing was
    /// cross-repo, so the answer taught its reader to discount reason text. The
    /// condition that actually held now names itself, and the word mismatch does
    /// not appear.
    #[tokio::test]
    async fn an_unregistered_repository_reports_itself_rather_than_a_root_mismatch() {
        let graph = InMemoryGraph::new();
        let target = make_entity("parse_note", "nk/parsing.rs");
        graph.upsert_entity(&target).unwrap();
        seed_cross_file_call_witness(&graph);
        let live_root = graph_root(&graph);

        // A spine that exists and has never been told about this repository,
        // which is the ordinary state of a fresh single-repo install.
        let spine = kin_spine::InMemorySpineBackend::new();

        let args = HashMap::from([(
            "entity_id".to_string(),
            serde_json::json!(target.id.to_string()),
        )]);
        let response = handle_find_references_with_authority(
            &args,
            &graph,
            FindReferencesAuthority {
                repo_id: "nk",
                graph_root: &live_root,
                spine: Some(&spine),
            },
            None,
        )
        .await
        .unwrap();
        let response = parsed_response(&crate::finalize_with_envelope(
            response,
            structurally_ready_envelope(),
            "find_references",
        ));

        assert_eq!(response["cross_repo"]["status"], "unavailable");
        assert_eq!(response["cross_repo"]["code"], SPINE_REPO_UNREGISTERED);
        let reason = response["cross_repo"]["reason"].as_str().unwrap();
        assert!(
            !reason.contains("mismatch"),
            "an unregistered repository has nothing to mismatch: {reason}"
        );
        // The state is reported in full under `cross_repo` above. What it must
        // NOT do is limit the verdict: an install with no spine registered is
        // the ordinary single-repo state, and quoting it back as the reason an
        // answer about THIS repository could not be trusted is FIR-2633.
        let trust_reason = response["negative"]["trust_reason"].as_str().unwrap();
        assert!(
            !trust_reason.contains(SPINE_REPO_UNREGISTERED),
            "a spine that was never configured limited nothing: {trust_reason}"
        );
        assert!(
            !trust_reason.contains("mismatch"),
            "and nothing mismatched: {trust_reason}"
        );
        assert_eq!(
            response["negative"]["trust"], "authoritative",
            "{}",
            response["negative"]
        );
        let notes = response["negative"]["notes"]
            .as_array()
            .unwrap_or_else(|| panic!("the condition is still stated: {}", response["negative"]));
        assert!(
            notes.iter().any(|note| note
                .as_str()
                .is_some_and(|note| note.starts_with(SPINE_REPO_UNREGISTERED))),
            "in the channel that limits nothing: {notes:?}"
        );
    }

    /// A relation at a chosen confidence, so a fixture can hold real callers and
    /// receiver-name guesses side by side. The tiers used below are the
    /// receiver-method fan-out, the exact-name match at `0.7` (also `name_only`,
    /// and still a caller), and parser-certain at `1.0`.
    fn make_relation_at(
        src: EntityId,
        dst: EntityId,
        kind: RelationKind,
        confidence: f32,
    ) -> Relation {
        Relation {
            confidence,
            ..make_relation(src, dst, kind)
        }
    }

    /// FIR-1552. `find_references(HTTPAdapter.send)` on psf/requests answered
    /// `total_upstream: 33` where `git grep` finds two call sites, and all 33
    /// rows carried `resolution: "name_only"`, so the per-row marker could not
    /// tell the two true rows from the 31 the receiver fan-out invented. The
    /// headline counts callers. Candidates travel in their own array under their
    /// own count, and adding the two numbers together is the only way to get the
    /// old one back.
    ///
    /// `resolution` is not the discriminator here and cannot be: an ordinary
    /// cross-file call whose callee name matches exactly one entity is
    /// `name_only` too, and demoting those would empty the headline on every
    /// repository. The candidate class is the receiver fan-out alone.
    ///
    /// The fixture is deliberately lopsided, three guesses against two proven
    /// callers, so no assertion here can pass on a fixture where every number
    /// happens to coincide.
    #[tokio::test]
    async fn a_receiver_name_row_is_a_candidate_and_never_a_counted_reference() {
        let store = InMemoryGraph::new();
        let target = make_entity("send", "src/adapters.rs");
        store.upsert_entity(&target).unwrap();

        let proven = ["Session.send", "handle_401"];
        // 0.7 is the exact-name tier: `name_only` by the ladder, and an ordinary
        // caller all the same. It has to land in the headline, or this fix takes
        // real callers out of every count with the invented ones.
        let exact_name_caller = "Session.request";
        let guessed = ["test_lowlevel", "text_response_server", "test_pickling"];
        for name in proven
            .iter()
            .chain(guessed.iter())
            .chain([&exact_name_caller])
        {
            let caller = make_entity(name, "src/callers.rs");
            store.upsert_entity(&caller).unwrap();
            let confidence = if guessed.contains(name) {
                kin_index::resolution::RECEIVER_NAME_FANOUT_CONFIDENCE
            } else if *name == exact_name_caller {
                0.7
            } else {
                1.0
            };
            store
                .upsert_relation(&make_relation_at(
                    caller.id,
                    target.id,
                    RelationKind::Calls,
                    confidence,
                ))
                .unwrap();
        }

        let args = HashMap::from([(
            "entity_id".to_string(),
            serde_json::json!(target.id.to_string()),
        )]);
        let body = parsed_response(&handle_find_references(&args, &store, None).await.unwrap());

        assert_eq!(
            body["total_upstream"], 3,
            "the headline counts callers, the exact-name one included: {body:#}"
        );
        assert_eq!(
            body["counts"]["referencing_entities"], 3,
            "the counts object must agree with the headline: {body:#}"
        );
        assert_eq!(
            body["counts"]["receiver_name_candidates"], 3,
            "and must state how many rows it held back: {body:#}"
        );

        let named = |rows: &serde_json::Value| -> Vec<String> {
            rows.as_array()
                .unwrap()
                .iter()
                .map(|row| row["name"].as_str().unwrap().to_string())
                .collect()
        };
        let references = named(&body["references"]);
        let candidates = named(&body["candidates"]);
        assert_eq!(references.len(), 3, "{body:#}");
        assert_eq!(candidates.len(), 3, "{body:#}");
        for name in proven {
            assert!(references.contains(&name.to_string()), "{body:#}");
        }
        // The positive control. This row's `resolution` reads `name_only`, and
        // it is still a caller.
        assert!(
            references.contains(&exact_name_caller.to_string()),
            "an exact-name caller must survive the split: {body:#}"
        );
        assert!(
            body["references"]
                .as_array()
                .unwrap()
                .iter()
                .any(|row| row["name"] == exact_name_caller && row["resolution"] == "name_only"),
            "and it must survive it while still reading name_only, which is what \
             makes this control able to fail: {body:#}"
        );
        for name in guessed {
            assert!(
                candidates.contains(&name.to_string()),
                "a guess belongs in `candidates`, never in `references`: {body:#}"
            );
            assert!(!references.contains(&name.to_string()), "{body:#}");
        }
        for row in body["candidates"].as_array().unwrap() {
            assert_eq!(row["resolution"], "name_only", "{body:#}");
        }
        // Nothing was dropped: every caller the graph holds is in one array or
        // the other, so this is a split rather than a filter.
        assert_eq!(references.len() + candidates.len(), 6, "{body:#}");
    }

    /// Holding candidates back is what makes the count honest, and saying
    /// nothing about it would make the count look whole instead. An answer that
    /// resolved nothing and withheld three candidates is the case that matters:
    /// its `references` array is empty, and an absence gate reading only that
    /// would certify a method as unused while three rows sat beside it.
    #[tokio::test]
    async fn withheld_candidates_are_disclosed_and_cannot_certify_an_absence() {
        let store = InMemoryGraph::new();
        let target = make_entity("send", "src/adapters.rs");
        store.upsert_entity(&target).unwrap();
        for name in ["test_one", "test_two", "test_three"] {
            let caller = make_entity(name, "tests/test_requests.rs");
            store.upsert_entity(&caller).unwrap();
            store
                .upsert_relation(&make_relation_at(
                    caller.id,
                    target.id,
                    RelationKind::Calls,
                    kin_index::resolution::RECEIVER_NAME_FANOUT_CONFIDENCE,
                ))
                .unwrap();
        }

        let args = HashMap::from([(
            "entity_id".to_string(),
            serde_json::json!(target.id.to_string()),
        )]);
        let response = parsed_response(&crate::finalize_with_envelope(
            handle_find_references(&args, &store, None).await.unwrap(),
            structurally_ready_envelope(),
            "find_references",
        ));

        assert_eq!(response["total_upstream"], 0, "{response:#}");
        assert!(response["references"].as_array().unwrap().is_empty());
        assert_eq!(response["candidates"].as_array().unwrap().len(), 3);

        let disclosed = response["degradations"]
            .as_array()
            .unwrap_or_else(|| panic!("withholding rows must be declared: {response:#}"))
            .iter()
            .any(|entry| {
                entry["component"] == "call_resolution"
                    && entry["reason"] == "receiver_name_candidates"
            });
        assert!(disclosed, "{response:#}");

        // The discriminating assertion. `safe_to_conclude_absent` is already
        // false in this fixture for an unrelated reason (no `KIN_REPO_ID`, so
        // cross-repo authority cannot bind), which would make an assertion on it
        // alone a check that cannot fail. What proves the gate consumed THIS
        // disclosure is the label reaching the signal list it reads.
        let signals = response["negative"]["degraded_signals"]
            .as_array()
            .unwrap_or_else(|| panic!("a negative carries its signals: {response:#}"));
        assert!(
            signals
                .iter()
                .any(|signal| signal == "call_resolution:receiver_name_candidates"),
            "the absence gate must see the rows this answer withheld: {response:#}"
        );
        assert_eq!(
            response["negative"]["safe_to_conclude_absent"], false,
            "an empty headline beside three withheld candidates is not an absence: {response:#}"
        );

        let counted = &response["_kin"]["completeness"]["counted"];
        assert_eq!(counted["reported"], 0, "{counted}");
        assert_eq!(counted["exact"], false, "{counted}");
        assert_eq!(counted["withheld_candidates"], 3, "{counted}");
        assert_eq!(
            counted["floor_reason"], "receiver_name_candidates_withheld",
            "{counted}"
        );
        assert_eq!(
            response["_kin"]["completeness"]["bound"], "at_least",
            "a count that withheld rows is a floor: {response:#}"
        );
    }

    /// The FIR-2353 headline, end to end through the handler: a graph holding
    /// entities and one intra-file call edge, healthy by every freshness signal,
    /// answering for a symbol a sibling file calls. The answer is empty because
    /// the graph holds no cross-file edge that could have carried the reference,
    /// and the envelope has to say so rather than certify the symbol as unused.
    #[tokio::test]
    async fn find_references_on_an_intra_file_only_graph_refuses_to_certify_absence() {
        let store = InMemoryGraph::new();
        let target = make_entity("parse_note", "nk/parsing.rs");
        let caller = make_entity("save_note", "nk/storage.rs");
        let sibling = make_entity("write_bytes", "nk/storage.rs");
        store.upsert_entity(&target).unwrap();
        store.upsert_entity(&caller).unwrap();
        store.upsert_entity(&sibling).unwrap();
        // The extractor linked what it could see inside one file and nothing
        // across files, which is the exact shape the isolated-install repro hit.
        store
            .upsert_relation(&make_relation(caller.id, sibling.id, RelationKind::Calls))
            .unwrap();

        let args = HashMap::from([(
            "entity_id".to_string(),
            serde_json::json!(target.id.to_string()),
        )]);
        let response = parsed_response(&crate::finalize_with_envelope(
            handle_find_references(&args, &store, None).await.unwrap(),
            structurally_ready_envelope(),
            "find_references",
        ));

        assert!(response["references"].as_array().unwrap().is_empty());
        assert_eq!(
            response["edge_coverage"]["cross_file_classes"],
            serde_json::json!([]),
            "the observation is what makes the gap visible: {}",
            response["edge_coverage"]
        );
        assert_eq!(
            response["negative"]["safe_to_conclude_absent"], false,
            "an agent acting on a true verdict here deletes live code: {}",
            response["negative"]
        );
        assert_eq!(response["negative"]["trust"], "inconclusive");
        // And the edge gap LEADS, ahead of the ambient path's own cross-repo
        // binding gap, because it is the factor that limited this answer.
        assert!(
            trust_reason(&response).starts_with("cross_file_edges_absent"),
            "{}",
            trust_reason(&response)
        );
    }

    /// A populated answer over a graph that demonstrably links calls across
    /// files reports itself complete, and its count is exact.
    ///
    /// This test asserted the opposite until FIR-2357: that a populated answer
    /// carried no observation at all, on the reasoning that rows prove the edges
    /// exist by existing. They prove the classes those rows came through and
    /// nothing about the class a caller the answer MISSED would have come
    /// through, which is how a 20%-complete answer shipped with no signal. The
    /// observation is now taken on every answer, and this is the direction that
    /// stops it from degrading into marking everything uncertain.
    #[tokio::test]
    async fn a_populated_cross_file_answer_reports_itself_complete() {
        let store = InMemoryGraph::new();
        let caller = make_entity("caller", "src/a.rs");
        let target = make_entity("target", "src/b.rs");
        store.upsert_entity(&caller).unwrap();
        store.upsert_entity(&target).unwrap();
        store
            .upsert_relation(&make_relation(caller.id, target.id, RelationKind::Calls))
            .unwrap();

        // Asked over the one class the row proves, so the answer witnesses every
        // requested class and the scan is skipped. Asked over the default three,
        // `imports` and `references` are unwitnessed and the scan runs, which
        // since FIR-2672 is the honest reading of a graph holding one call edge.
        let args = HashMap::from([
            (
                "entity_id".to_string(),
                serde_json::json!(target.id.to_string()),
            ),
            ("relation_kinds".to_string(), serde_json::json!(["calls"])),
        ]);
        let response = parsed_response(&crate::finalize_with_envelope(
            handle_find_references(&args, &store, None).await.unwrap(),
            structurally_ready_envelope(),
            "find_references",
        ));
        assert_eq!(response["total_upstream"], 1);

        let completeness = &response["_kin"]["completeness"];
        assert_eq!(completeness["status"], "complete", "{completeness}");
        assert_eq!(completeness["bound"], "exact", "{completeness}");
        assert_eq!(completeness["counted"]["reported"], 1);

        // The row itself was the witness, so the language scan never ran. That
        // is what keeps an observation on every answer from costing a
        // language-wide relation walk per call on a healthy graph.
        let coverage = &response[crate::edge_coverage::EDGE_COVERAGE_KEY];
        assert_eq!(coverage["scan"], "skipped_answer_witnessed", "{coverage}");
        assert_eq!(
            coverage["witnessed_by_answer"],
            serde_json::json!(["calls"])
        );
        assert_eq!(coverage["entities_examined"], 0);

        // The completeness signal is no longer the only thing carrying this
        // case: since FIR-2463 the qualifier rides a populated answer too, and
        // the two say the same thing. What the qualifier must never do here is
        // claim an absence off an answer holding a row.
        assert_eq!(
            response["negative"]["safe_to_conclude_absent"], false,
            "{}",
            response["negative"]
        );
        assert_eq!(response["negative"]["interpretation"], "qualified_answer");
        assert_eq!(
            response["negative"]["trust"], "authoritative",
            "a complete cross-file answer is the whole set, and the verdict says so on both \
             surfaces: {}",
            response["negative"]
        );
    }

    /// The FIR-2357 headline end to end. A graph holding one intra-file call
    /// edge answers for a symbol a sibling file also calls, and returns exactly
    /// one caller. Ground truth is more, and every freshness signal reads
    /// healthy, so nothing in the response used to suggest the answer was a
    /// fifth of the truth.
    ///
    /// This is the shape the isolated stranger hit on `normalize_title`: one
    /// reference back, `total_upstream: 1`, no negative because the answer was
    /// not empty, and an agent that reasonably concluded the function was local.
    #[tokio::test]
    async fn a_partial_reference_answer_says_its_count_is_a_floor() {
        let store = InMemoryGraph::new();
        let target = make_entity("normalize_title", "nk/parsing.rs");
        let same_file_caller = make_entity("extract_links", "nk/parsing.rs");
        // The sibling file that really calls the target. The extractor linked
        // nothing across files, so no edge represents it and the answer cannot
        // find it. That gap is the fact the response has to report.
        let cross_file_caller = make_entity("render_note", "nk/render.rs");
        store.upsert_entity(&target).unwrap();
        store.upsert_entity(&same_file_caller).unwrap();
        store.upsert_entity(&cross_file_caller).unwrap();
        store
            .upsert_relation(&make_relation(
                same_file_caller.id,
                target.id,
                RelationKind::Calls,
            ))
            .unwrap();

        let args = HashMap::from([(
            "entity_id".to_string(),
            serde_json::json!(target.id.to_string()),
        )]);
        let response = parsed_response(&crate::finalize_with_envelope(
            handle_find_references(&args, &store, None).await.unwrap(),
            structurally_ready_envelope(),
            "find_references",
        ));

        assert_eq!(
            response["total_upstream"], 1,
            "the answer itself is unchanged; what changes is what rides beside it"
        );
        // Since FIR-2463 the qualifier rides a populated answer too. What it
        // must never do there is claim an absence.
        assert_eq!(
            response["negative"]["safe_to_conclude_absent"], false,
            "a populated answer claims no absence: {}",
            response["negative"]
        );
        assert_eq!(response["negative"]["interpretation"], "qualified_answer");

        let completeness = &response["_kin"]["completeness"];
        assert_eq!(
            completeness["status"], "partial",
            "a graph with no cross-file call edge could not have found the sibling \
             caller: {completeness}"
        );
        assert_eq!(
            completeness["bound"], "at_least",
            "so the 1 is a floor rather than a fact: {completeness}"
        );
        assert_eq!(completeness["classes"]["calls"], "absent");
        assert_eq!(
            completeness["decided_by"],
            serde_json::json!(["calls", "imports", "references"])
        );
        assert!(
            completeness["limits"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("edge_coverage:calls_absent")),
            "{completeness}"
        );
        // The row's own caller sits in the target's file, so it witnesses
        // nothing cross-file and the scan runs.
        let coverage = &response[crate::edge_coverage::EDGE_COVERAGE_KEY];
        assert_eq!(coverage["scan"], "ran", "{coverage}");
        assert_eq!(coverage["witnessed_by_answer"], serde_json::json!([]));
    }

    /// The count side (FIR-2357 item 2). When the graph carries a parse-side
    /// call-site count, a short answer says how short: parsed call sites against
    /// the reference edges that resolved, so "1 of 5" is readable off the
    /// response instead of an unqualified "1".
    #[tokio::test]
    async fn a_partial_reference_answer_reports_parsed_against_resolved() {
        let store = InMemoryGraph::new();
        let mut target = make_entity("normalize_title", "nk/parsing.rs");
        let mut caller = make_entity("extract_links", "nk/parsing.rs");
        // What extraction recorded for the file: five call sites read from the
        // source, against the one edge that resolved.
        for entity in [&mut target, &mut caller] {
            entity.metadata.extra.insert(
                kin_parser::FILE_PARSED_CALL_SITES_KEY.to_string(),
                serde_json::json!(5),
            );
        }
        store.upsert_entity(&target).unwrap();
        store.upsert_entity(&caller).unwrap();
        store
            .upsert_relation(&make_relation(caller.id, target.id, RelationKind::Calls))
            .unwrap();

        let args = HashMap::from([(
            "entity_id".to_string(),
            serde_json::json!(target.id.to_string()),
        )]);
        let response = parsed_response(&crate::finalize_with_envelope(
            handle_find_references(&args, &store, None).await.unwrap(),
            structurally_ready_envelope(),
            "find_references",
        ));

        let resolution = &response["_kin"]["completeness"]["reference_resolution"];
        assert_eq!(resolution["parsed_call_sites"], 5, "{resolution}");
        assert_eq!(resolution["resolved_call_edges"], 1, "{resolution}");
        assert_eq!(resolution["call_percent"], 20, "{resolution}");
        assert_eq!(resolution["resolution"], "partial", "{resolution}");
        assert_eq!(response["_kin"]["completeness"]["bound"], "at_least");
    }

    /// The other half of the same claim, on the daemon authority path so nothing
    /// but the edge coverage differs: one cross-file call edge and the identical
    /// empty answer is certified again. A fix that made every absence
    /// inconclusive would pass the test above and fail this one.
    #[tokio::test]
    async fn find_references_certifies_absence_once_the_graph_links_calls_across_files() {
        let graph = InMemoryGraph::new();
        let target = make_entity("parse_note", "nk/parsing.rs");
        graph.upsert_entity(&target).unwrap();
        seed_cross_file_call_witness(&graph);
        let registered_root = graph_root(&graph);

        let spine = kin_spine::InMemorySpineBackend::new();
        spine.register_repo("nk", vec![spine_entry("nk", &target)], &registered_root);
        spine.refresh_cross_repo_edges("nk", &[], &[], &["nk".to_string()]);

        let args = HashMap::from([(
            "entity_id".to_string(),
            serde_json::json!(target.id.to_string()),
        )]);
        let response = parsed_response(&crate::finalize_with_envelope(
            handle_find_references_with_authority(
                &args,
                &graph,
                FindReferencesAuthority {
                    repo_id: "nk",
                    graph_root: &registered_root,
                    spine: Some(&spine),
                },
                None,
            )
            .await
            .unwrap(),
            structurally_ready_envelope(),
            "find_references",
        ));

        assert!(response["references"].as_array().unwrap().is_empty());
        assert_eq!(
            response["edge_coverage"]["cross_file_classes"],
            serde_json::json!(["calls", "imports", "references"]),
            "every requested class is linked across files, which since FIR-2672 is what an \
             earned absence needs: {}",
            response["edge_coverage"]
        );
        assert_eq!(
            response["negative"]["safe_to_conclude_absent"], true,
            "a graph that links every class across files still earns absence: {}",
            response["negative"]
        );
        assert_eq!(response["negative"]["trust"], "authoritative");

        // FIR-2463 case (b). The collapse must not degrade into refusing
        // everything: where every input agrees, the one verdict certifies, and a
        // hardcoded `inconclusive` in the verdict fails right here.
        assert_eq!(
            response["_kin"]["verdict"]["state"], "certified",
            "every input agreed, so the one verdict certifies: {}",
            response["_kin"]["verdict"]
        );
        assert_eq!(
            response["_kin"]["verdict"]["safe_to_conclude_absent"], true,
            "{}",
            response["_kin"]["verdict"]
        );
        assert_eq!(
            response["_kin"]["verdict"]["limiting_factor"],
            serde_json::Value::Null,
            "a certified verdict names no limiting factor: {}",
            response["_kin"]["verdict"]
        );
        assert!(
            response["_kin"]["verdict"]["inputs"]
                .as_object()
                .unwrap()
                .values()
                .all(|state| state == "certified" || state == "not_applicable"),
            "certification requires every input that spoke to agree: {}",
            response["_kin"]["verdict"]
        );
        assert_eq!(response["_kin"]["completeness"]["bound"], "exact");
        assert!(
            crate::verdict::disagreements(&response).is_empty(),
            "{:?}",
            crate::verdict::disagreements(&response)
        );
    }

    /// The one call site of `send` in the psf/requests shape, at whatever
    /// resolution confidence the caller chooses, answered on the daemon
    /// authority path so no cross-repo gap can stand in for the thing under
    /// test.
    ///
    /// `Session.send` calls `HTTPAdapter.send` at `sessions.py:784` through a
    /// receiver whose type nothing at the site settles. At the receiver-name
    /// tier that row is withheld from the headline; at the parser-certain tier
    /// the identical row is an ordinary caller. Nothing else about the graph
    /// changes between the two, which is what makes the pair a discriminator
    /// rather than two fixtures that happen to differ.
    async fn requests_shape_response(confidence: f32) -> serde_json::Value {
        let store = InMemoryGraph::new();
        let target = make_entity("send", "src/requests/adapters.rs");
        let caller = make_entity("Session.send", "src/requests/sessions.rs");
        store.upsert_entity(&target).unwrap();
        store.upsert_entity(&caller).unwrap();

        let mut relation = make_relation_at(caller.id, target.id, RelationKind::Calls, confidence);
        relation.evidence = vec![RelationEvidence {
            source_span: Some(kin_model::entity::SourceSpan {
                file: FilePathId::new("src/requests/sessions.rs"),
                start_byte: 0,
                end_byte: 1,
                start_line: 783,
                start_col: 0,
                end_line: 783,
                end_col: 1,
            }),
            ..RelationEvidence::default()
        }];
        store.upsert_relation(&relation).unwrap();
        // The language links every class across files, so the verdict below is
        // about the one proven caller and not about coverage (FIR-2672).
        seed_cross_file_call_witness(&store);
        let registered_root = graph_root(&store);

        let spine = kin_spine::InMemorySpineBackend::new();
        spine.register_repo(
            "requests",
            vec![spine_entry("requests", &target)],
            &registered_root,
        );
        spine.refresh_cross_repo_edges("requests", &[], &[], &["requests".to_string()]);

        let args = HashMap::from([(
            "entity_id".to_string(),
            serde_json::json!(target.id.to_string()),
        )]);
        parsed_response(&crate::finalize_with_envelope(
            handle_find_references_with_authority(
                &args,
                &store,
                FindReferencesAuthority {
                    repo_id: "requests",
                    graph_root: &registered_root,
                    spine: Some(&spine),
                },
                None,
            )
            .await
            .unwrap(),
            structurally_ready_envelope(),
            "find_references",
        ))
    }

    /// The control for [`a_withheld_caller_refuses_the_zero_it_was_held_out_of`]:
    /// the same fixture with the one relation at the parser-certain tier. The
    /// row is counted, nothing is withheld, and the one verdict certifies.
    ///
    /// Without this the refusal above proves only that the verdict CAN say
    /// inconclusive on this fixture, which a hardcoded refusal would satisfy
    /// too.
    #[tokio::test]
    async fn a_proven_caller_on_the_same_fixture_certifies() {
        let response = requests_shape_response(1.0).await;

        assert_eq!(response["total_upstream"], 1, "{response:#}");
        assert_eq!(response["unconfirmed_candidates"], 0, "{response:#}");
        assert!(response["candidates"].as_array().unwrap().is_empty());
        assert_eq!(
            response["_kin"]["verdict"]["state"], "certified",
            "one confidence value apart from the refusal above: {}",
            response["_kin"]["verdict"]
        );
        assert_eq!(
            response["_kin"]["verdict"]["inputs"]["withheld_candidates"], "certified",
            "{}",
            response["_kin"]["verdict"]
        );
        assert_eq!(response["_kin"]["completeness"]["bound"], "exact");
        assert!(
            crate::verdict::disagreements(&response).is_empty(),
            "{:?}",
            crate::verdict::disagreements(&response)
        );
    }

    /// FIR-2463 case (a), the shape a stranger hit on shipped v0.5.42 bytes.
    ///
    /// `find_references(HTTPAdapter.send)` on psf/requests answered
    /// `total_upstream: 0` and `counts.referencing_entities: 0` while the same
    /// payload carried the one real caller, `Session.send` at
    /// `sessions.py:784`, in `candidates` as `resolution: name_only`. A reader
    /// of the headline deletes working code and a reader of the array keeps it,
    /// off one response.
    ///
    /// The fixture is Rust on a graph that links calls across files, on the
    /// daemon authority path with a registered spine, so the coverage gate, the
    /// enrichment gate and the cross-repo gate all clear. The CONFIDENCE on the
    /// one relation is the only input left that can move the verdict, and
    /// [`a_proven_caller_on_the_same_fixture_certifies`] runs the identical
    /// fixture at the parser-certain tier and gets the opposite verdict. A
    /// hardcoded `inconclusive` fails there and a hardcoded `certified` fails
    /// here.
    #[tokio::test]
    async fn a_withheld_caller_refuses_the_zero_it_was_held_out_of() {
        let response =
            requests_shape_response(kin_index::resolution::RECEIVER_NAME_FANOUT_CONFIDENCE).await;

        assert_eq!(
            response["total_upstream"], 0,
            "the headline still counts only what resolved: {response:#}"
        );
        assert_eq!(response["counts"]["referencing_entities"], 0);
        let candidates = response["candidates"].as_array().unwrap();
        assert_eq!(candidates.len(), 1, "{response:#}");
        assert_eq!(
            candidates[0]["reference_lines"],
            serde_json::json!([784]),
            "the held row carries the real call site: {response:#}"
        );

        // The count may not be read alone.
        assert_eq!(
            response["unconfirmed_candidates"], 1,
            "the zero has to name the row it is holding, at the count: {response:#}"
        );
        assert_eq!(response["counts"]["receiver_name_candidates"], 1);
        assert_eq!(
            response["_kin"]["completeness"]["counted"]["withheld_candidates"], 1,
            "one withheld number, three placements: {}",
            response["_kin"]["completeness"]
        );

        // And the one verdict refuses.
        assert_eq!(
            response["_kin"]["verdict"]["state"], "inconclusive",
            "{}",
            response["_kin"]["verdict"]
        );
        assert_eq!(
            response["_kin"]["verdict"]["safe_to_conclude_absent"], false,
            "{}",
            response["_kin"]["verdict"]
        );
        assert_eq!(
            response["_kin"]["verdict"]["inputs"]["withheld_candidates"], "inconclusive",
            "the withheld row is the input that decided: {}",
            response["_kin"]["verdict"]
        );
        assert_eq!(response["negative"]["safe_to_conclude_absent"], false);
        assert_eq!(response["negative"]["trust"], "inconclusive");
        assert_eq!(
            response["_kin"]["completeness"]["bound"], "at_least",
            "{}",
            response["_kin"]["completeness"]
        );
        assert_eq!(
            response["_kin"]["completeness"]["counted"]["exact"], false,
            "{}",
            response["_kin"]["completeness"]
        );
        assert!(
            !response["_kin"]["completeness"]["note"]
                .as_str()
                .unwrap()
                .contains("the whole set"),
            "no block may call this the whole set: {}",
            response["_kin"]["completeness"]
        );
        assert!(
            crate::verdict::disagreements(&response).is_empty(),
            "{:?}",
            crate::verdict::disagreements(&response)
        );
    }

    /// FIR-2404 end to end, on a real store rather than a hand-written payload,
    /// and on the same daemon authority path as the test above so nothing but the
    /// language differs. This is the express shape: the linker resolves same-name
    /// bare calls across files, and the focal is a module's default export every
    /// consuming file reaches through a `require` nothing in this build can
    /// resolve, because no language-server adapter is wired for JavaScript.
    ///
    /// The pair matters more than either half. The test above certifies an
    /// absence on an identically-shaped Rust graph, so the only thing separating
    /// a certified absence from a refused one here is the language's reference
    /// enrichment, which is the fact FIR-2404 added to the gate.
    #[tokio::test]
    async fn a_javascript_export_is_not_certified_absent_when_requires_produce_no_edges() {
        // The express container: no language server installed at all.
        let _host = crate::edge_coverage::test_support::scoped_language_servers(&[]);
        let graph = InMemoryGraph::new();
        let target = make_entity_in(
            LanguageId::JavaScript,
            "createApplication",
            "lib/express.js",
        );
        // The witness the one-witness rule accepted: two JavaScript entities in
        // different files joined by a resolved call.
        let caller = make_entity_in(LanguageId::JavaScript, "handle", "lib/router/index.js");
        let callee = make_entity_in(LanguageId::JavaScript, "matchLayer", "lib/router/layer.js");
        graph.upsert_entity(&target).unwrap();
        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&callee).unwrap();
        graph
            .upsert_relation(&make_relation(caller.id, callee.id, RelationKind::Calls))
            .unwrap();
        let registered_root = graph_root(&graph);

        let spine = kin_spine::InMemorySpineBackend::new();
        spine.register_repo(
            "express",
            vec![spine_entry("express", &target)],
            &registered_root,
        );
        spine.refresh_cross_repo_edges("express", &[], &[], &["express".to_string()]);

        let args = HashMap::from([(
            "entity_id".to_string(),
            serde_json::json!(target.id.to_string()),
        )]);
        let response = parsed_response(&crate::finalize_with_envelope(
            handle_find_references_with_authority(
                &args,
                &graph,
                FindReferencesAuthority {
                    repo_id: "express",
                    graph_root: &registered_root,
                    spine: Some(&spine),
                },
                None,
            )
            .await
            .unwrap(),
            structurally_ready_envelope(),
            "find_references",
        ));

        assert!(response["references"].as_array().unwrap().is_empty());
        assert_eq!(
            response["edge_coverage"]["cross_file_classes"],
            serde_json::json!(["calls"]),
            "the fixture is the express shape: calls linked, imports not: {}",
            response["edge_coverage"]
        );
        assert_eq!(
            response["edge_coverage"]["reference_enrichment"], "no_language_server",
            "this build wires a JavaScript adapter, and no server is installed to run it: {}",
            response["edge_coverage"]
        );
        assert_eq!(
            response["negative"]["safe_to_conclude_absent"], false,
            "deleting what this called safe to delete deletes express: {}",
            response["negative"]
        );
        assert_eq!(response["negative"]["trust"], "inconclusive");
        assert!(
            trust_reason(&response).starts_with("reference_enrichment_unsupported"),
            "{}",
            trust_reason(&response)
        );
        assert!(
            trust_reason(&response).contains("JavaScript"),
            "the reason names the language whose reference edges cannot exist: {}",
            trust_reason(&response)
        );
        assert_eq!(
            response["negative"]["degraded_signals"],
            serde_json::json!([
                "edge_coverage:imports_absent",
                "edge_coverage:references_absent",
                "edge_coverage:reference_enrichment_unsupported"
            ]),
            "the shortfalls the observation names are disclosed beside the verdict"
        );

        // FIR-2463, and the exact three-verdict shape a stranger quoted off
        // shipped v0.5.42 bytes. `decided_by` used to be `calls` alone, which
        // IS present, so the completeness signal reached `complete` and `exact`
        // over the same zero the negative beside it refused to certify, and its
        // note called that zero the whole set. Since FIR-2672 every requested
        // class decides, so the two absent classes are on the record of what
        // decided. The substrate reading stays as measured, because it is the
        // evidence; what a reader acts on follows the one verdict.
        assert_eq!(
            response["_kin"]["verdict"]["state"], "inconclusive",
            "{}",
            response["_kin"]["verdict"]
        );
        assert_eq!(
            response["_kin"]["completeness"]["status"], "partial",
            "the one-word summary follows the verdict: {}",
            response["_kin"]["completeness"]
        );
        assert_eq!(
            response["_kin"]["completeness"]["classes"],
            serde_json::json!({"calls": "present", "imports": "absent", "references": "absent"}),
            "and the observation it was computed from is published unchanged beside it: {}",
            response["_kin"]["completeness"]
        );
        assert_eq!(
            response["_kin"]["completeness"]["decided_by"],
            serde_json::json!(["calls", "imports", "references"]),
            "{}",
            response["_kin"]["completeness"]
        );
        assert_eq!(
            response["_kin"]["completeness"]["bound"], "at_least",
            "a complete substrate cannot make this zero exact while the verdict refuses it: {}",
            response["_kin"]["completeness"]
        );
        assert_eq!(
            response["_kin"]["completeness"]["counted"]["exact"], false,
            "{}",
            response["_kin"]["completeness"]
        );
        assert!(
            !response["_kin"]["completeness"]["note"]
                .as_str()
                .unwrap()
                .contains("the whole set"),
            "the note that called four wrong dead-code rows the whole set: {}",
            response["_kin"]["completeness"]
        );
        assert!(
            response["_kin"]["completeness"]["limits"]
                .as_array()
                .unwrap()
                .contains(&serde_json::json!("verdict_inconclusive")),
            "the downgrade names itself: {}",
            response["_kin"]["completeness"]
        );
        assert!(
            crate::verdict::disagreements(&response).is_empty(),
            "{:?}",
            crate::verdict::disagreements(&response)
        );
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
        // A federated row has no local entity, so it has no role to read. Null
        // rather than the `EntityRole` default, which would label every
        // cross-repo caller product code on no evidence (FIR-1940). Asserted on
        // the row the spine path actually built, because a hand-made row proves
        // the serializer and not this constructor.
        assert_eq!(
            unfiltered["references"][0]["role"],
            serde_json::Value::Null,
            "{}",
            unfiltered["references"][0]
        );
    }

    #[tokio::test]
    async fn filtered_find_references_certifies_complete_federated_zero() {
        let graph = InMemoryGraph::new();
        let target = make_entity("target", "src/lib.rs");
        graph.upsert_entity(&target).unwrap();
        seed_cross_file_call_witness(&graph);
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
        seed_cross_file_call_witness(&graph);
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

    /// The tool has always described itself as returning "both what it depends
    /// on and what depends on it", but traversed the outgoing index alone, so
    /// `caller` — the only entity whose behavior a change to `focal` can
    /// break — was never in the answer. An agent asking this tool for blast
    /// radius got the focal's dependencies instead, with nothing in the output
    /// to reveal the substitution.
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
        // The promise is that the object arrives and says how far the walk can
        // be trusted. Since FIR-2496 the answer on this store is that it cannot
        // certify: the walk publishes an observation that measured no coverage
        // class, so "isolated" and "never linked" are the same reading of the
        // same zero, and the flag says so rather than picking one.
        assert_eq!(response["negative"]["safe_to_conclude_absent"], false);
        assert!(
            response["negative"]["trust_reason"]
                .as_str()
                .expect("the negative must carry a trust reason")
                .contains("absence_coverage_unmeasured"),
            "the reason names the measurement nothing took: {}",
            response["negative"]
        );
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
        assert_eq!(
            response["negative"]["safe_to_conclude_absent"], false,
            "a walk that found two edges must not be reported as an absence when the caller \
             capped the array: {}",
            response["negative"]
        );
        assert_eq!(
            response["negative"]["interpretation"], "qualified_answer",
            "it is a qualified answer rather than an absence: {}",
            response["negative"]
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

    /// A pair of entities in different files joined by every reference class
    /// the verdict reads: the witness that this graph does link references
    /// across files for the language, without which an empty walk is a fact
    /// about the graph rather than about the focal.
    ///
    /// This used to seed a `Calls` edge alone, on the reasoning that Kin
    /// resolved a cross-file use into exactly that edge plus an artifact-level
    /// import edge entity queries never reach, so an entity-level `Imports`
    /// edge was "a shape no real graph produces". That sentence was the
    /// codebase's own record of FIR-2672: since every requested class decides,
    /// a graph that links only its calls is honestly short of imports and
    /// references and cannot certify an absence, so a fixture standing for a
    /// linked graph links all three.
    ///
    /// The sentence is now false as a statement about the product, not only as
    /// a reason for a fixture. The linker emits an entity-level `Imports` edge
    /// from an importing file's module entity to each symbol its specifiers
    /// name, so real graphs produce that shape: 9,162 of them on django, 504 on
    /// fastapi. It stays quoted here because it is the record of how long an
    /// assumption can hold once nothing produces the thing it denies, and
    /// because the consumer that counted this class had been written against
    /// it and was double-counting the day it filled.
    fn seed_cross_file_call_witness(store: &InMemoryGraph) {
        let caller = make_entity("witness_caller", "src/witness_caller.rs");
        let callee = make_entity("witness_callee", "src/witness_callee.rs");
        store.upsert_entity(&caller).unwrap();
        store.upsert_entity(&callee).unwrap();
        for kind in [
            RelationKind::Calls,
            RelationKind::Imports,
            RelationKind::References,
        ] {
            store
                .upsert_relation(&make_relation(caller.id, callee.id, kind))
                .unwrap();
        }
    }

    /// `trace_data_flow` on this arm, with whatever arguments a test needs, and
    /// no envelope: these assert on the handler's own payload.
    fn traced_payload(
        store: &InMemoryGraph,
        args: &[(&str, serde_json::Value)],
    ) -> serde_json::Value {
        let mut arguments = HashMap::new();
        for (key, value) in args {
            arguments.insert((*key).to_string(), value.clone());
        }
        parsed_response(&handle_trace_data_flow(&arguments, store).unwrap())
    }

    /// The reported shape on this arm: a focal that names `typing.Any` in a
    /// signature, and an `Any` the graph holds with no file and 44 further
    /// referrers. `direction: "both"` is where it bit, because the inbound half
    /// of an annotation edge is every other thing that mentions the type.
    fn annotation_hub_store(other_referrers: usize) -> (InMemoryGraph, EntityId) {
        let store = InMemoryGraph::new();
        let focal = make_entity("cert_verify", "src/requests/adapters.py");
        let focal_id = focal.id;
        store.upsert_entity(&focal).unwrap();

        let mut hub = make_entity("Any", "unused");
        hub.kind = EntityKind::Module;
        hub.file_origin = None;
        let hub_id = hub.id;
        store.upsert_entity(&hub).unwrap();
        store
            .upsert_relation(&make_relation(focal_id, hub_id, RelationKind::References))
            .unwrap();

        for index in 0..other_referrers {
            let other = make_entity(
                &format!("unrelated_{index}"),
                &format!("src/requests/u_{index}.py"),
            );
            let other_id = other.id;
            store.upsert_entity(&other).unwrap();
            store
                .upsert_relation(&make_relation(other_id, hub_id, RelationKind::References))
                .unwrap();
        }
        (store, focal_id)
    }

    fn traced_step_names(payload: &serde_json::Value) -> Vec<String> {
        payload["chain"]
            .as_array()
            .unwrap()
            .iter()
            .map(|step| step["entity_name"].as_str().unwrap_or_default().to_string())
            .collect()
    }

    /// The fan-out the stranger measured, on the arm that has its own copy of
    /// the cap.
    ///
    /// Two walkers apply a per-step cap in this codebase, and a rule fixed in
    /// one of them is a rule that reads as fixed on both while only one is. So
    /// this fixture is the CLI walker's `requests_send_graph` again, at the
    /// same tiers, asserted through the GraphStore handler.
    fn requests_send_store() -> (InMemoryGraph, EntityId) {
        let store = InMemoryGraph::new();
        let focal = make_entity("Session.send", "src/requests/sessions.py");
        let focal_id = focal.id;
        store.upsert_entity(&focal).unwrap();

        let mut edges: Vec<(Entity, f32)> = Vec::new();
        for index in 0..11 {
            edges.push((
                make_entity(&format!("Session.own_{index}"), "src/requests/sessions.py"),
                1.0,
            ));
        }
        edges.push((
            make_entity("extract_cookies_to_jar", "src/requests/cookies.py"),
            0.9,
        ));
        edges.push((make_entity("dispatch_hook", "src/requests/hooks.py"), 0.9));
        edges.push((
            make_entity("HTTPAdapter.send", "src/requests/adapters.py"),
            0.85,
        ));

        for (entity, confidence) in &edges {
            store.upsert_entity(entity).unwrap();
            let mut relation = make_relation(focal_id, entity.id, RelationKind::Calls);
            relation.confidence = *confidence;
            store.upsert_relation(&relation).unwrap();
        }
        (store, focal_id)
    }

    #[test]
    fn trace_data_flow_offline_cap_leaves_the_module_and_names_the_target() {
        let (store, focal_id) = requests_send_store();
        let untargeted = traced_payload(
            &store,
            &[
                ("focal", serde_json::json!(focal_id.to_string())),
                ("direction", serde_json::json!("calls")),
                ("depth", serde_json::json!(1)),
                ("limit_per_step", serde_json::json!(4)),
            ],
        );
        let names = traced_step_names(&untargeted);
        assert_eq!(names.len(), 4);
        assert_eq!(
            names
                .iter()
                .filter(|name| !name.starts_with("Session."))
                .count(),
            1,
            "one slot leaves the file, on this arm too: {names:?}"
        );
        assert!(
            !names.iter().any(|name| name == "HTTPAdapter.send"),
            "and the hop nobody asked for is still not the one it keeps: {names:?}"
        );
        assert_eq!(
            untargeted["spine_clipped_steps"], 1,
            "the walk continued beneath the clipped focal: {untargeted}"
        );
        assert_eq!(
            untargeted["clipped_steps"][0]["dropped_crossing_file"], 2,
            "two module-crossing hops were dropped: {untargeted}"
        );
        assert!(
            untargeted["degradations"]
                .as_array()
                .is_some_and(|degradations| degradations
                    .iter()
                    .any(|degradation| degradation["reason"] == "spine_clipped")),
            "and the disclosure fires: {untargeted}"
        );

        let targeted = traced_payload(
            &store,
            &[
                ("focal", serde_json::json!(focal_id.to_string())),
                ("direction", serde_json::json!("calls")),
                ("depth", serde_json::json!(1)),
                ("limit_per_step", serde_json::json!(4)),
                ("target", serde_json::json!("HTTPAdapter.send")),
            ],
        );
        assert!(
            traced_step_names(&targeted)
                .iter()
                .any(|name| name == "HTTPAdapter.send"),
            "naming the hop keeps it here too: {:?}",
            traced_step_names(&targeted)
        );
        assert_eq!(targeted["target_name"], "HTTPAdapter.send");
    }

    /// An annotation edge's span is not a call site.
    ///
    /// The graph holds a `UsesType` edge beside the `Calls` edge for the same
    /// pair, and its span is the annotation's target, which is the callee's own
    /// definition rather than anywhere the caller calls it. `allowed` admits
    /// `UsesType` so an annotation target is a named leaf, and the reference
    /// surface deliberately does not read it, so publishing its span here made
    /// this tool disagree with `kin refs` about the same pair and gave every row
    /// a definition line beside its call line with nothing to tell them apart.
    ///
    /// Both spans are in the CALLER's file on purpose. The caller-file filter
    /// can never separate them, so passing this can only mean the edge class
    /// was consulted.
    #[test]
    fn trace_data_flow_offline_leaves_annotation_spans_out_of_call_sites() {
        let store = InMemoryGraph::new();
        let focal = make_entity("focal", "src/focal.rs");
        let callee = make_entity("callee", "src/callee.rs");
        for entity in [&focal, &callee] {
            store.upsert_entity(entity).unwrap();
        }
        store
            .upsert_relation(&make_relation_with_site(
                focal.id,
                callee.id,
                RelationKind::Calls,
                "src/focal.rs",
                11,
            ))
            .unwrap();
        store
            .upsert_relation(&make_relation_with_site(
                focal.id,
                callee.id,
                RelationKind::UsesType,
                "src/focal.rs",
                4,
            ))
            .unwrap();

        let response = traced_payload(
            &store,
            &[
                ("focal", serde_json::json!(focal.id.to_string())),
                ("direction", serde_json::json!("calls")),
                ("depth", serde_json::json!(1)),
                ("limit_per_step", serde_json::json!(25)),
            ],
        );
        let steps = response["chain"].as_array().unwrap();
        let row = steps
            .iter()
            .find(|step| step["entity_name"] == "callee")
            .unwrap_or_else(|| {
                panic!("the annotation edge must still reach the leaf: {response:#}")
            });

        // The premise: the leaf is here at all, which is what `UsesType` being
        // in `allowed` buys and what this fix must not take away.
        assert_eq!(
            row["reference_lines"],
            serde_json::json!([12]),
            "only the call site belongs here, not the annotation's target: {row}"
        );
        assert!(row["reference_lines_absent_reason"].is_null());
    }

    /// The call-site contract on the generic GraphStore arm. The line
    /// belongs to the referencing entity, which is the parent for a callee and
    /// the child for a caller. Duplicate edges contribute every site, and an
    /// empty list states whether evidence was missing or unusable.
    #[test]
    fn trace_data_flow_offline_carries_call_sites_for_every_chain_step() {
        let store = InMemoryGraph::new();
        let focal = make_entity("focal", "src/focal.rs");
        let callee = make_entity("callee", "src/callee.rs");
        let caller = make_entity("caller", "src/caller.rs");
        let missing = make_entity("missing_site", "src/missing.rs");
        let outside = make_entity("outside_site", "src/outside.rs");
        for entity in [&focal, &callee, &caller, &missing, &outside] {
            store.upsert_entity(entity).unwrap();
        }
        store
            .upsert_relation(&make_relation_with_site(
                focal.id,
                callee.id,
                RelationKind::Calls,
                "src/focal.rs",
                11,
            ))
            .unwrap();
        store
            .upsert_relation(&make_relation_with_site(
                focal.id,
                callee.id,
                RelationKind::References,
                "src/focal.rs",
                41,
            ))
            .unwrap();
        store
            .upsert_relation(&make_relation_with_site(
                focal.id,
                callee.id,
                RelationKind::Imports,
                "src/focal.rs",
                41,
            ))
            .unwrap();
        store
            .upsert_relation(&make_relation_with_site(
                caller.id,
                focal.id,
                RelationKind::Calls,
                "src/caller.rs",
                7,
            ))
            .unwrap();
        store
            .upsert_relation(&make_relation(focal.id, missing.id, RelationKind::Calls))
            .unwrap();
        store
            .upsert_relation(&make_relation_with_site(
                focal.id,
                outside.id,
                RelationKind::Calls,
                "src/not-the-caller.rs",
                19,
            ))
            .unwrap();

        let response = traced_payload(
            &store,
            &[
                ("focal", serde_json::json!(focal.id.to_string())),
                ("direction", serde_json::json!("both")),
                ("depth", serde_json::json!(1)),
                ("limit_per_step", serde_json::json!(25)),
            ],
        );
        let steps = response["chain"].as_array().unwrap();
        let step = |name: &str| {
            steps
                .iter()
                .find(|step| step["entity_name"] == name)
                .unwrap_or_else(|| panic!("missing {name}: {response:#}"))
        };
        assert_eq!(
            step("callee")["reference_lines"],
            serde_json::json!([12, 42])
        );
        assert!(step("callee")["reference_lines_absent_reason"].is_null());
        assert_eq!(step("caller")["reference_lines"], serde_json::json!([8]));
        assert!(step("caller")["reference_lines_absent_reason"].is_null());
        assert_eq!(
            step("missing_site")["reference_lines"],
            serde_json::json!([])
        );
        assert_eq!(
            step("missing_site")["reference_lines_absent_reason"],
            "no_evidence_span"
        );
        assert_eq!(
            step("outside_site")["reference_lines"],
            serde_json::json!([])
        );
        assert_eq!(
            step("outside_site")["reference_lines_absent_reason"],
            "span_outside_caller_file"
        );

        let expected: Vec<String> = steps[0].as_object().unwrap().keys().cloned().collect();
        for item in steps {
            let keys: Vec<String> = item.as_object().unwrap().keys().cloned().collect();
            assert_eq!(keys, expected, "every step carries one key set: {item}");
        }
    }

    /// Both arms of one tool have to answer the same way, so the offline arm
    /// gets the same fixture at the same reported parameters.
    #[test]
    fn trace_data_flow_offline_stops_at_an_external_annotation_hub() {
        let (store, focal_id) = annotation_hub_store(44);
        let payload = traced_payload(
            &store,
            &[
                ("focal", serde_json::json!(focal_id.to_string())),
                ("direction", serde_json::json!("both")),
                ("depth", serde_json::json!(2)),
                ("limit_per_step", serde_json::json!(8)),
            ],
        );

        let names = traced_step_names(&payload);
        assert_eq!(
            names,
            vec!["Any".to_string()],
            "the chain must end at the file-less hub; it reached {names:?}"
        );
        assert_eq!(
            payload["chain"][0]["terminal"],
            serde_json::json!("external_reference")
        );
        assert_eq!(payload["terminal_external_steps"], serde_json::json!(1));
        assert_eq!(payload["truncated"], serde_json::json!(false));
        assert_eq!(payload["clipped_steps"], serde_json::Value::Null);
    }

    /// `include_type_edges` opens a type edge to a type this repository
    /// defines, and opens nothing else. Both halves are asserted, because a
    /// parameter that reopened the external hub would put the defect back
    /// behind an argument.
    #[test]
    fn trace_data_flow_offline_type_edges_open_a_repo_type_and_never_an_external_one() {
        let store = InMemoryGraph::new();
        let focal = make_entity("ParsedNote", "src/notes.py");
        let repo_type = make_entity("WikiLink", "src/links.py");
        let beyond = make_entity("normalize_target", "src/links.py");
        let mut stdlib = make_entity("Any", "unused");
        stdlib.kind = EntityKind::Module;
        stdlib.file_origin = None;
        let unrelated = make_entity("unrelated", "src/other.py");
        for entity in [&focal, &repo_type, &beyond, &stdlib, &unrelated] {
            store.upsert_entity(entity).unwrap();
        }
        store
            .upsert_relation(&make_relation(
                focal.id,
                repo_type.id,
                RelationKind::UsesType,
            ))
            .unwrap();
        store
            .upsert_relation(&make_relation(repo_type.id, beyond.id, RelationKind::Calls))
            .unwrap();
        store
            .upsert_relation(&make_relation(focal.id, stdlib.id, RelationKind::UsesType))
            .unwrap();
        store
            .upsert_relation(&make_relation(
                unrelated.id,
                stdlib.id,
                RelationKind::UsesType,
            ))
            .unwrap();

        let args = |include: bool| {
            [
                ("focal", serde_json::json!(focal.id.to_string())),
                ("direction", serde_json::json!("both")),
                ("depth", serde_json::json!(3)),
                ("include_type_edges", serde_json::json!(include)),
            ]
        };

        let closed = traced_payload(&store, &args(false));
        let mut closed_names = traced_step_names(&closed);
        closed_names.sort();
        assert_eq!(
            closed_names,
            vec!["Any".to_string(), "WikiLink".to_string()]
        );
        assert_eq!(closed["terminal_annotation_steps"], serde_json::json!(1));
        assert_eq!(closed["terminal_external_steps"], serde_json::json!(1));
        assert_eq!(closed["include_type_edges"], serde_json::json!(false));

        let open = traced_payload(&store, &args(true));
        let mut open_names = traced_step_names(&open);
        open_names.sort();
        assert_eq!(
            open_names,
            vec![
                "Any".to_string(),
                "WikiLink".to_string(),
                "normalize_target".to_string(),
            ],
            "the repo type opens and the stdlib one does not"
        );
        assert_eq!(open["terminal_annotation_steps"], serde_json::Value::Null);
        assert_eq!(
            open["terminal_external_steps"],
            serde_json::json!(1),
            "no parameter makes a symbol this repository does not define walkable"
        );
        assert!(
            !open_names.iter().any(|name| name == "unrelated"),
            "the other annotator of the stdlib type is not in this flow: {open_names:?}"
        );
    }

    /// The recoverable half is disclosed on the envelope; the unrecoverable one
    /// is not, because no parameter would produce more of it.
    #[test]
    fn a_withheld_type_hop_is_named_in_completeness_limits_and_an_external_leaf_is_not() {
        let (store, focal_id) = annotation_hub_store(2);
        let mut args = HashMap::new();
        args.insert("focal".to_string(), serde_json::json!(focal_id.to_string()));
        args.insert("direction".to_string(), serde_json::json!("both"));
        let external_only = parsed_response(&crate::finalize_with_envelope(
            handle_trace_data_flow(&args, &store).unwrap(),
            populated_ready_envelope(),
            "trace_data_flow",
        ));
        let limits = external_only["_kin"]["completeness"]["limits"].to_string();
        assert!(
            !limits.contains("type_annotation_edges_not_walked"),
            "an external leaf is not a shortfall a parameter can repair: {limits}"
        );

        let annotated = InMemoryGraph::new();
        // The witness is what makes this fixture's `calls` class present, and
        // therefore its completeness `complete` and its bound `exact`. Without
        // it both runs below read `partial`/`at_least` for reasons that have
        // nothing to do with type edges, and the comparison could not detect a
        // label that decided either.
        seed_cross_file_call_witness(&annotated);
        let focal = make_entity("ParsedNote", "src/notes.py");
        let repo_type = make_entity("WikiLink", "src/links.py");
        annotated.upsert_entity(&focal).unwrap();
        annotated.upsert_entity(&repo_type).unwrap();
        annotated
            .upsert_relation(&make_relation(
                focal.id,
                repo_type.id,
                RelationKind::UsesType,
            ))
            .unwrap();
        let annotated_trace = |include_type_edges: bool| {
            let mut args = HashMap::new();
            args.insert("focal".to_string(), serde_json::json!(focal.id.to_string()));
            args.insert(
                "include_type_edges".to_string(),
                serde_json::json!(include_type_edges),
            );
            parsed_response(&crate::finalize_with_envelope(
                handle_trace_data_flow(&args, &annotated).unwrap(),
                populated_ready_envelope(),
                "trace_data_flow",
            ))
        };

        let withheld = annotated_trace(false);
        assert_eq!(
            withheld["_kin"]["completeness"]["status"],
            serde_json::json!("complete"),
            "the fixture must start complete or the comparison below cannot detect a flip"
        );
        let limits = withheld["_kin"]["completeness"]["limits"].to_string();
        assert!(
            limits.contains("type_annotation_edges_not_walked"),
            "a withheld type hop is disclosed: {limits}"
        );

        // Compared against the same walk with the hop taken, rather than
        // asserted against a literal. `bound` and `status` describe the edge
        // coverage of the graph under test, which this fixture is too small to
        // make `complete`, so a literal would be asserting the fixture rather
        // than the claim. The claim is that the label is disclosure: it must
        // move neither field.
        let opened = annotated_trace(true);
        assert!(
            !opened["_kin"]["completeness"]["limits"]
                .to_string()
                .contains("type_annotation_edges_not_walked"),
            "the label describes a hop that was withheld, and this one was not"
        );
        assert_eq!(
            withheld["_kin"]["completeness"]["bound"], opened["_kin"]["completeness"]["bound"],
            "disclosure only: declining a type hop must not make an honest chain read as a floor"
        );
        assert_eq!(
            withheld["_kin"]["completeness"]["status"], opened["_kin"]["completeness"]["status"],
            "disclosure only: a limit label must not decide the completeness status"
        );
    }

    /// The measured fan-out inversion on this arm: a node whose callees include
    /// two in its own file, a distant method, a test double, and a file-less
    /// import placeholder.
    fn trace_fanout_store() -> (InMemoryGraph, EntityId) {
        let store = InMemoryGraph::new();
        let focal = make_entity("resolve_redirects", "src/requests/sessions.py");
        let focal_id = focal.id;
        store.upsert_entity(&focal).unwrap();

        let mut candidates = vec![
            make_entity("get_redirect_target", "src/requests/sessions.py"),
            make_entity("rebuild_method", "src/requests/sessions.py"),
            make_entity("HTTPAdapter.close", "src/requests/adapters.py"),
        ];
        let mut harness = make_entity("RedirectSession.send", "tests/test_requests.py");
        harness.role = EntityRole::Test;
        candidates.push(harness);
        let mut placeholder = make_entity("urljoin", "unused");
        placeholder.kind = EntityKind::Module;
        placeholder.file_origin = None;
        candidates.push(placeholder);

        for candidate in &candidates {
            store.upsert_entity(candidate).unwrap();
            store
                .upsert_relation(&make_relation(focal_id, candidate.id, RelationKind::Calls))
                .unwrap();
        }
        (store, focal_id)
    }

    /// This arm serves the tool whenever the MCP server answers from an
    /// in-process store rather than delegating to the daemon, so it owes the same
    /// per-step cap behavior. A cap that kept whatever the relation table listed
    /// first dropped the two callees that decide the redirect.
    #[test]
    fn trace_data_flow_offline_cap_keeps_the_callees_that_continue_the_chain() {
        let (store, focal_id) = trace_fanout_store();
        let response = traced_payload(
            &store,
            &[
                ("focal", serde_json::json!(focal_id.to_string())),
                ("direction", serde_json::json!("calls")),
                ("depth", serde_json::json!(1)),
                ("limit_per_step", serde_json::json!(2)),
            ],
        );

        let mut kept: Vec<String> = response["chain"]
            .as_array()
            .unwrap()
            .iter()
            .map(|step| step["entity_name"].as_str().unwrap().to_string())
            .collect();
        kept.sort();
        assert_eq!(
            kept,
            vec![
                "get_redirect_target".to_string(),
                "rebuild_method".to_string()
            ],
            "the located source callees in the expanded node's own file must win the two slots"
        );
        assert_eq!(response["truncated"], serde_json::json!(true));
        let clip = &response["clipped_steps"][0];
        assert_eq!(clip["step"], serde_json::json!(0), "the focal is step 0");
        assert_eq!(clip["dropped_callees"], serde_json::json!(3));
        assert_eq!(clip["limit_per_step"], serde_json::json!(2));
    }

    /// One array, one key set, and one identity per symbol — on this arm too.
    #[test]
    fn trace_data_flow_offline_reports_one_shape_and_one_identity() {
        let store = InMemoryGraph::new();
        let focal = make_entity("Session.prepare_request", "src/requests/sessions.py");
        let admitted = make_entity("cookiejar_from_dict", "src/requests/cookies.py");
        let mut alias = make_entity("cookiejar_from_dict", "unused");
        alias.kind = EntityKind::Module;
        alias.file_origin = None;
        let mut placeholder = make_entity("urlparse", "unused");
        placeholder.kind = EntityKind::Module;
        placeholder.file_origin = None;
        let focal_id = focal.id;
        let admitted_id = admitted.id;

        for entity in [&focal, &admitted, &alias, &placeholder] {
            store.upsert_entity(entity).unwrap();
        }
        for target in [admitted.id, alias.id, placeholder.id] {
            store
                .upsert_relation(&make_relation(focal_id, target, RelationKind::Calls))
                .unwrap();
        }

        let response = traced_payload(
            &store,
            &[
                ("focal", serde_json::json!(focal_id.to_string())),
                ("direction", serde_json::json!("calls")),
                ("depth", serde_json::json!(1)),
                ("limit_per_step", serde_json::json!(25)),
            ],
        );

        let steps = response["chain"].as_array().unwrap();
        let cookiejar: Vec<&serde_json::Value> = steps
            .iter()
            .filter(|step| step["entity_name"] == serde_json::json!("cookiejar_from_dict"))
            .collect();
        assert_eq!(cookiejar.len(), 1, "one symbol, one step: {response}");
        assert_eq!(
            cookiejar[0]["entity_id"],
            serde_json::json!(admitted_id.to_string()),
            "the located record wins over the placeholder"
        );
        assert_eq!(response["external_identities_merged"], serde_json::json!(1));

        // The file-less import is kept, because nothing located stands for it,
        // and it carries the same keys with explicit nulls.
        let external = steps
            .iter()
            .find(|step| step["external"] == serde_json::json!(true))
            .expect("the file-less import must still be reported");
        assert!(external["entity_file"].is_null() && external["start_line"].is_null());
        let expected: Vec<String> = steps[0].as_object().unwrap().keys().cloned().collect();
        for step in steps {
            let keys: Vec<String> = step.as_object().unwrap().keys().cloned().collect();
            assert_eq!(keys, expected, "every step carries the same keys: {step}");
        }
    }

    /// A located record can arrive one depth after its file-less placeholder.
    /// Promotion replaces identity and location, but the edge into the existing
    /// step does not change, so its call-site evidence must not be reset to the
    /// later edge's site.
    #[test]
    fn trace_data_flow_offline_promotion_preserves_the_original_edge_site() {
        let store = InMemoryGraph::new();
        let focal = make_entity("focal", "src/focal.rs");
        let bridge = make_entity("bridge", "src/bridge.rs");
        let admitted = make_entity("shared", "src/shared.rs");
        let mut placeholder = make_entity("shared", "unused");
        placeholder.kind = EntityKind::Module;
        placeholder.file_origin = None;
        placeholder.span = None;
        for entity in [&focal, &bridge, &admitted, &placeholder] {
            store.upsert_entity(entity).unwrap();
        }
        store
            .upsert_relation(&make_relation_with_site(
                focal.id,
                placeholder.id,
                RelationKind::Calls,
                "src/focal.rs",
                4,
            ))
            .unwrap();
        store
            .upsert_relation(&make_relation(focal.id, bridge.id, RelationKind::Calls))
            .unwrap();
        store
            .upsert_relation(&make_relation_with_site(
                bridge.id,
                admitted.id,
                RelationKind::Calls,
                "src/bridge.rs",
                9,
            ))
            .unwrap();

        let response = traced_payload(
            &store,
            &[
                ("focal", serde_json::json!(focal.id.to_string())),
                ("direction", serde_json::json!("calls")),
                ("depth", serde_json::json!(2)),
                ("limit_per_step", serde_json::json!(25)),
            ],
        );
        let shared = response["chain"]
            .as_array()
            .unwrap()
            .iter()
            .find(|step| step["entity_name"] == "shared")
            .unwrap_or_else(|| panic!("missing promoted step: {response:#}"));
        assert_eq!(shared["entity_id"], admitted.id.to_string());
        assert_eq!(shared["entity_file"], "src/shared.rs");
        assert_eq!(shared["reference_lines"], serde_json::json!([5]));
        assert!(shared["reference_lines_absent_reason"].is_null());
        assert_ne!(
            shared["reference_lines"],
            serde_json::json!([10]),
            "the promoting edge's line does not replace the edge already in the chain"
        );
    }

    /// This arm inlines no bodies, so what it can shed is steps — and it must,
    /// because 200 steps of identity and signature is a six-figure character
    /// count on its own.
    #[test]
    fn trace_data_flow_offline_bounds_its_own_payload() {
        const BUDGET: usize = 4_000;
        let store = InMemoryGraph::new();
        let focal = make_entity("hub", "src/hub.rs");
        let focal_id = focal.id;
        store.upsert_entity(&focal).unwrap();
        for index in 0..25 {
            let callee = make_entity(&format!("callee_{index}"), &format!("src/c{index}.rs"));
            store.upsert_entity(&callee).unwrap();
            store
                .upsert_relation(&make_relation(focal_id, callee.id, RelationKind::Calls))
                .unwrap();
        }

        let unbounded = traced_payload(
            &store,
            &[
                ("focal", serde_json::json!(focal_id.to_string())),
                ("direction", serde_json::json!("calls")),
                ("depth", serde_json::json!(1)),
                ("limit_per_step", serde_json::json!(25)),
            ],
        );
        assert_eq!(unbounded["total_steps"], serde_json::json!(25));
        let unbounded_chars = serde_json::to_string_pretty(&unbounded).unwrap().len();
        assert!(
            unbounded_chars > BUDGET,
            "the fixture must exceed the budget under test: {unbounded_chars} chars"
        );

        let bounded = traced_payload(
            &store,
            &[
                ("focal", serde_json::json!(focal_id.to_string())),
                ("direction", serde_json::json!("calls")),
                ("depth", serde_json::json!(1)),
                ("limit_per_step", serde_json::json!(25)),
                ("max_response_chars", serde_json::json!(BUDGET)),
            ],
        );
        let bounded_chars = serde_json::to_string_pretty(&bounded).unwrap().len();
        assert!(
            bounded_chars <= BUDGET,
            "the tool must return what it promised to fit: {bounded_chars} chars against {BUDGET}"
        );
        let kept = bounded["total_steps"].as_u64().unwrap() as usize;
        assert!(kept > 0, "a bound is not a refusal: {bounded}");
        assert_eq!(
            bounded["steps_omitted"].as_u64().unwrap() as usize + kept,
            25
        );
        assert_eq!(
            bounded["truncated"],
            serde_json::json!(true),
            "dropped steps are edges the caller did not receive"
        );
        // A prefix, so no surviving step points at a parent that was dropped.
        for step in bounded["chain"].as_array().unwrap() {
            assert!(step["parent_step"].as_u64().unwrap() as usize <= kept);
        }
        let disclosure = bounded["degradations"]
            .as_array()
            .expect("a cut must be disclosed")
            .iter()
            .find(|entry| entry["component"] == serde_json::json!("response_budget"))
            .expect("the cut must name itself");
        assert_eq!(disclosure["reason"], serde_json::json!("steps_omitted"));
    }

    /// At the GraphStore arm's first response-boundary stage, the
    /// target branch is shallower than the distractor, so ordinary deep-branch
    /// preservation gives it up. Reading `target_name` is the only thing that
    /// can make the named and unnamed arms choose differently.
    #[test]
    fn trace_data_flow_offline_response_narrowing_keeps_the_named_branch() {
        let discovered = vec![
            serde_json::json!({
                "step": 1, "parent_step": 0, "entity_name": "target_parent", "pad": "p".repeat(300),
            }),
            serde_json::json!({
                "step": 2, "parent_step": 0, "entity_name": "distractor", "pad": "p".repeat(300),
            }),
            serde_json::json!({
                "step": 3, "parent_step": 1, "entity_name": "cert_verify", "pad": "p".repeat(300),
            }),
            serde_json::json!({
                "step": 4, "parent_step": 2, "entity_name": "deeper", "pad": "p".repeat(300),
            }),
            serde_json::json!({
                "step": 5, "parent_step": 4, "entity_name": "deepest", "pad": "p".repeat(300),
            }),
        ];
        let payload = |target_name: Option<&str>, chain: Vec<serde_json::Value>| {
            let mut value = serde_json::json!({
                "chain": chain,
                "total_steps": 5,
            });
            if let Some(name) = target_name {
                value["target_name"] = serde_json::json!(name);
            }
            value
        };
        let measure =
            |value: &serde_json::Value| serde_json::to_string_pretty(value).unwrap().len();
        let protected_shape = payload(
            Some("cert_verify"),
            vec![discovered[0].clone(), discovered[2].clone()],
        );
        let deep_shape = payload(
            None,
            vec![
                discovered[1].clone(),
                discovered[3].clone(),
                discovered[4].clone(),
            ],
        );
        let target_chars = measure(&protected_shape).max(measure(&deep_shape));
        let full = payload(Some("cert_verify"), discovered.clone());
        assert!(measure(&full) > target_chars, "the fixture must need a cut");

        let mut unnamed = payload(None, discovered.clone());
        let unnamed_dropped =
            narrow_trace_fanout_to_fit(&mut unnamed, &discovered, target_chars, measure);
        assert!(unnamed_dropped > 0, "the unnamed control must narrow");
        assert!(
            !traced_step_names(&unnamed)
                .iter()
                .any(|name| name == "cert_verify"),
            "the unnamed control kept the shallow target branch: {unnamed}"
        );

        let mut named = payload(Some("cert_verify"), discovered.clone());
        let named_dropped =
            narrow_trace_fanout_to_fit(&mut named, &discovered, target_chars, measure);
        assert!(named_dropped > 0, "the named arm must still narrow");
        let named_steps = named["chain"].as_array().unwrap();
        let names: std::collections::BTreeSet<&str> = named_steps
            .iter()
            .filter_map(|step| step["entity_name"].as_str())
            .collect();
        assert!(
            names.contains("cert_verify"),
            "the first response bounder dropped the named branch: {named}"
        );
        assert!(
            names.contains("target_parent"),
            "the target survived without the parent that introduced it: {named}"
        );
        let present: std::collections::BTreeSet<u64> = named_steps
            .iter()
            .filter_map(|step| step["step"].as_u64())
            .collect();
        assert!(named_steps.iter().all(|step| {
            let parent = step["parent_step"].as_u64().unwrap_or(0);
            parent == 0 || present.contains(&parent)
        }));
    }

    /// The authoritative side of the trace absence: a focal that is in the
    /// graph, carries a name nothing else shares, is not a method, and has no
    /// edges at all, on a graph that demonstrably links calls across files.
    /// That is a real absence, and the qualifier must still be willing to say
    /// so. A gate that never certifies anything is as useless as one that
    /// certifies everything.
    #[test]
    fn trace_data_flow_isolated_focal_is_authoritative_on_a_ready_graph() {
        let store = InMemoryGraph::new();
        let lonely = make_entity("lonely", "src/lonely.rs");
        store.upsert_entity(&lonely).unwrap();
        seed_cross_file_call_witness(&store);

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
            embedding_index_keys: None,
            durable_entity_count: None,
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
                embedding_index_keys: None,
                durable_entity_count: None,
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
    fn graph_status_names_index_staleness_beside_complete_coverage() {
        // The umbrella store reported coverage {complete: true,
        // indexed: 49, pending: 0, total: 49} beside entity_count 0, while
        // semantic_locate reported 40 of those ranked vector keys resolving to
        // entities the graph no longer holds. Coverage is measured against what
        // graph truth admits, so a fully stale index satisfied it perfectly and
        // staleness hid behind pending=0. The index population is now reported
        // beside the coverage and the difference is named.
        let result = handle_daemon_graph_status_observation(
            GraphStatusScope::Head,
            GraphStatusObservation {
                authority_epoch: 7,
                entity_count: 0,
                relation_count: 0,
                embeddings_indexed: 49,
                embeddings_pending: 0,
                embeddings_total: 49,
                embedding_index_keys: Some(89),
                durable_entity_count: None,
            },
        )
        .expect("a stale-but-covered graph is a reportable observation");
        let report: GraphStatusReport = serde_json::from_value(parsed_response(&result)).unwrap();
        assert_eq!(report.embedding_index_keys, Some(89));
        assert_eq!(report.embedding_keys_not_in_graph, Some(40));

        // Positive control: a graph whose index holds exactly what truth admits
        // reports zero stale keys, so the counter distinguishes the two states
        // rather than always firing.
        let result = handle_daemon_graph_status_observation(
            GraphStatusScope::Head,
            GraphStatusObservation {
                authority_epoch: 7,
                entity_count: 12,
                relation_count: 3,
                embeddings_indexed: 49,
                embeddings_pending: 0,
                embeddings_total: 49,
                embedding_index_keys: Some(49),
                durable_entity_count: None,
            },
        )
        .unwrap();
        let report: GraphStatusReport = serde_json::from_value(parsed_response(&result)).unwrap();
        assert_eq!(report.embedding_keys_not_in_graph, Some(0));

        // Negative control: no index to measure is absent, never a measured
        // zero, and the derived counter goes with it.
        let result = handle_daemon_graph_status_observation(
            GraphStatusScope::Head,
            GraphStatusObservation {
                authority_epoch: 7,
                entity_count: 12,
                relation_count: 3,
                embeddings_indexed: 0,
                embeddings_pending: 12,
                embeddings_total: 12,
                embedding_index_keys: None,
                durable_entity_count: None,
            },
        )
        .unwrap();
        let payload = parsed_response(&result);
        assert!(payload.get("embedding_index_keys").is_none(), "{payload}");
        assert!(
            payload.get("embedding_keys_not_in_graph").is_none(),
            "{payload}"
        );
    }

    #[test]
    fn graph_status_rejects_an_index_smaller_than_its_own_covered_keys() {
        // The staleness counter is a derivation of two sampled numbers, so a
        // report whose index holds fewer vectors than the coverage found in it
        // is incoherent and must not serialize.
        let error = handle_daemon_graph_status_observation(
            GraphStatusScope::Head,
            GraphStatusObservation {
                authority_epoch: 7,
                entity_count: 4,
                relation_count: 0,
                embeddings_indexed: 10,
                embeddings_pending: 0,
                embeddings_total: 10,
                embedding_index_keys: Some(9),
                durable_entity_count: None,
            },
        )
        .expect_err("an index below its own covered keys is not a reportable observation");
        assert!(
            error
                .to_string()
                .contains("embedding_index_keys (9) is below embeddings_indexed (10)"),
            "{error}"
        );
    }

    #[test]
    fn graph_status_rejects_a_staleness_figure_that_disagrees_with_its_coverage() {
        // A hand-built or drifted daemon payload cannot smuggle in a staleness
        // number that is not the difference between the two counters it claims
        // to derive from.
        let wire = serde_json::json!({
            "schema": GRAPH_STATUS_SCHEMA,
            "view": "daemon_selected_graph",
            "scope": "head",
            "authority": "repo-daemon",
            "sampling": "point_in_time_selected_graph",
            "authority_epoch": 7,
            "entity_count": 4,
            "relation_count": 0,
            "embedding_source": "selected_graph",
            "embeddings_indexed": 10,
            "embeddings_pending": 0,
            "embeddings_total": 10,
            "embedding_index_keys": 50,
            "embedding_keys_not_in_graph": 0,
            "completion_attested": false,
        });
        let error = serde_json::from_value::<GraphStatusReport>(wire)
            .expect_err("a staleness figure must agree with the counters it derives from");
        assert!(
            error
                .to_string()
                .contains("is not embedding_index_keys minus embeddings_indexed"),
            "{error}"
        );
    }

    #[test]
    fn graph_status_rejects_staleness_reported_without_an_index_population() {
        let wire = serde_json::json!({
            "schema": GRAPH_STATUS_SCHEMA,
            "view": "daemon_selected_graph",
            "scope": "head",
            "authority": "repo-daemon",
            "sampling": "point_in_time_selected_graph",
            "authority_epoch": 7,
            "entity_count": 4,
            "relation_count": 0,
            "embedding_source": "selected_graph",
            "embeddings_indexed": 10,
            "embeddings_pending": 0,
            "embeddings_total": 10,
            "embedding_keys_not_in_graph": 3,
            "completion_attested": false,
        });
        let error = serde_json::from_value::<GraphStatusReport>(wire)
            .expect_err("a derived counter cannot arrive without what it derives from");
        assert!(
            error
                .to_string()
                .contains("without the index population it is derived from"),
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

    // ---------------------------------------------------------------------
    // FIR-2396: the response budget, one test per retrieval tool.
    //
    // Each builds a fixture large enough to overflow the shared default, then
    // asserts the FINAL annotated text -- the bytes a client actually counts,
    // envelope and negative included -- stays under it. The control in every
    // case is the same call served at the clamp ceiling, which proves the
    // fixture overflows and that the bound, rather than the fixture, is what
    // shrank it.
    // ---------------------------------------------------------------------

    use crate::budget::{ResponseBudget, RESPONSE_DEFAULT_MAX_CHARS, RESPONSE_MAX_MAX_CHARS};

    /// The text a client receives for one tool result: the payload with `_kin`
    /// and `negative` attached, rendered exactly as the stdio path renders it.
    fn client_text(result: ToolCallResult, tool: &str, budget: &ResponseBudget) -> String {
        let enveloped =
            crate::envelope::finalize_bounded(result, crate::Envelope::offline(), tool, budget);
        let crate::types::ContentBlock::Text { text } = enveloped
            .content
            .into_iter()
            .next()
            .expect("one content block");
        text
    }

    /// A budget that cannot bind, for the control arm.
    fn unbounded() -> ResponseBudget {
        ResponseBudget {
            max_chars: RESPONSE_MAX_MAX_CHARS,
            compact: false,
            explicit_max_chars: true,
            envelope_reserve: 0,
        }
    }

    /// Assert one tool's overflow and its bound in the one unit the refusal was
    /// ever reported in, and hand back both numbers and the bounded payload.
    fn assert_bounded(
        tool: &str,
        unbounded_text: String,
        bounded_text: String,
    ) -> (usize, usize, serde_json::Value) {
        let before = unbounded_text.len();
        let after = bounded_text.len();
        assert!(
            before > RESPONSE_DEFAULT_MAX_CHARS,
            "{tool}: the fixture must overflow the default budget, or the bound is untested: \
             {before} chars"
        );
        assert!(
            after <= RESPONSE_DEFAULT_MAX_CHARS,
            "{tool}: the response a client receives must fit its budget: {after} chars against \
             {RESPONSE_DEFAULT_MAX_CHARS}"
        );
        let bounded: serde_json::Value = serde_json::from_str(&bounded_text)
            .unwrap_or_else(|error| panic!("{tool}: a bounded response is still JSON: {error}"));
        assert_eq!(
            bounded["_kin"]["response"]["max_chars"],
            serde_json::json!(RESPONSE_DEFAULT_MAX_CHARS),
            "{tool}: the applied budget is recorded on the envelope"
        );
        let chars_before = bounded["_kin"]["response"]["chars_before_budget"]
            .as_u64()
            .expect("the pre-truncation size is recorded") as usize;
        assert!(
            chars_before > 0,
            "{tool}: the envelope reports the size the response had before the budget"
        );
        // Bounded SOMEWHERE, and the response says where. The envelope stage
        // reports its own cut on `_kin`; a tool that enforces the same budget
        // inside its own walk has already fit by the time the envelope sees it,
        // and discloses that cut through `degradations` instead. Accepting only
        // the first reading would make this assertion fail on exactly the tool
        // that bounds itself best.
        let envelope_cut = bounded["_kin"]["response"]["bounded"] == serde_json::json!(true);
        let handler_cut = bounded["degradations"].as_array().is_some_and(|cuts| {
            cuts.iter()
                .any(|cut| cut["component"] == serde_json::json!("response_budget"))
        });
        assert!(
            envelope_cut || handler_cut,
            "{tool}: a response that was cut has to say so: {bounded}"
        );
        assert!(
            !envelope_cut || chars_before > RESPONSE_DEFAULT_MAX_CHARS,
            "{tool}: the envelope stage cuts only what was over its budget, and reports the size \
             it was over by: {chars_before} chars"
        );
        eprintln!("FIR-2396 {tool}: {before} chars unbounded, {after} chars bounded");
        (before, after, bounded)
    }

    fn wide_store(callers: usize) -> (InMemoryGraph, EntityId) {
        let store = InMemoryGraph::new();
        let focal = make_entity("resolve_redirects", "src/sessions.rs");
        let focal_id = focal.id;
        store.upsert_entity(&focal).unwrap();
        for index in 0..callers {
            let mut caller = make_entity(
                &format!("caller_number_{index}_with_a_realistic_symbol_name"),
                &format!("src/module_{index}/handler.rs"),
            );
            caller.doc_summary = Some(
                "Resolves the redirect chain for one request and replays the body when the \
                 method survives the hop."
                    .to_string(),
            );
            store.upsert_entity(&caller).unwrap();
            store
                .upsert_relation(&make_relation(caller.id, focal_id, RelationKind::Calls))
                .unwrap();
        }
        (store, focal_id)
    }

    #[test]
    fn semantic_search_response_fits_the_budget() {
        let (store, _) = wide_store(400);
        let args = |compact: bool| -> HashMap<String, serde_json::Value> {
            HashMap::from([
                ("query".to_string(), serde_json::json!("caller")),
                ("limit".to_string(), serde_json::json!(200)),
                ("compact".to_string(), serde_json::json!(compact)),
            ])
        };
        let before = client_text(
            handle_semantic_search(&args(false), &store).unwrap(),
            "semantic_search",
            &unbounded(),
        );
        let after = client_text(
            handle_semantic_search(&args(true), &store).unwrap(),
            "semantic_search",
            &ResponseBudget::default(),
        );
        assert_bounded("semantic_search", before, after);
    }

    #[tokio::test]
    async fn find_references_response_fits_the_budget() {
        let (store, focal_id) = wide_store(400);
        let args = HashMap::from([(
            "entity_id".to_string(),
            serde_json::json!(focal_id.to_string()),
        )]);
        let before = client_text(
            handle_find_references(&args, &store, None).await.unwrap(),
            "find_references",
            &unbounded(),
        );
        let after = client_text(
            handle_find_references(&args, &store, None).await.unwrap(),
            "find_references",
            &ResponseBudget::default(),
        );
        let (_, _, bounded) = assert_bounded("find_references", before, after);
        // The full count is still reported, so a caller reading a shortened list
        // can tell it from a complete one without comparing runs.
        assert_eq!(bounded["total_upstream"], serde_json::json!(400));
    }

    #[test]
    fn graph_neighborhood_response_fits_the_budget() {
        let (store, focal_id) = wide_store(400);
        let args = HashMap::from([
            (
                "entity_id".to_string(),
                serde_json::json!(focal_id.to_string()),
            ),
            ("limit".to_string(), serde_json::json!(400)),
            ("depth".to_string(), serde_json::json!(2)),
        ]);
        let before = client_text(
            handle_graph_neighborhood(&args, &store).unwrap(),
            "graph_neighborhood",
            &unbounded(),
        );
        let after = client_text(
            handle_graph_neighborhood(&args, &store).unwrap(),
            "graph_neighborhood",
            &ResponseBudget::default(),
        );
        assert_bounded("graph_neighborhood", before, after);
    }

    #[test]
    fn trace_data_flow_response_fits_the_budget() {
        let store = InMemoryGraph::new();
        let focal = make_entity("Session_request", "src/sessions.rs");
        let focal_id = focal.id;
        store.upsert_entity(&focal).unwrap();
        let mut previous = vec![focal_id];
        for depth in 0..4 {
            let mut next = Vec::new();
            for (parent_index, parent) in previous.iter().enumerate() {
                for index in 0..5 {
                    let callee = make_entity(
                        &format!("step_{depth}_{parent_index}_{index}_resolve_redirect_target"),
                        &format!("src/adapters/level_{depth}/module_{index}.rs"),
                    );
                    store.upsert_entity(&callee).unwrap();
                    store
                        .upsert_relation(&make_relation(*parent, callee.id, RelationKind::Calls))
                        .unwrap();
                    next.push(callee.id);
                }
            }
            previous = next;
        }
        let args = HashMap::from([
            ("focal".to_string(), serde_json::json!(focal_id.to_string())),
            ("direction".to_string(), serde_json::json!("calls")),
            ("depth".to_string(), serde_json::json!(4)),
            ("limit_per_step".to_string(), serde_json::json!(15)),
            ("include_body".to_string(), serde_json::json!(false)),
        ]);
        let mut wide = args.clone();
        wide.insert(
            "max_response_chars".to_string(),
            serde_json::json!(RESPONSE_MAX_MAX_CHARS),
        );
        let before = client_text(
            handle_trace_data_flow(&wide, &store).unwrap(),
            "trace_data_flow",
            &unbounded(),
        );
        let after = client_text(
            handle_trace_data_flow(&args, &store).unwrap(),
            "trace_data_flow",
            &ResponseBudget::default(),
        );
        let (_, _, bounded) = assert_bounded("trace_data_flow", before, after);
        // This tool bounds itself inside its own walk, so the number it enforces
        // has to BE the shared default rather than merely sit under it. A
        // per-tool budget of its own is what let a 79,278-character response
        // report success while the client refused it.
        assert_eq!(
            bounded["max_response_chars"],
            serde_json::json!(RESPONSE_DEFAULT_MAX_CHARS),
            "trace_data_flow answers under the one shared default, not a budget of its own"
        );
    }

    /// FIR-2775. Both reference surfaces must actually EMIT the arrival reading,
    /// not merely be able to read one.
    ///
    /// This exists because the falsification of the shared gate stayed green
    /// under the mutation that deletes the pack's publication. The envelope test
    /// injects the block into both payloads by hand, so it proves the gate reads
    /// a block and proves nothing about whether either handler produces one. Two
    /// tests, each correct, jointly guarding nothing: the property that matters
    /// lives in the agreement between what one side emits and what the other
    /// reads, and only this end asserts the emitting half.
    #[tokio::test]
    async fn both_reference_surfaces_publish_the_arrival_reading() {
        let (store, focal_id) = wide_store(3);
        let sessions = SessionRegistry::empty_for_test();
        let args = HashMap::from([(
            "entity_id".to_string(),
            serde_json::json!(focal_id.to_string()),
        )]);

        let pack = parsed_response(&crate::finalize_with_envelope(
            handle_get_context_pack(&args, &store, &sessions, None).unwrap(),
            structurally_ready_envelope(),
            "get_context_pack",
        ));
        let references = parsed_response(&crate::finalize_with_envelope(
            handle_find_references(&args, &store, None).await.unwrap(),
            structurally_ready_envelope(),
            "find_references",
        ));

        for (label, response) in [
            ("get_context_pack", &pack),
            ("find_references", &references),
        ] {
            let block = &response[crate::caller_arrival::CALLER_ARRIVAL_KEY];
            assert!(
                block.is_object(),
                "{label} must publish the arrival reading the negative envelope gates on; got \
                 {block}"
            );
            // A state the gate recognizes, so the block cannot be present and
            // inert. `caller_arrival_state_unknown` is what an unrecognized one
            // produces, and it would read as a gap for the wrong reason.
            let state = block["state"].as_str().unwrap_or_default();
            assert!(
                matches!(state, "accounted" | "unaccounted" | "unmeasured"),
                "{label} published an arrival state the gate does not recognize: {state:?}"
            );
            // The count the verdict rests on rides beside the rows on every
            // answer, populated or not, so a reader never has to tell "checked
            // and fine" from "not reported".
            assert!(
                block["unaccounted_file_count"].is_u64(),
                "{label} must publish the unaccounted count beside the rows; got {block}"
            );
        }
    }

    #[test]
    fn get_context_pack_response_fits_the_budget() {
        let (store, focal_id) = wide_store(0);
        for index in 0..300 {
            let dep = make_entity(
                &format!("dependency_{index}_rebuild_auth_and_replay_body"),
                &format!("src/deps/module_{index}/inner.rs"),
            );
            store.upsert_entity(&dep).unwrap();
            store
                .upsert_relation(&make_relation(focal_id, dep.id, RelationKind::Calls))
                .unwrap();
        }
        let sessions = SessionRegistry::empty_for_test();
        let args = HashMap::from([
            (
                "entity_id".to_string(),
                serde_json::json!(focal_id.to_string()),
            ),
            ("token_budget".to_string(), serde_json::json!(2_000_000u64)),
            ("depth".to_string(), serde_json::json!(2)),
        ]);
        let before = client_text(
            handle_get_context_pack(&args, &store, &sessions, None).unwrap(),
            "get_context_pack",
            &unbounded(),
        );
        let after = client_text(
            handle_get_context_pack(&args, &store, &sessions, None).unwrap(),
            "get_context_pack",
            &ResponseBudget::default(),
        );
        assert_bounded("get_context_pack", before, after);
    }

    #[test]
    fn bulk_check_references_response_fits_the_budget() {
        let (store, focal_id) = wide_store(200);
        let ids: Vec<serde_json::Value> = store
            .list_all_entities()
            .unwrap()
            .iter()
            .take(200)
            .map(|entity| serde_json::json!(entity.id.to_string()))
            .collect();
        let _ = focal_id;
        let args = |compact: bool| -> HashMap<String, serde_json::Value> {
            HashMap::from([
                ("entity_ids".to_string(), serde_json::json!(ids)),
                ("compact".to_string(), serde_json::json!(compact)),
            ])
        };
        let before = client_text(
            handle_bulk_check_references(&args(false), &store).unwrap(),
            "bulk_check_references",
            &unbounded(),
        );
        let after = client_text(
            handle_bulk_check_references(&args(true), &store).unwrap(),
            "bulk_check_references",
            &ResponseBudget::default(),
        );
        assert_bounded("bulk_check_references", before, after);
    }

    /// The envelope and the confidence-qualified negative are what a caller
    /// reads to know how far a shortened answer can be trusted, so they are the
    /// two things the budget may never take.
    #[test]
    fn the_budget_never_cuts_the_envelope_or_the_negative() {
        let (store, _) = wide_store(400);
        let args = HashMap::from([
            ("query".to_string(), serde_json::json!("caller")),
            ("limit".to_string(), serde_json::json!(200)),
        ]);
        let text = client_text(
            handle_semantic_search(&args, &store).unwrap(),
            "semantic_search",
            &ResponseBudget::default(),
        );
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(value["_kin"]["envelope_version"], serde_json::json!(1));
        assert_eq!(
            value["_kin"]["degraded"]["offline_fallback"],
            serde_json::json!(true)
        );
    }
}
