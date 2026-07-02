// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;

use kin_model::entity::EntityKind;
use kin_model::graph::{EntityFilter, GraphStore};
use kin_model::relation::RelationKind;

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
Rank the code most relevant to a natural-language query using Kin's full fused retrieval \
pipeline — the same multi-signal ranking `kin locate` serves: vector similarity, lexical \
search, and graph-structure signals fused with role-aware ranking, exact-name promotion, \
and (when its model is available) cross-encoder reranking. This is the tool to reach for \
when you are looking for \"where is the code that does X\" and you only have a \
description of the behavior, not an exact symbol name. Unlike semantic_search (which \
matches declarations by name/kind/language and ignores the query for ranking), \
semantic_locate ranks by query relevance and returns act-on-able hits: entity_id, file, \
line span, kind, score, and a bounded inline snippet. Set granularity to \"entity\" \
(default) for ranked declarations or \"file\" to roll results up to the most relevant \
files. The `routing` field reports which pipeline answered (`fused-v1` by default; \
`cosine-v0` when KIN_PROFILE=compat-v0 or `pipeline: \"cosine\"` selects the legacy \
single-vector ranking). The response also reports semantic_coverage — the fraction of \
the graph that has embeddings indexed — plus a `degradations` array naming any \
retrieval capability that could not fully run (empty vector index, reranker model not \
cached, …), so a thin result set is attributable instead of silent. Requires the Kin \
daemon: retrieval runs against the daemon's live graph, so this tool returns an error \
in offline/no-daemon mode. On an empty result the additive `negative` object's \
`safe_to_conclude_absent` flag distinguishes an authoritative \"no match\" from \"not \
yet embedded\".";

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
) -> Result<ToolCallResult> {
    let id_str = get_string_param(args, "entity_id")?;
    let entity_id = parse_entity_id(&id_str)?;

    match store.get_entity(&entity_id).map_err(McpError::graph)? {
        Some(entity) => {
            let value = entity_response_json(store, &entity)?;
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
) -> Result<ToolCallResult> {
    let id_str = get_string_param(args, "entity_id")?;
    let entity_id = parse_entity_id(&id_str)?;

    match store.get_entity(&entity_id).map_err(McpError::graph)? {
        Some(entity) => {
            let body = read_entity_source_excerpt_detailed(store, &entity, 10_000, 1_000_000)
                .ok_or_else(|| McpError::Context("entity source body unavailable".into()))?;
            let is_stale = LAST_READ_STALE.with(|f| f.get());
            let source = LAST_READ_SOURCE.with(|f| f.get());
            let span = entity.span.as_ref();
            let value = serde_json::json!({
                "id": entity.id,
                "name": entity.name,
                "kind": entity.kind,
                "language": entity.language,
                "file_path": entity.file_origin.as_ref().map(|p| p.to_string()),
                "read_path": entity_read_path(&entity),
                "start_line": span.map(|s| s.start_line),
                "end_line": span.map(|s| s.end_line),
                "signature": entity.signature,
                "body": body,
                "stale": is_stale,
                "source": source,
            });
            let json = serde_json::to_string_pretty(&value).map_err(McpError::Json)?;
            Ok(ToolCallResult::text(json))
        }
        None => Ok(ToolCallResult::error(format!(
            "Entity not found: {}",
            id_str
        ))),
    }
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
your context window — with one budgeted call that stays within the limit you set. If \
you only need the focal entity's raw body, get_entity_source is cheaper; if you need to \
follow an actual call chain step by step, use trace_data_flow.";

pub fn handle_get_context_pack<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
    sessions: &SessionRegistry,
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

    // Build structured response JSON.
    let focal_entry = pack.focal_entities.first();
    let focal_entity = store.get_entity(&entity_id).map_err(McpError::graph)?;

    let focal_json = if let (Some(entry), Some(entity)) = (focal_entry, &focal_entity) {
        focal_context_json(store, entry, entity, compact)
    } else {
        serde_json::json!(null)
    };

    let project_dep = |entry: &kin_model::context::ContextEntry| -> serde_json::Value {
        // Look up the entity for structured fields.
        if let Ok(Some(e)) = store.get_entity(&entry.entity_id) {
            let mut obj = serde_json::json!({
                "id": e.id,
                "name": e.name,
                "kind": e.kind,
                "signature": e.signature,
                "file_path": e.file_origin.as_ref().map(|p| p.to_string()),
                "read_path": entity_read_path(&e),
                "start_line": e.span.as_ref().map(|span| span.start_line),
                "end_line": e.span.as_ref().map(|span| span.end_line),
            });
            if !compact {
                obj["projection"] = serde_json::json!(format!("{:?}", entry.projection_level));
                let body = read_entity_source_excerpt_detailed(
                    store,
                    &e,
                    MCP_SOURCE_MAX_LINES,
                    MCP_SOURCE_MAX_CHARS,
                );
                let is_stale = LAST_READ_STALE.with(|f| f.get());
                let source = LAST_READ_SOURCE.with(|f| f.get());
                obj["stale"] = serde_json::json!(is_stale);
                obj["source"] = serde_json::json!(source);
                obj["body"] = serde_json::json!(body.unwrap_or_else(|| entry.content.clone()));
            }
            obj
        } else {
            serde_json::json!({
                "id": entry.entity_id.to_string(),
                "content": entry.content,
            })
        }
    };

    let dependencies: Vec<_> = pack
        .dependency_signatures
        .iter()
        .map(&project_dep)
        .collect();
    let transitive: Vec<_> = pack.transitive_deps.iter().map(&project_dep).collect();

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
        let tests: Vec<_> = pack.tests.iter().map(&project_dep).collect();
        if !tests.is_empty() {
            result["tests"] = serde_json::json!(tests);
        }
        let contracts: Vec<_> = pack.contracts.iter().map(&project_dep).collect();
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

    handle_get_context_pack(&merged, store, sessions)
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
before treating the entity as safe to delete.";

pub async fn handle_find_references<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
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
        return Ok(ToolCallResult::error("Entity not found"));
    };

    let mut rows = collect_graph_reference_rows(store, &target.id, &relation_kinds)?;
    rows.sort_by(|left, right| {
        left.file_path
            .cmp(&right.file_path)
            .then_with(|| left.name.cmp(&right.name))
    });

    // ── Federated Xrefs via Spine ─────────────────────────────────────
    let repo_id = std::env::var("KIN_REPO_ID").unwrap_or_else(|_| "unknown".into());
    match fetch_spine_xref(&repo_id, &target.id).await {
        kin_spine::SpineQuery::Found(body) => {
            if let Some(edges) = body.get("edges").and_then(|v| v.as_array()) {
                for edge in edges {
                    if edge["to_repo_id"] == repo_id && edge["repo_id"] != repo_id {
                        // This is an external caller pointing at us.
                        rows.push(ReferenceRow {
                            // Federated xref: the caller lives in another repo, so
                            // there is no local entity id or graph-owned body here.
                            entity_id: None,
                            name: edge["from_name"].as_str().unwrap_or("unknown").to_string(),
                            kind: edge["kind"].as_str().map(|s| s.to_string()),
                            file_path: Some(format!(
                                "[{}] {}",
                                edge["repo_id"].as_str().unwrap_or("?"),
                                edge["from_name"].as_str().unwrap_or("?")
                            )),
                            start_line: None,
                            signature: None,
                            snippet: None,
                            relation_kinds: vec![RelationKind::References], // Spine edges are generic xrefs
                        });
                    }
                }
            }
        }
        // Spine configured but unreachable: surface as a warning rather than
        // silently dropping cross-repo references (which would read as "none").
        kin_spine::SpineQuery::Unavailable(reason) => {
            tracing::warn!(reason = %reason, "cross-repo spine unavailable for references enrichment");
        }
        // Local-only (no spine configured): quiet — cross-repo refs don't apply.
        kin_spine::SpineQuery::NotConfigured => {}
    }

    let references = rows
        .into_iter()
        .map(|row| {
            serde_json::json!({
                // `entity_id` is the keystone: it lets the agent drill this
                // reference straight to the caller's body
                // (`get_entity_source`/`get_context_pack`) with no name
                // re-resolution and no filesystem fallback. `snippet` carries the
                // caller's bounded body inline so the common drill needs no
                // second round-trip.
                "entity_id": row.entity_id,
                "name": row.name,
                "kind": row.kind,
                "file_path": row.file_path,
                "start_line": row.start_line,
                "signature": row.signature,
                "snippet": row.snippet,
                "relation_kinds": row.relation_kinds.into_iter().map(relation_kind_name).collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>();

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
    });

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

/// Batched reachability check: classify many entities in a single call.
///
/// Returns one row per requested entity_id with `has_references`, `reference_count`,
/// and (in non-compact mode) the matching relation kinds and entity metadata.
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
\"safe to delete\", since an incomplete or stale index can report a false negative.";

pub fn handle_bulk_check_references<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
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
    let mut results = Vec::with_capacity(entity_ids_raw.len());
    let mut with_references = 0usize;

    for raw_id in &entity_ids_raw {
        let entity_id = match parse_entity_id(raw_id) {
            Ok(id) => id,
            Err(_) => {
                let mut row = serde_json::json!({
                    "entity_id": raw_id,
                    "error": "invalid entity_id (not a UUID)",
                });
                if !compact {
                    row["has_references"] = serde_json::json!(false);
                    row["reference_count"] = serde_json::json!(0);
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
                "has_references": false,
                "reference_count": 0,
            });
            if !compact {
                row["name"] = serde_json::Value::Null;
                row["kind"] = serde_json::Value::Null;
                row["file_path"] = serde_json::Value::Null;
                row["matched_kinds"] = serde_json::json!([]);
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

        let has_references = reference_count > 0;
        if has_references {
            with_references += 1;
        }

        if compact {
            results.push(serde_json::json!({
                "entity_id": entity_id,
                "has_references": has_references,
                "reference_count": reference_count,
            }));
        } else {
            matched_kinds.sort_by_key(|kind| relation_kind_rank(kind));
            results.push(serde_json::json!({
                "entity_id": entity_id,
                "name": entity.name,
                "kind": format!("{:?}", entity.kind),
                "file_path": entity.file_origin.as_ref().map(|p| p.to_string()),
                "has_references": has_references,
                "reference_count": reference_count,
                "matched_kinds": matched_kinds
                    .into_iter()
                    .map(relation_kind_name)
                    .collect::<Vec<_>>(),
            }));
        }
    }

    let total_checked = entity_ids_raw.len();
    let result = serde_json::json!({
        "total_checked": total_checked,
        "with_references": with_references,
        "without_references": total_checked - with_references,
        "relation_kinds": relation_kinds
            .iter()
            .copied()
            .map(relation_kind_name)
            .collect::<Vec<_>>(),
        "compact": compact,
        "results": results,
    });

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
) -> Result<ToolCallResult> {
    use kin_context::{build_context_pack, estimate_tokens, ContextOptions};
    use kin_model::context::TokenBudget;

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
                    output.push_str(&format!("  Lines: {}–{}\n", span.start_line, span.end_line));
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
                            if !push_with_budget(
                                &mut output,
                                &mut tokens_used,
                                token_budget,
                                &format!("   Lines: {}–{}\n", span.start_line, span.end_line),
                            ) {
                                output.push_str("  ... (truncated)\n");
                                break;
                            }
                        }

                        let outgoing_calls =
                            outgoing_related_entities(store, &step.id, &[RelationKind::Calls])?;
                        let step_body = trace_body(store, step);
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
                                if !push_indented_body(
                                    &mut output,
                                    &mut tokens_used,
                                    token_budget,
                                    &trace_body(store, constant),
                                ) {
                                    output.push_str("       ... [truncated]\n");
                                    break;
                                }
                            }
                        }
                    }
                }

                if let Some(input_literal) = trace_query.input_literal {
                    if let Some(evaluation) = evaluate_trace_chain(store, &chain, input_literal)? {
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
                        output
                            .push_str(&format!("  Lines: {}–{}\n", span.start_line, span.end_line));
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
flag says whether \"no flow from here\" is authoritative or merely \"not indexed yet\".";

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
    let focal_entity = if let Ok(uuid) = uuid::Uuid::parse_str(trimmed) {
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
    });

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

pub const GRAPH_NEIGHBORHOOD_DESC: &str = "\
Get the dependency neighborhood of an entity — both what it depends on and what depends \
on it — as a compact graph. Starting from an entity ID, Kin traverses the semantic \
relations (calls, imports, implements, …) out to the depth you specify and returns the \
reachable entities as lightweight summaries (id, name, kind, file, signature) plus the \
edges connecting them, along with total counts and a truncation flag. Reach for it when \
you want the structural shape around a symbol — its blast radius and its supports — \
rather than full source bodies: impact-scoping a change, understanding coupling, or \
mapping how a module hangs together. It returns summaries rather than code precisely so \
the neighborhood stays within token budgets even at depth; when you then want to read a \
specific neighbor's implementation, follow up with get_entity_source, and when you want \
a directional ordered chain with bodies inlined, use trace_data_flow. \
When no neighbors come back, the additive `negative` object's `safe_to_conclude_absent` \
flag says whether \"isolated, no dependencies\" is authoritative or merely \"not indexed yet\".";

pub fn handle_graph_neighborhood<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let id_str = get_string_param(args, "entity_id")?;
    let entity_id = parse_entity_id(&id_str)?;
    let depth = get_optional_u64(args, "depth", 2) as u32;
    let limit = get_optional_u64(args, "limit", 30) as usize;

    let neighborhood = store
        .get_dependency_neighborhood(&entity_id, depth)
        .map_err(McpError::graph)?;

    let total_entities = neighborhood.entities.len();
    let total_relations = neighborhood.relations.len();

    // Return compact entity summaries (name, kind, file, id) instead of full
    // entity objects to keep response sizes bounded.
    let compact_entities: Vec<_> = neighborhood
        .entities
        .values()
        .take(limit)
        .map(|e| {
            serde_json::json!({
                "id": e.id,
                "name": e.name,
                "kind": format!("{:?}", e.kind),
                "file_path": e.file_origin.as_ref().map(|p| p.to_string()),
                "signature": e.signature,
            })
        })
        .collect();

    // Cap relations to match the entity limit to avoid unbounded output.
    let compact_relations: Vec<_> = neighborhood
        .relations
        .iter()
        .take(limit * 3)
        .map(|r| {
            serde_json::json!({
                "src": r.src,
                "dst": r.dst,
                "kind": format!("{:?}", r.kind),
            })
        })
        .collect();

    let result = serde_json::json!({
        "entity_count": total_entities,
        "relation_count": total_relations,
        "truncated": total_entities > limit,
        "entities": compact_entities,
        "relations": compact_relations,
    });

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

pub const GRAPH_STATUS_DESC: &str = "\
Report the status of the semantic graph that MCP is serving from — the live entity \
count, embedding-index coverage (embeddings_indexed / embeddings_total / \
embeddings_pending), and the authority backing it. In product mode this is answered by \
the repo daemon, so it reflects the daemon-owned, live graph state rather than a stale \
MCP-local snapshot. Reach for it as a quick health/readiness check: confirm the graph \
is populated, check how much of it has embeddings indexed (so you know whether \
semantic_locate / vector retrieval will be complete or still warming up), and verify \
you're talking to graph-owned truth before relying on the other tools.";

/// Report the health of the graph visible to this dispatcher.
///
/// In product mode this handler runs inside the repo daemon, so the count
/// reflects daemon-owned live graph state. Offline tests may still call it
/// against an explicit in-process graph.
pub fn handle_graph_status<G: GraphStore>(
    _args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let entities = store.list_all_entities().map_err(McpError::graph)?;
    let entity_count = entities.len();

    let result = serde_json::json!({
        "entity_count": entity_count,
        "authority": "repo-daemon",
        "note": "Product MCP calls are served by the repo daemon. Offline in-process dispatch is test-only."
    });

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
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

    fn parsed_response(result: &ToolCallResult) -> serde_json::Value {
        let crate::types::ContentBlock::Text { text } = result
            .content
            .first()
            .expect("expected at least one content block");
        serde_json::from_str(text).expect("response must be valid JSON")
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
        assert_eq!(body["with_references"], 1);
        assert_eq!(body["without_references"], 1);
        assert_eq!(body["compact"], true);
        let rows = body["results"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        let live_row = rows
            .iter()
            .find(|r| r["entity_id"] == serde_json::json!(live_id))
            .unwrap();
        assert_eq!(live_row["has_references"], true);
        assert_eq!(live_row["reference_count"], 2);
        assert!(
            live_row.get("name").is_none(),
            "compact mode must omit name"
        );
        let dead_row = rows
            .iter()
            .find(|r| r["entity_id"] == serde_json::json!(dead_id))
            .unwrap();
        assert_eq!(dead_row["has_references"], false);
        assert_eq!(dead_row["reference_count"], 0);

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
        assert_eq!(calls_resp["results"][0]["reference_count"], 0);

        // Asking for Imports — should match.
        args.insert("relation_kind".to_string(), serde_json::json!("Imports"));
        let imports_resp = parsed_response(&handle_bulk_check_references(&args, &store).unwrap());
        assert_eq!(imports_resp["with_references"], 1);
        assert_eq!(imports_resp["results"][0]["reference_count"], 1);
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

        let body = parsed_response(&handle_find_references(&args, &store).await.unwrap());
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

        let body = parsed_response(&handle_find_references(&args, &store).await.unwrap());
        assert_eq!(body["total_upstream"], 0);
        assert!(body["references"].as_array().unwrap().is_empty());
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
}
