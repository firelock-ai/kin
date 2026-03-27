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

pub fn handle_get_entity<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let id_str = get_string_param(args, "entity_id")?;
    let entity_id = parse_entity_id(&id_str)?;

    match store.get_entity(&entity_id).map_err(McpError::graph)? {
        Some(entity) => {
            let value = entity_response_json(&entity)?;
            let json = serde_json::to_string_pretty(&value).map_err(McpError::Json)?;
            Ok(ToolCallResult::text(json))
        }
        None => Ok(ToolCallResult::error(format!(
            "Entity not found: {}",
            id_str
        ))),
    }
}

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
        focal_context_json(entry, entity, compact)
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
                obj["body"] = serde_json::json!(read_entity_source_excerpt(
                    &e,
                    MCP_SOURCE_MAX_LINES,
                    MCP_SOURCE_MAX_CHARS
                )
                .unwrap_or_else(|| entry.content.clone()));
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

pub fn handle_find_references<G: GraphStore>(
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
    if let Some(source_root) = resolve_reference_source_root() {
        let text_refs = kin_core::find_text_references(&source_root, &target, &relation_kinds);
        merge_text_reference_rows(&mut rows, text_refs);
    }
    rows.sort_by(|left, right| {
        left.file_path
            .cmp(&right.file_path)
            .then_with(|| left.name.cmp(&right.name))
    });

    let references = rows
        .into_iter()
        .map(|row| {
            serde_json::json!({
                "name": row.name,
                "kind": row.kind,
                "file_path": row.file_path,
                "start_line": row.start_line,
                "signature": row.signature,
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
                        let step_body = trace_body(step);
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
                                    &trace_body(constant),
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

                let mut decoy_candidates = matches;
                if decoy_candidates.len() <= 1 {
                    if let Some(broader_query) = broaden_trace_query(&trace_query.symbol) {
                        let broader_matches = store
                            .query_entities(&EntityFilter {
                                name_pattern: Some(broader_query),
                                ..Default::default()
                            })
                            .map_err(McpError::graph)?;
                        for entity in broader_matches {
                            if !decoy_candidates.iter().any(|known| known.id == entity.id) {
                                decoy_candidates.push(entity);
                            }
                        }
                    }
                }

                let decoys = decoy_candidates
                    .into_iter()
                    .filter(|entity| entity.id != focal.id)
                    .filter(|entity| {
                        looks_like_alt_name(&entity.name)
                            || entity
                                .file_origin
                                .as_ref()
                                .map(|path| looks_like_decoy_path(path.0.as_str()))
                                .unwrap_or(false)
                    })
                    .collect::<Vec<_>>();

                if !decoys.is_empty() {
                    let header = "\n## Similar/Decoy Matches\n";
                    if push_with_budget(&mut output, &mut tokens_used, token_budget, header) {
                        for entity in decoys {
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
