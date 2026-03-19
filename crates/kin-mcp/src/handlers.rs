// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Firelock, LLC

use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use kin_model::entity::{Entity, EntityKind, SourceSpan, Visibility};
use kin_model::graph::{EntityFilter, GraphStore};
use kin_model::ids::{
    EntityId, FilePathId, Hash256, IntentId, LanguageId, SemanticChangeId, SessionId,
};
use kin_model::relation::RelationKind;
use kin_model::session::{IntentScope, LockType, SessionCapabilities, SessionTransport};
use kin_model::timestamp::Timestamp;
use kin_review::{compute_diff, format_review, SemanticReview};

use crate::error::{McpError, Result};
use crate::session::SessionRegistry;
use crate::types::ToolCallResult;

/// Dispatch a tool call to the appropriate handler.
pub fn handle_tool_call<G: GraphStore>(
    tool_name: &str,
    arguments: &HashMap<String, serde_json::Value>,
    store: &G,
    sessions: &SessionRegistry,
) -> Result<ToolCallResult> {
    match tool_name {
        "semantic_search" => handle_semantic_search(arguments, store),
        "get_entity" => handle_get_entity(arguments, store),
        "get_context_pack" => handle_get_context_pack(arguments, store, sessions),
        "find_references" => handle_find_references(arguments, store),
        "impact_analysis" => handle_impact_analysis(arguments, store, sessions),
        "semantic_diff" => handle_semantic_diff(arguments, store),
        "semantic_review" => handle_semantic_review(arguments, store, sessions),
        "dead_code" => handle_dead_code(arguments, store),
        "entity_history" => handle_entity_history(arguments, store),
        "graph_neighborhood" => handle_graph_neighborhood(arguments, store),
        "benchmark" => handle_benchmark(arguments, store),
        "register_session" => handle_register_session(arguments, sessions),
        "explore_codebase" => handle_explore_codebase(arguments, store),
        // Phase 7: session/intent/traffic tools
        "kin_session_start" => handle_session_start(arguments, sessions),
        "kin_session_heartbeat" => handle_session_heartbeat(arguments, sessions),
        "kin_session_end" => handle_session_end(arguments, sessions),
        "kin_register_intent" => handle_register_intent(arguments, sessions),
        "kin_release_intent" => handle_release_intent(arguments, sessions),
        "kin_check_traffic" => handle_check_traffic(arguments, sessions),
        // Phase 8: work graph and annotation tools
        "kin_work_create" => handle_work_create(arguments, store),
        "kin_work_list" => handle_work_list(arguments, store),
        "kin_work_show" => handle_work_show(arguments, store),
        "kin_work_link" => handle_work_link(arguments, store),
        "kin_work_decompose" => handle_work_decompose(arguments, store),
        "kin_work_block" => handle_work_block(arguments, store),
        "kin_work_implement" => handle_work_implement(arguments, store),
        "kin_work_status" => handle_work_status(arguments, store),
        "kin_annotation_add" => handle_annotation_add(arguments, store),
        "kin_annotation_list" => handle_annotation_list(arguments, store),
        "kin_annotation_mark_resolved" => handle_annotation_mark_resolved(arguments, store),
        "kin_todo_import" => handle_todo_import(arguments, store),
        // Phase 9-10: verification, security, release, contract, provenance tools
        "kin_verify_entity" => handle_verify_entity(arguments, store),
        "kin_coverage_summary" => handle_coverage_summary(store),
        "kin_security_scan" => handle_security_scan(arguments, store),
        "kin_release_check" => handle_release_check(arguments, store),
        "kin_contract_check" => handle_contract_check(arguments, store),
        "kin_provenance_query" => handle_provenance_query(arguments, store),
        _ => Err(McpError::ToolNotFound(tool_name.to_string())),
    }
}

fn get_string_param(args: &HashMap<String, serde_json::Value>, key: &str) -> Result<String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| McpError::InvalidParams(format!("missing required parameter: {}", key)))
}

fn get_optional_u64(args: &HashMap<String, serde_json::Value>, key: &str, default: u64) -> u64 {
    args.get(key).and_then(|v| v.as_u64()).unwrap_or(default)
}

fn get_optional_bool(args: &HashMap<String, serde_json::Value>, key: &str, default: bool) -> bool {
    args.get(key).and_then(|v| v.as_bool()).unwrap_or(default)
}

fn get_optional_string_param(
    args: &HashMap<String, serde_json::Value>,
    key: &str,
) -> Option<String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn get_optional_string_array(
    args: &HashMap<String, serde_json::Value>,
    key: &str,
) -> Option<Vec<String>> {
    args.get(key).and_then(|value| {
        value.as_array().map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(|s| s.to_string()))
                .collect()
        })
    })
}

fn parse_entity_id(s: &str) -> Result<EntityId> {
    // EntityId wraps uuid::Uuid which is re-exported through its Display/FromStr
    let parsed: Result<EntityId> = serde_json::from_value(serde_json::json!(s))
        .map_err(|e| McpError::InvalidParams(format!("invalid entity_id: {}", e)));
    parsed
}

fn parse_change_id(s: &str) -> Result<SemanticChangeId> {
    Hash256::from_hex(s)
        .map(SemanticChangeId::from_hash)
        .map_err(|e| McpError::InvalidParams(format!("invalid change ID hex: {}", e)))
}

fn parse_session_id(s: &str) -> Result<SessionId> {
    serde_json::from_value(serde_json::json!(s))
        .map_err(|e| McpError::InvalidParams(format!("invalid session_id: {}", e)))
}

fn parse_intent_id(s: &str) -> Result<IntentId> {
    serde_json::from_value(serde_json::json!(s))
        .map_err(|e| McpError::InvalidParams(format!("invalid intent_id: {}", e)))
}

fn parse_transport(s: &str) -> SessionTransport {
    match s.to_lowercase().as_str() {
        "mcp" => SessionTransport::Mcp,
        "cli" => SessionTransport::Cli,
        "wrapper" => SessionTransport::Wrapper,
        "ui" => SessionTransport::Ui,
        _ => SessionTransport::Mcp,
    }
}

fn parse_lock_type(s: &str) -> LockType {
    match s.to_lowercase().as_str() {
        "hard" => LockType::Hard,
        _ => LockType::Soft,
    }
}

fn parse_reference_kind(kind: &str) -> Option<RelationKind> {
    match kind.to_ascii_lowercase().as_str() {
        "calls" | "call" => Some(RelationKind::Calls),
        "imports" | "import" => Some(RelationKind::Imports),
        "references" | "reference" | "refs" => Some(RelationKind::References),
        _ => None,
    }
}

fn default_reference_kinds() -> Vec<RelationKind> {
    vec![
        RelationKind::Calls,
        RelationKind::Imports,
        RelationKind::References,
    ]
}

fn relation_kind_name(kind: RelationKind) -> &'static str {
    match kind {
        RelationKind::Calls => "calls",
        RelationKind::Imports => "imports",
        RelationKind::References => "references",
        _ => "other",
    }
}

fn relation_kind_rank(kind: &RelationKind) -> usize {
    match kind {
        RelationKind::Imports => 0,
        RelationKind::Calls => 1,
        RelationKind::References => 2,
        _ => 3,
    }
}

fn select_best_reference_target<G: GraphStore>(
    store: &G,
    query: &str,
) -> std::result::Result<Option<Entity>, G::Error> {
    let matches = store.query_entities(&EntityFilter {
        name_pattern: Some(query.to_string()),
        ..Default::default()
    })?;
    if matches.is_empty() {
        return Ok(None);
    }

    type RankingKey = (bool, bool, usize, usize, usize, bool, bool, std::cmp::Reverse<usize>);
    let mut best: Option<(Entity, RankingKey)> = None;

    for entity in matches {
        let relations = store.get_all_relations_for_entity(&entity.id)?;
        let incoming_refs = relations
            .iter()
            .filter(|rel| {
                rel.dst == entity.id
                    && matches!(
                        rel.kind,
                        RelationKind::Calls | RelationKind::Imports | RelationKind::References
                    )
            })
            .count();
        let direct_signal = relations
            .iter()
            .filter(|rel| {
                rel.dst == entity.id
                    && matches!(rel.kind, RelationKind::Calls | RelationKind::Imports)
            })
            .count();
        let path = entity
            .file_origin
            .as_ref()
            .map(|f| f.0.as_str())
            .unwrap_or("");
        let looks_decoy = looks_like_decoy_path(path) || looks_like_alt_name(&entity.name);
        let exported = matches!(entity.visibility, Visibility::Public | Visibility::Internal);
        let score = (
            entity.name == query,
            exported,
            declaration_kind_rank(&entity.kind),
            direct_signal,
            incoming_refs,
            entity.file_origin.is_some(),
            !looks_decoy,
            std::cmp::Reverse(entity.name.len()),
        );
        if best
            .as_ref()
            .map(|(_, best_score)| score > *best_score)
            .unwrap_or(true)
        {
            best = Some((entity, score));
        }
    }

    Ok(best.map(|(entity, _)| entity))
}

fn declaration_kind_rank(kind: &EntityKind) -> usize {
    match kind {
        EntityKind::Function
        | EntityKind::Method
        | EntityKind::Interface
        | EntityKind::TypeAlias => 3,
        EntityKind::Class | EntityKind::TraitDef | EntityKind::EnumDef => 2,
        EntityKind::Constant | EntityKind::StaticVar => 1,
        _ => 0,
    }
}

fn looks_like_decoy_path(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.contains("/decoy")
        || lower.contains("decoy_")
        || lower.contains("/local_")
        || lower.contains("/fake_")
}

fn looks_like_alt_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    lower.contains("alt") || lower.contains("decoy")
}

fn entity_directory(entity: &Entity) -> Option<String> {
    entity
        .file_origin
        .as_ref()
        .and_then(|path| Path::new(path.0.as_str()).parent())
        .map(|dir| dir.to_string_lossy().into_owned())
}

fn broaden_trace_query(query: &str) -> Option<String> {
    query
        .rsplit_once('_')
        .map(|(prefix, _)| prefix.to_string())
        .filter(|prefix| prefix.len() >= 4 && prefix != query)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TraceQuery {
    symbol: String,
    input_literal: Option<i64>,
}

fn parse_trace_query(query: &str) -> TraceQuery {
    let trimmed = query.trim();
    if let Some(open_paren) = trimmed.find('(') {
        if trimmed.ends_with(')') && open_paren > 0 {
            let symbol = trimmed[..open_paren].trim();
            let arg = trimmed[open_paren + 1..trimmed.len() - 1].trim();
            if !symbol.is_empty() && !arg.is_empty() && !arg.contains(',') {
                if let Ok(input_literal) = arg.parse::<i64>() {
                    return TraceQuery {
                        symbol: symbol.to_string(),
                        input_literal: Some(input_literal),
                    };
                }
            }
        }
    }

    TraceQuery {
        symbol: trimmed.to_string(),
        input_literal: None,
    }
}

fn outgoing_related_entities<G: GraphStore>(
    store: &G,
    entity_id: &EntityId,
    allowed_kinds: &[RelationKind],
) -> Result<Vec<Entity>> {
    let allowed: HashSet<_> = allowed_kinds.iter().copied().collect();
    let mut seen = HashSet::new();
    let mut entities = Vec::new();

    for rel in store
        .get_all_relations_for_entity(entity_id)
        .map_err(McpError::graph)?
    {
        if rel.src != *entity_id || !allowed.contains(&rel.kind) || !seen.insert(rel.dst) {
            continue;
        }
        let Some(entity) = store.get_entity(&rel.dst).map_err(McpError::graph)? else {
            continue;
        };
        entities.push(entity);
    }

    Ok(entities)
}

fn outgoing_related_entities_with_kinds<G: GraphStore>(
    store: &G,
    entity_id: &EntityId,
    allowed_kinds: &[RelationKind],
) -> Result<Vec<(Entity, RelationKind)>> {
    let allowed: HashSet<_> = allowed_kinds.iter().copied().collect();
    let mut seen = HashSet::new();
    let mut entities = Vec::new();

    for rel in store
        .get_all_relations_for_entity(entity_id)
        .map_err(McpError::graph)?
    {
        if rel.src != *entity_id || !allowed.contains(&rel.kind) || !seen.insert(rel.dst) {
            continue;
        }
        let Some(entity) = store.get_entity(&rel.dst).map_err(McpError::graph)? else {
            continue;
        };
        entities.push((entity, rel.kind));
    }

    Ok(entities)
}

fn is_trace_function(entity: &Entity) -> bool {
    matches!(entity.kind, EntityKind::Function | EntityKind::Method)
}

fn trace_relation_rank(kind: RelationKind) -> usize {
    match kind {
        RelationKind::Calls => 2,
        RelationKind::Imports => 1,
        RelationKind::References => 0,
        _ => 0,
    }
}

fn trace_callee_score(
    entity: &Entity,
    relation_kind: RelationKind,
    focal_dir: Option<&str>,
) -> (usize, bool, bool, usize, bool, usize) {
    let same_dir = focal_dir
        .zip(entity_directory(entity))
        .map(|(root, dir)| root == dir)
        .unwrap_or(false);
    (
        trace_relation_rank(relation_kind),
        same_dir,
        !looks_like_alt_name(&entity.name)
            && entity
                .file_origin
                .as_ref()
                .map(|path| !looks_like_decoy_path(path.0.as_str()))
                .unwrap_or(true),
        declaration_kind_rank(&entity.kind),
        entity.file_origin.is_some(),
        usize::MAX.saturating_sub(entity.name.len()),
    )
}

fn next_trace_step<G: GraphStore>(
    store: &G,
    current: &Entity,
    focal_dir: Option<&str>,
) -> Result<Option<Entity>> {
    let mut successors = outgoing_related_entities_with_kinds(
        store,
        &current.id,
        &[
            RelationKind::Calls,
            RelationKind::Imports,
            RelationKind::References,
        ],
    )?
    .into_iter()
    .filter(|(entity, _)| is_trace_function(entity))
    .collect::<Vec<_>>();

    if successors.is_empty() {
        return Ok(None);
    }

    successors.sort_by(|(left_entity, left_kind), (right_entity, right_kind)| {
        trace_callee_score(right_entity, *right_kind, focal_dir)
            .cmp(&trace_callee_score(left_entity, *left_kind, focal_dir))
            .then_with(|| left_entity.name.cmp(&right_entity.name))
    });

    Ok(successors.into_iter().next().map(|(entity, _)| entity))
}

fn collect_primary_trace_chain<G: GraphStore>(
    store: &G,
    focal: &Entity,
    max_steps: usize,
) -> Result<Vec<Entity>> {
    let focal_dir = entity_directory(focal);
    let mut chain = Vec::new();
    let mut seen = HashSet::new();
    let mut current = focal.clone();

    while chain.len() < max_steps && seen.insert(current.id) {
        chain.push(current.clone());

        let Some(next) = next_trace_step(store, &current, focal_dir.as_deref())? else {
            break;
        };
        current = next;
    }

    Ok(chain)
}

fn trace_body(entity: &Entity) -> String {
    read_entity_source_excerpt(entity, MCP_SOURCE_MAX_LINES, MCP_SOURCE_MAX_CHARS)
        .unwrap_or_else(|| entity.signature.clone())
}

fn looks_like_constant_identifier(token: &str) -> bool {
    if token.len() < 3 {
        return false;
    }

    let mut has_upper = false;
    let mut has_underscore = false;
    for ch in token.chars() {
        if ch == '_' {
            has_underscore = true;
        } else if ch.is_ascii_uppercase() {
            has_upper = true;
        } else if !ch.is_ascii_alphanumeric() {
            return false;
        }
    }

    has_upper && has_underscore
}

fn extract_constant_identifiers(body: &str) -> Vec<String> {
    let mut identifiers = Vec::new();
    let mut seen = HashSet::new();
    let mut current = String::new();

    let flush =
        |current: &mut String, identifiers: &mut Vec<String>, seen: &mut HashSet<String>| {
            if current.is_empty() {
                return;
            }
            if looks_like_constant_identifier(current) && seen.insert(current.clone()) {
                identifiers.push(current.clone());
            }
            current.clear();
        };

    for ch in body.chars() {
        if ch.is_ascii_alphanumeric() || ch == '_' {
            current.push(ch);
        } else {
            flush(&mut current, &mut identifiers, &mut seen);
        }
    }
    flush(&mut current, &mut identifiers, &mut seen);

    identifiers
}

fn trace_constant_score(entity: &Entity, focal_dir: Option<&str>) -> (bool, bool, usize) {
    let same_dir = focal_dir
        .zip(entity_directory(entity))
        .map(|(root, dir)| root == dir)
        .unwrap_or(false);
    (
        same_dir,
        entity.file_origin.is_some(),
        usize::MAX.saturating_sub(entity.name.len()),
    )
}

fn inferred_trace_constants<G: GraphStore>(
    store: &G,
    step: &Entity,
    body: &str,
) -> Result<Vec<Entity>> {
    let focal_dir = entity_directory(step);
    let mut constants = Vec::new();
    let mut seen = HashSet::new();

    for identifier in extract_constant_identifiers(body) {
        let mut matches = store
            .query_entities(&EntityFilter {
                name_pattern: Some(identifier.clone()),
                ..Default::default()
            })
            .map_err(McpError::graph)?
            .into_iter()
            .filter(|entity| {
                entity.name == identifier
                    && matches!(entity.kind, EntityKind::Constant | EntityKind::StaticVar)
            })
            .collect::<Vec<_>>();

        matches.sort_by(|left, right| {
            trace_constant_score(right, focal_dir.as_deref())
                .cmp(&trace_constant_score(left, focal_dir.as_deref()))
                .then_with(|| left.name.cmp(&right.name))
        });

        if let Some(entity) = matches.into_iter().next() {
            if seen.insert(entity.id) {
                constants.push(entity);
            }
        }
    }

    Ok(constants)
}

fn trace_constants_for_step<G: GraphStore>(
    store: &G,
    step: &Entity,
    body: &str,
) -> Result<Vec<Entity>> {
    let mut constants = outgoing_related_entities(
        store,
        &step.id,
        &[RelationKind::Imports, RelationKind::References],
    )?
    .into_iter()
    .filter(|entity| matches!(entity.kind, EntityKind::Constant | EntityKind::StaticVar))
    .collect::<Vec<_>>();
    let mut seen_constant_ids = constants
        .iter()
        .map(|entity| entity.id)
        .collect::<HashSet<_>>();
    for constant in inferred_trace_constants(store, step, body)? {
        if seen_constant_ids.insert(constant.id) {
            constants.push(constant);
        }
    }
    Ok(constants)
}

fn parse_trace_constant_value(body: &str) -> Option<i64> {
    for line in body.lines() {
        let trimmed = line.trim();
        let Some((_, rhs)) = trimmed.split_once('=') else {
            continue;
        };
        let numeric = rhs.trim().trim_end_matches(';');
        if let Ok(value) = numeric.parse::<i64>() {
            return Some(value);
        }
    }
    None
}

fn clean_trace_expr(expr: &str) -> &str {
    expr.trim()
        .trim_end_matches(';')
        .trim_end_matches('{')
        .trim_end_matches('}')
        .trim()
}

fn parse_trace_assignment(line: &str) -> Option<(String, String)> {
    let trimmed = line.trim();
    if trimmed.starts_with("if ")
        || trimmed.starts_with("if(")
        || trimmed.starts_with("return ")
        || trimmed.starts_with("pub fn ")
        || trimmed.starts_with("fn ")
        || trimmed.starts_with("def ")
        || trimmed.starts_with("export function ")
    {
        return None;
    }

    let assignment = trimmed
        .strip_prefix("let ")
        .or_else(|| trimmed.strip_prefix("const "))
        .or_else(|| trimmed.strip_prefix("var "))
        .unwrap_or(trimmed);
    let (lhs, rhs) = assignment.split_once('=')?;
    let variable = lhs.split_whitespace().last()?.trim();
    if variable.is_empty() || variable.contains('(') {
        return None;
    }

    Some((variable.to_string(), clean_trace_expr(rhs).to_string()))
}

fn parse_trace_even_condition_var(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if !trimmed.starts_with("if") || !trimmed.contains("% 2") {
        return None;
    }

    let after_if = trimmed
        .strip_prefix("if")
        .unwrap_or(trimmed)
        .trim()
        .trim_start_matches('(');
    let variable = after_if
        .split("% 2")
        .next()?
        .trim()
        .trim_matches('(')
        .trim_matches(')');
    if variable.is_empty() {
        None
    } else {
        Some(variable.to_string())
    }
}

fn extract_trace_expression(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.is_empty()
        || trimmed == "{"
        || trimmed == "}"
        || trimmed == "else"
        || trimmed == "else:"
        || trimmed.starts_with("//")
        || trimmed.starts_with('#')
        || trimmed.starts_with("\"\"\"")
        || trimmed.starts_with("pub fn ")
        || trimmed.starts_with("fn ")
        || trimmed.starts_with("def ")
        || trimmed.starts_with("export function ")
        || trimmed.starts_with("if ")
        || trimmed.starts_with("if(")
        || trimmed.contains(" else ")
        || trimmed.starts_with("use ")
        || trimmed.starts_with("import ")
        || trimmed.starts_with("from ")
    {
        return None;
    }

    if let Some(expr) = trimmed.strip_prefix("return ") {
        return Some(clean_trace_expr(expr).to_string());
    }

    if trimmed.contains('=') {
        return None;
    }

    let expr = clean_trace_expr(trimmed);
    if expr.is_empty() {
        None
    } else {
        Some(expr.to_string())
    }
}

fn evaluate_trace_operand(
    operand: &str,
    env: &HashMap<String, i64>,
    function_values: &HashMap<String, i64>,
    constant_values: &HashMap<String, i64>,
) -> Option<(i64, String)> {
    let token = operand.trim().trim_end_matches(';');
    if token.is_empty() {
        return None;
    }

    if let Ok(value) = token.parse::<i64>() {
        return Some((value, value.to_string()));
    }

    if let Some(value) = env.get(token) {
        return Some((*value, value.to_string()));
    }

    if let Some(value) = constant_values.get(token) {
        return Some((*value, value.to_string()));
    }

    if let Some((name, _)) = token.split_once('(') {
        if let Some(value) = function_values.get(name.trim()) {
            return Some((*value, value.to_string()));
        }
    }

    None
}

fn evaluate_trace_expression(
    expr: &str,
    env: &HashMap<String, i64>,
    function_values: &HashMap<String, i64>,
    constant_values: &HashMap<String, i64>,
) -> Option<(i64, String)> {
    for operator in [" + ", " - ", " * "] {
        if let Some((left, right)) = expr.split_once(operator) {
            let (left_value, left_detail) =
                evaluate_trace_operand(left, env, function_values, constant_values)?;
            let (right_value, right_detail) =
                evaluate_trace_operand(right, env, function_values, constant_values)?;
            let value = match operator.trim() {
                "+" => left_value + right_value,
                "-" => left_value - right_value,
                "*" => left_value * right_value,
                _ => return None,
            };
            return Some((
                value,
                format!("{left_detail} {} {right_detail}", operator.trim()),
            ));
        }
    }

    evaluate_trace_operand(expr, env, function_values, constant_values)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TraceEvaluationStep {
    name: String,
    value: i64,
    detail: String,
}

fn evaluate_trace_step_body(
    body: &str,
    input_literal: i64,
    function_values: &HashMap<String, i64>,
    constant_values: &HashMap<String, i64>,
) -> Option<(i64, String)> {
    let mut env = HashMap::new();
    env.insert("n".to_string(), input_literal);
    let lines = body.lines().map(str::trim).collect::<Vec<_>>();
    let mut index = 0;

    while index < lines.len() {
        let line = lines[index];

        if let Some((variable, rhs)) = parse_trace_assignment(line) {
            let (value, _) =
                evaluate_trace_expression(&rhs, &env, function_values, constant_values)?;
            env.insert(variable, value);
            index += 1;
            continue;
        }

        if let Some(variable) = parse_trace_even_condition_var(line) {
            let subject = *env.get(&variable)?;
            let mut even_expr = None;
            let mut odd_expr = None;
            let mut in_else = false;
            index += 1;

            while index < lines.len() {
                let branch_line = lines[index];
                if branch_line.contains("else") {
                    in_else = true;
                    index += 1;
                    continue;
                }
                if let Some(expr) = extract_trace_expression(branch_line) {
                    if in_else {
                        odd_expr.get_or_insert(expr);
                    } else {
                        even_expr.get_or_insert(expr);
                    }
                }
                index += 1;
            }

            let (branch_name, chosen_expr) = if subject % 2 == 0 {
                ("even", even_expr?)
            } else {
                ("odd", odd_expr?)
            };
            let (value, detail) =
                evaluate_trace_expression(&chosen_expr, &env, function_values, constant_values)?;
            return Some((value, format!("{subject} is {branch_name}, so {detail}")));
        }

        if let Some(expr) = extract_trace_expression(line) {
            return evaluate_trace_expression(&expr, &env, function_values, constant_values);
        }

        index += 1;
    }

    None
}

fn evaluate_trace_chain<G: GraphStore>(
    store: &G,
    chain: &[Entity],
    input_literal: i64,
) -> Result<Option<Vec<TraceEvaluationStep>>> {
    let mut constant_values = HashMap::new();
    for step in chain {
        let body = trace_body(step);
        for constant in trace_constants_for_step(store, step, &body)? {
            if let Some(value) = parse_trace_constant_value(&trace_body(&constant)) {
                constant_values
                    .entry(constant.name.clone())
                    .or_insert(value);
            }
        }
    }

    let mut function_values = HashMap::new();
    let mut evaluation = Vec::new();

    for step in chain.iter().rev() {
        let body = trace_body(step);
        let Some((value, detail)) =
            evaluate_trace_step_body(&body, input_literal, &function_values, &constant_values)
        else {
            return Ok(None);
        };
        function_values.insert(step.name.clone(), value);
        evaluation.push(TraceEvaluationStep {
            name: step.name.clone(),
            value,
            detail,
        });
    }

    Ok(Some(evaluation))
}

fn push_with_budget(
    output: &mut String,
    tokens_used: &mut usize,
    token_budget: usize,
    text: &str,
) -> bool {
    let line_tokens = kin_context::estimate_tokens(text);
    if *tokens_used + line_tokens > token_budget {
        return false;
    }
    *tokens_used += line_tokens;
    output.push_str(text);
    true
}

fn push_indented_body(
    output: &mut String,
    tokens_used: &mut usize,
    token_budget: usize,
    body: &str,
) -> bool {
    for line in body.lines() {
        if !push_with_budget(
            output,
            tokens_used,
            token_budget,
            &format!("       {line}\n"),
        ) {
            return false;
        }
    }
    true
}

#[derive(Debug, Clone)]
struct ReferenceRow {
    name: String,
    kind: Option<String>,
    file_path: Option<String>,
    start_line: Option<u32>,
    signature: Option<String>,
    relation_kinds: Vec<RelationKind>,
}

fn collect_graph_reference_rows<G: GraphStore>(
    store: &G,
    entity_id: &EntityId,
    relation_kinds: &[RelationKind],
) -> Result<Vec<ReferenceRow>> {
    let allowed: std::collections::HashSet<_> = relation_kinds.iter().copied().collect();
    let mut grouped: HashMap<String, ReferenceRow> = HashMap::new();

    for rel in store
        .get_all_relations_for_entity(entity_id)
        .map_err(McpError::graph)?
    {
        if rel.dst != *entity_id || !allowed.contains(&rel.kind) {
            continue;
        }
        let Some(entity) = store.get_entity(&rel.src).map_err(McpError::graph)? else {
            continue;
        };

        let file_path = entity.file_origin.as_ref().map(|path| path.0.clone());
        let key = reference_row_key(file_path.as_deref(), &entity.name);
        let entry = grouped.entry(key).or_insert_with(|| ReferenceRow {
            name: entity.name.clone(),
            kind: Some(format!("{:?}", entity.kind)),
            file_path: file_path.clone(),
            start_line: entity.span.as_ref().map(|span| span.start_line),
            signature: Some(entity.signature.clone()),
            relation_kinds: Vec::new(),
        });
        if entry.file_path.is_none() {
            entry.file_path = file_path;
        }
        if entry.start_line.is_none() {
            entry.start_line = entity.span.as_ref().map(|span| span.start_line);
        }
        if entry.signature.is_none() {
            entry.signature = Some(entity.signature.clone());
        }
        push_reference_kind(&mut entry.relation_kinds, rel.kind);
    }

    let mut rows = grouped.into_values().collect::<Vec<_>>();
    for row in &mut rows {
        row.relation_kinds.sort_by_key(relation_kind_rank);
    }
    Ok(rows)
}

fn merge_text_reference_rows(
    rows: &mut Vec<ReferenceRow>,
    text_refs: Vec<kin_core::TextReferenceMatch>,
) {
    let mut index_by_key = HashMap::new();
    for (index, row) in rows.iter().enumerate() {
        index_by_key.insert(
            reference_row_key(row.file_path.as_deref(), &row.name),
            index,
        );
        if let Some(path) = row.file_path.as_deref() {
            index_by_key.insert(path.to_string(), index);
        }
    }

    for text_ref in text_refs {
        let key = text_ref.file_path.clone();
        if let Some(existing) = index_by_key.get(&key).copied() {
            let row = &mut rows[existing];
            if row.start_line.is_none() {
                row.start_line = text_ref.start_line;
            }
            for kind in text_ref.relation_kinds {
                push_reference_kind(&mut row.relation_kinds, kind);
            }
            row.relation_kinds.sort_by_key(relation_kind_rank);
            continue;
        }

        let index = rows.len();
        rows.push(ReferenceRow {
            name: label_from_path(&text_ref.file_path),
            kind: None,
            file_path: Some(text_ref.file_path.clone()),
            start_line: text_ref.start_line,
            signature: None,
            relation_kinds: text_ref.relation_kinds,
        });
        index_by_key.insert(key, index);
    }
}

fn reference_row_key(file_path: Option<&str>, name: &str) -> String {
    file_path
        .map(|path| path.to_string())
        .unwrap_or_else(|| format!("name:{name}"))
}

const MCP_SOURCE_MAX_LINES: usize = 40;
const MCP_SOURCE_MAX_CHARS: usize = 2400;

fn label_from_path(rel_path: &str) -> String {
    Path::new(rel_path)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or(rel_path)
        .to_string()
}

fn push_reference_kind(kinds: &mut Vec<RelationKind>, kind: RelationKind) {
    if !kinds.contains(&kind) {
        kinds.push(kind);
    }
}

fn resolve_reference_source_root() -> Option<PathBuf> {
    candidate_source_roots().into_iter().next()
}

fn candidate_source_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();

    if let Some(root) = std::env::var_os("KIN_SOURCE_ROOT") {
        let root = PathBuf::from(root);
        if root.is_dir() {
            roots.push(root);
        }
    }

    if let Ok(cwd) = std::env::current_dir() {
        if cwd.is_dir() && !roots.iter().any(|root| root == &cwd) {
            roots.push(cwd);
        }
    }

    roots
}

fn display_read_path(rel_path: &str) -> String {
    if std::env::var_os("KIN_SOURCE_ROOT").is_some() {
        format!(".kin/source-root/{rel_path}")
    } else {
        rel_path.to_string()
    }
}

fn entity_read_path(entity: &Entity) -> Option<String> {
    entity
        .file_origin
        .as_ref()
        .map(|path| display_read_path(path.0.as_str()))
}

fn resolve_entity_source_path(entity: &Entity) -> Option<PathBuf> {
    let rel_path = entity.file_origin.as_ref()?.0.as_str();

    for root in candidate_source_roots() {
        let candidate = root.join(rel_path);
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    None
}

fn read_entity_source_excerpt(
    entity: &Entity,
    max_lines: usize,
    max_chars: usize,
) -> Option<String> {
    let span = entity.span.as_ref()?;
    let path = resolve_entity_source_path(entity)?;
    let bytes = std::fs::read(path).ok()?;
    let excerpt = excerpt_from_span_bytes(&bytes, span, max_lines, max_chars);
    if let Some(ref excerpt) = excerpt {
        if !should_expand_excerpt(entity, excerpt) {
            return Some(excerpt.clone());
        }
    }

    let text = String::from_utf8_lossy(&bytes);
    expand_entity_source_excerpt(entity, &text, span.start_byte, max_lines, max_chars).or(excerpt)
}

fn excerpt_from_span_bytes(
    bytes: &[u8],
    span: &SourceSpan,
    max_lines: usize,
    max_chars: usize,
) -> Option<String> {
    let start = span.start_byte.min(bytes.len());
    let end = span.end_byte.min(bytes.len());
    if start < end {
        let snippet = String::from_utf8_lossy(&bytes[start..end]);
        let clipped = clip_rendered_text_with_cap(&snippet, max_lines, max_chars);
        if !clipped.trim().is_empty() {
            return Some(clipped);
        }
    }

    let text = String::from_utf8_lossy(bytes);
    excerpt_from_line_range(&text, span.start_line, span.end_line, max_lines, max_chars)
}

fn excerpt_from_line_range(
    content: &str,
    start_line: u32,
    end_line: u32,
    max_lines: usize,
    max_chars: usize,
) -> Option<String> {
    if start_line == 0 || end_line == 0 || end_line < start_line {
        return None;
    }

    let snippet = content
        .lines()
        .enumerate()
        .filter_map(|(idx, line)| {
            let line_no = idx as u32 + 1;
            (line_no >= start_line && line_no <= end_line).then_some(line)
        })
        .collect::<Vec<_>>()
        .join("\n");

    if snippet.trim().is_empty() {
        return None;
    }

    Some(clip_rendered_text_with_cap(&snippet, max_lines, max_chars))
}

fn should_expand_excerpt(entity: &Entity, excerpt: &str) -> bool {
    matches!(
        entity.kind,
        EntityKind::Function | EntityKind::Method | EntityKind::Class
    ) && (excerpt.trim() == entity.signature.trim()
        || excerpt
            .lines()
            .filter(|line| !line.trim().is_empty())
            .count()
            <= 1)
}

fn expand_entity_source_excerpt(
    entity: &Entity,
    content: &str,
    start_byte: usize,
    max_lines: usize,
    max_chars: usize,
) -> Option<String> {
    let start_idx = line_index_for_byte(content.as_bytes(), start_byte);
    match entity.language {
        LanguageId::Python => expand_python_block_excerpt(content, start_idx, max_lines, max_chars),
        LanguageId::JavaScript
        | LanguageId::TypeScript
        | LanguageId::Rust
        | LanguageId::Go
        | LanguageId::Java
        | LanguageId::C
        | LanguageId::Cpp
        | LanguageId::CSharp => {
            expand_brace_block_excerpt(content, start_idx, max_lines, max_chars)
        }
        LanguageId::Ruby => expand_ruby_block_excerpt(content, start_idx, max_lines, max_chars),
    }
}

fn line_index_for_byte(bytes: &[u8], byte: usize) -> usize {
    bytes[..byte.min(bytes.len())]
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
}

fn expand_python_block_excerpt(
    content: &str,
    start_idx: usize,
    max_lines: usize,
    max_chars: usize,
) -> Option<String> {
    let lines: Vec<&str> = content.lines().collect();
    let header = *lines.get(start_idx)?;
    if header.trim().is_empty() || !header.trim_end().ends_with(':') {
        return None;
    }

    let base_indent = leading_indent(header);
    let mut collected = vec![header];
    let mut saw_body = false;

    for line in lines.iter().skip(start_idx + 1) {
        if line.trim().is_empty() {
            collected.push(*line);
            continue;
        }

        let indent = leading_indent(line);
        if indent <= base_indent {
            break;
        }

        saw_body = true;
        collected.push(*line);
    }

    saw_body.then(|| clip_rendered_text_with_cap(&collected.join("\n"), max_lines, max_chars))
}

fn expand_brace_block_excerpt(
    content: &str,
    start_idx: usize,
    max_lines: usize,
    max_chars: usize,
) -> Option<String> {
    let lines: Vec<&str> = content.lines().collect();
    let first = *lines.get(start_idx)?;
    if first.trim().is_empty() {
        return None;
    }

    let mut collected = Vec::new();
    let mut depth: i32 = 0;
    let mut saw_open = false;

    for line in lines.iter().skip(start_idx) {
        collected.push(*line);
        for ch in line.chars() {
            match ch {
                '{' => {
                    depth += 1;
                    saw_open = true;
                }
                '}' if saw_open => depth -= 1,
                _ => {}
            }
        }

        if saw_open && depth <= 0 {
            return Some(clip_rendered_text_with_cap(
                &collected.join("\n"),
                max_lines,
                max_chars,
            ));
        }

        if !saw_open && collected.len() >= 3 {
            break;
        }
    }

    None
}

fn expand_ruby_block_excerpt(
    content: &str,
    start_idx: usize,
    max_lines: usize,
    max_chars: usize,
) -> Option<String> {
    let lines: Vec<&str> = content.lines().collect();
    let first = *lines.get(start_idx)?;
    if first.trim().is_empty() {
        return None;
    }

    let mut collected = Vec::new();
    let mut depth: i32 = 0;
    let mut saw_block = false;

    for line in lines.iter().skip(start_idx) {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            collected.push(*line);
            continue;
        }

        if starts_ruby_block(trimmed) {
            depth += 1;
            saw_block = true;
        }

        collected.push(*line);

        if saw_block && trimmed == "end" {
            depth -= 1;
            if depth <= 0 {
                return Some(clip_rendered_text_with_cap(
                    &collected.join("\n"),
                    max_lines,
                    max_chars,
                ));
            }
        }
    }

    None
}

fn starts_ruby_block(line: &str) -> bool {
    matches!(
        line.split_whitespace().next(),
        Some("class" | "module" | "def" | "if" | "unless" | "case" | "begin" | "do")
    )
}

fn leading_indent(line: &str) -> usize {
    line.chars()
        .take_while(|ch| matches!(ch, ' ' | '\t'))
        .count()
}

fn clip_rendered_text_with_cap(text: &str, max_lines: usize, max_chars: usize) -> String {
    let mut clipped_lines = Vec::new();
    let mut truncated = false;

    for (idx, line) in text.lines().enumerate() {
        if idx >= max_lines {
            truncated = true;
            break;
        }
        clipped_lines.push(line);
    }

    let mut out = clipped_lines.join("\n");
    if out.chars().count() > max_chars {
        out = out.chars().take(max_chars).collect::<String>();
        truncated = true;
    }
    if truncated {
        if !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str("... [truncated]");
    }
    out
}

fn entity_response_json(entity: &Entity) -> Result<serde_json::Value> {
    let mut value = serde_json::to_value(entity).map_err(McpError::Json)?;
    let Some(obj) = value.as_object_mut() else {
        return Ok(value);
    };

    if let Some(read_path) = entity_read_path(entity) {
        obj.insert("read_path".into(), serde_json::json!(read_path));
    }
    if let Some(span) = entity.span.as_ref() {
        obj.insert("start_line".into(), serde_json::json!(span.start_line));
        obj.insert("end_line".into(), serde_json::json!(span.end_line));
    }
    if let Some(source_excerpt) =
        read_entity_source_excerpt(entity, MCP_SOURCE_MAX_LINES, MCP_SOURCE_MAX_CHARS)
    {
        obj.insert("source_excerpt".into(), serde_json::json!(source_excerpt));
    }

    Ok(value)
}

fn focal_context_json(
    entry: &kin_model::ContextEntry,
    entity: &Entity,
    compact: bool,
) -> serde_json::Value {
    let start_line = entity.span.as_ref().map(|span| span.start_line);
    let end_line = entity.span.as_ref().map(|span| span.end_line);
    let source_excerpt =
        read_entity_source_excerpt(entity, MCP_SOURCE_MAX_LINES, MCP_SOURCE_MAX_CHARS);

    let mut obj = serde_json::json!({
        "id": entity.id,
        "name": entity.name,
        "kind": entity.kind,
        "signature": entity.signature,
        "file_path": entity.file_origin.as_ref().map(|p| p.to_string()),
        "read_path": entity_read_path(entity),
        "start_line": start_line,
        "end_line": end_line,
    });

    if !compact {
        obj["body"] = serde_json::json!(source_excerpt.unwrap_or_else(|| entry.content.clone()));
    }

    obj
}

fn parse_scopes(value: &serde_json::Value) -> Result<Vec<IntentScope>> {
    let arr = value
        .as_array()
        .ok_or_else(|| McpError::InvalidParams("scopes must be an array".into()))?;

    let mut scopes = Vec::with_capacity(arr.len());
    for item in arr {
        let scope: IntentScope = serde_json::from_value(item.clone()).map_err(|e| {
            McpError::InvalidParams(format!(
                "invalid scope: {}. Expected {{\"Entity\": \"uuid\"}}, {{\"Contract\": \"uuid\"}}, or {{\"Artifact\": \"path\"}}",
                e
            ))
        })?;
        scopes.push(scope);
    }
    Ok(scopes)
}

fn parse_capabilities(args: &HashMap<String, serde_json::Value>) -> SessionCapabilities {
    match args.get("capabilities") {
        Some(v) if v.is_object() => {
            let obj = v.as_object().unwrap();
            SessionCapabilities {
                can_read: obj
                    .get("can_read")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(true),
                can_write: obj
                    .get("can_write")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                can_execute: obj
                    .get("can_execute")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                can_branch: obj
                    .get("can_branch")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                can_commit: obj
                    .get("can_commit")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                max_concurrent_intents: obj
                    .get("max_concurrent_intents")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(1) as usize,
            }
        }
        _ => SessionCapabilities::default(),
    }
}

// ── Original tool handlers ──

fn handle_semantic_search<G: GraphStore>(
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

fn build_semantic_search_request(
    args: &HashMap<String, serde_json::Value>,
) -> Result<(String, usize, EntityFilter)> {
    let query = get_string_param(args, "query")?;
    let limit = get_optional_u64(args, "limit", 20) as usize;

    let kind_filter = args
        .get("kind")
        .and_then(|v| v.as_str())
        .and_then(parse_kind_filter);
    let language_filter = args
        .get("language")
        .and_then(|v| v.as_str())
        .and_then(parse_language_filter);

    let filter = EntityFilter {
        kinds: kind_filter,
        languages: language_filter,
        name_pattern: Some(query.clone()),
        ..Default::default()
    };

    Ok((query, limit, filter))
}

fn parse_kind_filter(kind: &str) -> Option<Vec<EntityKind>> {
    match kind.to_lowercase().as_str() {
        "function" | "fn" => Some(vec![EntityKind::Function, EntityKind::Method]),
        "class" => Some(vec![EntityKind::Class]),
        "interface" => Some(vec![EntityKind::Interface]),
        "trait" | "traitdef" => Some(vec![EntityKind::TraitDef]),
        "type_alias" => Some(vec![EntityKind::TypeAlias]),
        "module" => Some(vec![EntityKind::Module]),
        "package" => Some(vec![EntityKind::Package]),
        "test" => Some(vec![EntityKind::Test]),
        "schema" => Some(vec![EntityKind::Schema]),
        "api_endpoint" => Some(vec![EntityKind::ApiEndpoint]),
        "event_contract" => Some(vec![EntityKind::EventContract]),
        "method" => Some(vec![EntityKind::Method]),
        "enum" | "enumdef" => Some(vec![EntityKind::EnumDef]),
        "constant" => Some(vec![EntityKind::Constant]),
        _ => None,
    }
}

fn parse_language_filter(language: &str) -> Option<Vec<LanguageId>> {
    match language.to_lowercase().as_str() {
        "rust" => Some(vec![LanguageId::Rust]),
        "typescript" | "ts" => Some(vec![LanguageId::TypeScript]),
        "javascript" | "js" => Some(vec![LanguageId::JavaScript]),
        "python" | "py" => Some(vec![LanguageId::Python]),
        "go" => Some(vec![LanguageId::Go]),
        "java" => Some(vec![LanguageId::Java]),
        "c" => Some(vec![LanguageId::C]),
        "cpp" | "c++" | "cc" | "cxx" | "hpp" => Some(vec![LanguageId::Cpp]),
        "csharp" | "c#" | "cs" => Some(vec![LanguageId::CSharp]),
        "ruby" | "rb" => Some(vec![LanguageId::Ruby]),
        _ => None,
    }
}

#[derive(Debug, Serialize)]
struct SemanticSearchResponse {
    query: String,
    limit: usize,
    total_matches: usize,
    truncated: bool,
    results: Vec<SemanticSearchResult>,
}

#[derive(Debug, Serialize)]
struct SemanticSearchResult {
    id: EntityId,
    name: String,
    kind: EntityKind,
    language: LanguageId,
    file_path: Option<String>,
    start_line: Option<u32>,
    signature: String,
    doc_summary: Option<String>,
}

impl From<kin_model::entity::Entity> for SemanticSearchResult {
    fn from(entity: kin_model::entity::Entity) -> Self {
        let start_line = entity.span.as_ref().map(|span| span.start_line);
        Self {
            id: entity.id,
            name: entity.name,
            kind: entity.kind,
            language: entity.language,
            file_path: entity.file_origin.as_ref().map(|p| p.to_string()),
            start_line,
            signature: entity.signature,
            doc_summary: entity.doc_summary,
        }
    }
}

#[derive(Debug, Serialize)]
struct CompactSearchResponse {
    query: String,
    limit: usize,
    total_matches: usize,
    truncated: bool,
    results: Vec<CompactSearchResult>,
}

#[derive(Debug, Serialize)]
struct CompactSearchResult {
    id: EntityId,
    name: String,
    kind: EntityKind,
    language: LanguageId,
    file_path: Option<String>,
    start_line: Option<u32>,
    end_line: Option<u32>,
    signature: String,
}

impl From<kin_model::entity::Entity> for CompactSearchResult {
    fn from(entity: kin_model::entity::Entity) -> Self {
        let start_line = entity.span.as_ref().map(|span| span.start_line);
        let end_line = entity.span.as_ref().map(|span| span.end_line);
        Self {
            id: entity.id,
            name: entity.name,
            kind: entity.kind,
            language: entity.language,
            file_path: entity.file_origin.as_ref().map(|p| p.to_string()),
            start_line,
            end_line,
            signature: entity.signature,
        }
    }
}

fn handle_get_entity<G: GraphStore>(
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

fn handle_get_context_pack<G: GraphStore>(
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

fn handle_find_references<G: GraphStore>(
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

fn handle_explore_codebase<G: GraphStore>(
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

fn handle_impact_analysis<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
    sessions: &SessionRegistry,
) -> Result<ToolCallResult> {
    let base_hex = get_string_param(args, "base")?;
    let head_hex = get_string_param(args, "head")?;
    let base = parse_change_id(&base_hex)?;
    let head = parse_change_id(&head_hex)?;
    let include_traffic = get_optional_bool(args, "include_traffic", true);

    let diff = compute_diff(store, &base, &head).map_err(|e| McpError::Review(e.to_string()))?;

    let impact =
        kin_review::analyze_impact(store, &diff).map_err(|e| McpError::Review(e.to_string()))?;

    let mut result = serde_json::to_value(&impact).map_err(McpError::Json)?;

    if include_traffic {
        // Collect traffic for all changed entities.
        let mut all_traffic = Vec::new();
        for change in &diff.entity_changes {
            let traffic = sessions.get_traffic_near_entity(&change.entity_id);
            for summary in traffic {
                if !all_traffic
                    .iter()
                    .any(|t: &kin_model::session::IntentSummary| t.intent_id == summary.intent_id)
                {
                    all_traffic.push(summary);
                }
            }
        }
        if !all_traffic.is_empty() {
            result["active_traffic"] =
                serde_json::to_value(&all_traffic).map_err(McpError::Json)?;
        }
    }

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

fn handle_semantic_diff<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let base_hex = get_string_param(args, "base")?;
    let head_hex = get_string_param(args, "head")?;
    let base = parse_change_id(&base_hex)?;
    let head = parse_change_id(&head_hex)?;

    let diff = compute_diff(store, &base, &head).map_err(|e| McpError::Review(e.to_string()))?;

    let formatted = kin_review::format_diff(&diff);
    Ok(ToolCallResult::text(formatted))
}

fn handle_semantic_review<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
    sessions: &SessionRegistry,
) -> Result<ToolCallResult> {
    let base_hex = get_string_param(args, "base")?;
    let head_hex = get_string_param(args, "head")?;
    let base = parse_change_id(&base_hex)?;
    let head = parse_change_id(&head_hex)?;
    let include_traffic = get_optional_bool(args, "include_traffic", true);

    let review = SemanticReview::create_review(&base, &head, store)
        .map_err(|e| McpError::Review(e.to_string()))?;

    let formatted = format_review(&review);

    if include_traffic {
        // Collect traffic for all entities in the diff.
        let mut traffic_lines = Vec::new();
        for change in &review.diff.entity_changes {
            let traffic = sessions.get_traffic_near_entity(&change.entity_id);
            for summary in &traffic {
                traffic_lines.push(format!(
                    "  {} ({}) is {} entity {} [{}]",
                    summary.vendor,
                    summary.session_id,
                    summary.task_description,
                    change.entity_id,
                    summary.lock_type_label(),
                ));
            }
        }

        if traffic_lines.is_empty() {
            Ok(ToolCallResult::text(formatted))
        } else {
            let with_traffic = format!(
                "{}\n\n--- Active Traffic ---\n{}",
                formatted,
                traffic_lines.join("\n")
            );
            Ok(ToolCallResult::text(with_traffic))
        }
    } else {
        Ok(ToolCallResult::text(formatted))
    }
}

fn handle_dead_code<G: GraphStore>(
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
                    file_path: Some(FilePathId::new(file)),
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

fn handle_entity_history<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let id_str = get_string_param(args, "entity_id")?;
    let entity_id = parse_entity_id(&id_str)?;

    let history = store
        .get_entity_history(&entity_id)
        .map_err(McpError::graph)?;

    let json = serde_json::to_string_pretty(&history).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

fn handle_graph_neighborhood<G: GraphStore>(
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

fn handle_benchmark<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let _category = args.get("category").and_then(|v| v.as_str());

    // Collect available metrics
    let dep_coverage = kin_bench::MetricCollector::collect_dependency_coverage(store)
        .map_err(|e| McpError::Other(e.to_string()))?;

    let dead_code = kin_bench::MetricCollector::collect_dead_code_stats(store)
        .map_err(|e| McpError::Other(e.to_string()))?;

    let result = serde_json::json!({
        "dependency_coverage": dep_coverage,
        "dead_code": dead_code,
    });

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

fn handle_register_session(
    args: &HashMap<String, serde_json::Value>,
    sessions: &SessionRegistry,
) -> Result<ToolCallResult> {
    let assistant_name = get_string_param(args, "assistant_name")?;
    let session_id = args
        .get("session_id")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .unwrap_or_else(|| EntityId::new().to_string());

    sessions.register(&session_id, &assistant_name);

    let result = serde_json::json!({
        "session_id": session_id,
        "assistant": assistant_name,
        "status": "registered",
    });

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

// ── Phase 7: Session/Intent/Traffic handlers ──

fn handle_session_start(
    args: &HashMap<String, serde_json::Value>,
    sessions: &SessionRegistry,
) -> Result<ToolCallResult> {
    let vendor = get_string_param(args, "vendor")?;
    let client_name = get_string_param(args, "client_name")?;
    let cwd_str = get_string_param(args, "cwd")?;

    let transport_str = args
        .get("transport")
        .and_then(|v| v.as_str())
        .unwrap_or("mcp");
    let transport = parse_transport(transport_str);

    let pid = args.get("pid").and_then(|v| v.as_u64()).map(|p| p as u32);
    let cwd = PathBuf::from(cwd_str);
    let capabilities = parse_capabilities(args);

    let session =
        sessions.start_agent_session(&vendor, &client_name, transport, pid, cwd, capabilities);

    let result = serde_json::json!({
        "session_id": session.session_id.to_string(),
        "vendor": session.vendor,
        "client_name": session.client_name,
        "transport": session.transport,
        "started_at": session.started_at,
        "capabilities": session.capabilities,
        "status": "active",
    });

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

fn handle_session_heartbeat(
    args: &HashMap<String, serde_json::Value>,
    sessions: &SessionRegistry,
) -> Result<ToolCallResult> {
    let id_str = get_string_param(args, "session_id")?;
    let session_id = parse_session_id(&id_str)?;

    let alive = sessions.heartbeat(&session_id);

    if alive {
        let result = serde_json::json!({
            "session_id": id_str,
            "status": "alive",
            "heartbeat_at": Timestamp::now(),
        });
        let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
        Ok(ToolCallResult::text(json))
    } else {
        Ok(ToolCallResult::error(format!(
            "Session not found: {}",
            id_str
        )))
    }
}

fn handle_session_end(
    args: &HashMap<String, serde_json::Value>,
    sessions: &SessionRegistry,
) -> Result<ToolCallResult> {
    let id_str = get_string_param(args, "session_id")?;
    let session_id = parse_session_id(&id_str)?;

    match sessions.end_agent_session(&session_id) {
        Some(session) => {
            let result = serde_json::json!({
                "session_id": id_str,
                "vendor": session.vendor,
                "status": "ended",
                "started_at": session.started_at,
                "ended_at": Timestamp::now(),
            });
            let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
            Ok(ToolCallResult::text(json))
        }
        None => Ok(ToolCallResult::error(format!(
            "Session not found: {}",
            id_str
        ))),
    }
}

fn handle_register_intent(
    args: &HashMap<String, serde_json::Value>,
    sessions: &SessionRegistry,
) -> Result<ToolCallResult> {
    let id_str = get_string_param(args, "session_id")?;
    let session_id = parse_session_id(&id_str)?;
    let task_description = get_string_param(args, "task_description")?;

    let scopes_val = args
        .get("scopes")
        .ok_or_else(|| McpError::InvalidParams("missing required parameter: scopes".into()))?;
    let scopes = parse_scopes(scopes_val)?;

    let lock_type_str = args
        .get("lock_type")
        .and_then(|v| v.as_str())
        .unwrap_or("soft");
    let lock_type = parse_lock_type(lock_type_str);

    let expires_at: Option<Timestamp> = args
        .get("expires_at")
        .and_then(|v| v.as_str())
        .and_then(|s| serde_json::from_value(serde_json::json!(s)).ok());

    match sessions.register_intent(session_id, scopes, lock_type, task_description, expires_at) {
        Some(intent) => {
            let result = serde_json::json!({
                "intent_id": intent.intent_id.to_string(),
                "session_id": intent.session_id.to_string(),
                "scopes": intent.scopes,
                "lock_type": intent.lock_type,
                "task_description": intent.task_description,
                "registered_at": intent.registered_at,
                "status": "registered",
            });
            let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
            Ok(ToolCallResult::text(json))
        }
        None => Ok(ToolCallResult::error(format!(
            "Session not found: {}. Start a session with kin_session_start first.",
            id_str
        ))),
    }
}

fn handle_release_intent(
    args: &HashMap<String, serde_json::Value>,
    sessions: &SessionRegistry,
) -> Result<ToolCallResult> {
    let session_str = get_string_param(args, "session_id")?;
    let intent_str = get_string_param(args, "intent_id")?;
    let session_id = parse_session_id(&session_str)?;
    let intent_id = parse_intent_id(&intent_str)?;

    match sessions.release_intent(&session_id, &intent_id) {
        Some(intent) => {
            let result = serde_json::json!({
                "intent_id": intent_str,
                "session_id": session_str,
                "task_description": intent.task_description,
                "status": "released",
            });
            let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
            Ok(ToolCallResult::text(json))
        }
        None => Ok(ToolCallResult::error(format!(
            "Intent not found or not owned by session: intent={}, session={}",
            intent_str, session_str
        ))),
    }
}

fn handle_check_traffic(
    args: &HashMap<String, serde_json::Value>,
    sessions: &SessionRegistry,
) -> Result<ToolCallResult> {
    let scopes_val = args
        .get("scopes")
        .ok_or_else(|| McpError::InvalidParams("missing required parameter: scopes".into()))?;
    let scopes = parse_scopes(scopes_val)?;

    let reports = sessions.check_traffic(&scopes);

    let result = serde_json::json!({
        "reports": reports,
        "scope_count": scopes.len(),
    });

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

// ---------------------------------------------------------------------------
// Phase 8: Work graph and annotation handlers
// ---------------------------------------------------------------------------

fn handle_work_create<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let kind_str = get_string_param(args, "kind")?;
    let title = get_string_param(args, "title")?;
    let description = args
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let kind: kin_model::WorkKind = kind_str
        .parse()
        .map_err(|e: String| McpError::InvalidParams(e))?;

    let scopes = parse_work_scopes(args.get("scopes"))?;
    let acceptance_criteria = args
        .get("acceptance_criteria")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let item = kin_model::WorkItem {
        work_id: kin_model::WorkId::new(),
        kind,
        title: title.clone(),
        description,
        status: kin_model::WorkStatus::Proposed,
        priority: kin_model::Priority::None,
        scopes,
        acceptance_criteria,
        external_refs: vec![],
        created_by: kin_model::IdentityRef::assistant("mcp-client"),
        created_at: Timestamp::now(),
    };

    store
        .create_work_item(&item)
        .map_err(|e| McpError::Other(e.to_string()))?;
    for scope in &item.scopes {
        store
            .create_work_link(&kin_model::WorkLink::Affects {
                work_id: item.work_id,
                scope: scope.clone(),
            })
            .map_err(|e| McpError::Other(e.to_string()))?;
    }

    let result = serde_json::json!({
        "work_id": item.work_id.to_string(),
        "kind": item.kind.to_string(),
        "title": title,
        "status": "proposed",
    });
    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

fn handle_work_list<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let status = args.get("status").and_then(|v| v.as_str());
    let kind = args.get("kind").and_then(|v| v.as_str());
    let scope = args.get("scope").and_then(|v| v.as_str());

    let filter = kin_model::WorkFilter {
        statuses: status
            .map(|s| {
                s.parse::<kin_model::WorkStatus>()
                    .map(|ws| vec![ws])
                    .map_err(McpError::InvalidParams)
            })
            .transpose()?,
        kinds: kind
            .map(|k| {
                k.parse::<kin_model::WorkKind>()
                    .map(|wk| vec![wk])
                    .map_err(McpError::InvalidParams)
            })
            .transpose()?,
        scope: scope.map(parse_single_work_scope).transpose()?,
    };

    let items = store
        .list_work_items(&filter)
        .map_err(|e| McpError::Other(e.to_string()))?;

    let result: Vec<_> = items
        .iter()
        .map(|i| {
            serde_json::json!({
                "work_id": i.work_id.to_string(),
                "kind": i.kind.to_string(),
                "title": i.title,
                "status": i.status.to_string(),
                "priority": i.priority.to_string(),
            })
        })
        .collect();

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

fn handle_work_show<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let (work_id_str, id) = parse_work_id_param(args, "work_id")?;

    let item = store
        .get_work_item(&id)
        .map_err(|e| McpError::Other(e.to_string()))?
        .ok_or_else(|| McpError::InvalidParams(format!("work item not found: {}", work_id_str)))?;

    let children = store
        .get_child_work_items(&id)
        .map_err(|e| McpError::Other(e.to_string()))?;
    let parents = store
        .get_parent_work_items(&id)
        .map_err(|e| McpError::Other(e.to_string()))?;
    let blockers = store
        .get_blockers(&id)
        .map_err(|e| McpError::Other(e.to_string()))?;
    let blocked_items = store
        .get_blocked_work_items(&id)
        .map_err(|e| McpError::Other(e.to_string()))?;
    let implementors = store
        .get_implementors(&id)
        .map_err(|e| McpError::Other(e.to_string()))?;
    let annotations = store
        .get_annotations_for_work_item(&id)
        .map_err(|e| McpError::Other(e.to_string()))?;

    let result = serde_json::json!({
        "work_id": item.work_id.to_string(),
        "kind": item.kind.to_string(),
        "title": item.title,
        "description": item.description,
        "status": item.status.to_string(),
        "priority": item.priority.to_string(),
        "scopes": item.scopes.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        "acceptance_criteria": item.acceptance_criteria,
        "parents": parents.iter().map(summarize_work_item).collect::<Vec<_>>(),
        "children": children.iter().map(|c| serde_json::json!({
            "work_id": c.work_id.to_string(),
            "kind": c.kind.to_string(),
            "title": c.title,
            "status": c.status.to_string(),
        })).collect::<Vec<_>>(),
        "blockers": blockers.iter().map(summarize_work_item).collect::<Vec<_>>(),
        "blocked_items": blocked_items.iter().map(summarize_work_item).collect::<Vec<_>>(),
        "implementors": implementors.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        "annotations": annotations.iter().map(summarize_annotation).collect::<Vec<_>>(),
    });

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

fn handle_work_link<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let (work_id_str, id) = parse_work_id_param(args, "work_id")?;

    let scopes = parse_work_scopes(args.get("scopes"))?;
    if scopes.is_empty() {
        return Err(McpError::InvalidParams("scopes array is empty".into()));
    }

    let mut item = store
        .get_work_item(&id)
        .map_err(|e| McpError::Other(e.to_string()))?
        .ok_or_else(|| McpError::InvalidParams(format!("work item not found: {}", work_id_str)))?;

    for scope in &scopes {
        if !item.scopes.contains(scope) {
            item.scopes.push(scope.clone());
        }
        let link = kin_model::WorkLink::Affects {
            work_id: id,
            scope: scope.clone(),
        };
        store
            .create_work_link(&link)
            .map_err(|e| McpError::Other(e.to_string()))?;
    }
    store
        .create_work_item(&item)
        .map_err(|e| McpError::Other(e.to_string()))?;

    let result = serde_json::json!({
        "work_id": work_id_str,
        "linked_scopes": scopes.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
    });
    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

fn handle_work_decompose<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let (parent_work_id, parent) = parse_work_id_param(args, "parent_work_id")?;
    let (child_work_id, child) = parse_work_id_param(args, "child_work_id")?;
    ensure_work_item_exists(store, &parent, &parent_work_id)?;
    ensure_work_item_exists(store, &child, &child_work_id)?;
    store
        .create_work_link(&kin_model::WorkLink::DecomposesTo { parent, child })
        .map_err(|e| McpError::Other(e.to_string()))?;
    Ok(ToolCallResult::text(
        serde_json::to_string_pretty(&serde_json::json!({
            "parent_work_id": parent_work_id,
            "child_work_id": child_work_id,
            "linked": true,
        }))
        .map_err(McpError::Json)?,
    ))
}

fn handle_work_block<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let (blocked_work_id, blocked) = parse_work_id_param(args, "blocked_work_id")?;
    let (blocker_work_id, blocker) = parse_work_id_param(args, "blocker_work_id")?;
    ensure_work_item_exists(store, &blocked, &blocked_work_id)?;
    ensure_work_item_exists(store, &blocker, &blocker_work_id)?;
    store
        .create_work_link(&kin_model::WorkLink::BlockedBy { blocked, blocker })
        .map_err(|e| McpError::Other(e.to_string()))?;
    Ok(ToolCallResult::text(
        serde_json::to_string_pretty(&serde_json::json!({
            "blocked_work_id": blocked_work_id,
            "blocker_work_id": blocker_work_id,
            "linked": true,
        }))
        .map_err(McpError::Json)?,
    ))
}

fn handle_work_implement<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let (work_id_str, work_id) = parse_work_id_param(args, "work_id")?;
    ensure_work_item_exists(store, &work_id, &work_id_str)?;
    let scopes = parse_work_scopes(args.get("scopes"))?;
    if scopes.is_empty() {
        return Err(McpError::InvalidParams("scopes array is empty".into()));
    }
    for scope in &scopes {
        store
            .create_work_link(&kin_model::WorkLink::Implements {
                scope: scope.clone(),
                work_id,
            })
            .map_err(|e| McpError::Other(e.to_string()))?;
    }
    Ok(ToolCallResult::text(
        serde_json::to_string_pretty(&serde_json::json!({
            "work_id": work_id_str,
            "implementors": scopes.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        }))
        .map_err(McpError::Json)?,
    ))
}

fn handle_work_status<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let (work_id_str, work_id) = parse_work_id_param(args, "work_id")?;
    ensure_work_item_exists(store, &work_id, &work_id_str)?;
    let status_str = get_string_param(args, "status")?;
    let status = status_str
        .parse::<kin_model::WorkStatus>()
        .map_err(McpError::InvalidParams)?;
    store
        .update_work_status(&work_id, status)
        .map_err(|e| McpError::Other(e.to_string()))?;
    Ok(ToolCallResult::text(
        serde_json::to_string_pretty(&serde_json::json!({
            "work_id": work_id_str,
            "status": status.to_string(),
        }))
        .map_err(McpError::Json)?,
    ))
}

fn handle_annotation_add<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let kind_str = get_string_param(args, "kind")?;
    let body = get_string_param(args, "body")?;
    let kind: kin_model::AnnotationKind = kind_str
        .parse()
        .map_err(|e: String| McpError::InvalidParams(e))?;

    let targets = parse_annotation_targets(args)?;
    if targets.is_empty() {
        return Err(McpError::InvalidParams(
            "targets or scopes must contain at least one value".into(),
        ));
    }

    let mut scopes = Vec::new();
    let mut seen_scopes = std::collections::HashSet::new();
    for target in &targets {
        match target {
            kin_model::AnnotationTarget::Scope(scope) => {
                if seen_scopes.insert(scope.to_string()) {
                    scopes.push(scope.clone());
                }
            }
            kin_model::AnnotationTarget::Work(work_id) => {
                let item = ensure_work_item_exists(store, work_id, &work_id.to_string())?;
                for scope in item.scopes {
                    if seen_scopes.insert(scope.to_string()) {
                        scopes.push(scope);
                    }
                }
            }
        }
    }

    let ann = kin_model::Annotation {
        annotation_id: kin_model::AnnotationId::new(),
        kind,
        body: body.clone(),
        scopes,
        anchored_fingerprint: None,
        authored_by: kin_model::IdentityRef::assistant("mcp-client"),
        created_at: Timestamp::now(),
        staleness: kin_model::StalenessState::Fresh,
    };

    store
        .create_annotation(&ann)
        .map_err(|e| McpError::Other(e.to_string()))?;
    for target in &targets {
        store
            .create_work_link(&kin_model::WorkLink::AttachedTo {
                annotation_id: ann.annotation_id,
                target: target.clone(),
            })
            .map_err(|e| McpError::Other(e.to_string()))?;
    }

    let result = serde_json::json!({
        "annotation_id": ann.annotation_id.to_string(),
        "kind": ann.kind.to_string(),
        "targets": targets.iter().map(|t| t.to_string()).collect::<Vec<_>>(),
    });
    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

fn handle_annotation_list<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let include_stale = get_optional_bool(args, "include_stale", true);
    let targets = parse_annotation_targets(args)?;

    let annotations = if targets.is_empty() {
        let filter = kin_model::AnnotationFilter {
            include_stale,
            ..Default::default()
        };
        store
            .list_annotations(&filter)
            .map_err(|e| McpError::Other(e.to_string()))?
    } else {
        let mut seen = std::collections::HashSet::new();
        let mut collected = Vec::new();
        for target in targets {
            let items = match target {
                kin_model::AnnotationTarget::Scope(scope) => store
                    .get_annotations_for_scope(&scope)
                    .map_err(|e| McpError::Other(e.to_string()))?,
                kin_model::AnnotationTarget::Work(work_id) => store
                    .get_annotations_for_work_item(&work_id)
                    .map_err(|e| McpError::Other(e.to_string()))?,
            };
            for annotation in items {
                if (!matches!(annotation.staleness, kin_model::StalenessState::Stale)
                    || include_stale)
                    && seen.insert(annotation.annotation_id)
                {
                    collected.push(annotation);
                }
            }
        }
        collected
    };

    let result: Vec<_> = annotations
        .iter()
        .map(|a| {
            serde_json::json!({
                "annotation_id": a.annotation_id.to_string(),
                "kind": a.kind.to_string(),
                "body": a.body,
                "staleness": a.staleness.to_string(),
                "scopes": a.scopes.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
            })
        })
        .collect();

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

fn handle_annotation_mark_resolved<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let ann_id_str = get_string_param(args, "annotation_id")?;
    let uuid = uuid::Uuid::parse_str(&ann_id_str)
        .map_err(|_| McpError::InvalidParams(format!("invalid annotation_id: {}", ann_id_str)))?;
    let id = kin_model::AnnotationId(uuid);

    store
        .delete_annotation(&id)
        .map_err(|e| McpError::Other(e.to_string()))?;

    let result = serde_json::json!({
        "annotation_id": ann_id_str,
        "resolved": true,
    });
    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

fn handle_todo_import<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let path = args
        .get("path")
        .and_then(|v| v.as_str())
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_default());

    let todos = kin_parser::extract_todos(&path)
        .map_err(|e| McpError::Other(format!("todo extraction failed: {}", e)))?;

    let mut imported = 0usize;
    for todo in &todos {
        let work_kind = match todo.kind.as_str() {
            "FIXME" => kin_model::WorkKind::Issue,
            "HACK" => kin_model::WorkKind::Debt,
            _ => kin_model::WorkKind::Todo,
        };

        let item = kin_model::WorkItem {
            work_id: kin_model::WorkId::new(),
            kind: work_kind,
            title: todo.body.clone(),
            description: format!(
                "Imported from {} (line {})",
                todo.file_path, todo.line_number
            ),
            status: kin_model::WorkStatus::Proposed,
            priority: if todo.kind == "FIXME" {
                kin_model::Priority::High
            } else {
                kin_model::Priority::Medium
            },
            scopes: vec![kin_model::WorkScope::Artifact(kin_model::FilePathId::new(
                &todo.file_path,
            ))],
            acceptance_criteria: vec![],
            external_refs: vec![],
            created_by: kin_model::IdentityRef::assistant("kin-todo-import"),
            created_at: Timestamp::now(),
        };

        store
            .create_work_item(&item)
            .map_err(|e| McpError::Other(e.to_string()))?;
        imported += 1;
    }

    let result = serde_json::json!({
        "todos_found": todos.len(),
        "work_items_created": imported,
    });
    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

// ── Phase 9-10: Verification, security, release, contract, provenance handlers ──

fn handle_verify_entity<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let id_str = get_string_param(args, "entity_id")?;
    let entity_id = parse_entity_id(&id_str)?;
    let runner_filter = args
        .get("runner")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let mut tests = store
        .get_tests_for_entity(&entity_id)
        .map_err(McpError::graph)?;
    if let Some(ref runner) = runner_filter {
        tests.retain(|t| t.runner.to_string().eq_ignore_ascii_case(runner));
    }

    let coverage = store.get_coverage_summary().map_err(McpError::graph)?;
    let entity_covered = !tests.is_empty();

    let result = serde_json::json!({
        "entity_id": id_str,
        "covered": entity_covered,
        "test_count": tests.len(),
        "tests": tests,
        "coverage_summary": {
            "total_entities": coverage.total_entities,
            "covered_entities": coverage.covered_entities,
            "coverage_ratio": coverage.coverage_ratio,
        }
    });

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

fn handle_coverage_summary<G: GraphStore>(store: &G) -> Result<ToolCallResult> {
    let coverage = store.get_coverage_summary().map_err(McpError::graph)?;

    let result = serde_json::json!({
        "total_entities": coverage.total_entities,
        "covered_entities": coverage.covered_entities,
        "coverage_ratio": coverage.coverage_ratio,
        "missing_proof_count": coverage.missing_proof.len(),
        "missing_proof": coverage.missing_proof,
    });

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

fn handle_security_scan<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let propagate = get_optional_bool(args, "propagate", false);

    let dead = store.find_dead_code().map_err(McpError::graph)?;

    let findings: Vec<serde_json::Value> = dead
        .into_iter()
        .map(|entity| {
            let mut finding = serde_json::json!({
                "entity_id": entity.id,
                "name": entity.name,
                "kind": entity.kind,
                "file_path": entity.file_origin.as_ref().map(|p| p.to_string()),
                "finding_type": "dead_code",
                "severity": "low",
            });
            if propagate {
                if let Ok(impacted) = store.get_downstream_impact(&entity.id, 3) {
                    finding["downstream_impact_count"] = serde_json::json!(impacted.len());
                    finding["downstream_entities"] = serde_json::json!(impacted
                        .iter()
                        .map(|e| serde_json::json!({
                            "id": e.id,
                            "name": e.name,
                        }))
                        .collect::<Vec<_>>());
                }
            }
            finding
        })
        .collect();

    let result = serde_json::json!({
        "finding_count": findings.len(),
        "findings": findings,
    });

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

fn handle_release_check<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let require_proof = get_optional_bool(args, "require_proof", false);
    let require_approval = get_optional_bool(args, "require_approval", false);

    let coverage = store.get_coverage_summary().map_err(McpError::graph)?;

    let mut pass = true;
    let mut blockers: Vec<String> = Vec::new();

    if require_proof && !coverage.missing_proof.is_empty() {
        pass = false;
        blockers.push(format!(
            "{} entities missing test proof",
            coverage.missing_proof.len()
        ));
    }

    if require_approval {
        // Check if there are any approvals at all by querying recent audit events
        let events = store.query_audit_events(None, 1).map_err(McpError::graph)?;
        if events.is_empty() {
            pass = false;
            blockers.push("no audit events found — approval status unknown".into());
        }
    }

    let result = serde_json::json!({
        "pass": pass,
        "blockers": blockers,
        "coverage": {
            "total_entities": coverage.total_entities,
            "covered_entities": coverage.covered_entities,
            "coverage_ratio": coverage.coverage_ratio,
            "missing_proof_count": coverage.missing_proof.len(),
        }
    });

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

fn handle_contract_check<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let id_str = get_string_param(args, "contract_id")?;
    let uuid = uuid::Uuid::parse_str(&id_str)
        .map_err(|_| McpError::InvalidParams(format!("invalid contract_id: {}", id_str)))?;
    let contract_id = kin_model::ContractId(uuid);

    let tests = store
        .get_tests_covering_contract(&contract_id)
        .map_err(McpError::graph)?;

    let result = serde_json::json!({
        "contract_id": id_str,
        "covered": !tests.is_empty(),
        "test_count": tests.len(),
        "tests": tests,
    });

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

fn handle_provenance_query<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let id_str = get_string_param(args, "entity_id")?;
    let entity_id = parse_entity_id(&id_str)?;

    // Get the entity's history to find the latest change
    let history = store
        .get_entity_history(&entity_id)
        .map_err(McpError::graph)?;

    let mut approvals_json = serde_json::json!([]);
    if let Some(latest_change) = history.first() {
        let approvals = store
            .get_approvals_for_change(&latest_change.id)
            .map_err(McpError::graph)?;
        approvals_json = serde_json::json!(approvals);
    }

    // Get recent audit events (not actor-filtered, just recent)
    let events = store
        .query_audit_events(None, 20)
        .map_err(McpError::graph)?;

    let result = serde_json::json!({
        "entity_id": id_str,
        "change_count": history.len(),
        "latest_change": history.first(),
        "approvals": approvals_json,
        "recent_audit_events": events,
    });

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

/// Parse a JSON array of scope strings into WorkScope values.
fn parse_work_scopes(val: Option<&serde_json::Value>) -> Result<Vec<kin_model::WorkScope>> {
    let arr = match val {
        Some(serde_json::Value::Array(a)) => a,
        _ => return Ok(vec![]),
    };

    let mut scopes = Vec::new();
    for item in arr {
        if let Some(s) = item.as_str() {
            let scope = parse_single_work_scope(s)?;
            scopes.push(scope);
        }
    }
    Ok(scopes)
}

fn parse_annotation_targets(
    args: &HashMap<String, serde_json::Value>,
) -> Result<Vec<kin_model::AnnotationTarget>> {
    let raw_targets = match args.get("targets").or_else(|| args.get("scopes")) {
        Some(serde_json::Value::Array(values)) => values,
        _ => return Ok(vec![]),
    };

    let mut targets = Vec::new();
    for item in raw_targets {
        if let Some(s) = item.as_str() {
            targets.push(parse_annotation_target(s)?);
        }
    }
    Ok(targets)
}

fn parse_annotation_target(s: &str) -> Result<kin_model::AnnotationTarget> {
    if let Some(rest) = s.strip_prefix("work:") {
        let uuid = uuid::Uuid::parse_str(rest)
            .map_err(|_| McpError::InvalidParams(format!("invalid work UUID: {}", rest)))?;
        Ok(kin_model::AnnotationTarget::Work(kin_model::WorkId(uuid)))
    } else {
        Ok(kin_model::AnnotationTarget::Scope(parse_single_work_scope(
            s,
        )?))
    }
}

fn parse_single_work_scope(s: &str) -> Result<kin_model::WorkScope> {
    if let Some(rest) = s.strip_prefix("entity:") {
        let uuid = uuid::Uuid::parse_str(rest)
            .map_err(|_| McpError::InvalidParams(format!("invalid entity UUID: {}", rest)))?;
        Ok(kin_model::WorkScope::Entity(kin_model::EntityId(uuid)))
    } else if let Some(rest) = s.strip_prefix("contract:") {
        let uuid = uuid::Uuid::parse_str(rest)
            .map_err(|_| McpError::InvalidParams(format!("invalid contract UUID: {}", rest)))?;
        Ok(kin_model::WorkScope::Contract(kin_model::ContractId(uuid)))
    } else if let Some(rest) = s.strip_prefix("artifact:") {
        Ok(kin_model::WorkScope::Artifact(kin_model::FilePathId::new(
            rest,
        )))
    } else if let Some(rest) = s.strip_prefix("file:") {
        Ok(kin_model::WorkScope::Artifact(kin_model::FilePathId::new(
            rest,
        )))
    } else if let Some(rest) = s.strip_prefix("change:") {
        let hash = kin_model::Hash256::from_hex(rest).map_err(|_| {
            McpError::InvalidParams(format!("invalid semantic change ID: {}", rest))
        })?;
        Ok(kin_model::WorkScope::Change(
            kin_model::SemanticChangeId::from_hash(hash),
        ))
    } else {
        if let Ok(uuid) = uuid::Uuid::parse_str(s) {
            Ok(kin_model::WorkScope::Entity(kin_model::EntityId(uuid)))
        } else {
            Ok(kin_model::WorkScope::Artifact(kin_model::FilePathId::new(
                s,
            )))
        }
    }
}

fn parse_work_id_param(
    args: &HashMap<String, serde_json::Value>,
    key: &str,
) -> Result<(String, kin_model::WorkId)> {
    let work_id_str = get_string_param(args, key)?;
    let uuid = uuid::Uuid::parse_str(&work_id_str)
        .map_err(|_| McpError::InvalidParams(format!("invalid {}: {}", key, work_id_str)))?;
    Ok((work_id_str, kin_model::WorkId(uuid)))
}

fn ensure_work_item_exists<G: GraphStore>(
    store: &G,
    work_id: &kin_model::WorkId,
    display: &str,
) -> Result<kin_model::WorkItem> {
    store
        .get_work_item(work_id)
        .map_err(|e| McpError::Other(e.to_string()))?
        .ok_or_else(|| McpError::InvalidParams(format!("work item not found: {}", display)))
}

fn summarize_work_item(item: &kin_model::WorkItem) -> serde_json::Value {
    serde_json::json!({
        "work_id": item.work_id.to_string(),
        "kind": item.kind.to_string(),
        "title": item.title,
        "status": item.status.to_string(),
    })
}

fn summarize_annotation(annotation: &kin_model::Annotation) -> serde_json::Value {
    serde_json::json!({
        "annotation_id": annotation.annotation_id.to_string(),
        "kind": annotation.kind.to_string(),
        "body": annotation.body,
        "staleness": annotation.staleness.to_string(),
        "scopes": annotation.scopes.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_db::InMemoryGraph;
    use kin_model::branch::Branch;
    use kin_model::change::SemanticChange;
    use kin_model::entity::Entity;
    use kin_model::graph::{EntityFilter, SubGraph};
    use kin_model::ids::*;
    use kin_model::relation::{Relation, RelationKind};
    use std::collections::{HashMap, HashSet};
    use std::fs;
    use tempfile::tempdir;

    #[derive(Default)]
    struct EmptyStore {
        entities_by_file: HashMap<String, Vec<Entity>>,
        entities_by_id: HashMap<EntityId, Entity>,
        relations_by_entity: HashMap<EntityId, Vec<Relation>>,
        dead_entities: Vec<Entity>,
        live_entity_ids: HashSet<EntityId>,
    }

    impl GraphStore for EmptyStore {
        type Error = std::io::Error;
        fn get_entity(&self, id: &EntityId) -> std::result::Result<Option<Entity>, Self::Error> {
            Ok(self.entities_by_id.get(id).cloned())
        }
        fn get_relations(
            &self,
            id: &EntityId,
            kinds: &[RelationKind],
        ) -> std::result::Result<Vec<Relation>, Self::Error> {
            Ok(self
                .relations_by_entity
                .get(id)
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter(|relation| kinds.contains(&relation.kind))
                .collect())
        }
        fn get_all_relations_for_entity(
            &self,
            id: &EntityId,
        ) -> std::result::Result<Vec<Relation>, Self::Error> {
            Ok(self
                .relations_by_entity
                .get(id)
                .cloned()
                .unwrap_or_default())
        }
        fn get_downstream_impact(
            &self,
            _: &EntityId,
            _: u32,
        ) -> std::result::Result<Vec<Entity>, Self::Error> {
            Ok(vec![])
        }
        fn get_dependency_neighborhood(
            &self,
            _: &EntityId,
            _: u32,
        ) -> std::result::Result<SubGraph, Self::Error> {
            Ok(SubGraph::default())
        }
        fn find_dead_code(&self) -> std::result::Result<Vec<Entity>, Self::Error> {
            Ok(self.dead_entities.clone())
        }
        fn has_incoming_relation_kinds(
            &self,
            id: &EntityId,
            _: &[RelationKind],
            _: bool,
        ) -> std::result::Result<bool, Self::Error> {
            Ok(self.live_entity_ids.contains(id))
        }
        fn get_entity_history(
            &self,
            _: &EntityId,
        ) -> std::result::Result<Vec<SemanticChange>, Self::Error> {
            Ok(vec![])
        }
        fn find_merge_bases(
            &self,
            _: &SemanticChangeId,
            _: &SemanticChangeId,
        ) -> std::result::Result<Vec<SemanticChangeId>, Self::Error> {
            Ok(vec![])
        }
        fn query_entities(
            &self,
            filter: &EntityFilter,
        ) -> std::result::Result<Vec<Entity>, Self::Error> {
            if let Some(file_path) = filter.file_path.as_ref() {
                return Ok(self
                    .entities_by_file
                    .get(&file_path.0)
                    .cloned()
                    .unwrap_or_default());
            }

            let mut entities = self.entities_by_id.values().cloned().collect::<Vec<_>>();
            if let Some(name_pattern) = filter.name_pattern.as_ref() {
                let needle = name_pattern.to_ascii_lowercase();
                entities.retain(|entity| entity.name.to_ascii_lowercase().contains(&needle));
            }
            Ok(entities)
        }
        fn list_all_entities(&self) -> std::result::Result<Vec<Entity>, Self::Error> {
            Ok(self.entities_by_id.values().cloned().collect())
        }
        fn upsert_entity(&self, _: &Entity) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn upsert_relation(&self, _: &Relation) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn remove_entity(&self, _: &EntityId) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn remove_relation(&self, _: &RelationId) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn create_change(&self, _: &SemanticChange) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_change(
            &self,
            _: &SemanticChangeId,
        ) -> std::result::Result<Option<SemanticChange>, Self::Error> {
            Ok(None)
        }
        fn get_changes_since(
            &self,
            _: &SemanticChangeId,
            _: &SemanticChangeId,
        ) -> std::result::Result<Vec<SemanticChange>, Self::Error> {
            Ok(vec![])
        }
        fn get_branch(&self, _: &BranchName) -> std::result::Result<Option<Branch>, Self::Error> {
            Ok(None)
        }
        fn create_branch(&self, _: &Branch) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn update_branch_head(
            &self,
            _: &BranchName,
            _: &SemanticChangeId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn delete_branch(&self, _: &BranchName) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn list_branches(&self) -> std::result::Result<Vec<Branch>, Self::Error> {
            Ok(vec![])
        }
        fn create_work_item(
            &self,
            _: &kin_model::WorkItem,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_work_item(
            &self,
            _: &kin_model::WorkId,
        ) -> std::result::Result<Option<kin_model::WorkItem>, Self::Error> {
            Ok(None)
        }
        fn list_work_items(
            &self,
            _: &kin_model::WorkFilter,
        ) -> std::result::Result<Vec<kin_model::WorkItem>, Self::Error> {
            Ok(vec![])
        }
        fn update_work_status(
            &self,
            _: &kin_model::WorkId,
            _: kin_model::WorkStatus,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn delete_work_item(&self, _: &kin_model::WorkId) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn create_annotation(
            &self,
            _: &kin_model::Annotation,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_annotation(
            &self,
            _: &kin_model::AnnotationId,
        ) -> std::result::Result<Option<kin_model::Annotation>, Self::Error> {
            Ok(None)
        }
        fn list_annotations(
            &self,
            _: &kin_model::AnnotationFilter,
        ) -> std::result::Result<Vec<kin_model::Annotation>, Self::Error> {
            Ok(vec![])
        }
        fn update_annotation_staleness(
            &self,
            _: &kin_model::AnnotationId,
            _: kin_model::StalenessState,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn delete_annotation(
            &self,
            _: &kin_model::AnnotationId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn create_work_link(
            &self,
            _: &kin_model::WorkLink,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn delete_work_link(
            &self,
            _: &kin_model::WorkLink,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_work_for_scope(
            &self,
            _: &kin_model::WorkScope,
        ) -> std::result::Result<Vec<kin_model::WorkItem>, Self::Error> {
            Ok(vec![])
        }
        fn get_annotations_for_scope(
            &self,
            _: &kin_model::WorkScope,
        ) -> std::result::Result<Vec<kin_model::Annotation>, Self::Error> {
            Ok(vec![])
        }
        fn get_child_work_items(
            &self,
            _: &kin_model::WorkId,
        ) -> std::result::Result<Vec<kin_model::WorkItem>, Self::Error> {
            Ok(vec![])
        }
        fn get_parent_work_items(
            &self,
            _: &kin_model::WorkId,
        ) -> std::result::Result<Vec<kin_model::WorkItem>, Self::Error> {
            Ok(vec![])
        }
        fn get_blockers(
            &self,
            _: &kin_model::WorkId,
        ) -> std::result::Result<Vec<kin_model::WorkItem>, Self::Error> {
            Ok(vec![])
        }
        fn get_blocked_work_items(
            &self,
            _: &kin_model::WorkId,
        ) -> std::result::Result<Vec<kin_model::WorkItem>, Self::Error> {
            Ok(vec![])
        }
        fn get_implementors(
            &self,
            _: &kin_model::WorkId,
        ) -> std::result::Result<Vec<kin_model::WorkScope>, Self::Error> {
            Ok(vec![])
        }
        fn get_annotations_for_work_item(
            &self,
            _: &kin_model::WorkId,
        ) -> std::result::Result<Vec<kin_model::Annotation>, Self::Error> {
            Ok(vec![])
        }
        fn create_test_case(
            &self,
            _: &kin_model::verification::TestCase,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_test_case(
            &self,
            _: &kin_model::verification::TestId,
        ) -> std::result::Result<Option<kin_model::verification::TestCase>, Self::Error> {
            Ok(None)
        }
        fn get_tests_for_entity(
            &self,
            _: &EntityId,
        ) -> std::result::Result<Vec<kin_model::verification::TestCase>, Self::Error> {
            Ok(vec![])
        }
        fn delete_test_case(
            &self,
            _: &kin_model::verification::TestId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn create_assertion(
            &self,
            _: &kin_model::verification::Assertion,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_assertion(
            &self,
            _: &kin_model::verification::AssertionId,
        ) -> std::result::Result<Option<kin_model::verification::Assertion>, Self::Error> {
            Ok(None)
        }
        fn get_coverage_summary(
            &self,
        ) -> std::result::Result<kin_model::verification::CoverageSummary, Self::Error> {
            Ok(kin_model::verification::CoverageSummary {
                total_entities: 0,
                covered_entities: 0,
                coverage_ratio: 0.0,
                missing_proof: vec![],
            })
        }
        fn create_verification_run(
            &self,
            _: &kin_model::verification::VerificationRun,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_verification_run(
            &self,
            _: &kin_model::verification::VerificationRunId,
        ) -> std::result::Result<Option<kin_model::verification::VerificationRun>, Self::Error>
        {
            Ok(None)
        }
        fn list_runs_for_test(
            &self,
            _: &kin_model::verification::TestId,
        ) -> std::result::Result<Vec<kin_model::verification::VerificationRun>, Self::Error>
        {
            Ok(vec![])
        }
        fn create_test_covers_entity(
            &self,
            _: &kin_model::verification::TestId,
            _: &EntityId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn create_test_covers_contract(
            &self,
            _: &kin_model::verification::TestId,
            _: &ContractId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn create_test_verifies_work(
            &self,
            _: &kin_model::verification::TestId,
            _: &kin_model::WorkId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_tests_covering_contract(
            &self,
            _: &ContractId,
        ) -> std::result::Result<Vec<kin_model::verification::TestCase>, Self::Error> {
            Ok(vec![])
        }
        fn get_tests_verifying_work(
            &self,
            _: &kin_model::WorkId,
        ) -> std::result::Result<Vec<kin_model::verification::TestCase>, Self::Error> {
            Ok(vec![])
        }
        fn create_mock_hint(
            &self,
            _: &kin_model::verification::MockHint,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_mock_hints_for_test(
            &self,
            _: &kin_model::verification::TestId,
        ) -> std::result::Result<Vec<kin_model::verification::MockHint>, Self::Error> {
            Ok(vec![])
        }
        fn link_run_proves_entity(
            &self,
            _: &kin_model::verification::VerificationRunId,
            _: &EntityId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn link_run_proves_work(
            &self,
            _: &kin_model::verification::VerificationRunId,
            _: &kin_model::WorkId,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn list_runs_proving_entity(
            &self,
            _: &kin_model::EntityId,
        ) -> std::result::Result<Vec<kin_model::verification::VerificationRun>, Self::Error>
        {
            Ok(vec![])
        }
        fn list_runs_proving_work(
            &self,
            _: &kin_model::WorkId,
        ) -> std::result::Result<Vec<kin_model::verification::VerificationRun>, Self::Error>
        {
            Ok(vec![])
        }
        fn get_contract_coverage_summary(
            &self,
        ) -> std::result::Result<kin_model::verification::ContractCoverageSummary, Self::Error>
        {
            Ok(kin_model::verification::ContractCoverageSummary {
                total_contracts: 0,
                covered_contracts: 0,
                coverage_ratio: 0.0,
                uncovered_contract_ids: vec![],
            })
        }
        fn create_actor(
            &self,
            _: &kin_model::provenance::Actor,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_actor(
            &self,
            _: &kin_model::provenance::ActorId,
        ) -> std::result::Result<Option<kin_model::provenance::Actor>, Self::Error> {
            Ok(None)
        }
        fn list_actors(
            &self,
        ) -> std::result::Result<Vec<kin_model::provenance::Actor>, Self::Error> {
            Ok(vec![])
        }
        fn create_delegation(
            &self,
            _: &kin_model::provenance::Delegation,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_delegations_for_actor(
            &self,
            _: &kin_model::provenance::ActorId,
        ) -> std::result::Result<Vec<kin_model::provenance::Delegation>, Self::Error> {
            Ok(vec![])
        }
        fn create_approval(
            &self,
            _: &kin_model::provenance::Approval,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_approvals_for_change(
            &self,
            _: &SemanticChangeId,
        ) -> std::result::Result<Vec<kin_model::provenance::Approval>, Self::Error> {
            Ok(vec![])
        }
        fn record_audit_event(
            &self,
            _: &kin_model::provenance::AuditEvent,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn query_audit_events(
            &self,
            _: Option<&kin_model::provenance::ActorId>,
            _: usize,
        ) -> std::result::Result<Vec<kin_model::provenance::AuditEvent>, Self::Error> {
            Ok(vec![])
        }
        fn upsert_shallow_file(
            &self,
            _: &kin_model::ShallowTrackedFile,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn list_shallow_files(
            &self,
        ) -> std::result::Result<Vec<kin_model::ShallowTrackedFile>, Self::Error> {
            Ok(vec![])
        }
        fn create_contract(
            &self,
            _: &kin_model::contract::Contract,
        ) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_contract(
            &self,
            _: &kin_model::ids::ContractId,
        ) -> std::result::Result<Option<kin_model::contract::Contract>, Self::Error> {
            Ok(None)
        }
        fn list_contracts(
            &self,
        ) -> std::result::Result<Vec<kin_model::contract::Contract>, Self::Error> {
            Ok(vec![])
        }
    }

    #[test]
    fn parse_entity_id_valid() {
        let id = EntityId::new().to_string();
        let result = parse_entity_id(&id);
        assert!(result.is_ok());
    }

    #[test]
    fn parse_entity_id_invalid() {
        let result = parse_entity_id("not-a-uuid");
        assert!(result.is_err());
    }

    #[test]
    fn parse_change_id_valid() {
        let hex = "aa".repeat(32);
        let result = parse_change_id(&hex);
        assert!(result.is_ok());
    }

    #[test]
    fn parse_change_id_invalid() {
        let result = parse_change_id("zzz");
        assert!(result.is_err());
    }

    #[test]
    fn parse_transport_values() {
        assert_eq!(parse_transport("mcp"), SessionTransport::Mcp);
        assert_eq!(parse_transport("cli"), SessionTransport::Cli);
        assert_eq!(parse_transport("wrapper"), SessionTransport::Wrapper);
        assert_eq!(parse_transport("ui"), SessionTransport::Ui);
        assert_eq!(parse_transport("unknown"), SessionTransport::Mcp);
    }

    #[test]
    fn parse_lock_type_values() {
        assert_eq!(parse_lock_type("soft"), LockType::Soft);
        assert_eq!(parse_lock_type("hard"), LockType::Hard);
        assert_eq!(parse_lock_type("anything"), LockType::Soft);
    }

    #[test]
    fn parse_session_id_valid() {
        let id = SessionId::new().to_string();
        let result = parse_session_id(&id);
        assert!(result.is_ok());
    }

    #[test]
    fn parse_scopes_valid() {
        let entity_id = EntityId::new();
        let val = serde_json::json!([
            { "Entity": entity_id },
            { "Artifact": "src/main.rs" }
        ]);
        let result = parse_scopes(&val);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 2);
    }

    #[test]
    fn parse_scopes_invalid() {
        let val = serde_json::json!("not an array");
        let result = parse_scopes(&val);
        assert!(result.is_err());
    }

    #[test]
    fn unknown_tool_returns_error() {
        let store = EmptyStore::default();
        let sessions = SessionRegistry::new();
        let args = HashMap::new();
        let result = handle_tool_call("nonexistent_tool", &args, &store, &sessions);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), McpError::ToolNotFound(_)));
    }

    #[test]
    fn session_start_and_heartbeat_and_end() {
        let store = EmptyStore::default();
        let sessions = SessionRegistry::new();

        // Start a session
        let mut start_args = HashMap::new();
        start_args.insert("vendor".into(), serde_json::json!("claude-code"));
        start_args.insert("client_name".into(), serde_json::json!("test-client"));
        start_args.insert("cwd".into(), serde_json::json!("/project"));
        start_args.insert("transport".into(), serde_json::json!("mcp"));

        let result = handle_tool_call("kin_session_start", &start_args, &store, &sessions).unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let response: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(response["status"], "active");
        assert_eq!(response["vendor"], "claude-code");

        let session_id = response["session_id"].as_str().unwrap().to_string();

        // Heartbeat
        let mut hb_args = HashMap::new();
        hb_args.insert("session_id".into(), serde_json::json!(session_id));
        let result =
            handle_tool_call("kin_session_heartbeat", &hb_args, &store, &sessions).unwrap();
        assert!(result.is_error.is_none());

        // End session
        let mut end_args = HashMap::new();
        end_args.insert("session_id".into(), serde_json::json!(session_id));
        let result = handle_tool_call("kin_session_end", &end_args, &store, &sessions).unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let response: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(response["status"], "ended");
    }

    #[test]
    fn register_and_release_intent() {
        let sessions = SessionRegistry::new();

        // Start session first
        let session = sessions.start_agent_session(
            "codex",
            "test",
            SessionTransport::Cli,
            None,
            PathBuf::from("/tmp"),
            SessionCapabilities::default(),
        );
        let session_id_str = session.session_id.to_string();

        let entity_id = EntityId::new();

        // Register intent
        let mut args = HashMap::new();
        args.insert("session_id".into(), serde_json::json!(session_id_str));
        args.insert(
            "scopes".into(),
            serde_json::json!([{ "Entity": entity_id }]),
        );
        args.insert("lock_type".into(), serde_json::json!("hard"));
        args.insert(
            "task_description".into(),
            serde_json::json!("editing auth module"),
        );

        let result = handle_register_intent(&args, &sessions).unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let response: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(response["status"], "registered");
        let intent_id = response["intent_id"].as_str().unwrap().to_string();

        // Release intent
        let mut release_args = HashMap::new();
        release_args.insert("session_id".into(), serde_json::json!(session_id_str));
        release_args.insert("intent_id".into(), serde_json::json!(intent_id));
        let result = handle_release_intent(&release_args, &sessions).unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let response: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(response["status"], "released");
    }

    #[test]
    fn check_traffic_with_active_intents() {
        let sessions = SessionRegistry::new();

        let session = sessions.start_agent_session(
            "claude-code",
            "test",
            SessionTransport::Mcp,
            None,
            PathBuf::from("/project"),
            SessionCapabilities::default(),
        );

        let entity_id = EntityId::new();
        sessions.register_intent(
            session.session_id,
            vec![IntentScope::Entity(entity_id)],
            LockType::Soft,
            "refactoring".into(),
            None,
        );

        let mut args = HashMap::new();
        args.insert(
            "scopes".into(),
            serde_json::json!([{ "Entity": entity_id }]),
        );
        let result = handle_check_traffic(&args, &sessions).unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let response: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(response["scope_count"], 1);
        let reports = response["reports"].as_array().unwrap();
        assert_eq!(reports.len(), 1);
        assert!(!reports[0]["active_intents"].as_array().unwrap().is_empty());
    }

    #[test]
    fn register_intent_without_session_fails() {
        let sessions = SessionRegistry::new();

        let mut args = HashMap::new();
        args.insert(
            "session_id".into(),
            serde_json::json!(SessionId::new().to_string()),
        );
        args.insert(
            "scopes".into(),
            serde_json::json!([{ "Entity": EntityId::new() }]),
        );
        args.insert("task_description".into(), serde_json::json!("test"));

        let result = handle_register_intent(&args, &sessions).unwrap();
        assert_eq!(result.is_error, Some(true));
    }

    #[test]
    fn get_optional_bool_test() {
        let mut args = HashMap::new();
        args.insert("flag".into(), serde_json::json!(false));
        assert!(!get_optional_bool(&args, "flag", true));
        assert!(get_optional_bool(&args, "missing", true));
    }

    #[test]
    fn function_filter_includes_methods() {
        let kinds = parse_kind_filter("function").unwrap();
        assert!(kinds.contains(&EntityKind::Function));
        assert!(kinds.contains(&EntityKind::Method));
    }

    #[test]
    fn language_filter_supports_aliases() {
        assert_eq!(
            parse_language_filter("js"),
            Some(vec![LanguageId::JavaScript])
        );
        assert_eq!(
            parse_language_filter("ts"),
            Some(vec![LanguageId::TypeScript])
        );
        assert_eq!(parse_language_filter("py"), Some(vec![LanguageId::Python]));
        assert_eq!(parse_language_filter("c"), Some(vec![LanguageId::C]));
        assert_eq!(parse_language_filter("c++"), Some(vec![LanguageId::Cpp]));
        assert_eq!(parse_language_filter("cs"), Some(vec![LanguageId::CSharp]));
        assert_eq!(parse_language_filter("rb"), Some(vec![LanguageId::Ruby]));
    }

    #[test]
    fn build_semantic_search_request_applies_language_and_kind_filters() {
        let mut args = HashMap::new();
        args.insert("query".into(), serde_json::json!("save"));
        args.insert("kind".into(), serde_json::json!("function"));
        args.insert("language".into(), serde_json::json!("javascript"));
        args.insert("limit".into(), serde_json::json!(7));

        let (query, limit, filter) = build_semantic_search_request(&args).unwrap();
        assert_eq!(query, "save");
        assert_eq!(limit, 7);
        assert_eq!(filter.languages, Some(vec![LanguageId::JavaScript]));

        let kinds = filter.kinds.unwrap();
        assert!(kinds.contains(&EntityKind::Function));
        assert!(kinds.contains(&EntityKind::Method));
    }

    fn make_source_backed_entity(content: &str) -> (tempfile::TempDir, Entity) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("validate.ts");
        fs::write(&path, content).unwrap();
        let file_id = kin_model::ids::FilePathId::new(path.to_string_lossy());

        let entity = Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: "validate_probe_range_1d8f8275".into(),
            language: LanguageId::TypeScript,
            fingerprint: kin_model::entity::SemanticFingerprint {
                algorithm: kin_model::entity::FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([1; 32]),
                signature_hash: Hash256::from_bytes([2; 32]),
                behavior_hash: Hash256::from_bytes([3; 32]),
                stability_score: 0.9,
            },
            file_origin: Some(file_id.clone()),
            span: Some(kin_model::entity::SourceSpan {
                file: file_id,
                start_byte: 0,
                end_byte: content.len(),
                start_line: 1,
                start_col: 0,
                end_line: content.lines().count() as u32,
                end_col: 1,
            }),
            signature: "export function validate_probe_range_1d8f8275(value: number, minVal: number, maxVal: number): boolean".into(),
            visibility: kin_model::entity::Visibility::Public,
            doc_summary: Some("Validate an inclusive numeric range.".into()),
            metadata: kin_model::entity::EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };

        (dir, entity)
    }

    fn make_signature_only_python_entity(content: &str) -> (tempfile::TempDir, Entity) {
        let dir = tempdir().unwrap();
        let path = dir.path().join("validate.py");
        fs::write(&path, content).unwrap();
        let file_id = kin_model::ids::FilePathId::new(path.to_string_lossy());
        let signature = content
            .lines()
            .next()
            .unwrap_or_default()
            .trim_end_matches(':')
            .to_string();
        let end_byte = content.lines().next().unwrap_or_default().len();

        let entity = Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: "validate_probe_range_f0cc1f1d".into(),
            language: LanguageId::Python,
            fingerprint: kin_model::entity::SemanticFingerprint {
                algorithm: kin_model::entity::FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([9; 32]),
                signature_hash: Hash256::from_bytes([10; 32]),
                behavior_hash: Hash256::from_bytes([11; 32]),
                stability_score: 0.9,
            },
            file_origin: Some(file_id.clone()),
            span: Some(kin_model::entity::SourceSpan {
                file: file_id,
                start_byte: 0,
                end_byte,
                start_line: 1,
                start_col: 0,
                end_line: 1,
                end_col: end_byte as u32,
            }),
            signature,
            visibility: kin_model::entity::Visibility::Public,
            doc_summary: None,
            metadata: kin_model::entity::EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };

        (dir, entity)
    }

    fn make_dead_code_entity(file_path: &str, name: &str, start_line: u32) -> Entity {
        let file_id = kin_model::ids::FilePathId::new(file_path);
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.into(),
            language: LanguageId::TypeScript,
            fingerprint: kin_model::entity::SemanticFingerprint {
                algorithm: kin_model::entity::FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([4; 32]),
                signature_hash: Hash256::from_bytes([5; 32]),
                behavior_hash: Hash256::from_bytes([6; 32]),
                stability_score: 0.9,
            },
            file_origin: Some(file_id.clone()),
            span: Some(kin_model::entity::SourceSpan {
                file: file_id,
                start_byte: 0,
                end_byte: 32,
                start_line,
                start_col: 0,
                end_line: start_line + 1,
                end_col: 1,
            }),
            signature: format!("export function {name}(): number"),
            visibility: Visibility::Public,
            doc_summary: None,
            metadata: kin_model::entity::EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn make_trace_entity(
        dir: &tempfile::TempDir,
        rel_path: &str,
        name: &str,
        kind: EntityKind,
        signature: &str,
        content: &str,
    ) -> Entity {
        let path = dir.path().join(rel_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(&path, content).unwrap();
        let file_id = kin_model::ids::FilePathId::new(path.to_string_lossy());

        Entity {
            id: EntityId::new(),
            kind,
            name: name.into(),
            language: LanguageId::TypeScript,
            fingerprint: kin_model::entity::SemanticFingerprint {
                algorithm: kin_model::entity::FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([7; 32]),
                signature_hash: Hash256::from_bytes([8; 32]),
                behavior_hash: Hash256::from_bytes([9; 32]),
                stability_score: 0.9,
            },
            file_origin: Some(file_id.clone()),
            span: Some(kin_model::entity::SourceSpan {
                file: file_id,
                start_byte: 0,
                end_byte: content.len(),
                start_line: 1,
                start_col: 0,
                end_line: content.lines().count() as u32,
                end_col: 1,
            }),
            signature: signature.into(),
            visibility: Visibility::Public,
            doc_summary: None,
            metadata: kin_model::entity::EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn insert_trace_relation(
        store: &mut EmptyStore,
        src: &Entity,
        dst: &Entity,
        kind: RelationKind,
    ) {
        let relation = Relation {
            id: RelationId::new(),
            kind,
            src: src.id,
            dst: dst.id,
            confidence: 1.0,
            origin: kin_model::relation::RelationOrigin::Parsed,
            created_in: None,
        };
        store
            .relations_by_entity
            .entry(src.id)
            .or_default()
            .push(relation.clone());
        store
            .relations_by_entity
            .entry(dst.id)
            .or_default()
            .push(relation);
    }

    #[test]
    fn entity_response_json_includes_real_source_excerpt() {
        let content = "export function validate_probe_range_1d8f8275(value: number, minVal: number, maxVal: number): boolean {\n  if (value < minVal) {\n    return false;\n  }\n  return value <= maxVal;\n}\n";
        let (_dir, entity) = make_source_backed_entity(content);

        let value = entity_response_json(&entity).unwrap();
        let object = value.as_object().unwrap();
        let excerpt = object
            .get("source_excerpt")
            .and_then(|value| value.as_str())
            .unwrap();

        assert!(excerpt.contains("return value <= maxVal;"));
        assert_eq!(object.get("start_line").unwrap(), 1);
        assert_eq!(
            object
                .get("read_path")
                .and_then(|value| value.as_str())
                .unwrap(),
            entity.file_origin.as_ref().unwrap().0
        );
    }

    #[test]
    fn focal_context_json_prefers_real_source_excerpt() {
        let content = "export function validate_probe_range_1d8f8275(value: number, minVal: number, maxVal: number): boolean {\n  if (value < minVal) {\n    return false;\n  }\n  return value <= maxVal;\n}\n";
        let (_dir, entity) = make_source_backed_entity(content);
        let entry = kin_model::ContextEntry {
            entity_id: entity.id,
            projection_level: kin_model::ProjectionLevel::FullBody,
            content: entity.signature.clone(),
        };

        let value = focal_context_json(&entry, &entity, false);
        let object = value.as_object().unwrap();
        let body = object.get("body").and_then(|value| value.as_str()).unwrap();

        assert!(body.contains("return value <= maxVal;"));
        assert_ne!(body, entity.signature);
        assert_eq!(object.get("start_line").unwrap(), 1);
    }

    #[test]
    fn focal_context_json_expands_signature_only_python_span() {
        let content = "def validate_probe_range_f0cc1f1d(value: float, min_val: float, max_val: float) -> bool:\n    return min_val <= value and value <= max_val\n";
        let (_dir, entity) = make_signature_only_python_entity(content);
        let entry = kin_model::ContextEntry {
            entity_id: entity.id,
            projection_level: kin_model::ProjectionLevel::FullBody,
            content: entity.signature.clone(),
        };

        let value = focal_context_json(&entry, &entity, false);
        let object = value.as_object().unwrap();
        let body = object.get("body").and_then(|value| value.as_str()).unwrap();

        assert!(body.contains("value <= max_val"));
        assert_ne!(body.trim(), entity.signature);
    }

    #[test]
    fn handle_explore_codebase_trace_returns_ordered_bodies_and_constants() {
        let dir = tempdir().unwrap();
        let tag = "trace9f31";

        let entry = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step4_{tag}.ts"),
            &format!("probeFinalTransform_{tag}"),
            EntityKind::Function,
            &format!("function probeFinalTransform_{tag}(n: number): number"),
            &format!(
                "export function probeFinalTransform_{tag}(n: number): number {{\n  return probeReduce_{tag}(n) + 17;\n}}\n"
            ),
        );
        let reduce_step = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step3_{tag}.ts"),
            &format!("probeReduce_{tag}"),
            EntityKind::Function,
            &format!("function probeReduce_{tag}(n: number): number"),
            &format!(
                "export function probeReduce_{tag}(n: number): number {{\n  return probeConditionalAdjust_{tag}(n) - 5;\n}}\n"
            ),
        );
        let import_only_step = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step2_{tag}.ts"),
            &format!("probeConditionalAdjust_{tag}"),
            EntityKind::Function,
            &format!("function probeConditionalAdjust_{tag}(n: number): number"),
            &format!(
                "export function probeConditionalAdjust_{tag}(n: number): number {{\n  return probeDoubleShifted_{tag}(n) + 3;\n}}\n"
            ),
        );
        let step = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step1_{tag}.ts"),
            &format!("probeDoubleShifted_{tag}"),
            EntityKind::Function,
            &format!("function probeDoubleShifted_{tag}(n: number): number"),
            &format!(
                "export function probeDoubleShifted_{tag}(n: number): number {{\n  return probeAddOffset_{tag}(n) * 2;\n}}\n"
            ),
        );
        let base_step = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step0_{tag}.ts"),
            &format!("probeAddOffset_{tag}"),
            EntityKind::Function,
            &format!("function probeAddOffset_{tag}(n: number): number"),
            &format!(
                "import {{ PROBE_BASE_{tag} }} from './base_{tag}';\n\nexport function probeAddOffset_{tag}(n: number): number {{\n  return n + PROBE_BASE_{tag};\n}}\n"
            ),
        );
        let constant = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/base_{tag}.ts"),
            &format!("PROBE_BASE_{tag}"),
            EntityKind::Constant,
            &format!("const PROBE_BASE_{tag}: number"),
            &format!("export const PROBE_BASE_{tag} = 13;\n"),
        );
        let decoy = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/decoy_transform_{tag}.ts"),
            &format!("probeFinalTransformAlt_{tag}"),
            EntityKind::Function,
            &format!("function probeFinalTransformAlt_{tag}(n: number): number"),
            &format!(
                "export function probeFinalTransformAlt_{tag}(n: number): number {{\n  return n * 100;\n}}\n"
            ),
        );

        let mut store = EmptyStore::default();
        for entity in [
            entry.clone(),
            reduce_step.clone(),
            import_only_step.clone(),
            step.clone(),
            base_step.clone(),
            constant.clone(),
            decoy.clone(),
        ] {
            store.entities_by_id.insert(entity.id, entity);
        }
        insert_trace_relation(&mut store, &entry, &reduce_step, RelationKind::Calls);
        insert_trace_relation(
            &mut store,
            &reduce_step,
            &import_only_step,
            RelationKind::Imports,
        );
        insert_trace_relation(&mut store, &import_only_step, &step, RelationKind::Calls);
        insert_trace_relation(&mut store, &reduce_step, &step, RelationKind::References);
        insert_trace_relation(&mut store, &step, &base_step, RelationKind::Calls);
        insert_trace_relation(&mut store, &base_step, &constant, RelationKind::Imports);

        let mut args = HashMap::new();
        args.insert("query".into(), serde_json::json!(entry.name));
        args.insert("strategy".into(), serde_json::json!("trace"));
        args.insert("token_budget".into(), serde_json::json!(8000));

        let result = handle_explore_codebase(&args, &store).unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        let content = parsed["content"].as_str().unwrap();

        let entry_pos = content.find(&entry.name).unwrap();
        let reduce_pos = content.find(&reduce_step.name).unwrap();
        let import_only_pos = content.find(&import_only_step.name).unwrap();
        let step_pos = content.find(&step.name).unwrap();
        let base_step_pos = content.find(&base_step.name).unwrap();

        assert!(content.contains("## Ordered Call Chain"));
        assert!(entry_pos < reduce_pos);
        assert!(reduce_pos < import_only_pos);
        assert!(import_only_pos < step_pos);
        assert!(step_pos < base_step_pos);
        assert!(content.contains("Imported constants"));
        assert!(content.contains(&constant.name));
        assert!(content.contains("export const"));
        assert!(content.contains("Similar/Decoy Matches"));
        assert!(content.contains(&decoy.name));
        assert!(content.contains("return n + PROBE_BASE"));
    }

    #[test]
    fn handle_explore_codebase_trace_infers_constants_without_graph_edges() {
        let dir = tempdir().unwrap();
        let tag = "traceconst";

        let step = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step1_{tag}.ts"),
            &format!("probeAddOffset_{tag}"),
            EntityKind::Function,
            &format!("function probeAddOffset_{tag}(n: number): number"),
            &format!(
                "import {{ PROBE_BASE_{tag} }} from './base_{tag}';\n\nexport function probeAddOffset_{tag}(n: number): number {{\n  return n + PROBE_BASE_{tag};\n}}\n"
            ),
        );
        let constant = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/base_{tag}.ts"),
            &format!("PROBE_BASE_{tag}"),
            EntityKind::Constant,
            &format!("const PROBE_BASE_{tag}: number"),
            &format!("export const PROBE_BASE_{tag} = 13;\n"),
        );

        let mut store = EmptyStore::default();
        store.entities_by_id.insert(step.id, step.clone());
        store.entities_by_id.insert(constant.id, constant.clone());

        let mut args = HashMap::new();
        args.insert("query".into(), serde_json::json!(step.name));
        args.insert("strategy".into(), serde_json::json!("trace"));
        args.insert("token_budget".into(), serde_json::json!(8000));

        let result = handle_explore_codebase(&args, &store).unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        let content = parsed["content"].as_str().unwrap();

        assert!(content.contains("Imported constants"));
        assert!(content.contains(&constant.name));
        assert!(content.contains("export const"));
    }

    #[test]
    fn handle_explore_codebase_trace_evaluates_rust_call_query() {
        let dir = tempdir().unwrap();
        let tag = "traceeval";

        let entry = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step7_{tag}.rs"),
            &format!("probe_final_transform_{tag}"),
            EntityKind::Function,
            &format!("pub fn probe_final_transform_{tag}(n: i64) -> i64"),
            &format!(
                "pub fn probe_final_transform_{tag}(n: i64) -> i64 {{\n  probe_conditional_shift_{tag}(n) + 17\n}}\n"
            ),
        );
        let step6 = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step6_{tag}.rs"),
            &format!("probe_conditional_shift_{tag}"),
            EntityKind::Function,
            &format!("pub fn probe_conditional_shift_{tag}(n: i64) -> i64"),
            &format!(
                "pub fn probe_conditional_shift_{tag}(n: i64) -> i64 {{\n  let amplified = probe_amplify_{tag}(n);\n  if amplified % 2 == 0 {{\n    amplified + 7\n  }} else {{\n    amplified - 11\n  }}\n}}\n"
            ),
        );
        let step5 = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step5_{tag}.rs"),
            &format!("probe_amplify_{tag}"),
            EntityKind::Function,
            &format!("pub fn probe_amplify_{tag}(n: i64) -> i64"),
            &format!(
                "pub fn probe_amplify_{tag}(n: i64) -> i64 {{\n  probe_reduce_{tag}(n) * 3\n}}\n"
            ),
        );
        let step4 = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step4_{tag}.rs"),
            &format!("probe_reduce_{tag}"),
            EntityKind::Function,
            &format!("pub fn probe_reduce_{tag}(n: i64) -> i64"),
            &format!(
                "pub fn probe_reduce_{tag}(n: i64) -> i64 {{\n  probe_conditional_adjust_{tag}(n) - 5\n}}\n"
            ),
        );
        let step3 = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step3_{tag}.rs"),
            &format!("probe_conditional_adjust_{tag}"),
            EntityKind::Function,
            &format!("pub fn probe_conditional_adjust_{tag}(n: i64) -> i64"),
            &format!(
                "pub fn probe_conditional_adjust_{tag}(n: i64) -> i64 {{\n  let intermediate = probe_double_shifted_{tag}(n);\n  if intermediate % 2 == 0 {{\n    intermediate + 3\n  }} else {{\n    intermediate * 2\n  }}\n}}\n"
            ),
        );
        let step2 = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step2_{tag}.rs"),
            &format!("probe_double_shifted_{tag}"),
            EntityKind::Function,
            &format!("pub fn probe_double_shifted_{tag}(n: i64) -> i64"),
            &format!(
                "pub fn probe_double_shifted_{tag}(n: i64) -> i64 {{\n  probe_add_offset_{tag}(n) * 2\n}}\n"
            ),
        );
        let step1 = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/step1_{tag}.rs"),
            &format!("probe_add_offset_{tag}"),
            EntityKind::Function,
            &format!("pub fn probe_add_offset_{tag}(n: i64) -> i64"),
            &format!(
                "pub fn probe_add_offset_{tag}(n: i64) -> i64 {{\n  n + PROBE_BASE_{tag}\n}}\n"
            ),
        );
        let constant = make_trace_entity(
            &dir,
            &format!("src/_kin_probe_{tag}/compute/base_{tag}.rs"),
            &format!("PROBE_BASE_{tag}"),
            EntityKind::Constant,
            &format!("pub const PROBE_BASE_{tag}: i64"),
            &format!("pub const PROBE_BASE_{tag}: i64 = 13;\n"),
        );

        let mut store = EmptyStore::default();
        for entity in [
            entry.clone(),
            step6.clone(),
            step5.clone(),
            step4.clone(),
            step3.clone(),
            step2.clone(),
            step1.clone(),
            constant.clone(),
        ] {
            store.entities_by_id.insert(entity.id, entity);
        }

        insert_trace_relation(&mut store, &entry, &step6, RelationKind::Calls);
        insert_trace_relation(&mut store, &step6, &step5, RelationKind::Calls);
        insert_trace_relation(&mut store, &step5, &step4, RelationKind::Calls);
        insert_trace_relation(&mut store, &step4, &step3, RelationKind::Calls);
        insert_trace_relation(&mut store, &step3, &step2, RelationKind::Calls);
        insert_trace_relation(&mut store, &step2, &step1, RelationKind::Calls);
        insert_trace_relation(&mut store, &step1, &constant, RelationKind::Imports);

        let mut args = HashMap::new();
        args.insert(
            "query".into(),
            serde_json::json!(format!("{}(5)", entry.name)),
        );
        args.insert("strategy".into(), serde_json::json!("trace"));
        args.insert("token_budget".into(), serde_json::json!(8000));

        let result = handle_explore_codebase(&args, &store).unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let parsed: serde_json::Value = serde_json::from_str(&text).unwrap();
        let content = parsed["content"].as_str().unwrap();

        assert!(content.contains("## Evaluation Walkthrough"));
        assert!(content.contains("Input: 5"));
        assert!(content.contains("probe_add_offset"));
        assert!(content.contains("36 is even, so 36 + 3"));
        assert!(content.contains("102 is even, so 102 + 7"));
        assert!(content.contains("Final result: 126"));
    }

    #[test]
    fn handle_dead_code_scopes_to_requested_files() {
        let dead = make_dead_code_entity("src/probe_group0.ts", "probeDelta_1d8f8275", 10);
        let live = make_dead_code_entity("src/probe_group1.ts", "probeAlpha_1d8f8275", 20);
        let ignored = make_dead_code_entity("src/other.ts", "probeOutside_1d8f8275", 30);

        let mut store = EmptyStore::default();
        store
            .entities_by_file
            .insert("src/probe_group0.ts".into(), vec![dead.clone()]);
        store
            .entities_by_file
            .insert("src/probe_group1.ts".into(), vec![live.clone()]);
        store
            .entities_by_file
            .insert("src/other.ts".into(), vec![ignored.clone()]);
        store.live_entity_ids.insert(live.id);

        let mut args = HashMap::new();
        args.insert("limit".into(), serde_json::json!(50));
        args.insert(
            "files".into(),
            serde_json::json!(["src/probe_group0.ts", "src/probe_group1.ts"]),
        );

        let result = handle_dead_code(&args, &store).unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0]["name"], dead.name);
        assert_eq!(
            parsed[0]["file_origin"],
            dead.file_origin.as_ref().unwrap().0
        );
    }

    #[test]
    fn handle_dead_code_falls_back_to_global_query_without_files() {
        let dead = make_dead_code_entity("src/global.ts", "probeGlobal_1d8f8275", 5);
        let mut store = EmptyStore::default();
        store.dead_entities.push(dead.clone());

        let mut args = HashMap::new();
        args.insert("limit".into(), serde_json::json!(10));

        let result = handle_dead_code(&args, &store).unwrap();
        let text = match &result.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let parsed: Vec<serde_json::Value> = serde_json::from_str(&text).unwrap();

        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0]["name"], dead.name);
    }

    #[test]
    fn semantic_search_result_is_compact_summary() {
        let entity = kin_model::entity::Entity {
            id: EntityId::new(),
            kind: EntityKind::Method,
            name: "SnapDocsApp.saveDocument".into(),
            language: LanguageId::JavaScript,
            fingerprint: kin_model::entity::SemanticFingerprint {
                algorithm: kin_model::entity::FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([1; 32]),
                signature_hash: Hash256::from_bytes([2; 32]),
                behavior_hash: Hash256::from_bytes([3; 32]),
                stability_score: 0.9,
            },
            file_origin: Some(kin_model::ids::FilePathId::new("src/app.js")),
            span: Some(kin_model::entity::SourceSpan {
                file: kin_model::ids::FilePathId::new("src/app.js"),
                start_byte: 10,
                end_byte: 40,
                start_line: 12,
                start_col: 4,
                end_line: 16,
                end_col: 2,
            }),
            signature: "saveDocument(doc)".into(),
            visibility: kin_model::entity::Visibility::Public,
            doc_summary: Some("Persist one document.".into()),
            metadata: kin_model::entity::EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };

        let summary = SemanticSearchResult::from(entity);
        let value = serde_json::to_value(summary).unwrap();
        let object = value.as_object().unwrap();

        assert_eq!(object.get("name").unwrap(), "SnapDocsApp.saveDocument");
        assert_eq!(object.get("file_path").unwrap(), "src/app.js");
        assert_eq!(object.get("start_line").unwrap(), 12);
        assert!(object.get("signature").is_some());
        assert!(object.get("fingerprint").is_none());
        assert!(object.get("metadata").is_none());
    }

    #[test]
    fn work_handlers_manage_relationships_and_status() {
        let store = InMemoryGraph::default();

        let mut feature_args = HashMap::new();
        feature_args.insert("kind".into(), serde_json::json!("feature"));
        feature_args.insert("title".into(), serde_json::json!("Ship hosted review"));
        let feature = handle_work_create(&feature_args, &store).unwrap();
        let feature_text = match &feature.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let feature_json: serde_json::Value = serde_json::from_str(&feature_text).unwrap();
        let feature_id = feature_json["work_id"].as_str().unwrap().to_string();

        let mut task_args = HashMap::new();
        task_args.insert("kind".into(), serde_json::json!("task"));
        task_args.insert(
            "title".into(),
            serde_json::json!("Wire semantic work graph"),
        );
        task_args.insert("scopes".into(), serde_json::json!(["artifact:src/lib.rs"]));
        let task = handle_work_create(&task_args, &store).unwrap();
        let task_text = match &task.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let task_json: serde_json::Value = serde_json::from_str(&task_text).unwrap();
        let task_id = task_json["work_id"].as_str().unwrap().to_string();

        let mut blocker_args = HashMap::new();
        blocker_args.insert("kind".into(), serde_json::json!("issue"));
        blocker_args.insert("title".into(), serde_json::json!("Resolve sync edge cases"));
        let blocker = handle_work_create(&blocker_args, &store).unwrap();
        let blocker_text = match &blocker.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let blocker_json: serde_json::Value = serde_json::from_str(&blocker_text).unwrap();
        let blocker_id = blocker_json["work_id"].as_str().unwrap().to_string();

        let mut decompose_args = HashMap::new();
        decompose_args.insert("parent_work_id".into(), serde_json::json!(feature_id));
        decompose_args.insert("child_work_id".into(), serde_json::json!(task_id.clone()));
        handle_work_decompose(&decompose_args, &store).unwrap();

        let mut block_args = HashMap::new();
        block_args.insert("blocked_work_id".into(), serde_json::json!(task_id.clone()));
        block_args.insert("blocker_work_id".into(), serde_json::json!(blocker_id));
        handle_work_block(&block_args, &store).unwrap();

        let mut implement_args = HashMap::new();
        implement_args.insert("work_id".into(), serde_json::json!(task_id.clone()));
        implement_args.insert("scopes".into(), serde_json::json!(["artifact:src/lib.rs"]));
        handle_work_implement(&implement_args, &store).unwrap();

        let mut status_args = HashMap::new();
        status_args.insert("work_id".into(), serde_json::json!(task_id.clone()));
        status_args.insert("status".into(), serde_json::json!("in_progress"));
        handle_work_status(&status_args, &store).unwrap();

        let mut show_args = HashMap::new();
        show_args.insert("work_id".into(), serde_json::json!(task_id));
        let shown = handle_work_show(&show_args, &store).unwrap();
        let shown_text = match &shown.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let shown_json: serde_json::Value = serde_json::from_str(&shown_text).unwrap();

        assert_eq!(shown_json["status"], "in_progress");
        assert_eq!(shown_json["parents"].as_array().unwrap().len(), 1);
        assert_eq!(shown_json["blockers"].as_array().unwrap().len(), 1);
        assert_eq!(shown_json["implementors"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn annotation_handlers_support_work_targets() {
        let store = InMemoryGraph::default();

        let mut create_args = HashMap::new();
        create_args.insert("kind".into(), serde_json::json!("task"));
        create_args.insert("title".into(), serde_json::json!("Track proof gaps"));
        create_args.insert(
            "scopes".into(),
            serde_json::json!(["artifact:src/proof.rs"]),
        );
        let work = handle_work_create(&create_args, &store).unwrap();
        let work_text = match &work.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let work_json: serde_json::Value = serde_json::from_str(&work_text).unwrap();
        let work_id = work_json["work_id"].as_str().unwrap().to_string();

        let mut add_args = HashMap::new();
        add_args.insert("kind".into(), serde_json::json!("reasoning"));
        add_args.insert(
            "body".into(),
            serde_json::json!("Keep this attached to the work object."),
        );
        add_args.insert(
            "targets".into(),
            serde_json::json!([format!("work:{}", work_id)]),
        );
        let added = handle_annotation_add(&add_args, &store).unwrap();
        let added_text = match &added.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let added_json: serde_json::Value = serde_json::from_str(&added_text).unwrap();
        assert_eq!(added_json["kind"], "reasoning");

        let mut list_args = HashMap::new();
        list_args.insert(
            "targets".into(),
            serde_json::json!([format!("work:{}", work_id)]),
        );
        let listed = handle_annotation_list(&list_args, &store).unwrap();
        let listed_text = match &listed.content[0] {
            crate::types::ContentBlock::Text { text } => text.clone(),
        };
        let listed_json: serde_json::Value = serde_json::from_str(&listed_text).unwrap();
        assert_eq!(listed_json.as_array().unwrap().len(), 1);
        assert_eq!(listed_json[0]["scopes"].as_array().unwrap().len(), 1);
    }
}
