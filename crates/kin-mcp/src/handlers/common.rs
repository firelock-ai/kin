// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use kin_model::entity::{Entity, EntityKind, SourceSpan};
use kin_model::graph::{EntityFilter, GraphStore};
use kin_model::ids::{EntityId, Hash256, IntentId, LanguageId, SemanticChangeId, SessionId};
use kin_model::relation::{GraphNodeId, RelationKind};
use kin_model::session::{IntentScope, LockType, SessionCapabilities, SessionTransport};
use std::sync::atomic::{AtomicU64, Ordering};

pub static GRAPH_MISS_COUNT: AtomicU64 = AtomicU64::new(0);

thread_local! {
    pub static LAST_READ_STALE: std::cell::Cell<bool> = std::cell::Cell::new(false);
    pub static LAST_READ_SOURCE: std::cell::Cell<&'static str> = std::cell::Cell::new("unknown");
}

use crate::error::{McpError, Result};

// ── Parameter extraction helpers ──

pub fn get_string_param(args: &HashMap<String, serde_json::Value>, key: &str) -> Result<String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| McpError::InvalidParams(format!("missing required parameter: {}", key)))
}

pub fn get_optional_u64(args: &HashMap<String, serde_json::Value>, key: &str, default: u64) -> u64 {
    args.get(key).and_then(|v| v.as_u64()).unwrap_or(default)
}

pub fn get_optional_bool(
    args: &HashMap<String, serde_json::Value>,
    key: &str,
    default: bool,
) -> bool {
    args.get(key).and_then(|v| v.as_bool()).unwrap_or(default)
}

pub fn get_optional_string_param(
    args: &HashMap<String, serde_json::Value>,
    key: &str,
) -> Option<String> {
    args.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

pub fn get_optional_string_array(
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

// ── ID parsing helpers ──

pub fn parse_entity_id(s: &str) -> Result<EntityId> {
    serde_json::from_value(serde_json::json!(s))
        .map_err(|e| McpError::InvalidParams(format!("invalid entity_id: {}", e)))
}

pub fn parse_change_id(s: &str) -> Result<SemanticChangeId> {
    Hash256::from_hex(s)
        .map(SemanticChangeId::from_hash)
        .map_err(|e| McpError::InvalidParams(format!("invalid change ID hex: {}", e)))
}

pub fn parse_session_id(s: &str) -> Result<SessionId> {
    serde_json::from_value(serde_json::json!(s))
        .map_err(|e| McpError::InvalidParams(format!("invalid session_id: {}", e)))
}

pub fn parse_intent_id(s: &str) -> Result<IntentId> {
    serde_json::from_value(serde_json::json!(s))
        .map_err(|e| McpError::InvalidParams(format!("invalid intent_id: {}", e)))
}

pub fn parse_transport(s: &str) -> SessionTransport {
    match s.to_lowercase().as_str() {
        "mcp" => SessionTransport::Mcp,
        "cli" => SessionTransport::Cli,
        "wrapper" => SessionTransport::Wrapper,
        "ui" => SessionTransport::Ui,
        _ => SessionTransport::Mcp,
    }
}

pub fn parse_lock_type(s: &str) -> LockType {
    match s.to_lowercase().as_str() {
        "hard" => LockType::Hard,
        _ => LockType::Soft,
    }
}

pub fn parse_reference_kind(kind: &str) -> Option<RelationKind> {
    match kind.to_ascii_lowercase().as_str() {
        "calls" | "call" => Some(RelationKind::Calls),
        "imports" | "import" => Some(RelationKind::Imports),
        "references" | "reference" | "refs" => Some(RelationKind::References),
        _ => None,
    }
}

pub fn default_reference_kinds() -> Vec<RelationKind> {
    vec![
        RelationKind::Calls,
        RelationKind::Imports,
        RelationKind::References,
    ]
}

pub fn relation_kind_name(kind: RelationKind) -> &'static str {
    match kind {
        RelationKind::Calls => "calls",
        RelationKind::Imports => "imports",
        RelationKind::References => "references",
        _ => "other",
    }
}

// ── Spine Federation Helpers ──────────────────────────────────────────────

fn daemon_url_from_env() -> Result<String> {
    std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            McpError::Other(
                "KIN_DAEMON_URL is required; start MCP through `kin mcp start` so the repo daemon is supervisor-routed"
                    .to_string(),
            )
        })
}

/// Query the daemon for federated impact analysis across the spine.
pub async fn fetch_spine_impact(
    repo_id: &str,
    entity_id: &EntityId,
    depth: u32,
) -> Result<Option<serde_json::Value>> {
    let daemon_url = daemon_url_from_env()?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| McpError::Other(format!("failed to build reqwest client: {}", e)))?;

    let resp = client
        .get(format!(
            "{}/v1/spine/impact",
            daemon_url.trim_end_matches('/')
        ))
        .query(&[
            ("repo", repo_id),
            ("entity", &entity_id.to_string()),
            ("depth", &depth.to_string()),
        ])
        .send()
        .await
        .map_err(|e| McpError::Other(format!("failed to send spine request: {}", e)))?;

    if !resp.status().is_success() {
        return Ok(None);
    }

    let impact = resp
        .json::<serde_json::Value>()
        .await
        .map_err(|e| McpError::Other(format!("failed to parse spine response: {}", e)))?;
    Ok(Some(impact))
}

/// Query the daemon for federated impact analysis, returning the typed struct.
pub async fn fetch_spine_impact_typed(
    repo_id: &str,
    entity_id: &EntityId,
    depth: u32,
) -> Result<Option<kin_spine::FederatedImpact>> {
    let daemon_url = daemon_url_from_env()?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| McpError::Other(format!("failed to build reqwest client: {}", e)))?;

    let resp = client
        .get(format!(
            "{}/v1/spine/impact",
            daemon_url.trim_end_matches('/')
        ))
        .query(&[
            ("repo", repo_id),
            ("entity", &entity_id.to_string()),
            ("depth", &depth.to_string()),
        ])
        .send()
        .await
        .map_err(|e| McpError::Other(format!("failed to send spine request: {}", e)))?;

    if !resp.status().is_success() {
        return Ok(None);
    }

    let impact = resp
        .json::<kin_spine::FederatedImpact>()
        .await
        .map_err(|e| McpError::Other(format!("failed to parse spine impact response: {}", e)))?;
    Ok(Some(impact))
}

/// Query the daemon for cross-repo edges (xrefs) for a specific entity.
pub async fn fetch_spine_xref(
    repo_id: &str,
    entity_id: &EntityId,
) -> Result<Option<serde_json::Value>> {
    let daemon_url = daemon_url_from_env()?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .map_err(|e| McpError::Other(format!("failed to build reqwest client: {}", e)))?;

    let resp = client
        .get(format!(
            "{}/v1/spine/xref",
            daemon_url.trim_end_matches('/')
        ))
        .query(&[("repo", repo_id), ("entity", &entity_id.to_string())])
        .send()
        .await
        .map_err(|e| McpError::Other(format!("failed to send spine request: {}", e)))?;

    if !resp.status().is_success() {
        return Ok(None);
    }

    let body = resp
        .json::<serde_json::Value>()
        .await
        .map_err(|e| McpError::Other(format!("failed to parse spine response: {}", e)))?;
    Ok(Some(body))
}

// ── Entity selection and ranking ──
// Shared ranking primitives live in kin-search; re-exported here for backward
// compatibility with existing handler code.
pub use kin_ranking::entity_ranking::{
    declaration_kind_rank, entity_directory, relation_kind_rank,
    select_best_entity as select_best_reference_target,
};

// ── Trace helpers ──

pub fn broaden_trace_query(query: &str) -> Option<String> {
    query
        .rsplit_once('_')
        .map(|(prefix, _)| prefix.to_string())
        .filter(|prefix| prefix.len() >= 4 && prefix != query)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TraceQuery {
    pub symbol: String,
    pub input_literal: Option<i64>,
}

pub fn parse_trace_query(query: &str) -> TraceQuery {
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

pub fn outgoing_related_entities<G: GraphStore>(
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
        let Some(related_entity_id) = rel.dst.as_entity() else {
            continue;
        };
        if rel.src != GraphNodeId::Entity(*entity_id)
            || !allowed.contains(&rel.kind)
            || !seen.insert(related_entity_id)
        {
            continue;
        }
        let Some(entity) = store
            .get_entity(&related_entity_id)
            .map_err(McpError::graph)?
        else {
            continue;
        };
        entities.push(entity);
    }

    Ok(entities)
}

pub fn outgoing_related_entities_with_kinds<G: GraphStore>(
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
        let Some(related_entity_id) = rel.dst.as_entity() else {
            continue;
        };
        if rel.src != GraphNodeId::Entity(*entity_id)
            || !allowed.contains(&rel.kind)
            || !seen.insert(related_entity_id)
        {
            continue;
        }
        let Some(entity) = store
            .get_entity(&related_entity_id)
            .map_err(McpError::graph)?
        else {
            continue;
        };
        entities.push((entity, rel.kind));
    }

    Ok(entities)
}

pub fn is_trace_function(entity: &Entity) -> bool {
    matches!(entity.kind, EntityKind::Function | EntityKind::Method)
}

pub use kin_ranking::entity_ranking::{trace_callee_score, trace_relation_rank};

pub fn next_trace_step<G: GraphStore>(
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

pub fn collect_primary_trace_chain<G: GraphStore>(
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

pub fn trace_body<G: GraphStore>(store: &G, entity: &Entity) -> String {
    read_entity_source_excerpt_detailed(store, entity, MCP_SOURCE_MAX_LINES, MCP_SOURCE_MAX_CHARS)
        .unwrap_or_else(|| entity.signature.clone())
}

pub fn looks_like_constant_identifier(token: &str) -> bool {
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

pub fn extract_constant_identifiers(body: &str) -> Vec<String> {
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

pub use kin_ranking::entity_ranking::trace_constant_score;

pub fn inferred_trace_constants<G: GraphStore>(
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

pub fn trace_constants_for_step<G: GraphStore>(
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

pub fn parse_trace_constant_value(body: &str) -> Option<i64> {
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

pub fn clean_trace_expr(expr: &str) -> &str {
    expr.trim()
        .trim_end_matches(';')
        .trim_end_matches('{')
        .trim_end_matches('}')
        .trim()
}

pub fn parse_trace_assignment(line: &str) -> Option<(String, String)> {
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

pub fn parse_trace_even_condition_var(line: &str) -> Option<String> {
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

pub fn extract_trace_expression(line: &str) -> Option<String> {
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

pub fn evaluate_trace_operand(
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

pub fn evaluate_trace_expression(
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
pub struct TraceEvaluationStep {
    pub name: String,
    pub value: i64,
    pub detail: String,
}

pub fn evaluate_trace_step_body(
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

pub fn evaluate_trace_chain<G: GraphStore>(
    store: &G,
    chain: &[Entity],
    input_literal: i64,
) -> Result<Option<Vec<TraceEvaluationStep>>> {
    let mut constant_values = HashMap::new();
    for step in chain {
        let body = trace_body(store, step);
        for constant in trace_constants_for_step(store, step, &body)? {
            if let Some(value) = parse_trace_constant_value(&trace_body(store, &constant)) {
                constant_values
                    .entry(constant.name.clone())
                    .or_insert(value);
            }
        }
    }

    let mut function_values = HashMap::new();
    let mut evaluation = Vec::new();

    for step in chain.iter().rev() {
        let body = trace_body(store, step);
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

// ── Token budget helpers ──

pub fn push_with_budget(
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

pub fn push_indented_body(
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

// ── Reference row types ──

#[derive(Debug, Clone)]
pub struct ReferenceRow {
    pub name: String,
    pub kind: Option<String>,
    pub file_path: Option<String>,
    pub start_line: Option<u32>,
    pub signature: Option<String>,
    pub relation_kinds: Vec<RelationKind>,
}

pub fn collect_graph_reference_rows<G: GraphStore>(
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
        let Some(source_entity_id) = rel.src.as_entity() else {
            continue;
        };
        if rel.dst != GraphNodeId::Entity(*entity_id) || !allowed.contains(&rel.kind) {
            continue;
        }
        let Some(entity) = store
            .get_entity(&source_entity_id)
            .map_err(McpError::graph)?
        else {
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

pub fn merge_text_reference_rows(
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

pub fn reference_row_key(file_path: Option<&str>, name: &str) -> String {
    file_path
        .map(|path| path.to_string())
        .unwrap_or_else(|| format!("name:{name}"))
}

pub const MCP_SOURCE_MAX_LINES: usize = 40;
pub const MCP_SOURCE_MAX_CHARS: usize = 2400;

pub fn label_from_path(rel_path: &str) -> String {
    Path::new(rel_path)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or(rel_path)
        .to_string()
}

pub fn push_reference_kind(kinds: &mut Vec<RelationKind>, kind: RelationKind) {
    if !kinds.contains(&kind) {
        kinds.push(kind);
    }
}

pub fn resolve_reference_source_root() -> Option<PathBuf> {
    candidate_source_roots().into_iter().next()
}

pub fn candidate_source_roots() -> Vec<PathBuf> {
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

pub fn display_read_path(rel_path: &str) -> String {
    if std::env::var_os("KIN_SOURCE_ROOT").is_some() {
        format!(".kin/source-root/{rel_path}")
    } else {
        rel_path.to_string()
    }
}

pub fn entity_read_path(entity: &Entity) -> Option<String> {
    entity
        .file_origin
        .as_ref()
        .map(|path| display_read_path(path.0.as_str()))
}

pub fn resolve_entity_source_path(entity: &Entity) -> Option<PathBuf> {
    let rel_path = entity.file_origin.as_ref()?.0.as_str();

    for root in candidate_source_roots() {
        let candidate = root.join(rel_path);
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    None
}

pub fn read_entity_source_excerpt_detailed<G: GraphStore>(
    store: &G,
    entity: &Entity,
    max_lines: usize,
    max_chars: usize,
) -> Option<String> {
    LAST_READ_STALE.with(|f| f.set(false));
    LAST_READ_SOURCE.with(|f| f.set("unknown"));

    let span = entity.span.as_ref()?;

    // Retrieve graph hash
    let graph_hash = if let Some(ref file_origin) = entity.file_origin {
        store.get_file_hash(file_origin).ok().flatten()
    } else {
        None
    };

    let mut blob_bytes = None;
    if let Some(ref hash) = graph_hash {
        // Look through candidate source roots for a KinLayout
        for root in candidate_source_roots() {
            if let Some(layout) = kin_core::KinLayout::discover(&root) {
                if let Some(bytes) = kin_core::read_blob_from_layout(&layout, hash) {
                    let actual_hash = kin_blobs::digest(&bytes);
                    if actual_hash == *hash {
                        blob_bytes = Some(bytes);
                        break;
                    } else {
                        tracing::warn!(
                            "Hash mismatch for blob in layout at {:?}: expected {}, got {}",
                            layout.objects_dir(),
                            hash,
                            actual_hash
                        );
                    }
                }
            }
        }
    }

    if let Some(bytes) = blob_bytes {
        LAST_READ_SOURCE.with(|f| f.set("graph"));
        let excerpt = excerpt_from_span_bytes(&bytes, span, max_lines, max_chars);
        if let Some(ref excerpt) = excerpt {
            if !should_expand_excerpt(entity, excerpt) {
                return Some(excerpt.clone());
            }
        }
        let text = String::from_utf8_lossy(&bytes);
        return expand_entity_source_excerpt(entity, &text, span.start_byte, max_lines, max_chars)
            .or(excerpt);
    }

    // Fall back to disk
    GRAPH_MISS_COUNT.fetch_add(1, Ordering::SeqCst);
    LAST_READ_SOURCE.with(|f| f.set("disk"));

    let path = resolve_entity_source_path(entity)?;
    let disk_bytes = std::fs::read(&path).ok()?;

    // Verify span bounds sanity
    if span.start_byte > disk_bytes.len() || span.end_byte > disk_bytes.len() {
        tracing::warn!(
            "Span bounds sanity check failed for entity {} on file {:?}: start_byte={}, end_byte={}, file size={}",
            entity.id,
            path,
            span.start_byte,
            span.end_byte,
            disk_bytes.len()
        );
        return None;
    }

    // Detect if disk content is stale
    if let Some(ref gh) = graph_hash {
        let disk_hash = kin_blobs::digest(&disk_bytes);
        if disk_hash != *gh {
            LAST_READ_STALE.with(|f| f.set(true));
            tracing::warn!(
                "Disk content stale for {:?}: disk hash {} != graph hash {}",
                path,
                disk_hash,
                gh
            );
        }
    }

    let excerpt = excerpt_from_span_bytes(&disk_bytes, span, max_lines, max_chars);
    if let Some(ref excerpt) = excerpt {
        if !should_expand_excerpt(entity, excerpt) {
            return Some(excerpt.clone());
        }
    }

    let text = String::from_utf8_lossy(&disk_bytes);
    expand_entity_source_excerpt(entity, &text, span.start_byte, max_lines, max_chars).or(excerpt)
}

pub fn excerpt_from_span_bytes(
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

pub fn excerpt_from_line_range(
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

pub fn should_expand_excerpt(entity: &Entity, excerpt: &str) -> bool {
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

pub fn expand_entity_source_excerpt(
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
        | LanguageId::CSharp
        | LanguageId::Php
        | LanguageId::Swift
        | LanguageId::Kotlin
        | LanguageId::Hcl => expand_brace_block_excerpt(content, start_idx, max_lines, max_chars),
        LanguageId::Ruby => expand_ruby_block_excerpt(content, start_idx, max_lines, max_chars),
    }
}

pub fn line_index_for_byte(bytes: &[u8], byte: usize) -> usize {
    bytes[..byte.min(bytes.len())]
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
}

pub fn expand_python_block_excerpt(
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

pub fn expand_brace_block_excerpt(
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

pub fn expand_ruby_block_excerpt(
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

pub fn starts_ruby_block(line: &str) -> bool {
    matches!(
        line.split_whitespace().next(),
        Some("class" | "module" | "def" | "if" | "unless" | "case" | "begin" | "do")
    )
}

pub fn leading_indent(line: &str) -> usize {
    line.chars()
        .take_while(|ch| matches!(ch, ' ' | '\t'))
        .count()
}

pub fn clip_rendered_text_with_cap(text: &str, max_lines: usize, max_chars: usize) -> String {
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

// ── Entity JSON formatting ──

pub fn entity_response_json<G: GraphStore>(
    store: &G,
    entity: &Entity,
) -> Result<serde_json::Value> {
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
    if let Some(source_excerpt) = read_entity_source_excerpt_detailed(
        store,
        entity,
        MCP_SOURCE_MAX_LINES,
        MCP_SOURCE_MAX_CHARS,
    ) {
        obj.insert("source_excerpt".into(), serde_json::json!(source_excerpt));
    }

    let is_stale = LAST_READ_STALE.with(|f| f.get());
    obj.insert("stale".into(), serde_json::json!(is_stale));
    let source = LAST_READ_SOURCE.with(|f| f.get());
    obj.insert("source".into(), serde_json::json!(source));

    Ok(value)
}

pub fn focal_context_json<G: GraphStore>(
    store: &G,
    entry: &kin_model::ContextEntry,
    entity: &Entity,
    compact: bool,
) -> serde_json::Value {
    let start_line = entity.span.as_ref().map(|span| span.start_line);
    let end_line = entity.span.as_ref().map(|span| span.end_line);
    let source_excerpt = read_entity_source_excerpt_detailed(
        store,
        entity,
        MCP_SOURCE_MAX_LINES,
        MCP_SOURCE_MAX_CHARS,
    );
    let is_stale = LAST_READ_STALE.with(|f| f.get());
    let source = LAST_READ_SOURCE.with(|f| f.get());

    let mut obj = serde_json::json!({
        "id": entity.id,
        "name": entity.name,
        "kind": entity.kind,
        "signature": entity.signature,
        "file_path": entity.file_origin.as_ref().map(|p| p.to_string()),
        "read_path": entity_read_path(entity),
        "start_line": start_line,
        "end_line": end_line,
        "stale": is_stale,
        "source": source,
    });

    if !compact {
        obj["body"] = serde_json::json!(source_excerpt.unwrap_or_else(|| entry.content.clone()));
    }

    obj
}

// ── Scope/intent parsing ──

pub fn parse_scopes(value: &serde_json::Value) -> Result<Vec<IntentScope>> {
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

pub fn get_json_object<'a>(
    args: &'a HashMap<String, serde_json::Value>,
    key: &str,
) -> Result<&'a serde_json::Map<String, serde_json::Value>> {
    args.get(key)
        .and_then(|v| v.as_object())
        .ok_or_else(|| McpError::InvalidParams(format!("{} must be a valid JSON object", key)))
}

pub fn parse_capabilities(args: &HashMap<String, serde_json::Value>) -> SessionCapabilities {
    let Some(obj) = args.get("capabilities").and_then(|v| v.as_object()) else {
        return SessionCapabilities::default();
    };

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

// ── Search filter helpers ──

pub fn build_semantic_search_request(
    args: &HashMap<String, serde_json::Value>,
) -> Result<(String, usize, EntityFilter)> {
    let query = get_string_param(args, "query")?;
    let limit = get_optional_u64(args, "limit", 20) as usize;

    let kind_str = args.get("kind").and_then(|v| v.as_str());
    let kind_filter = kind_str.and_then(parse_kind_filter);
    let role_filter = match kind_str {
        Some(k) if k.eq_ignore_ascii_case("test") => Some(vec![kin_model::EntityRole::Test]),
        _ => None,
    };
    let language_filter = args
        .get("language")
        .and_then(|v| v.as_str())
        .and_then(parse_language_filter);

    let filter = EntityFilter {
        kinds: kind_filter,
        languages: language_filter,
        roles: role_filter,
        name_pattern: Some(query.clone()),
        ..Default::default()
    };

    Ok((query, limit, filter))
}

pub fn parse_kind_filter(kind: &str) -> Option<Vec<EntityKind>> {
    match kind.to_lowercase().as_str() {
        "function" | "fn" => Some(vec![EntityKind::Function, EntityKind::Method]),
        "class" => Some(vec![EntityKind::Class]),
        "interface" => Some(vec![EntityKind::Interface]),
        "trait" | "traitdef" => Some(vec![EntityKind::TraitDef]),
        "type_alias" => Some(vec![EntityKind::TypeAlias]),
        "module" => Some(vec![EntityKind::Module]),
        "package" => Some(vec![EntityKind::Package]),
        // "test" is role-based (EntityRole::Test), not kind-based.
        // Return None so the caller can apply role filtering instead.
        "test" => None,
        "schema" => Some(vec![EntityKind::Schema]),
        "api_endpoint" => Some(vec![EntityKind::ApiEndpoint]),
        "event_contract" => Some(vec![EntityKind::EventContract]),
        "method" => Some(vec![EntityKind::Method]),
        "enum" | "enumdef" => Some(vec![EntityKind::EnumDef]),
        "constant" => Some(vec![EntityKind::Constant]),
        _ => None,
    }
}

pub fn parse_language_filter(language: &str) -> Option<Vec<LanguageId>> {
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
        "php" => Some(vec![LanguageId::Php]),
        "swift" => Some(vec![LanguageId::Swift]),
        "kotlin" | "kt" | "kts" => Some(vec![LanguageId::Kotlin]),
        "hcl" | "terraform" | "tf" => Some(vec![LanguageId::Hcl]),
        _ => None,
    }
}

// ── Search result types ──

#[derive(Debug, Serialize)]
pub struct SemanticSearchResponse {
    pub query: String,
    pub limit: usize,
    pub total_matches: usize,
    pub truncated: bool,
    pub results: Vec<SemanticSearchResult>,
}

#[derive(Debug, Serialize)]
pub struct SemanticSearchResult {
    pub id: EntityId,
    pub name: String,
    pub kind: EntityKind,
    pub language: LanguageId,
    pub file_path: Option<String>,
    pub start_line: Option<u32>,
    pub signature: String,
    pub doc_summary: Option<String>,
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
pub struct CompactSearchResponse {
    pub query: String,
    pub limit: usize,
    pub total_matches: usize,
    pub truncated: bool,
    pub results: Vec<CompactSearchResult>,
}

#[derive(Debug, Serialize)]
pub struct CompactSearchResult {
    pub id: EntityId,
    pub name: String,
    pub kind: EntityKind,
    pub language: LanguageId,
    pub file_path: Option<String>,
    pub start_line: Option<u32>,
    pub end_line: Option<u32>,
    pub signature: String,
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

// ── Diff resolution ──

/// Resolve a SemanticDiff from whichever mode the caller specified:
///   1. entity_ids  → diff_from_entity_ids
///   2. files       → diff_from_files
///   3. change_ids  → fetch changes, diff_from_changes
///   4. base + head → compute_diff (original behavior)
pub fn resolve_diff<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<kin_review::SemanticDiff> {
    // Mode 1: explicit entity IDs
    if let Some(eids) = get_optional_string_array(args, "entity_ids") {
        if !eids.is_empty() {
            let entity_ids: Vec<EntityId> = eids
                .iter()
                .map(|s| parse_entity_id(s))
                .collect::<Result<Vec<_>>>()?;
            return kin_review::diff_from_entity_ids(store, &entity_ids)
                .map_err(|e| McpError::Review(e.to_string()));
        }
    }

    // Mode 2: file paths
    if let Some(files) = get_optional_string_array(args, "files") {
        if !files.is_empty() {
            return kin_review::diff_from_files(store, &files)
                .map_err(|e| McpError::Review(e.to_string()));
        }
    }

    // Mode 3: explicit change IDs
    if let Some(cids) = get_optional_string_array(args, "change_ids") {
        if !cids.is_empty() {
            let mut changes = Vec::new();
            for cid_hex in &cids {
                let cid = parse_change_id(cid_hex)?;
                let change = store
                    .get_change(&cid)
                    .map_err(|e| McpError::Review(e.to_string()))?
                    .ok_or_else(|| McpError::Review(format!("change {} not found", cid)))?;
                changes.push(change);
            }
            return Ok(kin_review::diff_from_changes(&changes));
        }
    }

    // Mode 4: base + head (original)
    let base_hex = get_string_param(args, "base")?;
    let head_hex = get_string_param(args, "head")?;
    let base = parse_change_id(&base_hex)?;
    let head = parse_change_id(&head_hex)?;
    kin_review::compute_diff(store, &base, &head).map_err(|e| McpError::Review(e.to_string()))
}

// ── Work/annotation helpers ──

pub fn parse_work_scopes(val: Option<&serde_json::Value>) -> Result<Vec<kin_model::WorkScope>> {
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

pub fn parse_annotation_targets(
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

pub fn parse_annotation_target(s: &str) -> Result<kin_model::AnnotationTarget> {
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

pub fn parse_single_work_scope(s: &str) -> Result<kin_model::WorkScope> {
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

pub fn parse_work_id_param(
    args: &HashMap<String, serde_json::Value>,
    key: &str,
) -> Result<(String, kin_model::WorkId)> {
    let work_id_str = get_string_param(args, key)?;
    let uuid = uuid::Uuid::parse_str(&work_id_str)
        .map_err(|_| McpError::InvalidParams(format!("invalid {}: {}", key, work_id_str)))?;
    Ok((work_id_str, kin_model::WorkId(uuid)))
}

pub fn ensure_work_item_exists<G: GraphStore>(
    store: &G,
    work_id: &kin_model::WorkId,
    display: &str,
) -> Result<kin_model::WorkItem> {
    store
        .get_work_item(work_id)
        .map_err(|e| McpError::Other(e.to_string()))?
        .ok_or_else(|| McpError::InvalidParams(format!("work item not found: {}", display)))
}

pub fn summarize_work_item(item: &kin_model::WorkItem) -> serde_json::Value {
    serde_json::json!({
        "work_id": item.work_id.to_string(),
        "kind": item.kind.to_string(),
        "title": item.title,
        "status": item.status.to_string(),
    })
}

pub fn summarize_annotation(annotation: &kin_model::Annotation) -> serde_json::Value {
    serde_json::json!({
        "annotation_id": annotation.annotation_id.to_string(),
        "kind": annotation.kind.to_string(),
        "body": annotation.body,
        "staleness": annotation.staleness.to_string(),
        "scopes": annotation.scopes.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
    })
}
