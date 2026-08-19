// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};

use kin_index::RelationResolution;
use kin_model::change::TreeEntry;
use kin_model::entity::{Entity, EntityKind, SourceSpan};
use kin_model::graph::{ChangeStore, EntityFilter, GraphStore};
use kin_model::ids::{
    EntityId, Hash256, IntentId, LanguageId, RepoPath, SemanticChangeId, SessionId,
};
use kin_model::relation::{GraphNodeId, RelationKind};
use kin_model::session::{IntentScope, LockType, SessionCapabilities, SessionTransport};
use kin_model::ArtifactId;
use std::sync::atomic::{AtomicU64, Ordering};

pub static GRAPH_MISS_COUNT: AtomicU64 = AtomicU64::new(0);

thread_local! {
    pub static LAST_READ_SOURCE: std::cell::Cell<&'static str> = std::cell::Cell::new("unknown");
}

use super::repository_authority::{
    ActiveRepositoryAuthority, RequestRepositoryAuthority, WorkspaceReadSample,
};
use crate::error::{McpError, Result};

pub use super::repository_authority::{
    repository_authority_opens_on_this_thread, REPOSITORY_AUTHORITY_OPEN_COUNT,
};
use kin_spine::{classify_spine_probe, SpineProbe, SpineQuery};

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

/// Query the daemon for federated impact analysis, returning the typed struct.
///
/// Returns a [`SpineQuery`] so callers can distinguish a spine that is simply
/// not configured (local-only: quiet) from one that is configured but
/// unavailable (surface it) and a healthy, possibly-empty answer.
pub async fn fetch_spine_impact_typed(
    repo_id: &str,
    entity_id: &EntityId,
    depth: u32,
) -> SpineQuery<kin_spine::FederatedImpact> {
    let Ok(daemon_url) = daemon_url_from_env() else {
        return SpineQuery::NotConfigured;
    };
    fetch_spine_impact_typed_at(&daemon_url, repo_id, entity_id, depth).await
}

/// Query an explicitly named daemon for federated impact analysis.
///
/// The endpoint is an argument so a caller that already knows it does not have
/// to publish it through `KIN_DAEMON_URL`. That variable is process-global, and
/// under `cargo test` a binary's tests are threads in one process, so a test
/// setting it to reach its own stub server also repoints every other test that
/// resolves a daemon. Endpoint resolution belongs at the entry boundary, where
/// it happens once, rather than inside a request that other code shares.
pub async fn fetch_spine_impact_typed_at(
    daemon_url: &str,
    repo_id: &str,
    entity_id: &EntityId,
    depth: u32,
) -> SpineQuery<kin_spine::FederatedImpact> {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(client) => client,
        Err(e) => return SpineQuery::Unavailable(format!("failed to build reqwest client: {e}")),
    };

    let resp = match crate::daemon_delegate::with_auth(
        client.get(format!("{}/spine/impact", daemon_url.trim_end_matches('/'))),
    )
    .query(&[
        ("repo", repo_id),
        ("entity", &entity_id.to_string()),
        ("depth", &depth.to_string()),
    ])
    .send()
    .await
    {
        Ok(resp) => resp,
        Err(e) => return SpineQuery::Unavailable(format!("spine request failed: {e}")),
    };

    match classify_spine_probe(true, Some(resp.status().as_u16())) {
        SpineProbe::Healthy => match resp.json::<kin_spine::FederatedImpact>().await {
            Ok(impact) => SpineQuery::Found(impact),
            Err(e) => SpineQuery::Unavailable(format!("malformed spine impact response: {e}")),
        },
        SpineProbe::Unavailable(reason) => SpineQuery::Unavailable(reason),
        SpineProbe::NotConfigured => {
            SpineQuery::Unavailable("spine endpoint unexpectedly unconfigured".to_string())
        }
    }
}

/// Query the daemon for cross-repo edges (xrefs) for a specific entity.
///
/// See [`fetch_spine_impact_typed`] for the [`SpineQuery`] three-state contract.
pub async fn fetch_spine_xref(
    repo_id: &str,
    entity_id: &EntityId,
) -> SpineQuery<kin_spine::SpineXrefResponse> {
    let Ok(daemon_url) = daemon_url_from_env() else {
        return SpineQuery::NotConfigured;
    };
    fetch_spine_xref_at(&daemon_url, repo_id, entity_id).await
}

/// Query an explicitly named daemon for cross-repo edges.
///
/// See [`fetch_spine_impact_typed_at`] for why the endpoint is an argument.
pub async fn fetch_spine_xref_at(
    daemon_url: &str,
    repo_id: &str,
    entity_id: &EntityId,
) -> SpineQuery<kin_spine::SpineXrefResponse> {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(client) => client,
        Err(e) => return SpineQuery::Unavailable(format!("failed to build reqwest client: {e}")),
    };

    let resp = match crate::daemon_delegate::with_auth(
        client.get(format!("{}/spine/xref", daemon_url.trim_end_matches('/'))),
    )
    .query(&[("repo", repo_id), ("entity", &entity_id.to_string())])
    .send()
    .await
    {
        Ok(resp) => resp,
        Err(e) => return SpineQuery::Unavailable(format!("spine request failed: {e}")),
    };

    match classify_spine_probe(true, Some(resp.status().as_u16())) {
        SpineProbe::Healthy => match resp.bytes().await {
            Ok(bytes) => {
                match kin_spine::SpineXrefResponse::from_slice_for(&bytes, repo_id, entity_id) {
                    Ok(body) => SpineQuery::Found(body),
                    Err(e) => SpineQuery::Unavailable(e.to_string()),
                }
            }
            Err(e) => SpineQuery::Unavailable(format!("failed to read spine response: {e}")),
        },
        SpineProbe::Unavailable(reason) => SpineQuery::Unavailable(reason),
        SpineProbe::NotConfigured => {
            SpineQuery::Unavailable("spine endpoint unexpectedly unconfigured".to_string())
        }
    }
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

pub use kin_ranking::entity_ranking::{
    trace_callee_score, trace_entity_is_external, trace_fanout_score, trace_relation_rank,
    trace_step_terminal, TraceTerminal,
};

/// Serialized characters one trace response may occupy before the tool cuts its
/// own payload.
///
/// Every other bound on a trace shapes the WALK, and none of them bounds the
/// ANSWER: a walk inside all of them returned 228,413 characters over 2,453
/// lines from a 777-entity repository and the client refused the whole result,
/// so the caller got neither the chain nor a way to ask for less.
///
/// This is now an alias for [`crate::budget::RESPONSE_DEFAULT_MAX_CHARS`], the
/// one default every retrieval tool is served under, rather than a number of its
/// own. It had one, 80,000, chosen against the same client ceiling this is
/// chosen against, and a `trace_data_flow` that came in at 79,278 characters,
/// inside that budget, was refused by the client anyway. A per-tool budget that
/// the tool alone believes in is how a bound reports success while the caller
/// gets a file to read, so there is one number and every retrieval tool answers
/// under it.
///
/// Defined through this module rather than beside either walk because BOTH walks
/// serve this one tool - the generic-store arm in `handlers::entities` and the
/// body-inlining arm in `kin_cli::commands::trace_data_flow`, which reads these
/// through here. Two definitions would let one arm promise a bound the other
/// does not keep.
pub const TRACE_DEFAULT_MAX_RESPONSE_CHARS: usize = crate::budget::RESPONSE_DEFAULT_MAX_CHARS;

/// Floor for a caller-supplied budget. Below this the envelope alone does not
/// fit, so a smaller number could only be honoured by returning nothing.
pub const TRACE_MIN_MAX_RESPONSE_CHARS: usize = crate::budget::RESPONSE_MIN_MAX_CHARS;

/// Ceiling for a caller-supplied budget. A caller with a larger window may raise
/// the bound, but not to unbounded: the daemon serving this has other callers,
/// and a response nothing can read is not worth building.
pub const TRACE_MAX_MAX_RESPONSE_CHARS: usize = crate::budget::RESPONSE_MAX_MAX_CHARS;

/// Characters held back from the budget for the disclosure a cut adds.
///
/// A response cut to exactly its ceiling and then told to explain the cut is
/// over its ceiling again, by the length of the explanation. Reserving the room
/// first is what makes the bound hold for the payload that actually ships.
pub const TRACE_DISCLOSURE_RESERVE_CHARS: usize = crate::budget::RESPONSE_DISCLOSURE_RESERVE_CHARS;

/// The budget a trace request asks for, clamped to what this tool will serve.
pub fn trace_response_budget(requested: Option<usize>) -> usize {
    requested
        .unwrap_or(TRACE_DEFAULT_MAX_RESPONSE_CHARS)
        .clamp(TRACE_MIN_MAX_RESPONSE_CHARS, TRACE_MAX_MAX_RESPONSE_CHARS)
}

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

pub fn trace_body<G: GraphStore>(
    store: &G,
    entity: &Entity,
    repository_authority: Option<&RequestRepositoryAuthority>,
) -> Result<String> {
    trace_body_held(
        &HeldSourceAuthority::new(store, repository_authority),
        entity,
    )
}

/// A trace step's body, served from authority this request already holds. A
/// trace walks a chain and reads a body per step, so the per-read variant costs
/// one authority recovery and one whole-history replay per step.
pub fn trace_body_held<G: GraphStore>(
    held: &HeldSourceAuthority<'_, G>,
    entity: &Entity,
) -> Result<String> {
    // A step whose file the current workspace does not contain has no body to
    // show, which is the same outcome as an entity with no projectable span and
    // takes the same signature fallback. The trace keeps walking; one historical
    // step does not end the chain.
    let source = match read_entity_source_excerpt_detailed_held(
        held,
        entity,
        MCP_SOURCE_MAX_LINES,
        MCP_SOURCE_MAX_CHARS,
        EntitySourceScope::WorkspaceHead,
    ) {
        Ok(source) => source,
        Err(error) if is_absent_at_generation(&error) => None,
        Err(error) => return Err(error),
    };
    Ok(source
        .map(|source| source.body)
        .unwrap_or_else(|| entity.signature.clone()))
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
    repository_authority: Option<&RequestRepositoryAuthority>,
) -> Result<Option<Vec<TraceEvaluationStep>>> {
    evaluate_trace_chain_held(
        &HeldSourceAuthority::new(store, repository_authority),
        chain,
        input_literal,
    )
}

/// Evaluate a trace chain from authority this request already holds.
///
/// The walk reads at least two bodies per step plus one per constant, so this is
/// the variant a request must use; the per-read one multiplies a full authority
/// recovery by the chain length.
pub fn evaluate_trace_chain_held<G: GraphStore>(
    held: &HeldSourceAuthority<'_, G>,
    chain: &[Entity],
    input_literal: i64,
) -> Result<Option<Vec<TraceEvaluationStep>>> {
    let store = held.store();
    let mut constant_values = HashMap::new();
    for step in chain {
        let body = trace_body_held(held, step)?;
        for constant in trace_constants_for_step(store, step, &body)? {
            if let Some(value) = parse_trace_constant_value(&trace_body_held(held, &constant)?) {
                constant_values
                    .entry(constant.name.clone())
                    .or_insert(value);
            }
        }
    }

    let mut function_values = HashMap::new();
    let mut evaluation = Vec::new();

    for step in chain.iter().rev() {
        let body = trace_body_held(held, step)?;
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

/// Default per-body clamp for the batched entity-source tool, matching the
/// single-entity `get_entity_source` generic path (which reads via
/// [`read_entity_source_excerpt_detailed`] with these same bounds). Callers can
/// tighten with `max_lines_per_body` / `max_bytes_per_body`; the batch never
/// serves an unbounded body.
pub const DEFAULT_SOURCE_MAX_LINES: usize = 10_000;
pub const DEFAULT_SOURCE_MAX_BYTES: usize = 1_000_000;

/// Clamp a source body to at most `max_lines` lines and `max_bytes` bytes.
///
/// Lines are bounded first (newlines preserved), then bytes, truncating at the
/// largest UTF-8 char boundary at or below `max_bytes` so the result is always
/// valid UTF-8. The batched entity-source tool applies this to each body
/// *before* token-budget accounting, so the clamp is independent of which
/// serving path (generic graph store or daemon graph) resolved the entity.
pub fn clamp_source_body(body: &str, max_lines: usize, max_bytes: usize) -> String {
    let mut clamped = String::new();
    for (idx, line) in body.split_inclusive('\n').enumerate() {
        if idx >= max_lines {
            break;
        }
        clamped.push_str(line);
    }
    if clamped.len() > max_bytes {
        let mut end = max_bytes;
        while end > 0 && !clamped.is_char_boundary(end) {
            end -= 1;
        }
        clamped.truncate(end);
    }
    clamped
}

// ── Reference row types ──

#[derive(Debug, Clone)]
pub struct ReferenceRow {
    /// Graph entity id of the referencing (caller) entity, when it is a
    /// graph-owned local entity. Lets an agent drill a reference straight to the
    /// caller's body (`get_entity_source`/`get_context_pack`) without re-resolving
    /// the caller by name. That is the keystone of the no-filesystem reference→body
    /// chain. `None` for federated spine xrefs (no local entity).
    pub entity_id: Option<String>,
    pub name: String,
    pub kind: Option<String>,
    pub file_path: Option<String>,
    /// 1-based line where the REFERENCING ENTITY begins -- the caller's
    /// definition, not the reference itself. Useful for locating the caller;
    /// useless for locating the usage. See `reference_lines`.
    pub start_line: Option<u32>,
    /// 1-based lines of the actual reference sites inside this caller, ascending
    /// and deduplicated, taken from each relation's own
    /// `RelationEvidence::source_span`.
    ///
    /// This exists because `start_line` alone forced agents to DERIVE call-site
    /// positions by counting forward from a function's start, which is wrong
    /// twice over: it assumes the agent can see the body it is counting through,
    /// and it compounds any staleness in the definition's own span. The reference
    /// site is a graph fact, so it is served as one. Empty when the parser
    /// recorded no span for any contributing edge, which is honest absence rather
    /// than a derived guess -- and `reference_lines_absent` then names which
    /// absence it is.
    pub reference_lines: Vec<u32>,
    /// Why this row carries no `reference_lines`, and `None` when it carries
    /// some.
    ///
    /// An empty list on a returned reference is the quiet-partial failure in
    /// miniature (FIR-2357 item 3): the row proves a caller exists while saying
    /// nothing about why its site could not be located, so a reader cannot tell
    /// a parser gap from a bug. The row is still reported, because dropping a
    /// caller whose site was never recorded would understate blast radius, but
    /// the reason is stated rather than left to inference.
    pub reference_lines_absent: Option<ReferenceLinesAbsent>,
    pub signature: Option<String>,
    /// Bounded inline body excerpt of the referencing entity, projected from the
    /// same content-addressed, hash-verified graph body that backs
    /// `get_entity_source` (never a working-tree read). `None` on a graph/blob
    /// miss or for pathless/federated rows.
    pub snippet: Option<String>,
    pub relation_kinds: Vec<RelationKind>,
    /// How strongly the strongest edge behind this row was resolved.
    ///
    /// A reference resolved from a bare method name is a candidate, not a fact:
    /// a same-named method on an unrelated type or a test double matches
    /// equally well. A row is reported when any edge reaches this entity, so
    /// the strongest contributing edge is the row's evidence. `name_only` means
    /// the reference is a guess and should be confirmed before being acted on.
    pub resolution: Option<RelationResolution>,
    /// Whether EVERY edge behind this row is a receiver-method call the linker
    /// matched on the bare leaf name.
    ///
    /// `resolution` cannot answer this. It reports the strongest contributing
    /// edge, and `name_only` covers four tiers of very different strength: a
    /// callee written `Error::msg` matching one entity in the repository lands
    /// there beside the receiver fan-out that answered
    /// `find_references(HTTPAdapter.send)` with 33 rows. Only the fan-out is a
    /// candidate rather than a reference (FIR-1552), and only a row with no
    /// other kind of edge behind it is one.
    pub receiver_name_guess: bool,
}

/// Why a reference row carries no site lines.
///
/// Each variant is one measured condition, not a label chosen for how it reads.
/// A consumer that wants to edit every call site needs to know whether the sites
/// are unknown because the parser recorded none, because the ones recorded
/// belong to another file, or because the edge lives in a graph this response
/// has no authority over -- those are three different follow-ups.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReferenceLinesAbsent {
    /// No edge behind this row carried a `RelationEvidence::source_span`: the
    /// relation was recorded without the syntax position that produced it.
    NoEvidenceSpan,
    /// Edges carried spans, but every one named a file other than the caller's.
    /// Reporting them under this row's `file_path` would print lines of one file
    /// as lines of another, so they are dropped and the drop is declared.
    SpanOutsideCallerFile,
    /// A federated cross-repository xref: the resolving edge and its span live in
    /// the other repository's graph.
    FederatedXref,
}

impl ReferenceLinesAbsent {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoEvidenceSpan => "no_evidence_span",
            Self::SpanOutsideCallerFile => "span_outside_caller_file",
            Self::FederatedXref => "federated_xref",
        }
    }
}

/// One row per REFERENCING ENTITY that reaches `entity_id` over an allowed
/// relation kind.
///
/// Rows are keyed on the caller's entity id. They were keyed on the caller's
/// FILE path, which collapsed every caller in one file into a single row that
/// kept the first caller's id, name and signature, and left `total_upstream`
/// reporting the number of distinct files: a function with eleven callers across
/// two files answered "2" with both completeness flags true (FIR-2398). Keying
/// on the entity also makes this agree with the shared CLI collector
/// (`kin refs`), which has always counted distinct referencing entities.
pub fn collect_graph_reference_rows<G: GraphStore>(
    store: &G,
    entity_id: &EntityId,
    relation_kinds: &[RelationKind],
    repository_authority: Option<&RequestRepositoryAuthority>,
) -> Result<Vec<ReferenceRow>> {
    let allowed: std::collections::HashSet<_> = relation_kinds.iter().copied().collect();
    let mut grouped: HashMap<EntityId, ReferenceRow> = HashMap::new();
    // Spans a row's edges carried that named some other file, counted so an
    // empty `reference_lines` can say which absence it is instead of collapsing
    // "the parser recorded nothing" and "what it recorded was unusable here"
    // into one silent empty list.
    let mut spans_outside_caller_file: HashMap<EntityId, usize> = HashMap::new();

    // One held authority for the whole reference set. This projects a body per
    // REFERENCING entity, so it is the same multi-entity shape the retrieval
    // surfaces have: deriving authority and committed state per row pays a full
    // authority recovery and a whole-history replay once per caller found.
    let held = HeldSourceAuthority::new(store, repository_authority);

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
        // A self/recursive edge does not make an entity its own upstream caller.
        // The shared CLI collector has always excluded it, so counting it here
        // would leave `kin refs` and `find_references` one apart on every
        // recursive function.
        if source_entity_id == *entity_id {
            continue;
        }
        let Some(entity) = store
            .get_entity(&source_entity_id)
            .map_err(McpError::graph)?
        else {
            continue;
        };

        let file_path = entity.file_origin.as_ref().map(|path| path.0.clone());
        // A referencing entity the current workspace does not contain is a
        // reference from history, not a caller of this code today, so it is not
        // reported as one. Failing the whole reference set over it -- the shape
        // this had -- made `find_references` unusable on any repository that
        // ever deleted a file.
        let snippet = match read_bounded_entity_snippet_held(
            &held,
            &entity,
            EntitySourceScope::WorkspaceHead,
        ) {
            Ok(snippet) => snippet,
            Err(error) if is_absent_at_generation(&error) => continue,
            Err(error) => return Err(error),
        };
        let entry = grouped
            .entry(source_entity_id)
            .or_insert_with(|| ReferenceRow {
                entity_id: Some(source_entity_id.to_string()),
                name: entity.name.clone(),
                kind: Some(format!("{:?}", entity.kind)),
                file_path: file_path.clone(),
                start_line: entity_presentation_start_line(&entity),
                reference_lines: Vec::new(),
                reference_lines_absent: None,
                signature: Some(entity.signature.clone()),
                // Project the caller's bounded body once, where the entity is in
                // hand, so `find_references` hands back act-on-able code per caller
                // without a follow-up id→body round-trip.
                snippet,
                relation_kinds: Vec::new(),
                resolution: None,
                // Every contributing edge has to be a guess for the row to be
                // one, so this starts true and any other edge clears it.
                receiver_name_guess: true,
            });
        if entry.file_path.is_none() {
            entry.file_path = file_path;
        }
        if entry.start_line.is_none() {
            entry.start_line = entity_presentation_start_line(&entity);
        }
        if entry.signature.is_none() {
            entry.signature = Some(entity.signature.clone());
        }
        // Every edge contributing to this row carries its own site span, so a
        // caller that references the target several times reports all of its
        // sites rather than the first. Only spans inside the referencing
        // entity's own file are taken: a cross-file evidence span would be a
        // line number the row's `file_path` does not explain.
        let tally = relation_reference_lines(&rel, entity.file_origin.as_ref());
        entry.reference_lines.extend(tally.lines);
        *spans_outside_caller_file
            .entry(source_entity_id)
            .or_default() += tally.outside_caller_file;
        push_reference_kind(&mut entry.relation_kinds, rel.kind);
        let resolution = RelationResolution::of(&rel);
        entry.resolution = Some(match entry.resolution {
            Some(current) => current.max(resolution),
            None => resolution,
        });
        entry.receiver_name_guess &= kin_index::resolution::is_receiver_name_guess(&rel);
    }

    let mut rows = Vec::with_capacity(grouped.len());
    for (source_entity_id, mut row) in grouped {
        row.relation_kinds.sort_by_key(relation_kind_rank);
        row.reference_lines.sort_unstable();
        row.reference_lines.dedup();
        row.reference_lines_absent = if !row.reference_lines.is_empty() {
            None
        } else if spans_outside_caller_file
            .get(&source_entity_id)
            .is_some_and(|dropped| *dropped > 0)
        {
            Some(ReferenceLinesAbsent::SpanOutsideCallerFile)
        } else {
            Some(ReferenceLinesAbsent::NoEvidenceSpan)
        };
        rows.push(row);
    }
    Ok(rows)
}

/// What one relation's evidence says about where its reference sites are.
pub struct RelationSpanTally {
    /// 1-based site lines inside the referencing entity's own file.
    pub lines: Vec<u32>,
    /// Spans that named a different file and were therefore not reportable under
    /// this row. Counted rather than discarded so an empty `lines` can be
    /// explained.
    pub outside_caller_file: usize,
}

/// 1-based reference-site lines a single relation records, restricted to the
/// referencing entity's own file.
///
/// The parser stores the syntax that produced each edge in
/// `RelationEvidence::source_span`, which makes the usage's position a graph fact
/// rather than something a consumer has to reconstruct. Evidence carrying no span
/// contributes nothing; a span in some other file is dropped because the row
/// reports one `file_path` and a line from a different file would read as a line
/// in that one. Both kinds of miss are counted, because an empty result that
/// cannot say why is the defect this reports around.
pub fn relation_reference_lines(
    rel: &kin_model::relation::Relation,
    caller_file: Option<&kin_model::ids::FilePathId>,
) -> RelationSpanTally {
    let mut tally = RelationSpanTally {
        lines: Vec::new(),
        outside_caller_file: 0,
    };
    for span in rel
        .evidence
        .iter()
        .filter_map(|evidence| evidence.source_span.as_ref())
    {
        if caller_file.is_none_or(|file| &span.file == file) {
            tally.lines.push(presentation_line(span.start_line));
        } else {
            tally.outside_caller_file += 1;
        }
    }
    tally
}

pub const MCP_SOURCE_MAX_LINES: usize = 40;
pub const MCP_SOURCE_MAX_CHARS: usize = 2400;

// ── Line-number convention ──
//
// Graph truth and presentation disagree on purpose, and they meet here.
//
// [`SourceSpan::start_line`]/[`SourceSpan::end_line`] carry tree-sitter
// `Point::row` values, which are 0-based. That stays the graph convention: it is
// what the parser produces, what spans are compared and stored as, and what
// every internal offset calculation assumes.
//
// Every agent-facing surface is 1-based, because every editor, `file:line`
// reference, diff hunk, and stack trace an agent has ever seen is 1-based. A
// surface that emits the raw graph row is off by one against all of them, and an
// agent acting on it edits the line above the one it meant.
//
// So conversion happens at exactly one seam per surface, through these helpers.
// Emitting `span.start_line` directly into a response is the bug these exist to
// prevent; reach for [`presentation_line`] or one of the entity accessors below
// instead.

/// Convert a graph-owned 0-based line index to the 1-based line number every
/// editor and agent convention uses.
pub fn presentation_line(graph_line: u32) -> u32 {
    graph_line.saturating_add(1)
}

/// 1-based inclusive `(start, end)` presentation lines for a graph span.
pub fn presentation_span_lines(span: &SourceSpan) -> (u32, u32) {
    (
        presentation_line(span.start_line),
        presentation_line(span.end_line),
    )
}

/// 1-based presentation start line for an entity, or `None` when the entity
/// carries no span. A spanless entity has no line to report, and reporting `0`
/// or `1` for one would be a fabricated position.
pub fn entity_presentation_start_line(entity: &Entity) -> Option<u32> {
    entity
        .span
        .as_ref()
        .map(|span| presentation_line(span.start_line))
}

/// 1-based presentation end line for an entity, or `None` when it has no span.
pub fn entity_presentation_end_line(entity: &Entity) -> Option<u32> {
    entity
        .span
        .as_ref()
        .map(|span| presentation_line(span.end_line))
}

pub fn push_reference_kind(kinds: &mut Vec<RelationKind>, kind: RelationKind) {
    if !kinds.contains(&kind) {
        kinds.push(kind);
    }
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

/// Which repository state the returned bytes actually came from.
///
/// A head read serves `WorkspaceState::tree`, which kin-model defines as
/// including uncommitted state, so it is routinely AHEAD of the workspace's
/// base: the watcher admission path advances the tree through
/// `publish_workspace_tree`, which creates no history node and moves no ref, on
/// every editor save it admits. Reporting the base change as the source of those
/// bytes attests committed provenance for state that no commit contains, and on a
/// substrate whose authority claim is graph-owned provenance that is worse than
/// reporting nothing.
///
/// So the two cases are separate variants rather than one change id with a
/// caveat: a consumer cannot accidentally read the uncommitted case as committed,
/// because the committed field is not there to read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceProvenance {
    /// The bytes ARE the committed state at `change_id`. Either a history read,
    /// or a head read of a workspace whose exact tree still hashes to the tree
    /// at its base.
    Committed { change_id: SemanticChangeId },
    /// The bytes came from the workspace's exact graph-owned tree, which does
    /// not hash to the tree at `base_change_id`. No committed change contains
    /// them, so `tree_hash` is their only durable identity.
    Workspace {
        tree_hash: Hash256,
        generation: u64,
        base_change_id: SemanticChangeId,
    },
}

impl SourceProvenance {
    /// `"committed"` or `"workspace"`: the discriminator every response carries
    /// so a consumer can branch before reading the case-specific fields.
    pub fn state_label(&self) -> &'static str {
        match self {
            Self::Committed { .. } => "committed",
            Self::Workspace { .. } => "workspace",
        }
    }

    /// The change containing these bytes, or `None` when no change does.
    pub fn committed_change_id(&self) -> Option<SemanticChangeId> {
        match self {
            Self::Committed { change_id } => Some(*change_id),
            Self::Workspace { .. } => None,
        }
    }
}

/// Whether the span used to cut a body was checked against the artifact the
/// body was cut from.
///
/// These are two independently updated stores. The bytes come from repository
/// authority; the span comes from the live graph, and the admission path updates
/// them in separate transactions (the exact tree is published first, entity spans
/// are re-derived by a later `apply_transaction_delta`). Between those two steps
/// the graph holds the new blob at a path and the old spans into it, so slicing
/// one with the other yields text that is syntactically plausible and is not the
/// entity's source. A bounds check does not catch it: stale offsets usually still
/// land inside the file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpanCoherence {
    /// Span and bytes were resolved from ONE committed state, so they describe
    /// the same instant by construction. This is the history-read case.
    CoherentByConstruction,
    /// The entity's recorded source digest equals the digest of the artifact
    /// these bytes were loaded from, so the span was derived from exactly these
    /// bytes.
    DigestVerified,
    /// The entity records no source digest, so the pair could not be checked.
    /// Honest absence, not a claim of coherence: entities admitted by paths that
    /// do not stamp provenance, and entities reconstructed from committed
    /// history, legitimately arrive without one.
    Unverified,
}

impl SpanCoherence {
    pub fn label(&self) -> &'static str {
        match self {
            Self::CoherentByConstruction => "coherent_by_construction",
            Self::DigestVerified => "digest_verified",
            Self::Unverified => "unverified",
        }
    }
}

#[derive(Debug)]
pub struct ExactEntitySource {
    pub body: String,
    pub provenance: SourceProvenance,
    pub span_coherence: SpanCoherence,
    pub artifact_id: ArtifactId,
    pub path: RepoPath,
    pub entry: TreeEntry,
}

/// The single seam that renders a source read's identity and provenance into a
/// response object.
///
/// Every body-serving surface routes through this, so the shape cannot drift
/// between `get_entity_source`, `get_entity`, and the context pack the way the
/// snippet field name did between the two `semantic_locate` arms.
///
/// Every content-addressed id here is hex, never the model's own byte-array
/// serialization. A `Hash256` derives `Serialize` over `[u8; 32]`, so a change
/// id reached an agent as 32 decimal numbers: about four times the bytes of the
/// hex it stands for, and not the spelling any Kin surface parses back. This
/// seam is per-dependency in a context pack, which is documented as fitted to a
/// token budget, so the waste scaled with the pack.
///
/// For the same reason this carries no `artifact_path` for a path a plain
/// string can spell. A `RepoPath` is bytes, and its wire form is a
/// `{"bytes_hex": …}` object, so the path arrived as twice its own length in
/// hex beside the plain `file_path` every caller of this seam already emits.
/// Two spellings of one path, one of them unreadable, per entry, inside a
/// budgeted pack.
///
/// A path whose bytes are not valid UTF-8 has no lossless plain form, so there
/// the byte-exact spelling is the only representation those bytes have and the
/// field is kept. `artifact_id` is emitted either way, and `kin_artifact_read`
/// resolves the byte-exact path from it.
pub fn source_provenance_fields(
    source: &ExactEntitySource,
) -> serde_json::Map<String, serde_json::Value> {
    let mut fields = serde_json::Map::new();
    fields.insert(
        "source_state".into(),
        serde_json::json!(source.provenance.state_label()),
    );
    match &source.provenance {
        SourceProvenance::Committed { change_id } => {
            fields.insert(
                "source_change_id".into(),
                serde_json::json!(change_id.to_string()),
            );
        }
        SourceProvenance::Workspace {
            tree_hash,
            generation,
            base_change_id,
        } => {
            // Deliberately NOT under `source_change_id`. These bytes are in no
            // change, and a consumer reading that key must never receive an id
            // that does not contain what it was handed.
            fields.insert(
                "workspace_tree_hash".into(),
                serde_json::json!(tree_hash.to_string()),
            );
            fields.insert("workspace_generation".into(), serde_json::json!(generation));
            fields.insert(
                "base_change_id".into(),
                serde_json::json!(base_change_id.to_string()),
            );
        }
    }
    fields.insert(
        "span_coherence".into(),
        serde_json::json!(source.span_coherence.label()),
    );
    fields.insert("artifact_id".into(), serde_json::json!(source.artifact_id));
    if source.path.as_utf8().is_none() {
        fields.insert("artifact_path".into(), serde_json::json!(source.path));
    }
    fields.insert(
        "artifact_entry".into(),
        serde_json::json!(super::artifacts::TreeEntryWire::from(source.entry)),
    );
    fields
}

fn record_graph_source_gap(error: McpError) -> McpError {
    GRAPH_MISS_COUNT.fetch_add(1, Ordering::SeqCst);
    LAST_READ_SOURCE.with(|source| source.set("graph-miss"));
    error
}

fn graph_source_gap(message: impl Into<String>) -> McpError {
    record_graph_source_gap(McpError::Context(format!(
        "graph authority gap: {}",
        message.into()
    )))
}

/// The entity's path does not exist at the workspace's current generation.
///
/// Deliberately NOT a [`graph_source_gap`]. Authority did not fail here and
/// nothing is missing that the graph promised: the graph ingests whole history,
/// so it carries entities for files a repository deleted or renamed, and the
/// current workspace correctly does not contain them. Counting this as a graph
/// miss would report every ordinary repository with a deletion in its history as
/// a broken store, and typing it as a gap is what made one historical candidate
/// fatal to a whole retrieval page.
fn entity_absent_at_generation(
    entity: &Entity,
    path: &str,
    generation: impl std::fmt::Display,
    workspace_id: impl std::fmt::Display,
) -> McpError {
    LAST_READ_SOURCE.with(|f| f.set("absent-at-generation"));
    McpError::WorkspaceAbsent(format!(
        "entity {} ({}) records its source at '{path}', which the workspace does not contain at \
         generation {generation}; the graph carries this entity from history, so it has no body \
         in the current workspace (workspace {workspace_id})",
        entity.id, entity.name
    ))
}

/// True when `error` reports an entity absent from the current generation.
///
/// The predicate a multi-entity projection uses to skip one candidate while
/// still failing loudly on every genuine authority gap: a tree that cannot be
/// sampled, a blob the graph promised and cannot produce, a span that does not
/// describe its bytes, or a path reused by a different artifact all remain
/// fatal.
pub fn is_absent_at_generation(error: &McpError) -> bool {
    matches!(error, McpError::WorkspaceAbsent(_))
}

/// The text a retained authority failure must replay verbatim.
///
/// A session opens authority once and reports that same failure to every read
/// that needed it, so the failure has to survive as text. `McpError::Context`
/// prints a `context error: ` prefix, so retaining the Display string and
/// re-wrapping it would nest that prefix once per replay and drift the message
/// away from the one a single read reports.
fn retained_gap_message(error: McpError) -> String {
    match error {
        McpError::Context(message) => message,
        other => other.to_string(),
    }
}

/// Which graph-owned repository state a source projection resolves against.
///
/// `EntitySourceScope::WorkspaceHead` reads the workspace's exact graph-owned
/// tree -- `WorkspaceState::tree`, which kin-model defines as including
/// uncommitted state -- paired with the live entity's own span. This is the same
/// truth `get_entity_source`, `get_entity_body`, and `kin trace` read, so every
/// HEAD-scoped agent surface answers from one state by construction.
///
/// `EntitySourceScope::At(change)` reads a specific committed change by replaying
/// history to it, and is mandatory whenever `store` is a ref-scoped historical
/// view: such a view holds only the changes reachable from its ref, so resolving
/// an entity revision or a tree against the workspace head is both the wrong
/// history and a hard graph-store miss for any ref that is not the head itself.
///
/// The distinction is load-bearing, and conflating the two is what previously
/// made head reads fail on coherent repositories: the workspace's `base_target`
/// is the change it was CREATED FROM, not its current state. Resolving a head
/// read against the base and then requiring the live entity to be the active
/// committed revision there rejects every workspace that has moved past its base
/// -- a fresh clone whose admission populated the live graph, a workspace holding
/// a semantic overlay, or any repository with a commit since. Those are normal
/// states, not authority gaps.
///
/// Deliberately has no `Default`: a caller that has not decided which state it
/// reads at has not decided whether its answer is history or head.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntitySourceScope {
    WorkspaceHead,
    At(SemanticChangeId),
}

/// The change that introduced `entity`'s active committed revision as of
/// `change_id`, or `None` when committed history records no such revision.
///
/// `None` is an ordinary answer, not a failure: the live graph legitimately
/// carries entities that committed history has not recorded a revision for yet.
/// Callers use this to enforce artifact-identity binding where history can
/// support it, so a replay that cannot answer must not turn into a read failure.
fn committed_introducing_change<G: GraphStore>(
    held: &HeldSourceAuthority<'_, G>,
    entity: &Entity,
    change_id: &SemanticChangeId,
) -> Option<SemanticChangeId> {
    held.graph_at(change_id)
        .ok()?
        .entity_revisions
        .get(&entity.id)?
        .iter()
        .rev()
        .find(|revision| revision.ended_by.is_none())
        .map(|revision| revision.introduced_by)
}

/// The digest of the source the entity's span was derived from, when the graph
/// recorded one.
///
/// The reconciler stamps this on every entity it admits, and its own comment
/// says why: "Span and blob provenance must advance even for source edits that
/// are semantically equivalent." So the graph already treats this digest as the
/// span's provenance; a read that slices bytes without consulting it is
/// discarding a coherence proof the writer went to the trouble of recording.
///
/// `None` means the entity carries no such stamp, which is an ordinary state and
/// must never be escalated into a read failure.
fn recorded_span_source_digest(entity: &Entity) -> Option<kin_blobs::Hash256> {
    let serde_json::Value::String(hex) = entity.metadata.extra.get("blob_hash")? else {
        return None;
    };
    kin_blobs::Hash256::from_hex(hex).ok()
}

/// Bind a live entity's span to the artifact bytes about to be sliced with it.
///
/// THE one implementation of the coherence rule, public because not every serving
/// arm resolves its bytes through [`read_entity_source_excerpt_detailed`]. The
/// daemon's `get_entity_source` and `get_entity_sources` reach source through
/// `kin_cli`'s own authority read, so a rule that lived only inside this module's
/// resolver would hold on the offline arm and not on the arm agents actually use
/// in product mode. One function, called from both, cannot drift that way.
///
/// `Err` means provable incoherence: the span was derived from different bytes
/// than the ones at this path now, so slicing would return text that is not the
/// entity's source. That is transient and retryable, and it is named as such,
/// because the reconciler re-derives the span against the admitted tree.
///
/// `Ok(Unverified)` means the entity records no digest, which is an ordinary state
/// and must never become a read failure.
pub fn span_source_coherence(
    entity: &Entity,
    artifact_blob: &Hash256,
    artifact_path: &str,
) -> Result<SpanCoherence> {
    match recorded_span_source_digest(entity) {
        Some(recorded) if recorded.as_bytes() == artifact_blob.as_bytes() => {
            Ok(SpanCoherence::DigestVerified)
        }
        Some(recorded) => Err(graph_source_gap(format!(
            "entity {} span was derived from source {recorded} but path '{artifact_path}' now \
             holds {artifact_blob} in the workspace tree, so the recorded span does not describe \
             these bytes; the graph has admitted the new source and not yet re-derived this \
             entity's span",
            entity.id
        ))),
        None => Ok(SpanCoherence::Unverified),
    }
}

/// One request's held repository authority and the committed states its source
/// reads derive from.
///
/// A source read needs three things a store cannot answer on its own: an open
/// repository authority (for the workspace tree and the source blobs), the
/// committed graph state at the change being read, and the tree at the change
/// that introduced an entity. Each is expensive and each is a pure function of
/// the store plus a change id, so deriving them once per REQUEST and deriving
/// them once per RESULT are the same answer at very different cost. Before this
/// type existed the projection derived all three per entity, which is what made
/// a 40-candidate `semantic_locate` perform 40 authority opens and 40 whole-
/// history replays and put a real repository out of service.
///
/// The replay reuse is sound because it is scoped, not cached. The session
/// borrows ONE store snapshot for its whole life, so a memoized replay is
/// byte-identical to the replay it replaces -- `resolve_graph_at` is
/// deterministic in (store, change). Nothing derived here survives the request.
///
/// The authority itself may outlive the request, and only under a condition the
/// caller has to have met. This type never caches an open and never decides
/// that one is still good: it opens from its binding, or it reads through an
/// authority a caller opened and labelled with the durable publication it was
/// loaded at. The shape this deliberately does not have is a process-wide cache
/// that keeps an open on nothing but its own say-so, because that is the one
/// that serves authority the store has already moved past. See
/// [`RequestRepositoryAuthority::shared`] for the obligation a caller takes on,
/// and note that a caller that meets it hands over exactly the bytes a fresh
/// open would have produced at the instant it sampled the publication.
///
/// Reusing one sample is also strictly MORE coherent than re-sampling per
/// entity. [`WorkspaceReadSample`] exists because pairing a tree from one
/// generation with provenance from another is a real defect; sampling once per
/// entity reintroduced exactly that hazard across a result set, where page 1 of
/// a response could describe a generation page 40 no longer read from.
///
/// Everything is derived lazily. An entity with no span or no file origin needs
/// no authority at all, and must keep returning "no source" rather than an
/// authority error, so constructing a session neither opens authority nor
/// replays anything.
///
/// [`WorkspaceReadSample`]: super::repository_authority::WorkspaceReadSample
pub struct HeldSourceAuthority<'store, G: GraphStore> {
    store: &'store G,
    source: Option<RequestRepositoryAuthority>,
    /// One open attempt for the session. The error is retained as its message so
    /// every entity that needs authority reports the same gap this session hit,
    /// instead of re-attempting a recovery that already failed.
    authority: std::sync::OnceLock<std::result::Result<Arc<ActiveRepositoryAuthority>, String>>,
    head_sample: std::sync::OnceLock<std::result::Result<Arc<WorkspaceReadSample>, String>>,
    graph_at: Mutex<HashMap<SemanticChangeId, Arc<kin_model::graph::ResolvedGraphState>>>,
    tree_at: Mutex<HashMap<SemanticChangeId, Arc<kin_model::ResolvedTree>>>,
    /// Replays this session actually performed, as opposed to served from its
    /// memo. The bound a query path has to hold is on this number, not on
    /// elapsed time, so it is observable.
    replays: AtomicU64,
}

impl<'store, G: GraphStore> HeldSourceAuthority<'store, G> {
    /// Hold authority for one request against one store snapshot.
    ///
    /// `repository_authority` names where this request's authority comes from,
    /// and is not itself an open: this constructor performs no IO whether the
    /// caller passed a startup-pinned binding or an authority it already
    /// opened. A `None` source is an ordinary state (a daemon serving hosted
    /// snapshot authority), and only a read that actually needs local authority
    /// turns it into a gap.
    pub fn new(
        store: &'store G,
        repository_authority: Option<&RequestRepositoryAuthority>,
    ) -> Self {
        Self {
            store,
            source: repository_authority.cloned(),
            authority: std::sync::OnceLock::new(),
            head_sample: std::sync::OnceLock::new(),
            graph_at: Mutex::new(HashMap::new()),
            tree_at: Mutex::new(HashMap::new()),
            replays: AtomicU64::new(0),
        }
    }

    /// Whole-history replays this session performed. A query path that derives
    /// committed state per request holds this at a small constant; one that
    /// derives it per result does not.
    pub fn replays_performed(&self) -> u64 {
        self.replays.load(Ordering::SeqCst)
    }

    /// The store this session is bound to, for graph reads that ride alongside
    /// the source projection in the same walk.
    pub fn store(&self) -> &'store G {
        self.store
    }

    fn authority(&self) -> Result<&ActiveRepositoryAuthority> {
        match self.authority.get_or_init(|| {
            let source = self.source.as_ref().ok_or_else(|| {
                "graph authority gap: this MCP runtime has no startup-pinned local repository \
                 authority binding"
                    .to_string()
            })?;
            source.open().map_err(retained_gap_message)
        }) {
            Ok(authority) => Ok(authority.as_ref()),
            Err(message) => Err(record_graph_source_gap(McpError::Context(message.clone()))),
        }
    }

    /// The one instant of workspace authority this request reads at.
    fn workspace_sample(&self) -> Result<&WorkspaceReadSample> {
        match self.head_sample.get_or_init(|| {
            self.authority()
                .and_then(|authority| authority.workspace_sample())
                .map(Arc::new)
                .map_err(retained_gap_message)
        }) {
            Ok(sample) => Ok(sample.as_ref()),
            Err(message) => Err(record_graph_source_gap(McpError::Context(message.clone()))),
        }
    }

    /// The committed graph state at `change`, replayed at most once per session.
    ///
    /// The store's own error is returned unwrapped so each call site keeps the
    /// message it already reports for a failed replay.
    fn graph_at(
        &self,
        change: &SemanticChangeId,
    ) -> std::result::Result<Arc<kin_model::graph::ResolvedGraphState>, <G as ChangeStore>::Error>
    {
        if let Some(state) = self.memo_hit(&self.graph_at, change) {
            return Ok(state);
        }
        // The replay runs with no lock held: it is the expensive step, and a
        // session shared across threads must not serialize on it. Losing the
        // race costs one redundant replay and cannot produce a different answer,
        // because the store is fixed for the session's life.
        let resolved = Arc::new(self.store.resolve_graph_at(change)?);
        self.replays.fetch_add(1, Ordering::SeqCst);
        Ok(self.memo_fill(&self.graph_at, *change, resolved))
    }

    /// The repository tree at `change`, replayed at most once per session.
    fn tree_at(
        &self,
        change: &SemanticChangeId,
    ) -> std::result::Result<Arc<kin_model::ResolvedTree>, <G as ChangeStore>::Error> {
        if let Some(tree) = self.memo_hit(&self.tree_at, change) {
            return Ok(tree);
        }
        let resolved = Arc::new(self.store.resolve_tree_at(change)?);
        self.replays.fetch_add(1, Ordering::SeqCst);
        Ok(self.memo_fill(&self.tree_at, *change, resolved))
    }

    fn memo_hit<T>(
        &self,
        memo: &Mutex<HashMap<SemanticChangeId, Arc<T>>>,
        change: &SemanticChangeId,
    ) -> Option<Arc<T>> {
        memo.lock()
            .expect("held source authority memo is never poisoned")
            .get(change)
            .map(Arc::clone)
    }

    fn memo_fill<T>(
        &self,
        memo: &Mutex<HashMap<SemanticChangeId, Arc<T>>>,
        change: SemanticChangeId,
        resolved: Arc<T>,
    ) -> Arc<T> {
        Arc::clone(
            memo.lock()
                .expect("held source authority memo is never poisoned")
                .entry(change)
                .or_insert(resolved),
        )
    }
}

fn resolve_entity_source_authority<G: GraphStore>(
    held: &HeldSourceAuthority<'_, G>,
    entity: &Entity,
    scope: EntitySourceScope,
) -> Result<Option<(ExactEntitySource, Vec<u8>, SourceSpan)>> {
    LAST_READ_SOURCE.with(|f| f.set("unknown"));

    let Some(recorded_span) = entity.span.as_ref() else {
        return Ok(None);
    };
    let Some(recorded_origin) = entity.file_origin.as_ref() else {
        return Ok(None);
    };
    if &recorded_span.file != recorded_origin {
        return Err(graph_source_gap(format!(
            "entity {} has divergent file_origin '{}' and span file '{}'",
            entity.id, recorded_origin.0, recorded_span.file.0
        )));
    }

    let authority = held.authority()?;

    let path = RepoPath::from_utf8(recorded_origin.0.clone()).map_err(|error| {
        graph_source_gap(format!(
            "entity {} has an invalid repository path '{}': {error}",
            entity.id, recorded_origin.0
        ))
    })?;

    // Resolve the artifact and the span to read from whichever state the scope
    // names. A head read and a history read are genuinely different questions and
    // resolve through different authority, so they are kept apart here rather
    // than approximated by one path.
    let (provenance, current_artifact, span) = match scope {
        // HEAD: the workspace's exact graph-owned tree paired with the live
        // entity's own span -- byte-for-byte the pair `get_entity_source` reads, so
        // the body-shaped surfaces cannot diverge on the same repository.
        //
        // What is NOT required here is that the live entity be byte-identical to
        // its active revision at `base_target`. The workspace tree already
        // includes state past base, so demanding that equality rejects ordinary
        // repositories (a fresh clone, a live overlay, any commit since) as
        // authority gaps. Span validity against the resolved bytes is still
        // enforced, and so is the artifact-identity binding below, which is the
        // check that actually protects a head read.
        EntitySourceScope::WorkspaceHead => {
            // ONE authority sample backs the whole head read. The sample is an
            // `Arc` snapshot of published authority, so the tree the bytes come
            // from, its identity and generation, and the change its base resolves
            // to all describe one instant. Reading the tree from one snapshot and
            // the change id from another let a response pair generation N's bytes
            // with generation N+1's provenance, with nothing serializing the two.
            let sample = held.workspace_sample()?;
            let workspace = &sample.workspace;
            // Absence from the current tree is graph truth answering, not
            // authority failing: the store carries history, and a file deleted
            // or renamed upstream is legitimately not here. Typed apart from a
            // gap so a multi-entity projection can skip THIS candidate while a
            // genuinely unservable path below still fails the read.
            let artifact = workspace
                .tree
                .artifact_at_path(&path)
                .cloned()
                .ok_or_else(|| {
                    entity_absent_at_generation(
                        entity,
                        &recorded_origin.0,
                        workspace.generation,
                        workspace.workspace_id,
                    )
                })?;
            let source_change_id = sample.base_change_id;

            // Report what these bytes actually are. The exact tree includes
            // uncommitted state, so it is only the committed state at base when
            // it still hashes to the tree at base; otherwise no change contains
            // it and the answer says so instead of naming one.
            let provenance = if workspace.base_tree_hash == Some(workspace.tree_hash) {
                SourceProvenance::Committed {
                    change_id: source_change_id,
                }
            } else {
                SourceProvenance::Workspace {
                    tree_hash: workspace.tree_hash,
                    generation: workspace.generation,
                    base_change_id: source_change_id,
                }
            };

            // Bind the entity to the artifact identity that occupied its path when
            // its revision was introduced, so a path later reused by a DIFFERENT
            // artifact cannot feed an old entity's span someone else's bytes. The
            // hazard is real even when the bytes are identical, because identity --
            // not content -- is what says these are the same artifact.
            //
            // Only committed history knows the introducing artifact, so the check
            // runs when history records a revision and is skipped when it does not.
            // An entity the live graph carries without a committed revision has no
            // prior binding to contradict, and rejecting it was exactly the false
            // gap that closed body reads on fresh clones.
            if let Some(introduced_by) =
                committed_introducing_change(held, entity, &source_change_id)
            {
                let introduced_tree = held.tree_at(&introduced_by).map_err(|error| {
                    graph_source_gap(format!(
                        "cannot resolve entity {} introduction tree at {introduced_by}: {error}",
                        entity.id
                    ))
                })?;
                let introduced_artifact =
                    introduced_tree.artifact_at_path(&path).ok_or_else(|| {
                        graph_source_gap(format!(
                            "entity {} was introduced at {introduced_by} without an artifact at \
                             '{}'",
                            entity.id, recorded_origin.0
                        ))
                    })?;
                if introduced_artifact.artifact_id != artifact.artifact_id {
                    return Err(graph_source_gap(format!(
                        "path '{}' was reused: entity {} is bound to artifact {:?}, current \
                         artifact is {:?}",
                        recorded_origin.0,
                        entity.id,
                        introduced_artifact.artifact_id,
                        artifact.artifact_id
                    )));
                }
            }

            (provenance, artifact, recorded_span.clone())
        }
        // HISTORY: replay the COMPLETE first-parent history at the named change,
        // then read this entity's active revision out of that state.
        // `resolve_entity_revision_at` is not usable here: it replays only the
        // changes that mention this entity, yet validates every delta those
        // changes carry. A change that introduces this entity while removing or
        // modifying another one is then checked against a state the other
        // entity's own history was filtered out of, and a sound repository
        // reports a false history conflict. Resolving the whole state also yields
        // the tree at the same change, so this replaces a separate tree
        // resolution rather than adding to it.
        EntitySourceScope::At(source_change_id) => {
            let committed = held.graph_at(&source_change_id).map_err(|error| {
                graph_source_gap(format!(
                    "cannot resolve committed repository state at {source_change_id}: {error}"
                ))
            })?;
            let revision = committed
                .entity_revisions
                .get(&entity.id)
                .and_then(|revisions| {
                    revisions
                        .iter()
                        .rev()
                        .find(|revision| revision.ended_by.is_none())
                })
                .cloned()
                .ok_or_else(|| {
                    graph_source_gap(format!(
                        "entity {} has no active committed revision at {}",
                        entity.id, source_change_id
                    ))
                })?;
            let current_artifact =
                committed
                    .tree
                    .artifact_at_path(&path)
                    .cloned()
                    .ok_or_else(|| {
                        graph_source_gap(format!(
                            "entity {} points at '{}' but that path is absent at {}",
                            entity.id, recorded_origin.0, source_change_id
                        ))
                    })?;

            // Bind the entity revision to the artifact identity that occupied its
            // path when that revision was introduced. A later path reuse must not
            // make an old entity read bytes from a different artifact.
            let introduced_tree = held.tree_at(&revision.introduced_by).map_err(|error| {
                graph_source_gap(format!(
                    "cannot resolve entity {} introduction tree at {}: {error}",
                    entity.id, revision.introduced_by
                ))
            })?;
            let introduced_artifact = introduced_tree.artifact_at_path(&path).ok_or_else(|| {
                graph_source_gap(format!(
                    "entity {} revision {} was introduced without an artifact at '{}'",
                    entity.id, revision.revision_id, recorded_origin.0
                ))
            })?;
            if introduced_artifact.artifact_id != current_artifact.artifact_id {
                return Err(graph_source_gap(format!(
                    "path '{}' was reused: entity {} is bound to artifact {:?}, current artifact \
                     is {:?}",
                    recorded_origin.0,
                    entity.id,
                    introduced_artifact.artifact_id,
                    current_artifact.artifact_id
                )));
            }

            // A history read answers with the revision's OWN span, not the live
            // entity's: at an older change the entity may have occupied different
            // bytes, and reading it with today's span would slice the wrong text
            // out of the right artifact.
            let span = revision
                .entity
                .span
                .clone()
                .expect("active source revision was checked for a span");
            (
                SourceProvenance::Committed {
                    change_id: source_change_id,
                },
                current_artifact,
                span,
            )
        }
    };

    let TreeEntry::Blob { hash, .. } = current_artifact.entry else {
        return Err(graph_source_gap(format!(
            "entity {} resolves to non-source tree entry {:?} for artifact {:?}",
            entity.id, current_artifact.entry, current_artifact.artifact_id
        )));
    };

    // Bind the span to the bytes it is about to cut.
    //
    // Blobs are content-addressed and `load_source_blob` re-verifies the digest,
    // so the bytes below are provably the bytes of the artifact resolved above --
    // that half needs no further guarding. The gap is the other half: the span
    // came from the live graph, and the admission path advances the exact tree in
    // one transaction and re-derives entity spans in a later one. Between them the
    // graph holds a path's new blob and the old spans into it. Comparing the
    // digest the span was derived from against the digest actually being sliced is
    // what closes that window, and it is a real comparison rather than a bounds
    // check: stale offsets normally still land inside the file, so the mis-slice
    // returns plausible text and no error.
    //
    // A history read needs none of this: its span and its tree came out of one
    // resolved committed state.
    let span_coherence = match scope {
        EntitySourceScope::At(_) => SpanCoherence::CoherentByConstruction,
        EntitySourceScope::WorkspaceHead => {
            span_source_coherence(entity, &hash, &recorded_origin.0)?
        }
    };
    let bytes = authority.load_source_blob(hash).map_err(|error| {
        graph_source_gap(format!(
            "blob {hash} for entity {} artifact {:?} is unavailable or corrupt: {error}",
            entity.id, current_artifact.artifact_id
        ))
    })?;
    if span.start_byte >= span.end_byte || span.end_byte > bytes.len() {
        return Err(graph_source_gap(format!(
            "entity {} span {}..{} is invalid for artifact {:?} ({} bytes)",
            entity.id,
            span.start_byte,
            span.end_byte,
            current_artifact.artifact_id,
            bytes.len()
        )));
    }
    LAST_READ_SOURCE.with(|f| f.set("graph"));
    Ok(Some((
        ExactEntitySource {
            body: String::new(),
            provenance,
            span_coherence,
            artifact_id: current_artifact.artifact_id,
            path,
            entry: current_artifact.entry,
        },
        bytes,
        span,
    )))
}

/// One-shot body projection: holds authority for the duration of this ONE read.
///
/// Correct for a single-entity surface (`get_entity_source`, `get_entity_body`).
/// A surface that projects many entities for one request must instead build one
/// [`HeldSourceAuthority`] and call
/// [`read_entity_source_excerpt_detailed_held`], or it pays a full authority
/// recovery and a whole-history replay per result.
pub fn read_entity_source_excerpt_detailed<G: GraphStore>(
    store: &G,
    entity: &Entity,
    max_lines: usize,
    max_chars: usize,
    repository_authority: Option<&RequestRepositoryAuthority>,
    scope: EntitySourceScope,
) -> Result<Option<ExactEntitySource>> {
    read_entity_source_excerpt_detailed_held(
        &HeldSourceAuthority::new(store, repository_authority),
        entity,
        max_lines,
        max_chars,
        scope,
    )
}

/// Body projection served from authority this request already holds.
pub fn read_entity_source_excerpt_detailed_held<G: GraphStore>(
    held: &HeldSourceAuthority<'_, G>,
    entity: &Entity,
    max_lines: usize,
    max_chars: usize,
    scope: EntitySourceScope,
) -> Result<Option<ExactEntitySource>> {
    let Some((mut source, bytes, span)) = resolve_entity_source_authority(held, entity, scope)?
    else {
        return Ok(None);
    };
    let text = std::str::from_utf8(&bytes).map_err(|error| {
        graph_source_gap(format!(
            "artifact {:?} at {} is not valid UTF-8 for semantic source: {error}",
            source.artifact_id, source.path
        ))
    })?;
    let excerpt = excerpt_from_span_bytes(&bytes, &span, max_lines, max_chars);
    let body = if excerpt
        .as_ref()
        .is_some_and(|excerpt| !should_expand_excerpt(entity, excerpt))
    {
        excerpt
    } else {
        expand_entity_source_excerpt(entity, text, span.start_byte, max_lines, max_chars)
            .or(excerpt)
    };
    let Some(body) = body else {
        return Ok(None);
    };
    source.body = body;
    Ok(Some(source))
}

/// Explain, in agent-actionable terms, why an entity has no graph-owned body.
///
/// Reached only when the projection returned no body without erroring, which is
/// always a structural property of the entity rather than a read failure: an
/// entity with no file origin or no span has no source to project. The message
/// names the missing coordinate so an agent stops asking for the body instead of
/// retrying, and never mistakes absence for an empty implementation.
pub fn entity_body_gap_reason(entity: &Entity) -> String {
    let missing = match (entity.file_origin.is_some(), entity.span.is_some()) {
        (false, false) => "no file origin and no source span",
        (false, true) => "no file origin",
        (true, false) => "no source span",
        // Coordinates present but the projection still produced nothing: the
        // span resolved to empty or whitespace-only text.
        (true, true) => "a source span that projects to no text",
    };
    format!(
        "entity {} ({}) has {missing} in graph truth, so no body can be served from it; \
         its signature is authoritative but its implementation is not available",
        entity.id, entity.name
    )
}

/// Caps for the inline snippet surfaced on a retrieval hit (`kin locate --json`
/// symbols, `semantic_locate` entity results): a signature plus the first
/// several body lines, dense enough for an agent to act on without a follow-up
/// read, but far tighter than the full-body excerpt
/// ([`MCP_SOURCE_MAX_LINES`]/[`MCP_SOURCE_MAX_CHARS`]) `get_entity_source` and
/// `get_context_pack` serve. One bound shared by every agent surface so the
/// snippet is identical wherever it appears.
pub const RETRIEVAL_SNIPPET_MAX_LINES: usize = 12;
pub const RETRIEVAL_SNIPPET_MAX_CHARS: usize = 800;

/// Graph-native bounded snippet for an entity. Delegates to the same
/// content-addressed, hash-verified body projection
/// ([`read_entity_source_excerpt_detailed`]) that backs `get_entity_source` and
/// `get_context_pack`, capped to
/// [`RETRIEVAL_SNIPPET_MAX_LINES`]/[`RETRIEVAL_SNIPPET_MAX_CHARS`] for inline use
/// on retrieval hits. Returns `None` only when the entity has no source
/// coordinates. A tree, identity, span, UTF-8, or blob authority gap is an
/// error; callers must surface it rather than reading the working tree.
pub fn read_bounded_entity_snippet<G: GraphStore>(
    store: &G,
    entity: &Entity,
    repository_authority: Option<&RequestRepositoryAuthority>,
    scope: EntitySourceScope,
) -> Result<Option<String>> {
    read_bounded_entity_snippet_held(
        &HeldSourceAuthority::new(store, repository_authority),
        entity,
        scope,
    )
}

/// Bounded snippet served from authority this request already holds.
///
/// This is the variant every retrieval surface must use. A retrieval result set
/// projects one snippet per hit, so opening authority and replaying history per
/// hit multiplies process-startup work by the page size -- the defect that made
/// `semantic_locate` unusable on a real repository.
pub fn read_bounded_entity_snippet_held<G: GraphStore>(
    held: &HeldSourceAuthority<'_, G>,
    entity: &Entity,
    scope: EntitySourceScope,
) -> Result<Option<String>> {
    Ok(read_entity_source_excerpt_detailed_held(
        held,
        entity,
        RETRIEVAL_SNIPPET_MAX_LINES,
        RETRIEVAL_SNIPPET_MAX_CHARS,
        scope,
    )?
    .map(|source| source.body))
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
    // `excerpt_from_line_range` counts lines 1-based; the span carries 0-based
    // graph rows. Converting here is what keeps the fallback from clipping one
    // line short, and from dropping an entity that starts on the file's first
    // line (graph row 0) entirely.
    let (start_line, end_line) = presentation_span_lines(span);
    excerpt_from_line_range(&text, start_line, end_line, max_lines, max_chars)
}

/// Slice a 1-based inclusive line range out of `content`.
///
/// Takes PRESENTATION lines, not graph rows: callers holding a [`SourceSpan`]
/// must convert through [`presentation_span_lines`] first.
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
    repository_authority: Option<&RequestRepositoryAuthority>,
) -> Result<serde_json::Value> {
    let mut value = serde_json::to_value(entity).map_err(McpError::Json)?;
    let Some(obj) = value.as_object_mut() else {
        return Ok(value);
    };

    if let Some(read_path) = entity_read_path(entity) {
        obj.insert("read_path".into(), serde_json::json!(read_path));
    }
    if let Some(span) = entity.span.as_ref() {
        let (start_line, end_line) = presentation_span_lines(span);
        obj.insert("start_line".into(), serde_json::json!(start_line));
        obj.insert("end_line".into(), serde_json::json!(end_line));
    }
    if let Some(source) = read_entity_source_excerpt_detailed(
        store,
        entity,
        MCP_SOURCE_MAX_LINES,
        MCP_SOURCE_MAX_CHARS,
        repository_authority,
        EntitySourceScope::WorkspaceHead,
    )? {
        obj.insert("source_excerpt".into(), serde_json::json!(source.body));
        obj.extend(source_provenance_fields(&source));
    }

    let source = LAST_READ_SOURCE.with(|f| f.get());
    obj.insert("source".into(), serde_json::json!(source));

    Ok(value)
}

/// Project the focal entity of a context pack, including its graph-owned body.
///
/// `entry.content` is NOT used as the body. The context builder projects a
/// synthesized `// name (Kind, language)` header plus the signature for its token
/// accounting, and serving that as `body` produced the worst possible failure for
/// a writing agent: source-shaped text that is not the entity's source, with no
/// signal that the real body was never read. An agent restating it as a body
/// update deletes the implementation.
///
/// So the body is the graph-owned projection or nothing. When the graph cannot
/// serve it, `body` is null and `body_unavailable` says why, which an agent can
/// act on by stopping rather than by guessing.
/// Takes no `ContextEntry`: it used to, and then ignored it. The pack's
/// `entry.content` is a token-accounting stub, and once it stopped being a body
/// fallback the parameter only obliged callers to build a value this function
/// discards.
///
/// Takes no `compact` flag either. Compact mode used to drop the focal body
/// while still paying for the read that produced it, which left the one thing
/// the pack is for out of the cheaper mode: a caller asking for a bounded pack
/// spent a whole call learning it had to ask again. Compact now bounds the
/// dependency rows, and the focal body it serves is already capped at
/// [`MCP_SOURCE_MAX_LINES`]/[`MCP_SOURCE_MAX_CHARS`].
pub fn focal_context_json<G: GraphStore>(
    store: &G,
    entity: &Entity,
    repository_authority: Option<&RequestRepositoryAuthority>,
) -> Result<serde_json::Value> {
    focal_context_json_held(
        &HeldSourceAuthority::new(store, repository_authority),
        entity,
    )
}

/// The focal entity's context projection, served from authority this request
/// already holds. A context pack projects the focal entity and then every
/// dependency it carries, so all of those reads belong to one session.
pub fn focal_context_json_held<G: GraphStore>(
    held: &HeldSourceAuthority<'_, G>,
    entity: &Entity,
) -> Result<serde_json::Value> {
    let start_line = entity_presentation_start_line(entity);
    let end_line = entity_presentation_end_line(entity);
    let source_excerpt = read_entity_source_excerpt_detailed_held(
        held,
        entity,
        MCP_SOURCE_MAX_LINES,
        MCP_SOURCE_MAX_CHARS,
        EntitySourceScope::WorkspaceHead,
    )?;
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
        "source": source,
    });

    match source_excerpt.as_ref() {
        Some(source) => obj["body"] = serde_json::json!(source.body),
        None => {
            obj["body"] = serde_json::Value::Null;
            obj["body_unavailable"] = serde_json::json!(entity_body_gap_reason(entity));
        }
    }
    if let Some(source) = source_excerpt {
        if let Some(map) = obj.as_object_mut() {
            map.extend(source_provenance_fields(&source));
        }
    }

    Ok(obj)
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

/// Read the capabilities a client declared for itself, or `None` when it
/// declared none.
///
/// Materializing the read-only default here loses the distinction the daemon
/// needs: a client that says nothing is not a client that says it cannot write,
/// and the session report is only able to tell the truth about what the session
/// may do if the two arrive differently.
pub fn parse_capabilities(
    args: &HashMap<String, serde_json::Value>,
) -> Option<SessionCapabilities> {
    let obj = args.get("capabilities").and_then(|v| v.as_object())?;

    Some(SessionCapabilities {
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
    })
}

// ── Search filter helpers ──

pub fn build_semantic_search_request(
    args: &HashMap<String, serde_json::Value>,
) -> Result<(String, usize, EntityFilter)> {
    const MAX_LIMIT: usize = 200;
    let query = get_string_param(args, "query")?;
    let limit = (get_optional_u64(args, "limit", 20) as usize).clamp(1, MAX_LIMIT);

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
        let start_line = entity_presentation_start_line(&entity);
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
        let start_line = entity_presentation_start_line(&entity);
        let end_line = entity_presentation_end_line(&entity);
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
            return kin_review::diff_from_files(store, &files).map_err(|error| match error {
                // Files mode resolves each path to the entities the graph holds
                // for it and diffs those. When none resolve there is nothing to
                // diff, and the shared review error for that is worded for the
                // base/head mode: "no changes between base and head". A caller
                // who passed neither a base nor a head reads a complaint about
                // a comparison that never happened and looks for a diff
                // problem, when the fact is that the paths named no entities.
                // Tracked paths with no parser-emitted entities are the common
                // case here: a workflow file is a real artifact and resolves to
                // nothing.
                kin_review::ReviewError::NoChanges => McpError::Review(format!(
                    "no entity resolved from the given files, so nothing was diffed: [{}]. \
                     These paths named no entities in this graph, which is what a tracked file \
                     the parsers emit no entities for looks like; no base or head was \
                     compared. Confirm the paths with kin_artifact_list, or pass entity_ids \
                     for the declarations you mean.",
                    files.join(", ")
                )),
                other => McpError::Review(other.to_string()),
            });
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
