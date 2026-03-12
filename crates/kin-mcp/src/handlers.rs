use std::collections::HashMap;
use serde::Serialize;
use std::path::PathBuf;

use kin_model::entity::EntityKind;
use kin_model::graph::{EntityFilter, GraphStore};
use kin_model::ids::{EntityId, Hash256, IntentId, LanguageId, SemanticChangeId, SessionId};
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
        "impact_analysis" => handle_impact_analysis(arguments, store, sessions),
        "semantic_diff" => handle_semantic_diff(arguments, store),
        "semantic_review" => handle_semantic_review(arguments, store, sessions),
        "dead_code" => handle_dead_code(arguments, store),
        "entity_history" => handle_entity_history(arguments, store),
        "graph_neighborhood" => handle_graph_neighborhood(arguments, store),
        "benchmark" => handle_benchmark(arguments, store),
        "register_session" => handle_register_session(arguments, sessions),
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

    let entities = store.query_entities(&filter).map_err(McpError::graph)?;
    let total_matches = entities.len();
    let limited: Vec<_> = entities
        .into_iter()
        .take(limit)
        .map(SemanticSearchResult::from)
        .collect();
    let json = serde_json::to_string_pretty(&SemanticSearchResponse {
        query,
        limit,
        total_matches,
        truncated: total_matches > limited.len(),
        results: limited,
    })
    .map_err(McpError::Json)?;

    Ok(ToolCallResult::text(json))
}

fn build_semantic_search_request(
    args: &HashMap<String, serde_json::Value>,
) -> Result<(String, usize, EntityFilter)> {
    let query = get_string_param(args, "query")?;
    let limit = get_optional_u64(args, "limit", 20) as usize;

    let kind_filter = args.get("kind").and_then(|v| v.as_str()).and_then(parse_kind_filter);
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

fn handle_get_entity<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let id_str = get_string_param(args, "entity_id")?;
    let entity_id = parse_entity_id(&id_str)?;

    match store.get_entity(&entity_id).map_err(McpError::graph)? {
        Some(entity) => {
            let json = serde_json::to_string_pretty(&entity).map_err(McpError::Json)?;
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
    let id_str = get_string_param(args, "entity_id")?;
    let entity_id = parse_entity_id(&id_str)?;
    let token_budget = get_optional_u64(args, "token_budget", 16000) as u32;
    let depth = get_optional_u64(args, "depth", 2) as u32;
    let include_traffic = get_optional_bool(args, "include_traffic", true);

    // Get the focal entity
    let entity = store
        .get_entity(&entity_id)
        .map_err(McpError::graph)?
        .ok_or_else(|| McpError::InvalidParams(format!("Entity not found: {}", id_str)))?;

    // Get neighborhood for context
    let neighborhood = store
        .get_dependency_neighborhood(&entity_id, depth)
        .map_err(McpError::graph)?;

    let mut result = serde_json::json!({
        "focal_entity": entity,
        "token_budget": token_budget,
        "depth": depth,
        "neighborhood": {
            "entity_count": neighborhood.entities.len(),
            "relation_count": neighborhood.relations.len(),
            "entities": neighborhood.entities.values().collect::<Vec<_>>(),
        }
    });

    if include_traffic {
        let traffic = sessions.get_traffic_near_entity(&entity_id);
        if !traffic.is_empty() {
            result["nearby_traffic"] = serde_json::to_value(&traffic).map_err(McpError::Json)?;
        }
    }

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

    let neighborhood = store
        .get_dependency_neighborhood(&entity_id, depth)
        .map_err(McpError::graph)?;

    let result = serde_json::json!({
        "entity_count": neighborhood.entities.len(),
        "relation_count": neighborhood.relations.len(),
        "entities": neighborhood.entities.values().collect::<Vec<_>>(),
        "relations": neighborhood.relations,
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

    let filter = kin_model::WorkFilter {
        statuses: status
            .map(|s| {
                s.parse::<kin_model::WorkStatus>()
                    .map(|ws| vec![ws])
                    .map_err(|e| McpError::InvalidParams(e))
            })
            .transpose()?,
        kinds: kind
            .map(|k| {
                k.parse::<kin_model::WorkKind>()
                    .map(|wk| vec![wk])
                    .map_err(|e| McpError::InvalidParams(e))
            })
            .transpose()?,
        scope: None,
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
    let work_id_str = get_string_param(args, "work_id")?;
    let uuid = uuid::Uuid::parse_str(&work_id_str)
        .map_err(|_| McpError::InvalidParams(format!("invalid work_id: {}", work_id_str)))?;
    let id = kin_model::WorkId(uuid);

    let item = store
        .get_work_item(&id)
        .map_err(|e| McpError::Other(e.to_string()))?
        .ok_or_else(|| McpError::InvalidParams(format!("work item not found: {}", work_id_str)))?;

    let children = store
        .get_child_work_items(&id)
        .map_err(|e| McpError::Other(e.to_string()))?;
    let implementors = store
        .get_implementors(&id)
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
        "children": children.iter().map(|c| serde_json::json!({
            "work_id": c.work_id.to_string(),
            "kind": c.kind.to_string(),
            "title": c.title,
            "status": c.status.to_string(),
        })).collect::<Vec<_>>(),
        "implementors": implementors.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
    });

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

fn handle_work_link<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let work_id_str = get_string_param(args, "work_id")?;
    let uuid = uuid::Uuid::parse_str(&work_id_str)
        .map_err(|_| McpError::InvalidParams(format!("invalid work_id: {}", work_id_str)))?;
    let id = kin_model::WorkId(uuid);

    let scopes = parse_work_scopes(args.get("scopes"))?;
    if scopes.is_empty() {
        return Err(McpError::InvalidParams("scopes array is empty".into()));
    }

    for scope in &scopes {
        let link = kin_model::WorkLink::Affects {
            work_id: id,
            scope: scope.clone(),
        };
        store
            .create_work_link(&link)
            .map_err(|e| McpError::Other(e.to_string()))?;
    }

    let result = serde_json::json!({
        "work_id": work_id_str,
        "linked_scopes": scopes.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
    });
    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
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

    let scopes = parse_work_scopes(args.get("scopes"))?;

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

    let result = serde_json::json!({
        "annotation_id": ann.annotation_id.to_string(),
        "kind": ann.kind.to_string(),
    });
    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

fn handle_annotation_list<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let scopes = parse_work_scopes(args.get("scopes"))?;
    let include_stale = get_optional_bool(args, "include_stale", true);

    let filter = kin_model::AnnotationFilter {
        scopes: if scopes.is_empty() {
            None
        } else {
            Some(scopes)
        },
        include_stale,
        ..Default::default()
    };

    let annotations = store
        .list_annotations(&filter)
        .map_err(|e| McpError::Other(e.to_string()))?;

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
    let runner_filter = args.get("runner").and_then(|v| v.as_str()).map(|s| s.to_string());

    let mut tests = store.get_tests_for_entity(&entity_id).map_err(McpError::graph)?;
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

fn handle_coverage_summary<G: GraphStore>(
    store: &G,
) -> Result<ToolCallResult> {
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
                    finding["downstream_entities"] = serde_json::json!(
                        impacted.iter().map(|e| serde_json::json!({
                            "id": e.id,
                            "name": e.name,
                        })).collect::<Vec<_>>()
                    );
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
    let history = store.get_entity_history(&entity_id).map_err(McpError::graph)?;

    let mut approvals_json = serde_json::json!([]);
    if let Some(latest_change) = history.first() {
        let approvals = store
            .get_approvals_for_change(&latest_change.id)
            .map_err(McpError::graph)?;
        approvals_json = serde_json::json!(approvals);
    }

    // Get recent audit events (not actor-filtered, just recent)
    let events = store.query_audit_events(None, 20).map_err(McpError::graph)?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::branch::Branch;
    use kin_model::change::SemanticChange;
    use kin_model::entity::Entity;
    use kin_model::graph::{EntityFilter, SubGraph};
    use kin_model::ids::*;
    use kin_model::relation::{Relation, RelationKind};

    struct EmptyStore;
    impl GraphStore for EmptyStore {
        type Error = std::io::Error;
        fn get_entity(&self, _: &EntityId) -> std::result::Result<Option<Entity>, Self::Error> {
            Ok(None)
        }
        fn get_relations(
            &self,
            _: &EntityId,
            _: &[RelationKind],
        ) -> std::result::Result<Vec<Relation>, Self::Error> {
            Ok(vec![])
        }
        fn get_all_relations_for_entity(
            &self,
            _: &EntityId,
        ) -> std::result::Result<Vec<Relation>, Self::Error> {
            Ok(vec![])
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
            Ok(vec![])
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
            _: &EntityFilter,
        ) -> std::result::Result<Vec<Entity>, Self::Error> {
            Ok(vec![])
        }
        fn list_all_entities(&self) -> std::result::Result<Vec<Entity>, Self::Error> {
            Ok(vec![])
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
        fn delete_work_item(
            &self,
            _: &kin_model::WorkId,
        ) -> std::result::Result<(), Self::Error> {
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
        fn get_implementors(
            &self,
            _: &kin_model::WorkId,
        ) -> std::result::Result<Vec<kin_model::WorkScope>, Self::Error> {
            Ok(vec![])
        }
        fn create_test_case(&self, _: &kin_model::verification::TestCase) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_test_case(&self, _: &kin_model::verification::TestId) -> std::result::Result<Option<kin_model::verification::TestCase>, Self::Error> {
            Ok(None)
        }
        fn get_tests_for_entity(&self, _: &EntityId) -> std::result::Result<Vec<kin_model::verification::TestCase>, Self::Error> {
            Ok(vec![])
        }
        fn delete_test_case(&self, _: &kin_model::verification::TestId) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn create_assertion(&self, _: &kin_model::verification::Assertion) -> std::result::Result<(), Self::Error> {
            Ok(())
        }
        fn get_assertion(&self, _: &kin_model::verification::AssertionId) -> std::result::Result<Option<kin_model::verification::Assertion>, Self::Error> {
            Ok(None)
        }
        fn get_coverage_summary(&self) -> std::result::Result<kin_model::verification::CoverageSummary, Self::Error> {
            Ok(kin_model::verification::CoverageSummary {
                total_entities: 0,
                covered_entities: 0,
                coverage_ratio: 0.0,
                missing_proof: vec![],
            })
        }
        fn create_verification_run(&self, _: &kin_model::verification::VerificationRun) -> std::result::Result<(), Self::Error> { Ok(()) }
        fn get_verification_run(&self, _: &kin_model::verification::VerificationRunId) -> std::result::Result<Option<kin_model::verification::VerificationRun>, Self::Error> { Ok(None) }
        fn list_runs_for_test(&self, _: &kin_model::verification::TestId) -> std::result::Result<Vec<kin_model::verification::VerificationRun>, Self::Error> { Ok(vec![]) }
        fn create_test_covers_entity(&self, _: &kin_model::verification::TestId, _: &EntityId) -> std::result::Result<(), Self::Error> { Ok(()) }
        fn create_test_covers_contract(&self, _: &kin_model::verification::TestId, _: &ContractId) -> std::result::Result<(), Self::Error> { Ok(()) }
        fn create_test_verifies_work(&self, _: &kin_model::verification::TestId, _: &kin_model::WorkId) -> std::result::Result<(), Self::Error> { Ok(()) }
        fn get_tests_covering_contract(&self, _: &ContractId) -> std::result::Result<Vec<kin_model::verification::TestCase>, Self::Error> { Ok(vec![]) }
        fn get_tests_verifying_work(&self, _: &kin_model::WorkId) -> std::result::Result<Vec<kin_model::verification::TestCase>, Self::Error> { Ok(vec![]) }
        fn create_mock_hint(&self, _: &kin_model::verification::MockHint) -> std::result::Result<(), Self::Error> { Ok(()) }
        fn get_mock_hints_for_test(&self, _: &kin_model::verification::TestId) -> std::result::Result<Vec<kin_model::verification::MockHint>, Self::Error> { Ok(vec![]) }
        fn link_run_proves_entity(&self, _: &kin_model::verification::VerificationRunId, _: &EntityId) -> std::result::Result<(), Self::Error> { Ok(()) }
        fn link_run_proves_work(&self, _: &kin_model::verification::VerificationRunId, _: &kin_model::WorkId) -> std::result::Result<(), Self::Error> { Ok(()) }
        fn get_contract_coverage_summary(&self) -> std::result::Result<kin_model::verification::ContractCoverageSummary, Self::Error> {
            Ok(kin_model::verification::ContractCoverageSummary {
                total_contracts: 0,
                covered_contracts: 0,
                coverage_ratio: 0.0,
                uncovered_contract_ids: vec![],
            })
        }
        fn create_actor(&self, _: &kin_model::provenance::Actor) -> std::result::Result<(), Self::Error> { Ok(()) }
        fn get_actor(&self, _: &kin_model::provenance::ActorId) -> std::result::Result<Option<kin_model::provenance::Actor>, Self::Error> { Ok(None) }
        fn list_actors(&self) -> std::result::Result<Vec<kin_model::provenance::Actor>, Self::Error> { Ok(vec![]) }
        fn create_delegation(&self, _: &kin_model::provenance::Delegation) -> std::result::Result<(), Self::Error> { Ok(()) }
        fn get_delegations_for_actor(&self, _: &kin_model::provenance::ActorId) -> std::result::Result<Vec<kin_model::provenance::Delegation>, Self::Error> { Ok(vec![]) }
        fn create_approval(&self, _: &kin_model::provenance::Approval) -> std::result::Result<(), Self::Error> { Ok(()) }
        fn get_approvals_for_change(&self, _: &SemanticChangeId) -> std::result::Result<Vec<kin_model::provenance::Approval>, Self::Error> { Ok(vec![]) }
        fn record_audit_event(&self, _: &kin_model::provenance::AuditEvent) -> std::result::Result<(), Self::Error> { Ok(()) }
        fn query_audit_events(&self, _: Option<&kin_model::provenance::ActorId>, _: usize) -> std::result::Result<Vec<kin_model::provenance::AuditEvent>, Self::Error> { Ok(vec![]) }
        fn upsert_shallow_file(&self, _: &kin_model::ShallowTrackedFile) -> std::result::Result<(), Self::Error> { Ok(()) }
        fn list_shallow_files(&self) -> std::result::Result<Vec<kin_model::ShallowTrackedFile>, Self::Error> { Ok(vec![]) }
        fn create_contract(&self, _: &kin_model::contract::Contract) -> std::result::Result<(), Self::Error> { Ok(()) }
        fn get_contract(&self, _: &kin_model::ids::ContractId) -> std::result::Result<Option<kin_model::contract::Contract>, Self::Error> { Ok(None) }
        fn list_contracts(&self) -> std::result::Result<Vec<kin_model::contract::Contract>, Self::Error> { Ok(vec![]) }
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
        let store = EmptyStore;
        let sessions = SessionRegistry::new();
        let args = HashMap::new();
        let result = handle_tool_call("nonexistent_tool", &args, &store, &sessions);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), McpError::ToolNotFound(_)));
    }

    #[test]
    fn session_start_and_heartbeat_and_end() {
        let store = EmptyStore;
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
        assert_eq!(parse_language_filter("js"), Some(vec![LanguageId::JavaScript]));
        assert_eq!(parse_language_filter("ts"), Some(vec![LanguageId::TypeScript]));
        assert_eq!(parse_language_filter("py"), Some(vec![LanguageId::Python]));
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
}
