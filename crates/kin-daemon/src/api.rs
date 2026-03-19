// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Firelock, LLC

use std::net::{Ipv4Addr, SocketAddrV4, TcpListener as StdTcpListener};
use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use kin_model::session::{Intent, IntentScope, IntentSummary, LockType};
use kin_model::{
    ContractId, EntityId, FilePathId, IntentId, SessionCapabilities, SessionId, SessionTransport,
};
use socket2::{Domain, Protocol, Socket, Type};
use serde::{Deserialize, Serialize};
use tracing::info;
use uuid::Uuid;

use crate::state::DaemonState;

/// Health check response.
#[derive(Debug, Serialize, serde::Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub uptime_seconds: u64,
    pub graph_entity_count: Option<usize>,
    pub graph_loaded: bool,
    pub reconciliation_status: String,
}

/// Readiness response.
#[derive(Debug, Serialize)]
pub struct ReadinessResponse {
    pub ready: bool,
}

/// Working copy status response.
#[derive(Debug, Serialize)]
pub struct StatusResponse {
    pub base_change: String,
    pub entity_adds: usize,
    pub entity_mods: usize,
    pub entity_removes: usize,
    pub relation_adds: usize,
    pub relation_removes: usize,
}

/// JSON-friendly intent payload for CLI and adapter consumers.
#[derive(Debug, Serialize, Deserialize)]
pub struct IntentResponse {
    pub intent_id: String,
    pub session_id: String,
    pub scopes: Vec<String>,
    pub lock_type: String,
    pub task_description: String,
    pub registered_at: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RegisterIntentRequest {
    scope: String,
    lock_type: String,
    task_description: String,
    #[serde(default)]
    session_id: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct RegisterIntentResponse {
    intent_id: String,
    session_id: String,
    status: String,
    conflicts: Vec<IntentSummary>,
    downstream_warnings: Vec<IntentSummary>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ClearedIntentsResponse {
    cleared: usize,
}

#[derive(Debug, Serialize, Deserialize)]
struct TrafficResponse {
    active_intents: Vec<IntentSummary>,
    downstream_warnings: Vec<IntentSummary>,
    hard_blocks: usize,
    soft_locks: usize,
    downstream_count: usize,
}

/// Build the axum router with all daemon API routes.
pub fn router(state: Arc<DaemonState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/readiness", get(readiness))
        .route("/status", get(status))
        .route("/session", get(list_sessions))
        .route("/session/{session_id}", get(get_session))
        .route(
            "/session/{session_id}/intents",
            get(list_session_intents).delete(clear_session_intents),
        )
        .route("/intent", get(list_intents))
        .route("/intent/register", post(register_intent))
        .route("/intent/{intent_id}", delete(release_intent))
        .route("/traffic/{scope}", get(traffic))
        .with_state(state)
}

/// GET /health — liveness check with extended diagnostics.
async fn health(State(state): State<Arc<DaemonState>>) -> impl IntoResponse {
    let uptime_seconds = state.started_at.elapsed().as_secs();
    let entity_count = state.graph.entity_count();
    let graph_loaded = entity_count > 0;

    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds,
        graph_entity_count: Some(entity_count),
        graph_loaded,
        reconciliation_status: state.reconciliation_status_str().to_string(),
    })
}

/// GET /readiness — returns 200 when initialized, 503 otherwise.
/// An initialized daemon has either loaded a snapshot or completed at least
/// one reconciliation cycle. An empty but initialized workspace is ready.
async fn readiness(State(state): State<Arc<DaemonState>>) -> impl IntoResponse {
    let initialized = state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed);

    if initialized {
        (StatusCode::OK, Json(ReadinessResponse { ready: true }))
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(ReadinessResponse { ready: false }),
        )
    }
}

/// GET /status — current working copy status.
async fn status(State(state): State<Arc<DaemonState>>) -> Result<impl IntoResponse, StatusCode> {
    let wc = state.working_copy.read().await;
    let overlay = &wc.uncommitted_mutations;

    Ok(Json(StatusResponse {
        base_change: wc.base_change.to_string(),
        entity_adds: overlay.entity_adds.len(),
        entity_mods: overlay.entity_mods.len(),
        entity_removes: overlay.entity_removes.len(),
        relation_adds: overlay.relation_adds.len(),
        relation_removes: overlay.relation_removes.len(),
    }))
}

/// GET /session — list all active sessions.
async fn list_sessions(
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let sessions = state.coordinator.list_sessions().map_err(internal_error)?;
    Ok(Json(sessions))
}

/// GET /session/{session_id} — fetch a single active session.
async fn get_session(
    Path(session_id): Path<String>,
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let session_id = parse_session_id(&session_id)?;
    let session = state
        .coordinator
        .get_session(&session_id)
        .map_err(internal_error)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("session not found: {session_id}"),
            )
        })?;
    Ok(Json(session))
}

/// GET /session/{session_id}/intents — list intents owned by a session.
async fn list_session_intents(
    Path(session_id): Path<String>,
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let session_id = parse_session_id(&session_id)?;
    let intents = state
        .coordinator
        .list_intents(&session_id)
        .map_err(internal_error)?;
    Ok(Json(
        intents
            .into_iter()
            .map(IntentResponse::from)
            .collect::<Vec<_>>(),
    ))
}

/// DELETE /session/{session_id}/intents — clear all intents for a session.
async fn clear_session_intents(
    Path(session_id): Path<String>,
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let session_id = parse_session_id(&session_id)?;
    let intents = state
        .coordinator
        .list_intents(&session_id)
        .map_err(internal_error)?;

    for intent in &intents {
        state
            .coordinator
            .release_intent(&session_id, &intent.intent_id)
            .map_err(internal_error)?;
    }

    Ok(Json(ClearedIntentsResponse {
        cleared: intents.len(),
    }))
}

/// GET /intent — list all active intents.
async fn list_intents(
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let intents = state.graph.list_all_intents().map_err(internal_error)?;
    Ok(Json(
        intents
            .into_iter()
            .map(IntentResponse::from)
            .collect::<Vec<_>>(),
    ))
}

/// POST /intent/register — register a new intent against the daemon-backed coordinator.
async fn register_intent(
    State(state): State<Arc<DaemonState>>,
    Json(request): Json<RegisterIntentRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let scope = parse_scope(&request.scope)?;
    let lock_type = parse_lock_type(&request.lock_type)?;
    let session_id = resolve_or_create_session(&state, request.session_id.as_deref())?;
    let result = state
        .coordinator
        .register_intent(
            &session_id,
            vec![scope],
            lock_type,
            &request.task_description,
            None,
        )
        .map_err(internal_error)?;

    let response = match result {
        crate::session_registry::IntentRegistrationResult::Registered {
            intent_id,
            downstream_warnings,
        } => RegisterIntentResponse {
            intent_id: intent_id.to_string(),
            session_id: session_id.to_string(),
            status: "registered".to_string(),
            conflicts: Vec::new(),
            downstream_warnings,
        },
        crate::session_registry::IntentRegistrationResult::Blocked {
            intent_id,
            conflicts,
        } => RegisterIntentResponse {
            intent_id: intent_id.to_string(),
            session_id: session_id.to_string(),
            status: "blocked".to_string(),
            conflicts,
            downstream_warnings: Vec::new(),
        },
    };

    Ok(Json(response))
}

/// DELETE /intent/{intent_id} — release an active intent.
async fn release_intent(
    Path(intent_id): Path<String>,
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let intent_id = parse_intent_id(&intent_id)?;
    let intent = state
        .graph
        .get_intent(&intent_id)
        .map_err(internal_error)?
        .ok_or_else(|| {
            (
                StatusCode::NOT_FOUND,
                format!("intent not found: {intent_id}"),
            )
        })?;

    state
        .coordinator
        .release_intent(&intent.session_id, &intent_id)
        .map_err(internal_error)?;
    Ok(StatusCode::NO_CONTENT)
}

/// GET /traffic/{scope} — summarize active locks and downstream warnings.
async fn traffic(
    Path(scope): Path<String>,
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let scope = parse_scope(&scope)?;
    let mut reports = state
        .coordinator
        .check_traffic(&[scope])
        .map_err(internal_error)?
        .reports;
    let report = reports.pop().ok_or_else(|| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "traffic report missing for requested scope".to_string(),
        )
    })?;
    let hard_blocks = report
        .active_intents
        .iter()
        .filter(|intent| intent.lock_type == LockType::Hard)
        .count();
    let soft_locks = report.active_intents.len().saturating_sub(hard_blocks);
    let downstream_count = report.downstream_warnings.len();

    Ok(Json(TrafficResponse {
        active_intents: report.active_intents,
        downstream_warnings: report.downstream_warnings,
        hard_blocks,
        soft_locks,
        downstream_count,
    }))
}

fn resolve_or_create_session(
    state: &DaemonState,
    session_id: Option<&str>,
) -> Result<SessionId, (StatusCode, String)> {
    if let Some(session_id) = session_id {
        let session_id = parse_session_id(session_id)?;
        let exists = state
            .coordinator
            .get_session(&session_id)
            .map_err(internal_error)?
            .is_some();
        if !exists {
            return Err((
                StatusCode::NOT_FOUND,
                format!("session not found: {session_id}"),
            ));
        }
        return Ok(session_id);
    }

    state
        .coordinator
        .register_session(
            "kin-cli",
            "daemon-intent",
            SessionTransport::Cli,
            None,
            state.layout.working_dir().to_path_buf(),
            SessionCapabilities::default(),
        )
        .map_err(internal_error)
}

fn parse_lock_type(lock_type: &str) -> Result<LockType, (StatusCode, String)> {
    match lock_type.trim().to_ascii_lowercase().as_str() {
        "hard" => Ok(LockType::Hard),
        "soft" => Ok(LockType::Soft),
        _ => Err((
            StatusCode::BAD_REQUEST,
            format!("invalid lock type '{lock_type}': expected 'hard' or 'soft'"),
        )),
    }
}

fn parse_scope(scope: &str) -> Result<IntentScope, (StatusCode, String)> {
    if let Some(rest) = scope.strip_prefix("entity:") {
        return Ok(IntentScope::Entity(EntityId(parse_uuid(rest, "entity")?)));
    }
    if let Some(rest) = scope.strip_prefix("contract:") {
        return Ok(IntentScope::Contract(ContractId(parse_uuid(
            rest, "contract",
        )?)));
    }
    if let Some(rest) = scope.strip_prefix("file:") {
        return Ok(IntentScope::Artifact(FilePathId::new(rest)));
    }
    if let Ok(uuid) = Uuid::parse_str(scope) {
        return Ok(IntentScope::Entity(EntityId(uuid)));
    }
    Ok(IntentScope::Artifact(FilePathId::new(scope)))
}

fn parse_session_id(value: &str) -> Result<SessionId, (StatusCode, String)> {
    Ok(SessionId(parse_uuid(value, "session")?))
}

fn parse_intent_id(value: &str) -> Result<IntentId, (StatusCode, String)> {
    Ok(IntentId(parse_uuid(value, "intent")?))
}

fn parse_uuid(value: &str, kind: &str) -> Result<Uuid, (StatusCode, String)> {
    Uuid::parse_str(value).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            format!("invalid {kind} UUID: {value}"),
        )
    })
}

fn format_scope(scope: &IntentScope) -> String {
    match scope {
        IntentScope::Entity(id) => format!("entity:{id}"),
        IntentScope::Contract(id) => format!("contract:{id}"),
        IntentScope::Artifact(id) => format!("file:{id}"),
    }
}

fn internal_error<E: std::fmt::Display>(error: E) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

impl From<Intent> for IntentResponse {
    fn from(intent: Intent) -> Self {
        Self {
            intent_id: intent.intent_id.to_string(),
            session_id: intent.session_id.to_string(),
            scopes: intent.scopes.iter().map(format_scope).collect(),
            lock_type: match intent.lock_type {
                LockType::Hard => "hard".to_string(),
                LockType::Soft => "soft".to_string(),
            },
            task_description: intent.task_description,
            registered_at: intent.registered_at.to_string(),
            expires_at: intent.expires_at.map(|timestamp| timestamp.to_string()),
        }
    }
}

/// Start the API server on the given port.
pub async fn serve(state: Arc<DaemonState>, port: u16) -> std::io::Result<()> {
    let app = router(state);
    let listener = bind_listener(port)?;

    info!(port, "daemon API server listening");

    axum::serve(listener, app).await
}

fn bind_listener(port: u16) -> std::io::Result<tokio::net::TcpListener> {
    let address = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port);
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.bind(&address.into())?;
    socket.listen(1024)?;

    let listener: StdTcpListener = socket.into();
    listener.set_nonblocking(true)?;
    tokio::net::TcpListener::from_std(listener)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use kin_model::{AgentSession, IntentScope};
    use tower::ServiceExt;

    fn test_state() -> Arc<DaemonState> {
        let dir = tempfile::tempdir().unwrap();
        let kin_dir = dir.path().join(".kin");
        std::fs::create_dir_all(kin_dir.join("objects")).unwrap();
        std::fs::create_dir_all(kin_dir.join("working")).unwrap();
        let layout = kin_core::KinLayout::new(kin_dir);
        Arc::new(DaemonState::open(layout).unwrap())
    }

    #[tokio::test]
    async fn health_returns_ok_with_extended_fields() {
        let state = test_state();
        let app = router(state);
        let response = app
            .oneshot(Request::get("/health").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let json: HealthResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.status, "ok");
        assert!(json.uptime_seconds < 5);
        assert!(json.graph_entity_count.is_some());
    }

    #[tokio::test]
    async fn readiness_returns_503_when_empty() {
        let state = test_state();
        let app = router(state);
        let response = app
            .oneshot(Request::get("/readiness").body(Body::empty()).unwrap())
            .await
            .unwrap();
        // Empty graph → not ready
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn sessions_and_intents_endpoints_return_live_state() {
        let state = test_state();
        let session_id = state
            .coordinator
            .register_session(
                "codex",
                "api-test",
                SessionTransport::Cli,
                None,
                state.layout.working_dir().to_path_buf(),
                SessionCapabilities::default(),
            )
            .unwrap();
        let entity_id = EntityId::new();
        state
            .coordinator
            .register_intent(
                &session_id,
                vec![IntentScope::Entity(entity_id)],
                LockType::Hard,
                "touch parser",
                None,
            )
            .unwrap();

        let app = router(state.clone());
        let sessions = app
            .clone()
            .oneshot(Request::get("/session").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(sessions.status(), StatusCode::OK);
        let sessions_body = axum::body::to_bytes(sessions.into_body(), 4096)
            .await
            .unwrap();
        let sessions_json: Vec<AgentSession> = serde_json::from_slice(&sessions_body).unwrap();
        assert_eq!(sessions_json.len(), 1);
        assert_eq!(sessions_json[0].session_id, session_id);

        let intents = app
            .oneshot(Request::get("/intent").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(intents.status(), StatusCode::OK);
        let intents_body = axum::body::to_bytes(intents.into_body(), 4096)
            .await
            .unwrap();
        let intents_json: Vec<IntentResponse> = serde_json::from_slice(&intents_body).unwrap();
        assert_eq!(intents_json.len(), 1);
        assert_eq!(intents_json[0].session_id, session_id.to_string());
        assert_eq!(intents_json[0].scopes, vec![format!("entity:{entity_id}")]);
    }

    #[tokio::test]
    async fn register_clear_and_traffic_endpoints_use_daemon_coordinator() {
        let state = test_state();
        let app = router(state.clone());

        let response = app
            .clone()
            .oneshot(
                Request::post("/intent/register")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "scope": "file:src/lib.rs",
                            "lock_type": "hard",
                            "task_description": "edit lib"
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 4096)
            .await
            .unwrap();
        let registered: RegisterIntentResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(registered.status, "registered");
        assert!(!registered.session_id.is_empty());

        let traffic = app
            .clone()
            .oneshot(
                Request::get("/traffic/file%3Asrc%2Flib.rs")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(traffic.status(), StatusCode::OK);
        let traffic_body = axum::body::to_bytes(traffic.into_body(), 4096)
            .await
            .unwrap();
        let traffic_json: TrafficResponse = serde_json::from_slice(&traffic_body).unwrap();
        assert_eq!(traffic_json.hard_blocks, 1);
        assert_eq!(traffic_json.soft_locks, 0);

        let clear = app
            .oneshot(
                Request::delete(format!("/session/{}/intents", registered.session_id))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(clear.status(), StatusCode::OK);
        let clear_body = axum::body::to_bytes(clear.into_body(), 4096).await.unwrap();
        let cleared: ClearedIntentsResponse = serde_json::from_slice(&clear_body).unwrap();
        assert_eq!(cleared.cleared, 1);
    }
}
