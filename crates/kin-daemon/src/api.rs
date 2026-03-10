use std::sync::Arc;

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use tracing::info;

use crate::state::DaemonState;

/// Health check response.
#[derive(Debug, Serialize, serde::Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
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

/// Build the axum router with all daemon API routes.
pub fn router(state: Arc<DaemonState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/status", get(status))
        .with_state(state)
}

/// GET /health — liveness check.
async fn health() -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

/// GET /status — current working copy status.
async fn status(
    State(state): State<Arc<DaemonState>>,
) -> Result<impl IntoResponse, StatusCode> {
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

/// Start the API server on the given port.
pub async fn serve(state: Arc<DaemonState>, port: u16) -> std::io::Result<()> {
    let app = router(state);
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}")).await?;

    info!(port, "daemon API server listening");

    axum::serve(listener, app).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn health_returns_ok() {
        let response = health().await.into_response();
        let body = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        let json: HealthResponse = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.status, "ok");
    }
}
