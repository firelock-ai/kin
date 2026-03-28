// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Go module proxy (GOPROXY) protocol adapter.
//!
//! Implements: <https://go.dev/ref/mod#goproxy-protocol>
//!
//! Endpoints:
//! - GET /registry/go/{module}/@v/list -- list available versions
//! - GET /registry/go/{module}/@v/{version}.info -- version metadata (JSON)
//! - GET /registry/go/{module}/@v/{version}.mod -- go.mod file
//! - GET /registry/go/{module}/@v/{version}.zip -- module source zip

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::get,
    Router,
};
use std::sync::Arc;

use crate::{Ecosystem, ManifestStore};

/// Shared state for the Go module proxy routes
pub struct GoProxyState {
    pub manifest_store: ManifestStore,
    pub blobs_dir: std::path::PathBuf,
}

/// Create axum router for Go module proxy endpoints
pub fn go_routes(state: Arc<GoProxyState>) -> Router {
    Router::new()
        .route("/registry/go/{module}/@v/list", get(list_versions))
        .route("/registry/go/{module}/@v/{version}.info", get(version_info))
        .route("/registry/go/{module}/@v/{version}.mod", get(version_mod))
        .route("/registry/go/{module}/@v/{version}.zip", get(version_zip))
        .with_state(state)
}

/// GET /registry/go/{module}/@v/list -- list all available versions (plain text, one per line)
async fn list_versions(
    State(state): State<Arc<GoProxyState>>,
    Path(module): Path<String>,
) -> Response {
    let versions = match state.manifest_store.get_versions(Ecosystem::Go, &module) {
        Ok(v) => v,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let body = versions
        .iter()
        .map(|v| v.version.clone())
        .collect::<Vec<_>>()
        .join("\n");
    (StatusCode::OK, [("content-type", "text/plain")], body).into_response()
}

/// GET /registry/go/{module}/@v/{version}.info -- version metadata
async fn version_info(
    State(state): State<Arc<GoProxyState>>,
    Path((module, version)): Path<(String, String)>,
) -> Response {
    let version = version.strip_suffix(".info").unwrap_or(&version);
    let versions = match state.manifest_store.get_versions(Ecosystem::Go, &module) {
        Ok(v) => v,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    match versions.iter().find(|v| v.version == version) {
        Some(v) => Json(serde_json::json!({
            "Version": v.version,
            "Time": v.published_at.to_rfc3339(),
        }))
        .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// GET /registry/go/{module}/@v/{version}.mod -- go.mod file contents
async fn version_mod(
    State(state): State<Arc<GoProxyState>>,
    Path((module, version)): Path<(String, String)>,
) -> Response {
    let version = version.strip_suffix(".mod").unwrap_or(&version);
    let versions = match state.manifest_store.get_versions(Ecosystem::Go, &module) {
        Ok(v) => v,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    match versions.iter().find(|v| v.version == version) {
        Some(v) => {
            let default_mod = format!("module {}\n\ngo 1.21\n", module);
            let go_mod = v
                .metadata
                .get("go_mod")
                .and_then(|m| m.as_str())
                .unwrap_or(&default_mod);
            (
                StatusCode::OK,
                [("content-type", "text/plain")],
                go_mod.to_string(),
            )
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// GET /registry/go/{module}/@v/{version}.zip -- module source archive
async fn version_zip(
    State(state): State<Arc<GoProxyState>>,
    Path((module, version)): Path<(String, String)>,
) -> Response {
    let version = version.strip_suffix(".zip").unwrap_or(&version);
    let zip_path = state
        .blobs_dir
        .join(format!("{}-{}.zip", module.replace('/', "_"), version));
    match std::fs::read(&zip_path) {
        Ok(bytes) => (StatusCode::OK, [("content-type", "application/zip")], bytes).into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}
