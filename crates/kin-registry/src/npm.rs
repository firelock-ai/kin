// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! npm sparse registry protocol adapter.
//!
//! Implements a subset of the npm registry API:
//! - GET /registry/npm/{package} -- full package metadata (all versions)
//! - GET /registry/npm/{package}/{version} -- single version metadata
//! - GET /registry/npm/{package}/-/{tarball} -- download tarball

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::get,
    Router,
};
use std::sync::Arc;

use crate::{Ecosystem, ManifestStore};

/// Shared state for the npm registry routes
pub struct NpmRegistryState {
    pub manifest_store: ManifestStore,
    pub blobs_dir: std::path::PathBuf,
    pub base_url: String,
}

/// Create axum router for npm registry endpoints
pub fn npm_routes(state: Arc<NpmRegistryState>) -> Router {
    Router::new()
        .route("/registry/npm/{package}", get(package_metadata))
        .route(
            "/registry/npm/{package}/{version}",
            get(version_metadata),
        )
        .route(
            "/registry/npm/{package}/-/{tarball}",
            get(download_tarball),
        )
        .with_state(state)
}

/// GET /registry/npm/{package} -- full package metadata (all versions)
async fn package_metadata(
    State(state): State<Arc<NpmRegistryState>>,
    Path(package): Path<String>,
) -> Response {
    let versions = match state.manifest_store.get_versions(Ecosystem::Npm, &package) {
        Ok(v) if v.is_empty() => return StatusCode::NOT_FOUND.into_response(),
        Ok(v) => v,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };

    let mut version_map = serde_json::Map::new();
    let mut dist_tags = serde_json::Map::new();

    for v in &versions {
        let entry = serde_json::json!({
            "name": v.id.name,
            "version": v.version,
            "dist": {
                "tarball": format!(
                    "{}/registry/npm/{}/-/{}-{}.tgz",
                    state.base_url, package, package, v.version
                ),
                "shasum": v.checksum,
            },
            "dependencies": v.metadata.get("dependencies")
                .cloned()
                .unwrap_or(serde_json::json!({})),
        });
        version_map.insert(v.version.clone(), entry);
    }

    if let Some(latest) = versions.last() {
        dist_tags.insert(
            "latest".to_string(),
            serde_json::Value::String(latest.version.clone()),
        );
    }

    let response = serde_json::json!({
        "name": package,
        "versions": version_map,
        "dist-tags": dist_tags,
    });

    Json(response).into_response()
}

/// GET /registry/npm/{package}/{version} -- single version metadata
async fn version_metadata(
    State(state): State<Arc<NpmRegistryState>>,
    Path((package, version)): Path<(String, String)>,
) -> Response {
    let versions = match state.manifest_store.get_versions(Ecosystem::Npm, &package) {
        Ok(v) => v,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };

    match versions.iter().find(|v| v.version == version) {
        Some(v) => {
            let response = serde_json::json!({
                "name": v.id.name,
                "version": v.version,
                "dist": {
                    "tarball": format!(
                        "{}/registry/npm/{}/-/{}-{}.tgz",
                        state.base_url, package, package, v.version
                    ),
                    "shasum": v.checksum,
                },
            });
            Json(response).into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// GET /registry/npm/{package}/-/{tarball} -- download tarball
async fn download_tarball(
    State(state): State<Arc<NpmRegistryState>>,
    Path((_package, tarball)): Path<(String, String)>,
) -> Response {
    let tarball_path = state.blobs_dir.join(&tarball);
    match std::fs::read(&tarball_path) {
        Ok(bytes) => (
            StatusCode::OK,
            [("content-type", "application/octet-stream")],
            bytes,
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}
