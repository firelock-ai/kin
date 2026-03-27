// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Cargo sparse registry protocol adapter.
//!
//! Implements: <https://doc.rust-lang.org/cargo/reference/registries.html>
//!
//! Endpoints:
//! - GET /registry/cargo/config.json -- registry config
//! - GET /registry/cargo/{prefix}/{name} -- package index (newline-delimited JSON)
//! - GET /registry/cargo/dl/{name}/{version} -- download .crate file

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::get,
    Router,
};
use serde::Serialize;
use std::sync::Arc;

use crate::{Ecosystem, ManifestStore, PackageVersion};

/// Shared state for the Cargo registry routes
pub struct CargoRegistryState {
    pub manifest_store: ManifestStore,
    pub blobs_dir: std::path::PathBuf,
    pub base_url: String,
}

/// Create axum router for Cargo registry endpoints
pub fn cargo_routes(state: Arc<CargoRegistryState>) -> Router {
    Router::new()
        .route("/registry/cargo/config.json", get(config_json))
        .route("/registry/cargo/dl/{name}/{version}", get(download_crate))
        // Cargo sparse index: 1-char names under /1/, 2-char under /2/,
        // 3-char under /3/{first-char}/, 4+ under /{first-two}/{second-two}/
        .route("/registry/cargo/1/{name}", get(index_lookup))
        .route("/registry/cargo/2/{name}", get(index_lookup))
        .route(
            "/registry/cargo/3/{prefix}/{name}",
            get(index_lookup),
        )
        .route(
            "/registry/cargo/{prefix1}/{prefix2}/{name}",
            get(index_lookup),
        )
        .with_state(state)
}

/// GET /registry/cargo/config.json
async fn config_json(State(state): State<Arc<CargoRegistryState>>) -> Json<CargoConfig> {
    Json(CargoConfig {
        dl: format!(
            "{}/registry/cargo/dl/{{crate}}/{{version}}",
            state.base_url
        ),
        api: format!("{}/registry/cargo", state.base_url),
    })
}

#[derive(Serialize)]
struct CargoConfig {
    dl: String,
    api: String,
}

/// GET /registry/cargo/{prefix...}/{name} -- sparse index lookup
async fn index_lookup(
    State(state): State<Arc<CargoRegistryState>>,
    Path(params): Path<Vec<(String, String)>>,
) -> Response {
    // Extract the package name (last path segment)
    let name = params.last().map(|(_, v)| v.as_str()).unwrap_or("");

    let versions = match state.manifest_store.get_versions(Ecosystem::Cargo, name) {
        Ok(v) if v.is_empty() => return StatusCode::NOT_FOUND.into_response(),
        Ok(v) => v,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };

    // Cargo expects newline-delimited JSON, one entry per version
    let mut body = String::new();
    for v in &versions {
        let entry = CargoIndexEntry::from_version(v);
        if let Ok(line) = serde_json::to_string(&entry) {
            body.push_str(&line);
            body.push('\n');
        }
    }

    (StatusCode::OK, [("content-type", "text/plain")], body).into_response()
}

/// GET /registry/cargo/dl/{name}/{version} -- download .crate file
async fn download_crate(
    State(state): State<Arc<CargoRegistryState>>,
    Path((name, version)): Path<(String, String)>,
) -> Response {
    let versions = match state.manifest_store.get_versions(Ecosystem::Cargo, &name) {
        Ok(v) => v,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };

    let pkg_version = match versions.iter().find(|v| v.version == version) {
        Some(v) => v,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    // Read the .crate file from blob store
    let crate_path = state
        .blobs_dir
        .join(format!("{}-{}.crate", name, version));
    match std::fs::read(&crate_path) {
        Ok(bytes) => (
            StatusCode::OK,
            [
                ("content-type", "application/x-tar"),
                ("etag", &format!("\"{}\"", pkg_version.checksum)),
            ],
            bytes,
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Cargo index entry format (one per version, newline-delimited JSON)
#[derive(Serialize)]
struct CargoIndexEntry {
    name: String,
    vers: String,
    deps: Vec<CargoIndexDep>,
    cksum: String,
    features: serde_json::Value,
    yanked: bool,
}

#[derive(Serialize, serde::Deserialize)]
struct CargoIndexDep {
    name: String,
    req: String,
    features: Vec<String>,
    optional: bool,
    default_features: bool,
    target: Option<String>,
    kind: String,
    registry: Option<String>,
    package: Option<String>,
}

impl CargoIndexEntry {
    fn from_version(v: &PackageVersion) -> Self {
        // Extract deps from metadata if present
        let deps = v
            .metadata
            .get("deps")
            .and_then(|d| serde_json::from_value::<Vec<CargoIndexDep>>(d.clone()).ok())
            .unwrap_or_default();
        let features = v
            .metadata
            .get("features")
            .cloned()
            .unwrap_or_else(|| serde_json::json!({}));

        Self {
            name: v.id.name.clone(),
            vers: v.version.clone(),
            deps,
            cksum: v.checksum.clone(),
            features,
            yanked: v.yanked,
        }
    }
}
