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
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::{Ecosystem, ManifestStore, PackageId, PackageVersion};

/// Shared state for the Cargo registry routes
pub struct CargoRegistryState {
    pub manifest_store: ManifestStore,
    pub blobs_dir: std::path::PathBuf,
    pub base_url: String,
}

const CRATES_IO_INDEX_URL: &str = "https://github.com/rust-lang/crates.io-index";

/// Create axum router for Cargo registry endpoints
pub fn cargo_routes(state: Arc<CargoRegistryState>) -> Router {
    Router::new()
        .route("/registry/cargo/config.json", get(config_json))
        .route("/registry/cargo/dl/{name}/{version}", get(download_crate))
        // Cargo sparse index: 1-char names under /1/, 2-char under /2/,
        // 3-char under /3/{first-char}/, 4+ under /{first-two}/{second-two}/
        .route("/registry/cargo/1/{name}", get(index_lookup))
        .route("/registry/cargo/2/{name}", get(index_lookup))
        .route("/registry/cargo/3/{prefix}/{name}", get(index_lookup))
        .route(
            "/registry/cargo/{prefix1}/{prefix2}/{name}",
            get(index_lookup),
        )
        .route("/registry/cargo/api/v1/crates/publish", post(publish_crate))
        .with_state(state)
}

/// GET /registry/cargo/config.json
async fn config_json(State(state): State<Arc<CargoRegistryState>>) -> Json<CargoConfig> {
    Json(CargoConfig {
        dl: format!("{}/registry/cargo/dl/{{crate}}/{{version}}", state.base_url),
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

    let mut versions = match state.manifest_store.get_versions(Ecosystem::Cargo, name) {
        Ok(v) if v.is_empty() => return StatusCode::NOT_FOUND.into_response(),
        Ok(v) => v,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };

    backfill_cargo_metadata_from_crate(&state, &mut versions);

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
    let crate_path = state.blobs_dir.join(format!("{}-{}.crate", name, version));
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

/// Query parameters for the publish endpoint
#[derive(Debug, Deserialize)]
struct PublishParams {
    name: String,
    version: String,
}

/// POST /registry/cargo/api/v1/crates/publish
///
/// Accepts a `.crate` file as the request body (application/octet-stream).
/// Query params: `name` and `version`.
/// Computes SHA-256 checksum, stores the .crate file, and registers the version.
async fn publish_crate(
    State(state): State<Arc<CargoRegistryState>>,
    Query(params): Query<PublishParams>,
    body: axum::body::Bytes,
) -> Response {
    if params.name.is_empty() || params.version.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "name and version are required" })),
        )
            .into_response();
    }

    // Compute SHA-256 checksum of the .crate bytes
    let checksum = hex::encode(Sha256::digest(&body));

    // Ensure blobs directory exists
    if let Err(e) = std::fs::create_dir_all(&state.blobs_dir) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("failed to create blobs dir: {e}") })),
        )
            .into_response();
    }

    // Write .crate file to blobs directory
    let crate_path = state
        .blobs_dir
        .join(format!("{}-{}.crate", params.name, params.version));
    if let Err(e) = std::fs::write(&crate_path, &body) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("failed to write crate file: {e}") })),
        )
            .into_response();
    }

    // Extract features and deps from the .crate tarball's Cargo.toml
    let metadata = extract_crate_metadata(&body, &params.name, &params.version);

    // Register the version in the manifest store
    let pkg_version = PackageVersion {
        id: PackageId {
            ecosystem: Ecosystem::Cargo,
            scope: None,
            name: params.name.clone(),
        },
        version: params.version.clone(),
        blob_hash: checksum.clone(),
        blob_size: body.len() as u64,
        checksum: checksum.clone(),
        metadata,
        published_at: Utc::now(),
        published_by: "anonymous".to_string(),
        yanked: false,
    };

    match state.manifest_store.add_version(&pkg_version) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "name": params.name,
                "version": params.version,
                "checksum": checksum,
            })),
        )
            .into_response(),
        Err(crate::RegistryError::VersionExists(name, version)) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": format!("version already exists: {name}@{version}")
            })),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("{e}") })),
        )
            .into_response(),
    }
}

/// Extract features and dependencies from a .crate tarball.
///
/// .crate files are gzipped tarballs containing `{name}-{version}/Cargo.toml`.
/// We parse this to extract features (for feature resolution) and dependencies
/// (for the sparse index).
fn extract_crate_metadata(crate_bytes: &[u8], name: &str, version: &str) -> serde_json::Value {
    use flate2::read::GzDecoder;
    use std::io::Read;

    let expected_manifest = format!("{}-{}/Cargo.toml", name, version);
    let gz = GzDecoder::new(crate_bytes);
    let mut archive = tar::Archive::new(gz);

    let mut cargo_toml_content = String::new();
    if let Ok(entries) = archive.entries() {
        for entry in entries.flatten() {
            if let Ok(path) = entry.path() {
                if path.to_str() == Some(&expected_manifest) {
                    let mut entry = entry;
                    if entry.read_to_string(&mut cargo_toml_content).is_ok() {
                        break;
                    }
                }
            }
        }
    }

    if cargo_toml_content.is_empty() {
        return serde_json::json!({});
    }

    // Parse Cargo.toml to extract features and deps
    let toml_value: toml::Value = match cargo_toml_content.parse() {
        Ok(v) => v,
        Err(_) => return serde_json::json!({}),
    };

    let mut metadata = serde_json::json!({});

    // Extract [features]
    if let Some(features) = toml_value.get("features") {
        if let Ok(features_json) = serde_json::to_value(features) {
            metadata["features"] = features_json;
        }
    }

    // Extract [dependencies] as deps array for the index
    let mut deps = Vec::new();
    if let Some(dep_table) = toml_value.get("dependencies").and_then(|d| d.as_table()) {
        for (dep_name, dep_value) in dep_table {
            let (req, optional, default_features, dep_features, registry, package) = match dep_value
            {
                toml::Value::String(version_str) => (
                    version_str.clone(),
                    false,
                    true,
                    vec![],
                    Some(CRATES_IO_INDEX_URL.to_string()),
                    None,
                ),
                toml::Value::Table(t) => {
                    let req = t
                        .get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("*")
                        .to_string();
                    let optional = t.get("optional").and_then(|v| v.as_bool()).unwrap_or(false);
                    let default_features = t
                        .get("default-features")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true);
                    let features: Vec<String> = t
                        .get("features")
                        .and_then(|v| v.as_array())
                        .map(|arr| {
                            arr.iter()
                                .filter_map(|v| v.as_str().map(String::from))
                                .collect()
                        })
                        .unwrap_or_default();
                    let registry = match t.get("registry").and_then(|v| v.as_str()) {
                        None | Some("") | Some("crates-io") => {
                            Some(CRATES_IO_INDEX_URL.to_string())
                        }
                        Some("kin") => None,
                        Some(other) => Some(other.to_string()),
                    };
                    let package = t.get("package").and_then(|v| v.as_str()).map(String::from);
                    (req, optional, default_features, features, registry, package)
                }
                _ => continue,
            };

            deps.push(serde_json::json!({
                "name": dep_name,
                "req": req,
                "features": dep_features,
                "optional": optional,
                "default_features": default_features,
                "target": null,
                "kind": "normal",
                "registry": registry,
                "package": package,
            }));
        }
    }

    if !deps.is_empty() {
        metadata["deps"] = serde_json::Value::Array(deps);
    }

    metadata
}

fn backfill_cargo_metadata_from_crate(state: &CargoRegistryState, versions: &mut [PackageVersion]) {
    let mut changed = false;

    for version in versions.iter_mut() {
        let crate_path = state
            .blobs_dir
            .join(format!("{}-{}.crate", version.id.name, version.version));
        let Ok(crate_bytes) = std::fs::read(&crate_path) else {
            continue;
        };
        let extracted = extract_crate_metadata(&crate_bytes, &version.id.name, &version.version);
        let merged = merge_cargo_metadata(&version.metadata, &extracted);
        if merged != version.metadata {
            version.metadata = merged;
            changed = true;
        }
    }

    if changed {
        if let Some(first) = versions.first() {
            let _ = state.manifest_store.replace_versions(&first.id, versions);
        }
    }
}

fn merge_cargo_metadata(
    existing: &serde_json::Value,
    extracted: &serde_json::Value,
) -> serde_json::Value {
    let Some(extracted_obj) = extracted.as_object() else {
        return existing.clone();
    };

    let mut merged = existing.clone();
    if !merged.is_object() {
        merged = serde_json::json!({});
    }

    let Some(merged_obj) = merged.as_object_mut() else {
        return existing.clone();
    };

    for key in ["features", "deps"] {
        if let Some(value) = extracted_obj.get(key) {
            merged_obj.insert(key.to_string(), value.clone());
        }
    }

    merged
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn registry_state() -> (tempfile::TempDir, Arc<CargoRegistryState>) {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(".kin")).unwrap();
        let state = Arc::new(CargoRegistryState {
            manifest_store: ManifestStore::new(&root.path().join(".kin")),
            blobs_dir: root.path().join("cargo"),
            base_url: "https://kinlab.ai".to_string(),
        });
        (root, state)
    }

    fn build_test_crate(name: &str, version: &str, cargo_toml: &str) -> Vec<u8> {
        use flate2::{write::GzEncoder, Compression};

        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = tar::Builder::new(encoder);
        let manifest_path = format!("{name}-{version}/Cargo.toml");

        let mut header = tar::Header::new_gnu();
        header.set_size(cargo_toml.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, manifest_path, cargo_toml.as_bytes())
            .unwrap();

        let encoder = builder.into_inner().unwrap();
        encoder.finish().unwrap()
    }

    #[tokio::test]
    async fn sparse_index_backfills_missing_dependency_metadata_from_crate_blob() {
        let (_root, state) = registry_state();
        std::fs::create_dir_all(&state.blobs_dir).unwrap();

        let crate_bytes = build_test_crate(
            "kin-infer",
            "0.1.2",
            r#"
[package]
name = "kin-infer"
version = "0.1.2"
edition = "2021"

[dependencies]
serde = { version = "1", features = ["derive"] }
ndarray = "0.16"
kin-blobs = { version = "0.1.0", registry = "kin", features = ["schema"] }
"#,
        );
        std::fs::write(state.blobs_dir.join("kin-infer-0.1.2.crate"), &crate_bytes).unwrap();

        state
            .manifest_store
            .add_version(&PackageVersion {
                id: PackageId {
                    ecosystem: Ecosystem::Cargo,
                    scope: None,
                    name: "kin-infer".to_string(),
                },
                version: "0.1.2".to_string(),
                blob_hash: "hash".to_string(),
                blob_size: crate_bytes.len() as u64,
                checksum: "checksum".to_string(),
                metadata: serde_json::json!({}),
                published_at: Utc::now(),
                published_by: "test".to_string(),
                yanked: false,
            })
            .unwrap();

        let response = cargo_routes(state.clone())
            .oneshot(
                Request::builder()
                    .uri("/registry/cargo/ki/n-/kin-infer")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let line = String::from_utf8(body.to_vec()).unwrap();
        let index_entry: serde_json::Value = serde_json::from_str(line.trim()).unwrap();
        let deps = index_entry["deps"].as_array().unwrap();

        let serde_dep = deps.iter().find(|dep| dep["name"] == "serde").unwrap();
        assert_eq!(serde_dep["registry"], CRATES_IO_INDEX_URL);

        let ndarray_dep = deps.iter().find(|dep| dep["name"] == "ndarray").unwrap();
        assert_eq!(ndarray_dep["registry"], CRATES_IO_INDEX_URL);

        let kin_dep = deps.iter().find(|dep| dep["name"] == "kin-blobs").unwrap();
        assert!(kin_dep["registry"].is_null());

        let versions = state
            .manifest_store
            .get_versions(Ecosystem::Cargo, "kin-infer")
            .unwrap();
        let deps = versions[0].metadata["deps"].as_array().unwrap();
        assert_eq!(deps.len(), 3);
    }
}
