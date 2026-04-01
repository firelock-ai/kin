// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! OCI Distribution Specification adapter.
//!
//! Implements core OCI distribution endpoints:
//! - GET  /v2/ -- version check
//! - HEAD /v2/{name}/blobs/{digest} -- check blob existence
//! - GET  /v2/{name}/blobs/{digest} -- pull blob
//! - POST /v2/{name}/blobs/uploads/ -- initiate upload
//! - PUT  /v2/{name}/blobs/uploads/{id} -- complete upload
//! - GET  /v2/{name}/manifests/{reference} -- pull manifest
//! - PUT  /v2/{name}/manifests/{reference} -- push manifest
//! - DELETE /v2/{name}/manifests/{reference} -- delete manifest

use axum::{
    body::Bytes,
    extract::{Path, State},
    http::{header, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, head, post, put},
    Router,
};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Shared state for the OCI registry routes
pub struct OciRegistryState {
    pub blobs_dir: std::path::PathBuf,
    /// reference -> manifest bytes
    pub manifests: RwLock<HashMap<String, Vec<u8>>>,
    /// upload ID -> partial data
    pub uploads: RwLock<HashMap<String, Vec<u8>>>,
}

/// Create axum router for OCI distribution endpoints
pub fn oci_routes(state: Arc<OciRegistryState>) -> Router {
    Router::new()
        .route("/v2/", get(version_check))
        .route("/v2/{name}/blobs/{digest}", head(check_blob).get(get_blob))
        .route("/v2/{name}/blobs/uploads/", post(initiate_upload))
        .route("/v2/{name}/blobs/uploads/{id}", put(complete_upload))
        .route(
            "/v2/{name}/manifests/{reference}",
            get(get_manifest).put(put_manifest).delete(delete_manifest),
        )
        .with_state(state)
}

/// GET /v2/ -- OCI version check (returns 200 OK)
async fn version_check() -> impl IntoResponse {
    StatusCode::OK
}

/// HEAD /v2/{name}/blobs/{digest} -- check if blob exists
async fn check_blob(
    State(state): State<Arc<OciRegistryState>>,
    Path((_name, digest)): Path<(String, String)>,
) -> Response {
    let blob_path = state.blobs_dir.join(digest.replace(':', "_"));
    if blob_path.exists() {
        let size = std::fs::metadata(&blob_path).map(|m| m.len()).unwrap_or(0);
        (
            StatusCode::OK,
            [
                ("docker-content-digest", digest.as_str()),
                ("content-length", &size.to_string()),
            ],
        )
            .into_response()
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

/// GET /v2/{name}/blobs/{digest} -- pull a blob by digest
async fn get_blob(
    State(state): State<Arc<OciRegistryState>>,
    Path((_name, digest)): Path<(String, String)>,
) -> Response {
    let blob_path = state.blobs_dir.join(digest.replace(':', "_"));
    match std::fs::read(&blob_path) {
        Ok(bytes) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE.as_str(), "application/octet-stream"),
                ("docker-content-digest", &digest),
            ],
            bytes,
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

/// POST /v2/{name}/blobs/uploads/ -- initiate a blob upload
async fn initiate_upload(
    State(state): State<Arc<OciRegistryState>>,
    Path(name): Path<String>,
) -> Response {
    // Generate a unique upload ID without uuid crate
    let upload_id = {
        use std::time::SystemTime;
        let nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let hash = Sha256::digest(format!("{}-{}", name, nanos).as_bytes());
        hex::encode(&hash[..16])
    };

    state
        .uploads
        .write()
        .await
        .insert(upload_id.clone(), Vec::new());

    (
        StatusCode::ACCEPTED,
        [(
            "location",
            format!("/v2/{}/blobs/uploads/{}", name, upload_id).as_str(),
        )],
    )
        .into_response()
}

/// PUT /v2/{name}/blobs/uploads/{id} -- complete a blob upload
async fn complete_upload(
    State(state): State<Arc<OciRegistryState>>,
    Path((_name, id)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    // Merge any existing upload data with final chunk
    let mut uploads = state.uploads.write().await;
    let mut data = uploads.remove(&id).unwrap_or_default();
    data.extend_from_slice(&body);

    let digest = format!("sha256:{}", sha2_hex(&data));
    let blob_path = state.blobs_dir.join(digest.replace(':', "_"));

    if let Err(e) = std::fs::write(&blob_path, &data) {
        return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response();
    }

    (
        StatusCode::CREATED,
        [("docker-content-digest", digest.as_str())],
    )
        .into_response()
}

/// GET /v2/{name}/manifests/{reference} -- pull a manifest
async fn get_manifest(
    State(state): State<Arc<OciRegistryState>>,
    Path((_name, reference)): Path<(String, String)>,
) -> Response {
    let manifests = state.manifests.read().await;
    match manifests.get(&reference) {
        Some(bytes) => (
            StatusCode::OK,
            [(
                header::CONTENT_TYPE.as_str(),
                "application/vnd.oci.image.manifest.v1+json",
            )],
            bytes.clone(),
        )
            .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// PUT /v2/{name}/manifests/{reference} -- push a manifest
async fn put_manifest(
    State(state): State<Arc<OciRegistryState>>,
    Path((_name, reference)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    let digest = format!("sha256:{}", sha2_hex(&body));
    let mut manifests = state.manifests.write().await;
    manifests.insert(reference, body.to_vec());
    manifests.insert(digest.clone(), body.to_vec());
    (
        StatusCode::CREATED,
        [("docker-content-digest", digest.as_str())],
    )
        .into_response()
}

/// DELETE /v2/{name}/manifests/{reference} -- delete a manifest
async fn delete_manifest(
    State(state): State<Arc<OciRegistryState>>,
    Path((_name, reference)): Path<(String, String)>,
) -> Response {
    let mut manifests = state.manifests.write().await;
    manifests.remove(&reference);
    StatusCode::ACCEPTED.into_response()
}

/// Compute SHA-256 hex digest of data
fn sha2_hex(data: &[u8]) -> String {
    let hash = Sha256::digest(data);
    hex::encode(hash)
}
