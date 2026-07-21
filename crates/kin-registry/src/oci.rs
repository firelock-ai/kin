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
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

const SHA256_HEX_LEN: usize = 64;

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
    let Some(blob_path) = blob_path_for_digest(&state.blobs_dir, &digest) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
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
    let Some(blob_path) = blob_path_for_digest(&state.blobs_dir, &digest) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
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
    let blob_path = blob_path_for_digest(&state.blobs_dir, &digest)
        .expect("internally generated sha256 digest must be valid");

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

/// Map a canonical SHA-256 digest to its on-disk blob filename.
///
/// The caller-controlled digest is never joined directly. Only a fixed prefix
/// plus 64 lowercase hexadecimal bytes can reach the filesystem, so path
/// separators, dot components, alternate algorithms, and encoded traversal
/// payloads are rejected before any filesystem operation.
fn blob_path_for_digest(blobs_dir: &FsPath, digest: &str) -> Option<PathBuf> {
    let encoded = digest.strip_prefix("sha256:")?;
    if encoded.len() != SHA256_HEX_LEN
        || !encoded
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }

    Some(blobs_dir.join(format!("sha256_{encoded}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn registry_state() -> (tempfile::TempDir, Arc<OciRegistryState>) {
        let root = tempfile::tempdir().unwrap();
        let blobs_dir = root.path().join("oci");
        std::fs::create_dir_all(&blobs_dir).unwrap();
        let state = Arc::new(OciRegistryState {
            blobs_dir,
            manifests: Default::default(),
            uploads: Default::default(),
        });
        (root, state)
    }

    #[test]
    fn blob_path_accepts_only_canonical_sha256_digests() {
        let root = std::path::Path::new("/registry/blobs");
        let digest = format!("sha256:{}", "a".repeat(SHA256_HEX_LEN));
        assert_eq!(
            blob_path_for_digest(root, &digest),
            Some(root.join(format!("sha256_{}", "a".repeat(SHA256_HEX_LEN))))
        );

        for invalid in [
            "sha256:../outside",
            "sha256:%2e%2e%2foutside",
            "sha256:ABCDEF",
            "sha512:abcdef",
            "sha256:",
        ] {
            assert_eq!(blob_path_for_digest(root, invalid), None, "{invalid}");
        }
        assert_eq!(
            blob_path_for_digest(root, &format!("sha256:{}", "a".repeat(63))),
            None
        );
        assert_eq!(
            blob_path_for_digest(root, &format!("sha256:{}", "a".repeat(65))),
            None
        );
    }

    #[tokio::test]
    async fn public_blob_reads_accept_valid_digests_without_authorization() {
        let (_root, state) = registry_state();
        let bytes = b"public oci blob";
        let digest = format!("sha256:{}", sha2_hex(bytes));
        let blob_path = blob_path_for_digest(&state.blobs_dir, &digest).unwrap();
        std::fs::write(blob_path, bytes).unwrap();

        let response = oci_routes(state)
            .oneshot(
                Request::get(format!("/v2/demo/blobs/{digest}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()["docker-content-digest"], digest.as_str());
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(&body[..], bytes);
    }

    #[tokio::test]
    async fn blob_routes_reject_noncanonical_digest_paths() {
        let (_root, state) = registry_state();
        let outside = state.blobs_dir.parent().unwrap().join("outside");
        std::fs::write(&outside, b"must not be served").unwrap();

        for method in ["GET", "HEAD"] {
            let noncanonical = format!("/v2/demo/blobs/sha256:{}", "A".repeat(SHA256_HEX_LEN));
            let response = oci_routes(state.clone())
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(noncanonical)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);

            let response = oci_routes(state.clone())
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri("/v2/demo/blobs/sha256:..%2Foutside")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_ne!(response.status(), StatusCode::OK);
        }
        assert_eq!(std::fs::read(outside).unwrap(), b"must not be served");
    }
}
