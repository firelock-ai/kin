// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! OCI Distribution Specification adapter.
//!
//! Pulls are intentionally public. Every mutating route is protected by the
//! registry write token and fails closed when no token is configured.

use axum::{
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{get, head, post, put},
    Router,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path as FsPath, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::sync::RwLock;

const SHA256_HEX_LEN: usize = 64;
const UPLOAD_ID_HEX_LEN: usize = 32;
const MAX_REPOSITORY_NAME_LEN: usize = 255;
const MAX_MANIFEST_REFERENCE_LEN: usize = 128;
const MAX_OCI_BLOB_SIZE: usize = 512 * 1024 * 1024;
const MAX_OCI_MANIFEST_SIZE: usize = 4 * 1024 * 1024;
const MAX_ACTIVE_UPLOADS: usize = 1024;
const UPLOAD_TTL: Duration = Duration::from_secs(15 * 60);

static UPLOAD_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct PendingUpload {
    repository: String,
    created_at: Instant,
    data: Vec<u8>,
}

/// Shared state for the OCI registry routes.
pub struct OciRegistryState {
    blobs_dir: PathBuf,
    /// (repository, reference) -> manifest bytes
    manifests: RwLock<HashMap<(String, String), Vec<u8>>>,
    /// upload ID -> bounded, expiring partial data
    uploads: RwLock<HashMap<String, PendingUpload>>,
    /// Shared secret for OCI writes. `None` disables every mutation.
    write_token: Option<String>,
}

impl OciRegistryState {
    pub fn new(blobs_dir: PathBuf, write_token: Option<String>) -> Self {
        Self {
            blobs_dir,
            manifests: RwLock::new(HashMap::new()),
            uploads: RwLock::new(HashMap::new()),
            write_token: write_token
                .map(|token| token.trim().to_string())
                .filter(|token| !token.is_empty()),
        }
    }
}

/// Create axum router for OCI distribution endpoints.
pub fn oci_routes(state: Arc<OciRegistryState>) -> Router {
    let public = Router::new()
        .route("/v2/", get(version_check))
        .route("/v2/{name}/blobs/{digest}", head(check_blob).get(get_blob))
        .route("/v2/{name}/manifests/{reference}", get(get_manifest));

    // The auth middleware executes before body extraction, so an unauthorized
    // caller cannot make the handlers buffer an upload. Axum's body limits also
    // cap chunked requests for which Content-Length cannot be trusted.
    let writes = Router::new()
        .route("/v2/{name}/blobs/uploads/", post(initiate_upload))
        .route(
            "/v2/{name}/blobs/uploads/{id}",
            put(complete_upload).layer(DefaultBodyLimit::max(MAX_OCI_BLOB_SIZE)),
        )
        .route(
            "/v2/{name}/manifests/{reference}",
            put(put_manifest)
                .delete(delete_manifest)
                .layer(DefaultBodyLimit::max(MAX_OCI_MANIFEST_SIZE)),
        )
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            authorize_oci_write,
        ));

    Router::new().merge(public).merge(writes).with_state(state)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (left, right) in a.iter().zip(b.iter()) {
        diff |= left ^ right;
    }
    diff == 0
}

async fn authorize_oci_write(
    State(state): State<Arc<OciRegistryState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let Some(expected) = state.write_token.as_deref() else {
        return oci_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "DENIED",
            "OCI registry writes are disabled: no registry token is configured",
            None,
        );
    };

    let provided = bearer_token(request.headers());
    if !provided.is_some_and(|token| constant_time_eq(token.as_bytes(), expected.as_bytes())) {
        let mut response = oci_error(
            StatusCode::UNAUTHORIZED,
            "UNAUTHORIZED",
            "authentication required for OCI registry writes",
            None,
        );
        response.headers_mut().insert(
            header::WWW_AUTHENTICATE,
            HeaderValue::from_static("Bearer realm=\"kin OCI registry\""),
        );
        return response;
    }

    if let Some(limit) = oci_write_body_limit(request.method(), request.uri().path()) {
        let declared = request
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        if declared.is_some_and(|length| length > limit as u64) {
            return oci_error(
                StatusCode::PAYLOAD_TOO_LARGE,
                "SIZE_INVALID",
                "request body exceeds the configured OCI limit",
                Some(request.uri().path()),
            );
        }
    }

    next.run(request).await
}

fn oci_write_body_limit(method: &Method, path: &str) -> Option<usize> {
    if method == Method::PUT && path.contains("/blobs/uploads/") {
        Some(MAX_OCI_BLOB_SIZE)
    } else if method == Method::PUT && path.contains("/manifests/") {
        Some(MAX_OCI_MANIFEST_SIZE)
    } else {
        None
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|token| !token.is_empty())
}

fn oci_error(status: StatusCode, code: &str, message: &str, location: Option<&str>) -> Response {
    let mut response = (
        status,
        Json(serde_json::json!({
            "errors": [{
                "code": code,
                "message": message,
            }]
        })),
    )
        .into_response();
    if let Some(location) = location {
        insert_header(response.headers_mut(), header::LOCATION, location);
    }
    response
}

fn insert_header(headers: &mut HeaderMap, name: header::HeaderName, value: &str) {
    if let Ok(value) = HeaderValue::from_str(value) {
        headers.insert(name, value);
    }
}

/// GET /v2/ -- OCI version check (returns 200 OK).
async fn version_check() -> impl IntoResponse {
    StatusCode::OK
}

/// HEAD /v2/{name}/blobs/{digest} -- check if blob exists.
async fn check_blob(
    State(state): State<Arc<OciRegistryState>>,
    Path((name, digest)): Path<(String, String)>,
) -> Response {
    if !valid_repository_name(&name) {
        return oci_error(
            StatusCode::BAD_REQUEST,
            "NAME_INVALID",
            "invalid OCI repository name",
            None,
        );
    }
    let Some(blob_path) = blob_path_for_digest(&state.blobs_dir, &digest) else {
        return digest_invalid("invalid non-canonical blob digest", None);
    };
    if blob_path.is_file() {
        let size = std::fs::metadata(&blob_path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        let mut response = StatusCode::OK.into_response();
        insert_header(
            response.headers_mut(),
            header::HeaderName::from_static("docker-content-digest"),
            &digest,
        );
        insert_header(
            response.headers_mut(),
            header::CONTENT_LENGTH,
            &size.to_string(),
        );
        response
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

/// GET /v2/{name}/blobs/{digest} -- pull a blob by digest.
async fn get_blob(
    State(state): State<Arc<OciRegistryState>>,
    Path((name, digest)): Path<(String, String)>,
) -> Response {
    if !valid_repository_name(&name) {
        return oci_error(
            StatusCode::BAD_REQUEST,
            "NAME_INVALID",
            "invalid OCI repository name",
            None,
        );
    }
    let Some(blob_path) = blob_path_for_digest(&state.blobs_dir, &digest) else {
        return digest_invalid("invalid non-canonical blob digest", None);
    };
    match std::fs::read(&blob_path) {
        Ok(bytes) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE.as_str(), "application/octet-stream"),
                ("docker-content-digest", digest.as_str()),
            ],
            bytes,
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

/// POST /v2/{name}/blobs/uploads/ -- initiate a blob upload.
async fn initiate_upload(
    State(state): State<Arc<OciRegistryState>>,
    Path(name): Path<String>,
) -> Response {
    if !valid_repository_name(&name) {
        return oci_error(
            StatusCode::BAD_REQUEST,
            "NAME_INVALID",
            "invalid OCI repository name",
            None,
        );
    }

    let upload_id = new_upload_id(&name);
    let mut uploads = state.uploads.write().await;
    prune_expired_uploads(&mut uploads);
    if uploads.len() >= MAX_ACTIVE_UPLOADS {
        return oci_error(
            StatusCode::TOO_MANY_REQUESTS,
            "TOOMANYREQUESTS",
            "too many active OCI uploads",
            None,
        );
    }
    uploads.insert(
        upload_id.clone(),
        PendingUpload {
            repository: name.clone(),
            created_at: Instant::now(),
            data: Vec::new(),
        },
    );
    drop(uploads);

    let location = upload_location(&name, &upload_id);
    let mut response = StatusCode::ACCEPTED.into_response();
    insert_header(response.headers_mut(), header::LOCATION, &location);
    response
}

#[derive(Debug, Default, Deserialize)]
struct CompleteUploadQuery {
    digest: Option<String>,
}

/// PUT /v2/{name}/blobs/uploads/{id}?digest=sha256:... -- complete upload.
async fn complete_upload(
    State(state): State<Arc<OciRegistryState>>,
    Path((name, id)): Path<(String, String)>,
    Query(query): Query<CompleteUploadQuery>,
    body: Bytes,
) -> Response {
    let location = upload_location(&name, &id);
    if !valid_repository_name(&name) || !valid_upload_id(&id) {
        return oci_error(
            StatusCode::BAD_REQUEST,
            "BLOB_UPLOAD_INVALID",
            "invalid OCI upload coordinate",
            Some(&location),
        );
    }
    let Some(expected_digest) = query.digest.as_deref() else {
        return digest_invalid(
            "completion requires a digest query parameter",
            Some(&location),
        );
    };
    if sha256_hex(expected_digest).is_none() {
        return digest_invalid(
            "completion digest must be canonical lowercase sha256",
            Some(&location),
        );
    }

    let mut uploads = state.uploads.write().await;
    let Some(pending) = uploads.get(&id) else {
        return oci_error(
            StatusCode::NOT_FOUND,
            "BLOB_UPLOAD_UNKNOWN",
            "blob upload is unknown or expired",
            Some(&location),
        );
    };
    if pending.repository != name || pending.created_at.elapsed() >= UPLOAD_TTL {
        uploads.remove(&id);
        return oci_error(
            StatusCode::NOT_FOUND,
            "BLOB_UPLOAD_UNKNOWN",
            "blob upload is unknown or expired",
            Some(&location),
        );
    }
    let Some(completed_size) = pending.data.len().checked_add(body.len()) else {
        return oci_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "BLOB_UPLOAD_INVALID",
            "blob upload exceeds the configured size limit",
            Some(&location),
        );
    };
    if completed_size > MAX_OCI_BLOB_SIZE {
        return oci_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "BLOB_UPLOAD_INVALID",
            "blob upload exceeds the configured size limit",
            Some(&location),
        );
    }

    let mut hasher = Sha256::new();
    hasher.update(&pending.data);
    hasher.update(&body);
    let computed_digest = format!("sha256:{}", hex::encode(hasher.finalize()));
    if expected_digest != computed_digest {
        return digest_invalid(
            "provided digest does not match uploaded content",
            Some(&location),
        );
    }

    let mut pending = uploads
        .remove(&id)
        .expect("upload remained present while write lock was held");
    drop(uploads);
    let partial_len = pending.data.len();
    pending.data.extend_from_slice(&body);

    let blob_path = blob_path_for_digest(&state.blobs_dir, &computed_digest)
        .expect("computed sha256 digest is canonical");
    // Stage beside the digest path, fsync the complete bytes, and atomically
    // rename them into place. Public GET/HEAD requests therefore see either no
    // blob (or the prior complete blob) or the complete replacement, never a
    // partially written digest object.
    let write_result = crate::atomic_file::write(&blob_path, &pending.data);
    if let Err(error) = write_result {
        // Preserve the pre-completion upload state so the same final request
        // can be retried after the storage failure without duplicating bytes.
        pending.data.truncate(partial_len);
        state.uploads.write().await.insert(id, pending);
        return oci_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "UNKNOWN",
            &format!("failed to persist OCI blob: {error}"),
            Some(&location),
        );
    }

    let blob_location = format!("/v2/{name}/blobs/{computed_digest}");
    let mut response = StatusCode::CREATED.into_response();
    insert_header(
        response.headers_mut(),
        header::HeaderName::from_static("docker-content-digest"),
        &computed_digest,
    );
    insert_header(response.headers_mut(), header::LOCATION, &blob_location);
    response
}

/// GET /v2/{name}/manifests/{reference} -- pull a manifest.
async fn get_manifest(
    State(state): State<Arc<OciRegistryState>>,
    Path((name, reference)): Path<(String, String)>,
) -> Response {
    if !valid_repository_name(&name) || !valid_manifest_reference(&reference) {
        return oci_error(
            StatusCode::BAD_REQUEST,
            "MANIFEST_INVALID",
            "invalid OCI manifest coordinate",
            None,
        );
    }
    let manifests = state.manifests.read().await;
    match manifests.get(&(name, reference)) {
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

/// PUT /v2/{name}/manifests/{reference} -- push a manifest.
async fn put_manifest(
    State(state): State<Arc<OciRegistryState>>,
    Path((name, reference)): Path<(String, String)>,
    body: Bytes,
) -> Response {
    if !valid_repository_name(&name) || !valid_manifest_reference(&reference) {
        return oci_error(
            StatusCode::BAD_REQUEST,
            "MANIFEST_INVALID",
            "invalid OCI manifest coordinate",
            None,
        );
    }
    if body.is_empty() || body.len() > MAX_OCI_MANIFEST_SIZE {
        return oci_error(
            if body.len() > MAX_OCI_MANIFEST_SIZE {
                StatusCode::PAYLOAD_TOO_LARGE
            } else {
                StatusCode::BAD_REQUEST
            },
            "MANIFEST_INVALID",
            "manifest body is empty or exceeds the configured size limit",
            None,
        );
    }

    let digest = format!("sha256:{}", sha2_hex(&body));
    if reference.starts_with("sha256:") && reference != digest {
        return digest_invalid(
            "manifest digest reference does not match uploaded content",
            None,
        );
    }
    let mut manifests = state.manifests.write().await;
    manifests.insert((name.clone(), reference), body.to_vec());
    manifests.insert((name.clone(), digest.clone()), body.to_vec());
    drop(manifests);

    let mut response = StatusCode::CREATED.into_response();
    insert_header(
        response.headers_mut(),
        header::HeaderName::from_static("docker-content-digest"),
        &digest,
    );
    insert_header(
        response.headers_mut(),
        header::LOCATION,
        &format!("/v2/{name}/manifests/{digest}"),
    );
    response
}

/// DELETE /v2/{name}/manifests/{reference} -- delete a manifest.
async fn delete_manifest(
    State(state): State<Arc<OciRegistryState>>,
    Path((name, reference)): Path<(String, String)>,
) -> Response {
    if !valid_repository_name(&name) || !valid_manifest_reference(&reference) {
        return oci_error(
            StatusCode::BAD_REQUEST,
            "MANIFEST_INVALID",
            "invalid OCI manifest coordinate",
            None,
        );
    }
    state.manifests.write().await.remove(&(name, reference));
    StatusCode::ACCEPTED.into_response()
}

fn new_upload_id(name: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let sequence = UPLOAD_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let hash = Sha256::digest(format!("{name}-{nanos}-{sequence}").as_bytes());
    hex::encode(&hash[..UPLOAD_ID_HEX_LEN / 2])
}

fn upload_location(name: &str, id: &str) -> String {
    format!("/v2/{name}/blobs/uploads/{id}")
}

fn valid_upload_id(id: &str) -> bool {
    id.len() == UPLOAD_ID_HEX_LEN && id.bytes().all(is_lower_hex)
}

fn prune_expired_uploads(uploads: &mut HashMap<String, PendingUpload>) {
    uploads.retain(|_, pending| pending.created_at.elapsed() < UPLOAD_TTL);
}

fn valid_repository_name(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_REPOSITORY_NAME_LEN {
        return false;
    }
    let bytes = name.as_bytes();
    bytes
        .first()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn valid_manifest_reference(reference: &str) -> bool {
    if reference.starts_with("sha256:") {
        return sha256_hex(reference).is_some();
    }
    if reference.is_empty() || reference.len() > MAX_MANIFEST_REFERENCE_LEN {
        return false;
    }
    let bytes = reference.as_bytes();
    bytes
        .first()
        .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

/// Compute SHA-256 hex digest of data.
fn sha2_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn is_lower_hex(byte: u8) -> bool {
    matches!(byte, b'0'..=b'9' | b'a'..=b'f')
}

fn sha256_hex(digest: &str) -> Option<&str> {
    let encoded = digest.strip_prefix("sha256:")?;
    (encoded.len() == SHA256_HEX_LEN && encoded.as_bytes().iter().all(|byte| is_lower_hex(*byte)))
        .then_some(encoded)
}

/// Map a canonical SHA-256 digest to its on-disk blob filename.
///
/// The caller-controlled digest is never joined directly. Only a fixed prefix
/// plus 64 lowercase hexadecimal bytes can reach the filesystem, so path
/// separators, dot components, alternate algorithms, and encoded traversal
/// payloads are rejected before any filesystem operation.
fn blob_path_for_digest(blobs_dir: &FsPath, digest: &str) -> Option<PathBuf> {
    let encoded = sha256_hex(digest)?;
    let path = blobs_dir.join(format!("sha256_{encoded}"));
    (path.parent() == Some(blobs_dir)).then_some(path)
}

fn digest_invalid(message: &str, location: Option<&str>) -> Response {
    oci_error(StatusCode::BAD_REQUEST, "DIGEST_INVALID", message, location)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use tower::ServiceExt;

    fn registry_state_with_token(
        write_token: Option<&str>,
    ) -> (tempfile::TempDir, Arc<OciRegistryState>) {
        let root = tempfile::tempdir().unwrap();
        let blobs_dir = root.path().join("oci");
        std::fs::create_dir_all(&blobs_dir).unwrap();
        (
            root,
            Arc::new(OciRegistryState::new(
                blobs_dir,
                write_token.map(String::from),
            )),
        )
    }

    fn registry_state() -> (tempfile::TempDir, Arc<OciRegistryState>) {
        registry_state_with_token(None)
    }

    fn authenticated_request(method: &str, uri: &str, body: Body) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header(header::AUTHORIZATION, "Bearer registry-secret")
            .body(body)
            .unwrap()
    }

    async fn initiate(state: Arc<OciRegistryState>) -> String {
        let response = oci_routes(state)
            .oneshot(authenticated_request(
                "POST",
                "/v2/demo/blobs/uploads/",
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        response.headers()[header::LOCATION]
            .to_str()
            .unwrap()
            .to_string()
    }

    async fn error_code(response: Response) -> String {
        let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        json["errors"][0]["code"].as_str().unwrap().to_string()
    }

    #[test]
    fn blob_path_accepts_only_canonical_sha256_digests() {
        let root = FsPath::new("/registry/blobs");
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
        let (_root, state) = registry_state_with_token(Some("registry-secret"));
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
        let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
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

    #[tokio::test]
    async fn writes_fail_closed_but_reads_remain_public() {
        let (_root, disabled_state) = registry_state();
        let disabled = oci_routes(disabled_state)
            .oneshot(
                Request::post("/v2/demo/blobs/uploads/")
                    .header(header::AUTHORIZATION, "Bearer anything")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(disabled.status(), StatusCode::SERVICE_UNAVAILABLE);

        let (_root, state) = registry_state_with_token(Some("registry-secret"));
        for token in [None, Some("wrong")] {
            let mut builder = Request::post("/v2/demo/blobs/uploads/");
            if let Some(token) = token {
                builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
            }
            let response = oci_routes(state.clone())
                .oneshot(builder.body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert!(response.headers().contains_key(header::WWW_AUTHENTICATE));
        }

        let accepted = oci_routes(state.clone())
            .oneshot(authenticated_request(
                "POST",
                "/v2/demo/blobs/uploads/",
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::ACCEPTED);

        let public = oci_routes(state)
            .oneshot(Request::get("/v2/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(public.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn shared_manifest_url_keeps_get_public_but_rejects_unauthenticated_mutations() {
        let original = br#"{"schemaVersion":2,"marker":"original"}"#.to_vec();
        let coordinate = ("demo".to_string(), "latest".to_string());

        let (_root, state) = registry_state_with_token(Some("registry-secret"));
        state
            .manifests
            .write()
            .await
            .insert(coordinate.clone(), original.clone());

        let public_get = oci_routes(state.clone())
            .oneshot(
                Request::get("/v2/demo/manifests/latest")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(public_get.status(), StatusCode::OK);
        assert_eq!(
            to_bytes(public_get.into_body(), MAX_OCI_MANIFEST_SIZE)
                .await
                .unwrap()
                .as_ref(),
            original.as_slice()
        );

        for request in [
            Request::put("/v2/demo/manifests/latest")
                .body(Body::from(
                    br#"{"schemaVersion":2,"marker":"forged"}"#.as_slice(),
                ))
                .unwrap(),
            Request::delete("/v2/demo/manifests/latest")
                .body(Body::empty())
                .unwrap(),
        ] {
            let rejected = oci_routes(state.clone()).oneshot(request).await.unwrap();
            assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
            assert_eq!(error_code(rejected).await, "UNAUTHORIZED");
            assert_eq!(
                state.manifests.read().await.get(&coordinate),
                Some(&original)
            );
        }

        let (_root, disabled) = registry_state_with_token(None);
        disabled
            .manifests
            .write()
            .await
            .insert(coordinate.clone(), original.clone());
        for request in [
            Request::put("/v2/demo/manifests/latest")
                .header(header::AUTHORIZATION, "Bearer registry-secret")
                .body(Body::from(
                    br#"{"schemaVersion":2,"marker":"forged"}"#.as_slice(),
                ))
                .unwrap(),
            Request::delete("/v2/demo/manifests/latest")
                .header(header::AUTHORIZATION, "Bearer registry-secret")
                .body(Body::empty())
                .unwrap(),
        ] {
            let rejected = oci_routes(disabled.clone()).oneshot(request).await.unwrap();
            assert_eq!(rejected.status(), StatusCode::SERVICE_UNAVAILABLE);
            assert_eq!(error_code(rejected).await, "DENIED");
            assert_eq!(
                disabled.manifests.read().await.get(&coordinate),
                Some(&original)
            );
        }
    }

    #[tokio::test]
    async fn completion_requires_matching_canonical_digest_and_preserves_upload_on_error() {
        let (_root, state) = registry_state_with_token(Some("registry-secret"));
        let location = initiate(state.clone()).await;
        let body = b"verified OCI layer";
        let digest = format!("sha256:{}", sha2_hex(body));

        for uri in [
            location.clone(),
            format!("{location}?digest=sha256:{}", "0".repeat(SHA256_HEX_LEN)),
            format!("{location}?digest={}", digest.to_ascii_uppercase()),
        ] {
            let response = oci_routes(state.clone())
                .oneshot(authenticated_request(
                    "PUT",
                    &uri,
                    Body::from(body.as_slice()),
                ))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(response.headers()[header::LOCATION], location.as_str());
            assert_eq!(error_code(response).await, "DIGEST_INVALID");
            assert_eq!(state.uploads.read().await.len(), 1);
        }

        let success = oci_routes(state.clone())
            .oneshot(authenticated_request(
                "PUT",
                &format!("{location}?digest={digest}"),
                Body::from(body.as_slice()),
            ))
            .await
            .unwrap();
        assert_eq!(success.status(), StatusCode::CREATED);
        assert_eq!(success.headers()["docker-content-digest"], digest.as_str());
        assert!(state.uploads.read().await.is_empty());
        let blob_path = blob_path_for_digest(&state.blobs_dir, &digest).unwrap();
        assert_eq!(std::fs::read(blob_path).unwrap(), body);
    }

    #[tokio::test]
    async fn failed_blob_commit_preserves_upload_and_leaves_no_partial_file() {
        let (_root, state) = registry_state_with_token(Some("registry-secret"));
        let location = initiate(state.clone()).await;
        let body = b"complete bytes that must publish atomically";
        let digest = format!("sha256:{}", sha2_hex(body));
        let blob_path = blob_path_for_digest(&state.blobs_dir, &digest).unwrap();

        // A directory at the final digest coordinate forces the atomic rename
        // to fail after the temporary file has been fully written and synced.
        std::fs::create_dir(&blob_path).unwrap();
        let failed = oci_routes(state.clone())
            .oneshot(authenticated_request(
                "PUT",
                &format!("{location}?digest={digest}"),
                Body::from(body.as_slice()),
            ))
            .await
            .unwrap();
        assert_eq!(failed.status(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(state.uploads.read().await.len(), 1);
        assert!(blob_path.is_dir());
        assert_eq!(std::fs::read_dir(&state.blobs_dir).unwrap().count(), 1);

        // The retained upload can be retried after the storage fault clears.
        std::fs::remove_dir(&blob_path).unwrap();
        let retried = oci_routes(state.clone())
            .oneshot(authenticated_request(
                "PUT",
                &format!("{location}?digest={digest}"),
                Body::from(body.as_slice()),
            ))
            .await
            .unwrap();
        assert_eq!(retried.status(), StatusCode::CREATED);
        assert!(state.uploads.read().await.is_empty());
        assert_eq!(std::fs::read(&blob_path).unwrap(), body);
        assert_eq!(std::fs::read_dir(&state.blobs_dir).unwrap().count(), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_blob_reads_observe_only_absent_or_complete_bytes() {
        let (_root, state) = registry_state_with_token(Some("registry-secret"));
        let location = initiate(state.clone()).await;
        let body = vec![b'x'; 8 * 1024 * 1024];
        let digest = format!("sha256:{}", sha2_hex(&body));
        let start = Arc::new(tokio::sync::Barrier::new(3));
        let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));

        let writer = {
            let state = state.clone();
            let start = start.clone();
            let body = body.clone();
            let digest = digest.clone();
            let finished = finished.clone();
            tokio::spawn(async move {
                start.wait().await;
                let response = oci_routes(state)
                    .oneshot(authenticated_request(
                        "PUT",
                        &format!("{location}?digest={digest}"),
                        Body::from(body),
                    ))
                    .await
                    .unwrap();
                finished.store(true, Ordering::Release);
                response.status()
            })
        };
        let reader = {
            let state = state.clone();
            let start = start.clone();
            let body = body.clone();
            let digest = digest.clone();
            let finished = finished.clone();
            tokio::spawn(async move {
                start.wait().await;
                let mut reads = 0usize;
                loop {
                    let response = oci_routes(state.clone())
                        .oneshot(
                            Request::get(format!("/v2/demo/blobs/{digest}"))
                                .body(Body::empty())
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    match response.status() {
                        StatusCode::NOT_FOUND => {}
                        StatusCode::OK => {
                            let observed = to_bytes(response.into_body(), MAX_OCI_BLOB_SIZE)
                                .await
                                .unwrap();
                            assert_eq!(observed.as_ref(), body.as_slice());
                        }
                        status => panic!("unexpected concurrent read status {status}"),
                    }
                    reads += 1;
                    if finished.load(Ordering::Acquire) && reads >= 4 {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
        };
        start.wait().await;

        assert_eq!(writer.await.unwrap(), StatusCode::CREATED);
        reader.await.unwrap();
        let blob_path = blob_path_for_digest(&state.blobs_dir, &digest).unwrap();
        assert_eq!(std::fs::read(blob_path).unwrap(), body);
        assert_eq!(std::fs::read_dir(&state.blobs_dir).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn manifest_digest_reference_must_equal_the_uploaded_body_digest() {
        let (_root, state) = registry_state_with_token(Some("registry-secret"));
        let body = br#"{"schemaVersion":2}"#;
        let computed = format!("sha256:{}", sha2_hex(body));
        let mismatched = format!("sha256:{}", "0".repeat(SHA256_HEX_LEN));

        let rejected = oci_routes(state.clone())
            .oneshot(authenticated_request(
                "PUT",
                &format!("/v2/demo/manifests/{mismatched}"),
                Body::from(body.as_slice()),
            ))
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
        assert_eq!(error_code(rejected).await, "DIGEST_INVALID");
        assert!(state.manifests.read().await.is_empty());

        let accepted = oci_routes(state.clone())
            .oneshot(authenticated_request(
                "PUT",
                &format!("/v2/demo/manifests/{computed}"),
                Body::from(body.as_slice()),
            ))
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::CREATED);
        assert_eq!(state.manifests.read().await.len(), 1);
        assert_eq!(
            state
                .manifests
                .read()
                .await
                .get(&("demo".to_string(), computed))
                .map(Vec::as_slice),
            Some(body.as_slice())
        );
    }

    #[tokio::test]
    async fn expired_upload_is_removed_and_cannot_be_completed() {
        let (_root, state) = registry_state_with_token(Some("registry-secret"));
        let id = "a".repeat(UPLOAD_ID_HEX_LEN);
        state.uploads.write().await.insert(
            id.clone(),
            PendingUpload {
                repository: "demo".to_string(),
                created_at: Instant::now() - UPLOAD_TTL - Duration::from_secs(1),
                data: Vec::new(),
            },
        );
        let body = b"expired";
        let digest = format!("sha256:{}", sha2_hex(body));
        let location = upload_location("demo", &id);
        let response = oci_routes(state.clone())
            .oneshot(authenticated_request(
                "PUT",
                &format!("{location}?digest={digest}"),
                Body::from(body.as_slice()),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(error_code(response).await, "BLOB_UPLOAD_UNKNOWN");
        assert!(state.uploads.read().await.is_empty());
    }

    #[tokio::test]
    async fn manifest_body_is_bounded_before_handler_buffering() {
        let (_root, state) = registry_state_with_token(Some("registry-secret"));
        let response = oci_routes(state)
            .oneshot(authenticated_request(
                "PUT",
                "/v2/demo/manifests/latest",
                Body::from(vec![b'x'; MAX_OCI_MANIFEST_SIZE + 1]),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn blob_body_is_bounded_before_handler_buffering() {
        let (_root, state) = registry_state_with_token(Some("registry-secret"));
        let location = initiate(state.clone()).await;
        let digest = format!("sha256:{}", sha2_hex(b""));
        let response = oci_routes(state)
            .oneshot(
                Request::put(format!("{location}?digest={digest}"))
                    .header(header::AUTHORIZATION, "Bearer registry-secret")
                    .header(header::CONTENT_LENGTH, MAX_OCI_BLOB_SIZE + 1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }
}
