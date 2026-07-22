// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! OCI Distribution Specification adapter.
//!
//! Pulls are intentionally public. Every mutating route is protected by the
//! registry write token and fails closed when no token is configured.

use axum::{
    body::{to_bytes, Body, Bytes},
    extract::{Path, State},
    http::{header, HeaderMap, HeaderValue, Method, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{any, get},
    Router,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::path::{Path as FsPath, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime};
use tokio::io::AsyncReadExt;
use tokio::sync::{RwLock, RwLockWriteGuard};

const SHA256_HEX_LEN: usize = 64;
const UPLOAD_ID_HEX_LEN: usize = 32;
const MAX_REPOSITORY_NAME_LEN: usize = 255;
const MAX_MANIFEST_REFERENCE_LEN: usize = 128;
const MAX_OCI_BLOB_SIZE: usize = 512 * 1024 * 1024;
const MAX_OCI_MANIFEST_SIZE: usize = 4 * 1024 * 1024;
const MAX_ACTIVE_UPLOADS: usize = 1024;
const UPLOAD_TTL: Duration = Duration::from_secs(15 * 60);
const OCI_METADATA_VERSION: u32 = 1;
const BLOB_STREAM_CHUNK_SIZE: usize = 64 * 1024;
const DEFAULT_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";

static UPLOAD_SEQUENCE: AtomicU64 = AtomicU64::new(0);

struct PendingUpload {
    repository: String,
    created_at: Instant,
    data: Vec<u8>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct ManifestDescriptor {
    digest: String,
    media_type: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct RepositoryMetadata {
    blobs: BTreeSet<String>,
    manifests: HashMap<String, ManifestDescriptor>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct OciMetadata {
    version: u32,
    repositories: HashMap<String, RepositoryMetadata>,
}

impl Default for OciMetadata {
    fn default() -> Self {
        Self {
            version: OCI_METADATA_VERSION,
            repositories: HashMap::new(),
        }
    }
}

/// Shared state for the OCI registry routes.
pub struct OciRegistryState {
    blobs_dir: PathBuf,
    metadata_path: PathBuf,
    metadata_lock_path: PathBuf,
    metadata: RwLock<OciMetadata>,
    /// upload ID -> bounded, expiring partial data
    uploads: RwLock<HashMap<String, PendingUpload>>,
    /// OCI-specific secret for writes. `None` disables every mutation.
    write_token: Option<String>,
}

impl OciRegistryState {
    pub fn new(blobs_dir: PathBuf, write_token: Option<String>) -> Self {
        let metadata_path = blobs_dir.join("metadata.json");
        let metadata_lock_path = blobs_dir.join(".metadata.lock");
        // This cache is only an in-process observation surface. Every request
        // reloads durable authority under a storage-scoped advisory lock, so a
        // corrupt file or another daemon's publication can never be hidden by
        // startup state.
        let metadata = read_metadata_file(&metadata_path).unwrap_or_default();
        Self {
            blobs_dir,
            metadata_path,
            metadata_lock_path,
            metadata: RwLock::new(metadata),
            uploads: RwLock::new(HashMap::new()),
            write_token: write_token
                .map(|token| token.trim().to_string())
                .filter(|token| !token.is_empty()),
        }
    }
}

/// Create axum router for OCI distribution endpoints.
pub fn oci_routes(state: Arc<OciRegistryState>) -> Router {
    Router::new()
        .route("/v2/", get(version_check))
        // A final wildcard is required because OCI repository names commonly
        // contain namespace slashes (for example `firelock-ai/kin`). The
        // dispatcher parses fixed protocol markers from the right and validates
        // every repository segment before any storage access.
        .route("/v2/{*path}", any(dispatch))
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            authorize_oci_write,
        ))
        .with_state(state)
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
    if matches!(*request.method(), Method::GET | Method::HEAD) {
        return next.run(request).await;
    }
    if !matches!(
        *request.method(),
        Method::POST | Method::PUT | Method::DELETE
    ) {
        return next.run(request).await;
    }
    let Some(expected) = state.write_token.as_deref() else {
        return oci_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "DENIED",
            "OCI registry writes are disabled: no OCI write token is configured",
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

async fn dispatch(
    State(state): State<Arc<OciRegistryState>>,
    Path(path): Path<String>,
    request: Request<Body>,
) -> Response {
    let method = request.method().clone();

    if method == Method::POST {
        if let Some(repository) = path.strip_suffix("/blobs/uploads/") {
            return initiate_upload_inner(&state, repository).await;
        }
    }

    if let Some((repository, upload_id)) = path.rsplit_once("/blobs/uploads/") {
        if method == Method::PUT {
            let digest = request
                .uri()
                .query()
                .and_then(|query| query_parameter(query, "digest"));
            let body = match read_bounded_body(request.into_body(), MAX_OCI_BLOB_SIZE).await {
                Ok(body) => body,
                Err(response) => return response,
            };
            return complete_upload_inner(&state, repository, upload_id, digest.as_deref(), body)
                .await;
        }
        return StatusCode::METHOD_NOT_ALLOWED.into_response();
    }

    if let Some((repository, digest)) = path.rsplit_once("/blobs/") {
        return match method {
            Method::GET => get_blob_inner(&state, repository, digest, false).await,
            Method::HEAD => get_blob_inner(&state, repository, digest, true).await,
            _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
        };
    }

    if let Some((repository, reference)) = path.rsplit_once("/manifests/") {
        return match method {
            Method::GET => get_manifest_inner(&state, repository, reference, false).await,
            Method::HEAD => get_manifest_inner(&state, repository, reference, true).await,
            Method::PUT => {
                let media_type = request
                    .headers()
                    .get(header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or(DEFAULT_MANIFEST_MEDIA_TYPE)
                    .to_string();
                let body = match read_bounded_body(request.into_body(), MAX_OCI_MANIFEST_SIZE).await
                {
                    Ok(body) => body,
                    Err(response) => return response,
                };
                put_manifest_inner(&state, repository, reference, &media_type, body).await
            }
            Method::DELETE => delete_manifest_inner(&state, repository, reference).await,
            _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
        };
    }

    StatusCode::NOT_FOUND.into_response()
}

async fn read_bounded_body(body: Body, limit: usize) -> Result<Bytes, Response> {
    to_bytes(body, limit).await.map_err(|_| {
        oci_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "SIZE_INVALID",
            "request body exceeds the configured OCI limit",
            None,
        )
    })
}

fn query_parameter(query: &str, wanted: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        (key == wanted).then(|| {
            percent_encoding::percent_decode_str(value)
                .decode_utf8()
                .ok()
                .map(|value| value.into_owned())
        })?
    })
}

fn metadata_authority_error(error: &str) -> Response {
    oci_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "UNKNOWN",
        &format!("OCI metadata authority is unavailable: {error}"),
        None,
    )
}

fn read_metadata_file(path: &FsPath) -> Result<OciMetadata, String> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let metadata = serde_json::from_slice::<OciMetadata>(&bytes)
                .map_err(|error| format!("cannot decode OCI metadata: {error}"))?;
            if metadata.version != OCI_METADATA_VERSION {
                return Err(format!(
                    "unsupported OCI metadata version {} (expected {OCI_METADATA_VERSION})",
                    metadata.version
                ));
            }
            Ok(metadata)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(OciMetadata::default()),
        Err(error) => Err(format!("cannot read OCI metadata: {error}")),
    }
}

/// Reload the durable authority for every read. The local write guard prevents
/// same-process readers from racing a local publisher while the shared file
/// lock orders this snapshot against publishers in other daemon processes.
async fn metadata_snapshot(state: &OciRegistryState) -> Result<OciMetadata, String> {
    let mut cache = state.metadata.write().await;
    let _storage_lock = crate::storage_lock::StorageLock::shared(&state.metadata_lock_path)
        .map_err(|error| format!("failed to lock OCI metadata for reading: {error}"))?;
    let fresh = read_metadata_file(&state.metadata_path)?;
    *cache = fresh.clone();
    Ok(fresh)
}

/// Begin a cross-process read/modify/write transaction from the latest durable
/// metadata. Callers must keep both returned guards alive through persistence.
async fn begin_metadata_write(
    state: &OciRegistryState,
) -> Result<
    (
        RwLockWriteGuard<'_, OciMetadata>,
        crate::storage_lock::StorageLock,
        OciMetadata,
    ),
    String,
> {
    let cache = state.metadata.write().await;
    let storage_lock = crate::storage_lock::StorageLock::exclusive(&state.metadata_lock_path)
        .map_err(|error| format!("failed to lock OCI metadata for writing: {error}"))?;
    let fresh = read_metadata_file(&state.metadata_path)?;
    Ok((cache, storage_lock, fresh))
}

fn persist_metadata(state: &OciRegistryState, metadata: &OciMetadata) -> Result<(), String> {
    let bytes = serde_json::to_vec(metadata)
        .map_err(|error| format!("failed to encode OCI metadata: {error}"))?;
    crate::atomic_file::write(&state.metadata_path, &bytes)
        .map_err(|error| format!("failed to persist OCI metadata: {error}"))
}

/// HEAD /v2/{name}/blobs/{digest} -- check if blob exists.
async fn get_blob_inner(
    state: &OciRegistryState,
    name: &str,
    digest: &str,
    head_only: bool,
) -> Response {
    if !valid_repository_name(name) {
        return oci_error(
            StatusCode::BAD_REQUEST,
            "NAME_INVALID",
            "invalid OCI repository name",
            None,
        );
    }
    let Some(blob_path) = blob_path_for_digest(&state.blobs_dir, digest) else {
        return digest_invalid("invalid non-canonical blob digest", None);
    };
    let metadata = match metadata_snapshot(state).await {
        Ok(metadata) => metadata,
        Err(error) => return metadata_authority_error(&error),
    };
    let is_member = metadata
        .repositories
        .get(name)
        .is_some_and(|repository| repository.blobs.contains(digest));
    if !is_member {
        return StatusCode::NOT_FOUND.into_response();
    }
    let file = match tokio::fs::File::open(&blob_path).await {
        Ok(file) => file,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let size = match file.metadata().await {
        Ok(metadata) => metadata.len(),
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let body = if head_only {
        Body::empty()
    } else {
        let stream = async_stream::stream! {
            let mut file = file;
            let mut buffer = vec![0u8; BLOB_STREAM_CHUNK_SIZE];
            loop {
                match file.read(&mut buffer).await {
                    Ok(0) => break,
                    Ok(read) => {
                        yield Ok::<Bytes, std::io::Error>(Bytes::copy_from_slice(&buffer[..read]));
                    }
                    Err(error) => {
                        yield Err::<Bytes, std::io::Error>(error);
                        break;
                    }
                }
            }
        };
        Body::from_stream(stream)
    };
    let mut response = (StatusCode::OK, body).into_response();
    insert_header(
        response.headers_mut(),
        header::CONTENT_TYPE,
        "application/octet-stream",
    );
    insert_header(
        response.headers_mut(),
        header::HeaderName::from_static("docker-content-digest"),
        digest,
    );
    insert_header(
        response.headers_mut(),
        header::CONTENT_LENGTH,
        &size.to_string(),
    );
    response
}

async fn initiate_upload_inner(state: &OciRegistryState, name: &str) -> Response {
    if !valid_repository_name(name) {
        return oci_error(
            StatusCode::BAD_REQUEST,
            "NAME_INVALID",
            "invalid OCI repository name",
            None,
        );
    }
    if let Err(error) = metadata_snapshot(state).await {
        return metadata_authority_error(&error);
    }

    let upload_id = new_upload_id(name);
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
            repository: name.to_string(),
            created_at: Instant::now(),
            data: Vec::new(),
        },
    );
    drop(uploads);

    let location = upload_location(name, &upload_id);
    let mut response = StatusCode::ACCEPTED.into_response();
    insert_header(response.headers_mut(), header::LOCATION, &location);
    response
}

async fn complete_upload_inner(
    state: &OciRegistryState,
    name: &str,
    id: &str,
    expected_digest: Option<&str>,
    body: Bytes,
) -> Response {
    let location = upload_location(name, id);
    if !valid_repository_name(name) || !valid_upload_id(id) {
        return oci_error(
            StatusCode::BAD_REQUEST,
            "BLOB_UPLOAD_INVALID",
            "invalid OCI upload coordinate",
            Some(&location),
        );
    }
    let Some(expected_digest) = expected_digest else {
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
    if let Err(error) = metadata_snapshot(state).await {
        return metadata_authority_error(&error);
    }

    let mut uploads = state.uploads.write().await;
    let Some(pending) = uploads.get(id) else {
        return oci_error(
            StatusCode::NOT_FOUND,
            "BLOB_UPLOAD_UNKNOWN",
            "blob upload is unknown or expired",
            Some(&location),
        );
    };
    if pending.repository != name || pending.created_at.elapsed() >= UPLOAD_TTL {
        uploads.remove(id);
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
        .remove(id)
        .expect("upload remained present while write lock was held");
    drop(uploads);
    let partial_len = pending.data.len();
    pending.data.extend_from_slice(&body);

    let blob_path = blob_path_for_digest(&state.blobs_dir, &computed_digest)
        .expect("computed sha256 digest is canonical");
    let (mut metadata_guard, storage_lock, mut replacement) =
        match begin_metadata_write(state).await {
            Ok(transaction) => transaction,
            Err(error) => {
                pending.data.truncate(partial_len);
                state.uploads.write().await.insert(id.to_string(), pending);
                return metadata_authority_error(&error);
            }
        };
    // Stage beside the digest path, fsync the complete bytes, and atomically
    // rename them into place. Public GET/HEAD requests therefore see either no
    // blob (or the prior complete blob) or the complete replacement, never a
    // partially written digest object.
    let write_result = crate::atomic_file::write(&blob_path, &pending.data);
    if let Err(error) = write_result {
        // Preserve the pre-completion upload state so the same final request
        // can be retried after the storage failure without duplicating bytes.
        drop(storage_lock);
        drop(metadata_guard);
        pending.data.truncate(partial_len);
        state.uploads.write().await.insert(id.to_string(), pending);
        return oci_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "UNKNOWN",
            &format!("failed to persist OCI blob: {error}"),
            Some(&location),
        );
    }

    // The content-addressed object is global, but public availability is scoped
    // to the repository that completed the upload. Persist membership before
    // acknowledging the write; an orphaned content file after a crash is safe
    // because reads consult this durable authority first.
    replacement
        .repositories
        .entry(name.to_string())
        .or_default()
        .blobs
        .insert(computed_digest.clone());
    if let Err(error) = persist_metadata(state, &replacement) {
        drop(storage_lock);
        drop(metadata_guard);
        pending.data.truncate(partial_len);
        state.uploads.write().await.insert(id.to_string(), pending);
        return oci_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "UNKNOWN",
            &error,
            Some(&location),
        );
    }
    *metadata_guard = replacement;
    drop(storage_lock);
    drop(metadata_guard);

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

async fn get_manifest_inner(
    state: &OciRegistryState,
    name: &str,
    reference: &str,
    head_only: bool,
) -> Response {
    if !valid_repository_name(name) || !valid_manifest_reference(reference) {
        return oci_error(
            StatusCode::BAD_REQUEST,
            "MANIFEST_INVALID",
            "invalid OCI manifest coordinate",
            None,
        );
    }
    let metadata = match metadata_snapshot(state).await {
        Ok(metadata) => metadata,
        Err(error) => return metadata_authority_error(&error),
    };
    let descriptor = metadata
        .repositories
        .get(name)
        .and_then(|repository| repository.manifests.get(reference))
        .cloned();
    let Some(descriptor) = descriptor else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(path) = manifest_path_for_digest(&state.blobs_dir, &descriptor.digest) else {
        return oci_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "UNKNOWN",
            "stored OCI manifest digest is invalid",
            None,
        );
    };
    let bytes = match tokio::fs::read(path).await {
        Ok(bytes) => bytes,
        Err(error) => {
            return oci_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "UNKNOWN",
                &format!("stored OCI manifest is unavailable: {error}"),
                None,
            );
        }
    };
    let length = bytes.len();
    let body = if head_only { Vec::new() } else { bytes };
    let mut response = (StatusCode::OK, body).into_response();
    insert_header(
        response.headers_mut(),
        header::CONTENT_TYPE,
        &descriptor.media_type,
    );
    insert_header(
        response.headers_mut(),
        header::HeaderName::from_static("docker-content-digest"),
        &descriptor.digest,
    );
    insert_header(
        response.headers_mut(),
        header::CONTENT_LENGTH,
        &length.to_string(),
    );
    response
}

/// PUT /v2/{name}/manifests/{reference} -- push a manifest.
async fn put_manifest_inner(
    state: &OciRegistryState,
    name: &str,
    reference: &str,
    media_type: &str,
    body: Bytes,
) -> Response {
    if !valid_repository_name(name) || !valid_manifest_reference(reference) {
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
    if media_type.is_empty()
        || media_type.len() > 255
        || !media_type
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
    {
        return oci_error(
            StatusCode::BAD_REQUEST,
            "MANIFEST_INVALID",
            "manifest Content-Type is invalid",
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
    let manifest_path = manifest_path_for_digest(&state.blobs_dir, &digest)
        .expect("computed manifest digest is canonical");
    let (mut metadata_guard, storage_lock, mut replacement) =
        match begin_metadata_write(state).await {
            Ok(transaction) => transaction,
            Err(error) => return metadata_authority_error(&error),
        };
    if let Err(error) = crate::atomic_file::write(&manifest_path, &body) {
        return oci_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "UNKNOWN",
            &format!("failed to persist OCI manifest: {error}"),
            None,
        );
    }
    let descriptor = ManifestDescriptor {
        digest: digest.clone(),
        media_type: media_type.to_string(),
    };
    let repository = replacement
        .repositories
        .entry(name.to_string())
        .or_default();
    repository
        .manifests
        .insert(reference.to_string(), descriptor.clone());
    repository.manifests.insert(digest.clone(), descriptor);
    if let Err(error) = persist_metadata(state, &replacement) {
        return oci_error(StatusCode::INTERNAL_SERVER_ERROR, "UNKNOWN", &error, None);
    }
    *metadata_guard = replacement;
    drop(storage_lock);
    drop(metadata_guard);

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
async fn delete_manifest_inner(state: &OciRegistryState, name: &str, reference: &str) -> Response {
    if !valid_repository_name(name) || !valid_manifest_reference(reference) {
        return oci_error(
            StatusCode::BAD_REQUEST,
            "MANIFEST_INVALID",
            "invalid OCI manifest coordinate",
            None,
        );
    }
    let (mut metadata_guard, storage_lock, mut replacement) =
        match begin_metadata_write(state).await {
            Ok(transaction) => transaction,
            Err(error) => return metadata_authority_error(&error),
        };
    let Some(repository) = replacement.repositories.get_mut(name) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(descriptor) = repository.manifests.get(reference).cloned() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if sha256_hex(reference).is_some() {
        repository
            .manifests
            .retain(|_, candidate| candidate.digest != descriptor.digest);
    } else {
        repository.manifests.remove(reference);
    }
    if let Err(error) = persist_metadata(state, &replacement) {
        return oci_error(StatusCode::INTERNAL_SERVER_ERROR, "UNKNOWN", &error, None);
    }
    *metadata_guard = replacement;
    drop(storage_lock);
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
    name.split('/').all(|segment| {
        let bytes = segment.as_bytes();
        !segment.is_empty()
            && segment != "."
            && segment != ".."
            && bytes
                .first()
                .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            && bytes
                .last()
                .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
            && bytes.iter().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            })
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

fn manifest_path_for_digest(blobs_dir: &FsPath, digest: &str) -> Option<PathBuf> {
    let encoded = sha256_hex(digest)?;
    let manifests_dir = blobs_dir.join("manifests");
    Some(manifests_dir.join(format!("sha256_{encoded}")))
}

fn digest_invalid(message: &str, location: Option<&str>) -> Response {
    oci_error(StatusCode::BAD_REQUEST, "DIGEST_INVALID", message, location)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use futures_util::StreamExt;
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
        initiate_repository(state, "demo").await
    }

    async fn initiate_repository(state: Arc<OciRegistryState>, repository: &str) -> String {
        let response = oci_routes(state)
            .oneshot(authenticated_request(
                "POST",
                &format!("/v2/{repository}/blobs/uploads/"),
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

    async fn seed_blob(state: &OciRegistryState, repository: &str, bytes: &[u8]) -> String {
        let digest = format!("sha256:{}", sha2_hex(bytes));
        let blob_path = blob_path_for_digest(&state.blobs_dir, &digest).unwrap();
        let (mut guard, storage_lock, mut replacement) = begin_metadata_write(state).await.unwrap();
        crate::atomic_file::write(&blob_path, bytes).unwrap();
        replacement
            .repositories
            .entry(repository.to_string())
            .or_default()
            .blobs
            .insert(digest.clone());
        persist_metadata(state, &replacement).unwrap();
        *guard = replacement;
        drop(storage_lock);
        digest
    }

    async fn seed_manifest(
        state: &OciRegistryState,
        repository: &str,
        reference: &str,
        media_type: &str,
        bytes: &[u8],
    ) -> String {
        let response = put_manifest_inner(
            state,
            repository,
            reference,
            media_type,
            Bytes::copy_from_slice(bytes),
        )
        .await;
        assert_eq!(response.status(), StatusCode::CREATED);
        format!("sha256:{}", sha2_hex(bytes))
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
        let digest = seed_blob(&state, "demo", bytes).await;

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
    async fn namespaced_repository_routes_are_safe_and_blob_membership_isolated() {
        let (_root, state) = registry_state_with_token(Some("registry-secret"));
        let repository = "firelock-ai/platform/kin";
        let body = b"repository-scoped layer";
        let digest = format!("sha256:{}", sha2_hex(body));
        let location = initiate_repository(state.clone(), repository).await;
        assert!(location.starts_with(&format!("/v2/{repository}/blobs/uploads/")));

        let completed = oci_routes(state.clone())
            .oneshot(authenticated_request(
                "PUT",
                &format!("{location}?digest={digest}"),
                Body::from(body.as_slice()),
            ))
            .await
            .unwrap();
        assert_eq!(completed.status(), StatusCode::CREATED);

        let own_read = oci_routes(state.clone())
            .oneshot(
                Request::get(format!("/v2/{repository}/blobs/{digest}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(own_read.status(), StatusCode::OK);
        assert_eq!(
            to_bytes(own_read.into_body(), 1024).await.unwrap().as_ref(),
            body
        );

        // The global content object exists, but another repository cannot use
        // its digest as an ambient capability.
        assert!(blob_path_for_digest(&state.blobs_dir, &digest)
            .unwrap()
            .is_file());
        let cross_repository = oci_routes(state)
            .oneshot(
                Request::get(format!("/v2/other/team/blobs/{digest}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(cross_repository.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn public_blob_get_streams_bounded_chunks() {
        let (_root, state) = registry_state_with_token(Some("registry-secret"));
        let body = vec![b'x'; BLOB_STREAM_CHUNK_SIZE * 4 + 17];
        let digest = seed_blob(&state, "demo", &body).await;
        let response = oci_routes(state)
            .oneshot(
                Request::get(format!("/v2/demo/blobs/{digest}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let mut stream = response.into_body().into_data_stream();
        let first = stream.next().await.unwrap().unwrap();
        assert!(first.len() <= BLOB_STREAM_CHUNK_SIZE);
        assert!(first.len() < body.len());
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
        let (_root, state) = registry_state_with_token(Some("registry-secret"));
        let digest = seed_manifest(
            &state,
            "demo",
            "latest",
            DEFAULT_MANIFEST_MEDIA_TYPE,
            &original,
        )
        .await;

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
                state.metadata.read().await.repositories["demo"].manifests["latest"].digest,
                digest
            );
        }

        let (_root, disabled) = registry_state_with_token(None);
        let disabled_digest = seed_manifest(
            &disabled,
            "demo",
            "latest",
            DEFAULT_MANIFEST_MEDIA_TYPE,
            &original,
        )
        .await;
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
                disabled.metadata.read().await.repositories["demo"].manifests["latest"].digest,
                disabled_digest
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
        assert_eq!(std::fs::read_dir(&state.blobs_dir).unwrap().count(), 2);

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
        assert_eq!(std::fs::read_dir(&state.blobs_dir).unwrap().count(), 3);
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
        assert_eq!(std::fs::read_dir(&state.blobs_dir).unwrap().count(), 3);
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
        assert!(state.metadata.read().await.repositories.is_empty());

        let accepted = oci_routes(state.clone())
            .oneshot(authenticated_request(
                "PUT",
                &format!("/v2/demo/manifests/{computed}"),
                Body::from(body.as_slice()),
            ))
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::CREATED);
        assert_eq!(
            state.metadata.read().await.repositories["demo"]
                .manifests
                .len(),
            1
        );
        let manifest_path = manifest_path_for_digest(&state.blobs_dir, &computed).unwrap();
        assert_eq!(std::fs::read(manifest_path).unwrap(), body);
    }

    #[tokio::test]
    async fn manifest_metadata_survives_restart_and_digest_delete_revokes_every_reference() {
        let (root, state) = registry_state_with_token(Some("registry-secret"));
        let repository = "firelock-ai/kin";
        let body = br#"{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json"}"#;
        let digest = format!("sha256:{}", sha2_hex(body));
        let media_type = "application/vnd.docker.distribution.manifest.v2+json";

        for tag in ["latest", "stable"] {
            let response = oci_routes(state.clone())
                .oneshot(
                    Request::put(format!("/v2/{repository}/manifests/{tag}"))
                        .header(header::AUTHORIZATION, "Bearer registry-secret")
                        .header(header::CONTENT_TYPE, media_type)
                        .body(Body::from(body.as_slice()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::CREATED);
            assert_eq!(response.headers()["docker-content-digest"], digest);
        }

        let restarted = Arc::new(OciRegistryState::new(
            root.path().join("oci"),
            Some("registry-secret".to_string()),
        ));
        for method in [Method::GET, Method::HEAD] {
            let response = oci_routes(restarted.clone())
                .oneshot(
                    Request::builder()
                        .method(method.clone())
                        .uri(format!("/v2/{repository}/manifests/latest"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response.headers()[header::CONTENT_TYPE], media_type);
            assert_eq!(response.headers()["docker-content-digest"], digest);
            let observed = to_bytes(response.into_body(), MAX_OCI_MANIFEST_SIZE)
                .await
                .unwrap();
            if method == Method::GET {
                assert_eq!(observed.as_ref(), body);
            } else {
                assert!(observed.is_empty());
            }
        }

        let deleted = oci_routes(restarted.clone())
            .oneshot(authenticated_request(
                "DELETE",
                &format!("/v2/{repository}/manifests/{digest}"),
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(deleted.status(), StatusCode::ACCEPTED);
        for reference in ["latest", "stable", digest.as_str()] {
            let response = oci_routes(restarted.clone())
                .oneshot(
                    Request::get(format!("/v2/{repository}/manifests/{reference}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::NOT_FOUND, "{reference}");
        }

        let after_delete_restart = Arc::new(OciRegistryState::new(
            root.path().join("oci"),
            Some("registry-secret".to_string()),
        ));
        let absent = oci_routes(after_delete_restart)
            .oneshot(
                Request::get(format!("/v2/{repository}/manifests/latest"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(absent.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn independent_states_merge_writes_and_observe_fresh_durable_metadata() {
        let root = tempfile::tempdir().unwrap();
        let blobs_dir = root.path().join("oci");
        std::fs::create_dir_all(&blobs_dir).unwrap();
        // Both long-lived states start from the same empty snapshot. A
        // startup-cached implementation would let the second publication
        // erase the first.
        let first = Arc::new(OciRegistryState::new(
            blobs_dir.clone(),
            Some("registry-secret".to_string()),
        ));
        let second = Arc::new(OciRegistryState::new(
            blobs_dir,
            Some("registry-secret".to_string()),
        ));
        let start = Arc::new(tokio::sync::Barrier::new(3));

        let publish = |state: Arc<OciRegistryState>,
                       repository: &'static str,
                       tag: &'static str,
                       marker: &'static str,
                       start: Arc<tokio::sync::Barrier>| {
            tokio::spawn(async move {
                start.wait().await;
                put_manifest_inner(
                    &state,
                    repository,
                    tag,
                    DEFAULT_MANIFEST_MEDIA_TYPE,
                    Bytes::from(format!(r#"{{"schemaVersion":2,"marker":"{marker}"}}"#)),
                )
                .await
                .status()
            })
        };
        let left = publish(
            first.clone(),
            "team/first",
            "stable",
            "first",
            start.clone(),
        );
        let right = publish(
            second.clone(),
            "team/second",
            "latest",
            "second",
            start.clone(),
        );
        start.wait().await;
        assert_eq!(left.await.unwrap(), StatusCode::CREATED);
        assert_eq!(right.await.unwrap(), StatusCode::CREATED);

        let durable = read_metadata_file(&first.metadata_path).unwrap();
        assert!(durable.repositories.contains_key("team/first"));
        assert!(durable.repositories.contains_key("team/second"));

        // Each pre-existing process must see the other process's publication
        // without a restart.
        let observed_by_first = oci_routes(first)
            .oneshot(
                Request::get("/v2/team/second/manifests/latest")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(observed_by_first.status(), StatusCode::OK);
        let observed_by_second = oci_routes(second)
            .oneshot(
                Request::get("/v2/team/first/manifests/stable")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(observed_by_second.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn corrupt_durable_metadata_fails_loud_instead_of_appearing_empty() {
        let (root, _state) = registry_state_with_token(Some("registry-secret"));
        std::fs::write(root.path().join("oci/metadata.json"), b"not-json").unwrap();
        let corrupt = Arc::new(OciRegistryState::new(
            root.path().join("oci"),
            Some("registry-secret".to_string()),
        ));
        let digest = format!("sha256:{}", "0".repeat(SHA256_HEX_LEN));
        let read = oci_routes(corrupt.clone())
            .oneshot(
                Request::get(format!("/v2/demo/blobs/{digest}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(read.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let write = oci_routes(corrupt)
            .oneshot(authenticated_request(
                "POST",
                "/v2/demo/blobs/uploads/",
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(write.status(), StatusCode::INTERNAL_SERVER_ERROR);
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
