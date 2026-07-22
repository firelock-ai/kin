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
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeSet, HashMap};
use std::path::{Path as FsPath, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{Mutex, MutexGuard, RwLock, RwLockWriteGuard};

const SHA256_HEX_LEN: usize = 64;
const UPLOAD_ID_HEX_LEN: usize = 32;
const MAX_REPOSITORY_NAME_LEN: usize = 255;
const MAX_MANIFEST_REFERENCE_LEN: usize = 128;
const MAX_OCI_BLOB_SIZE: usize = 512 * 1024 * 1024;
const MAX_OCI_MANIFEST_SIZE: usize = 4 * 1024 * 1024;
const MAX_ACTIVE_UPLOADS: usize = 1024;
const MAX_TOTAL_ACTIVE_UPLOAD_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const UPLOAD_TTL: Duration = Duration::from_secs(15 * 60);
const OCI_METADATA_VERSION: u32 = 1;
const OCI_UPLOAD_METADATA_VERSION: u32 = 1;
const BLOB_STREAM_CHUNK_SIZE: usize = 64 * 1024;
const DEFAULT_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const DOCKER_MANIFEST_MEDIA_TYPE: &str = "application/vnd.docker.distribution.manifest.v2+json";
const MAX_MANIFEST_LAYERS: usize = 4096;

static UPLOAD_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug, Deserialize, Serialize)]
struct PendingUpload {
    version: u32,
    repository: String,
    created_at_unix_secs: u64,
    updated_at_unix_secs: u64,
    size: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    expected_digest: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImageManifest {
    schema_version: u32,
    #[serde(default)]
    media_type: Option<String>,
    config: ImageDescriptor,
    layers: Vec<ImageDescriptor>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ImageDescriptor {
    media_type: String,
    digest: String,
    size: u64,
}

struct ManifestValidationError {
    status: StatusCode,
    code: &'static str,
    message: String,
}

impl ManifestValidationError {
    fn response(self) -> Response {
        oci_error(self.status, self.code, &self.message, None)
    }
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
    uploads_dir: PathBuf,
    uploads_lock_path: PathBuf,
    /// Serializes this process before the shared storage lock is acquired.
    upload_gate: Mutex<()>,
    max_active_upload_bytes: u64,
    /// OCI-specific secret for writes. `None` disables every mutation.
    write_token: Option<String>,
}

impl OciRegistryState {
    pub fn new(blobs_dir: PathBuf, write_token: Option<String>) -> Self {
        // Pin the storage identity once. macOS temporary paths commonly enter
        // through `/var` while descriptor-anchored storage resolves them under
        // `/private/var`; a canonical root keeps every later no-follow boundary
        // and cross-process lock keyed to the same directory.
        let blobs_dir = std::fs::canonicalize(&blobs_dir).unwrap_or(blobs_dir);
        let metadata_path = blobs_dir.join("metadata.json");
        let metadata_lock_path = blobs_dir.join(".metadata.lock");
        let uploads_dir = blobs_dir.join("uploads");
        let uploads_lock_path = blobs_dir.join(".uploads.lock");
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
            uploads_dir,
            uploads_lock_path,
            upload_gate: Mutex::new(()),
            max_active_upload_bytes: MAX_TOTAL_ACTIVE_UPLOAD_BYTES,
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
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
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
    if matches!(*method, Method::PUT | Method::PATCH) && path.contains("/blobs/uploads/") {
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
        let declared_length = request
            .headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok());
        let content_range = request
            .headers()
            .get(header::CONTENT_RANGE)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        return match method {
            Method::PATCH => {
                patch_upload_inner(
                    &state,
                    repository,
                    upload_id,
                    content_range.as_deref(),
                    declared_length,
                    request.into_body(),
                )
                .await
            }
            Method::PUT => {
                let digest = request
                    .uri()
                    .query()
                    .and_then(|query| query_parameter(query, "digest"));
                complete_upload_inner(
                    &state,
                    repository,
                    upload_id,
                    digest.as_deref(),
                    declared_length,
                    request.into_body(),
                )
                .await
            }
            _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
        };
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
    let _storage_lock = crate::storage_lock::StorageLock::shared_async(&state.metadata_lock_path)
        .await
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
    let storage_lock = crate::storage_lock::StorageLock::exclusive_async(&state.metadata_lock_path)
        .await
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
    if !std::fs::symlink_metadata(&blob_path)
        .ok()
        .is_some_and(|metadata| metadata.file_type().is_file())
    {
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

struct UploadWriteTransaction<'a> {
    _local: MutexGuard<'a, ()>,
    _storage: crate::storage_lock::StorageLock,
}

#[derive(Debug)]
enum UploadAppendError {
    Limit,
    Body(String),
    Storage(String),
}

async fn begin_upload_write(
    state: &OciRegistryState,
) -> Result<UploadWriteTransaction<'_>, String> {
    let local = state.upload_gate.lock().await;
    let storage = crate::storage_lock::StorageLock::exclusive_async(&state.uploads_lock_path)
        .await
        .map_err(|error| format!("failed to lock OCI uploads: {error}"))?;
    crate::atomic_file::ensure_directory_durable(&state.uploads_dir)
        .map_err(|error| format!("failed to create OCI upload storage: {error}"))?;
    Ok(UploadWriteTransaction {
        _local: local,
        _storage: storage,
    })
}

fn upload_metadata_path(state: &OciRegistryState, id: &str) -> Option<PathBuf> {
    valid_upload_id(id).then(|| state.uploads_dir.join(format!("{id}.json")))
}

fn upload_data_path(state: &OciRegistryState, id: &str) -> Option<PathBuf> {
    valid_upload_id(id).then(|| state.uploads_dir.join(format!("{id}.data")))
}

fn now_unix_secs() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| format!("system clock is before the Unix epoch: {error}"))
}

fn read_upload_session(
    state: &OciRegistryState,
    id: &str,
) -> Result<Option<PendingUpload>, String> {
    let metadata_path = upload_metadata_path(state, id)
        .ok_or_else(|| "invalid OCI upload identifier".to_string())?;
    let bytes = match std::fs::read(&metadata_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("failed to read OCI upload metadata: {error}")),
    };
    let upload = serde_json::from_slice::<PendingUpload>(&bytes)
        .map_err(|error| format!("failed to decode OCI upload metadata: {error}"))?;
    if upload.version != OCI_UPLOAD_METADATA_VERSION
        || !valid_repository_name(&upload.repository)
        || upload.created_at_unix_secs > upload.updated_at_unix_secs
        || upload.size > MAX_OCI_BLOB_SIZE as u64
        || upload
            .expected_digest
            .as_deref()
            .is_some_and(|digest| sha256_hex(digest).is_none())
    {
        return Err("OCI upload metadata failed validation".to_string());
    }
    let data_path = upload_data_path(state, id).expect("validated upload identifier");
    match std::fs::symlink_metadata(&data_path) {
        Ok(metadata) if metadata.file_type().is_file() && metadata.len() == upload.size => {}
        Ok(metadata) if metadata.file_type().is_file() && metadata.len() > upload.size => {
            // The durable metadata offset is the commit point. Bytes beyond it
            // can only be an interrupted PATCH/final PUT and are safe to drop.
            let file = std::fs::OpenOptions::new()
                .write(true)
                .open(&data_path)
                .map_err(|error| format!("failed to reopen interrupted OCI upload: {error}"))?;
            file.set_len(upload.size)
                .map_err(|error| format!("failed to roll back interrupted OCI upload: {error}"))?;
            file.sync_all()
                .map_err(|error| format!("failed to sync interrupted OCI upload: {error}"))?;
        }
        Ok(_) => return Err("OCI upload staged data does not match its metadata".to_string()),
        Err(error)
            if error.kind() == std::io::ErrorKind::NotFound
                && upload.expected_digest.as_ref().is_some_and(|digest| {
                    blob_path_for_digest(&state.blobs_dir, digest)
                        .and_then(|path| std::fs::symlink_metadata(path).ok())
                        .is_some_and(|metadata| {
                            metadata.file_type().is_file() && metadata.len() == upload.size
                        })
                }) => {}
        Err(error) => return Err(format!("failed to inspect OCI upload data: {error}")),
    }
    Ok(Some(upload))
}

fn persist_upload_session(
    state: &OciRegistryState,
    id: &str,
    upload: &PendingUpload,
) -> Result<(), String> {
    let metadata_path = upload_metadata_path(state, id)
        .ok_or_else(|| "invalid OCI upload identifier".to_string())?;
    let bytes = serde_json::to_vec(upload)
        .map_err(|error| format!("failed to encode OCI upload metadata: {error}"))?;
    crate::atomic_file::write(&metadata_path, &bytes)
        .map_err(|error| format!("failed to persist OCI upload metadata: {error}"))
}

fn remove_upload_session(state: &OciRegistryState, id: &str) -> Result<(), String> {
    for path in [
        upload_metadata_path(state, id)
            .ok_or_else(|| "invalid OCI upload identifier".to_string())?,
        upload_data_path(state, id).ok_or_else(|| "invalid OCI upload identifier".to_string())?,
    ] {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "failed to remove OCI upload state {}: {error}",
                    path.display()
                ));
            }
        }
    }
    Ok(())
}

/// Prune expired durable sessions and return (active count, aggregate bytes).
/// The caller holds the shared-storage upload lock, so all daemon processes
/// enforce the same count and byte budget.
fn prune_and_measure_uploads(state: &OciRegistryState) -> Result<(usize, u64), String> {
    let now = now_unix_secs()?;
    let mut active_ids = BTreeSet::new();
    let mut active_count = 0usize;
    let mut active_bytes = 0u64;
    for entry in std::fs::read_dir(&state.uploads_dir)
        .map_err(|error| format!("failed to enumerate OCI uploads: {error}"))?
    {
        let entry = entry.map_err(|error| format!("failed to enumerate OCI uploads: {error}"))?;
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            return Err("OCI upload storage contains a non-UTF-8 entry".to_string());
        };
        let Some(id) = file_name.strip_suffix(".json") else {
            continue;
        };
        if !valid_upload_id(id) {
            return Err(format!(
                "OCI upload storage contains invalid metadata entry {file_name}"
            ));
        }
        let Some(upload) = read_upload_session(state, id)? else {
            continue;
        };
        if now.saturating_sub(upload.updated_at_unix_secs) >= UPLOAD_TTL.as_secs() {
            remove_upload_session(state, id)?;
            continue;
        }
        active_count = active_count
            .checked_add(1)
            .ok_or_else(|| "OCI upload count overflowed".to_string())?;
        active_bytes = active_bytes
            .checked_add(upload.size)
            .ok_or_else(|| "OCI upload byte count overflowed".to_string())?;
        if active_bytes > state.max_active_upload_bytes {
            return Err("durable OCI uploads exceed the configured aggregate limit".to_string());
        }
        active_ids.insert(id.to_string());
    }

    // A crash between the empty data write and metadata publication can leave
    // an unowned stage. Remove only canonical unowned stages; every unexpected
    // entry fails closed instead of being omitted from the aggregate budget.
    for entry in std::fs::read_dir(&state.uploads_dir)
        .map_err(|error| format!("failed to enumerate OCI upload data: {error}"))?
    {
        let entry =
            entry.map_err(|error| format!("failed to enumerate OCI upload data: {error}"))?;
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            return Err("OCI upload storage contains a non-UTF-8 entry".to_string());
        };
        if let Some(id) = file_name.strip_suffix(".json") {
            if !valid_upload_id(id) {
                return Err(format!(
                    "OCI upload storage contains invalid metadata entry {file_name}"
                ));
            }
            continue;
        }
        if let Some(id) = file_name.strip_suffix(".data") {
            if !valid_upload_id(id) {
                return Err(format!(
                    "OCI upload storage contains invalid data entry {file_name}"
                ));
            }
            if !active_ids.contains(id) {
                std::fs::remove_file(entry.path()).map_err(|error| {
                    format!("failed to prune orphaned OCI upload data: {error}")
                })?;
            }
            continue;
        }
        return Err(format!(
            "OCI upload storage contains unexpected entry {file_name}"
        ));
    }
    Ok((active_count, active_bytes))
}

async fn rollback_staged_file(file: &mut tokio::fs::File, size: u64) -> Result<(), String> {
    file.set_len(size)
        .await
        .map_err(|error| format!("failed to roll back OCI upload data: {error}"))?;
    file.sync_all()
        .await
        .map_err(|error| format!("failed to sync rolled-back OCI upload data: {error}"))
}

async fn append_upload_body(
    path: &FsPath,
    original_size: u64,
    aggregate_remaining: u64,
    declared_length: Option<u64>,
    body: Body,
    mut hasher: Option<&mut Sha256>,
) -> Result<u64, UploadAppendError> {
    let session_remaining = (MAX_OCI_BLOB_SIZE as u64).saturating_sub(original_size);
    let allowed = session_remaining.min(aggregate_remaining);
    if declared_length.is_some_and(|length| length > allowed) {
        return Err(UploadAppendError::Limit);
    }
    let mut file = tokio::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .await
        .map_err(|error| {
            UploadAppendError::Storage(format!("failed to open OCI upload data: {error}"))
        })?;
    let mut written = 0u64;
    let mut stream = body.into_data_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = match chunk {
            Ok(chunk) => chunk,
            Err(error) => {
                rollback_staged_file(&mut file, original_size)
                    .await
                    .map_err(UploadAppendError::Storage)?;
                return Err(UploadAppendError::Body(format!(
                    "failed to read OCI upload body: {error}"
                )));
            }
        };
        let chunk_len = u64::try_from(chunk.len()).map_err(|_| UploadAppendError::Limit)?;
        if written
            .checked_add(chunk_len)
            .is_none_or(|total| total > allowed)
        {
            rollback_staged_file(&mut file, original_size)
                .await
                .map_err(UploadAppendError::Storage)?;
            return Err(UploadAppendError::Limit);
        }
        if let Err(error) = file.write_all(&chunk).await {
            rollback_staged_file(&mut file, original_size)
                .await
                .map_err(UploadAppendError::Storage)?;
            return Err(UploadAppendError::Storage(format!(
                "failed to append OCI upload data: {error}"
            )));
        }
        if let Some(hasher) = hasher.as_deref_mut() {
            hasher.update(&chunk);
        }
        written += chunk_len;
    }
    if let Err(error) = file.flush().await {
        rollback_staged_file(&mut file, original_size)
            .await
            .map_err(UploadAppendError::Storage)?;
        return Err(UploadAppendError::Storage(format!(
            "failed to flush OCI upload data: {error}"
        )));
    }
    if let Err(error) = file.sync_all().await {
        rollback_staged_file(&mut file, original_size)
            .await
            .map_err(UploadAppendError::Storage)?;
        return Err(UploadAppendError::Storage(format!(
            "failed to sync OCI upload data: {error}"
        )));
    }
    Ok(written)
}

async fn hash_upload_file(path: &FsPath, expected_size: u64) -> Result<Sha256, String> {
    let mut file = tokio::fs::File::open(path)
        .await
        .map_err(|error| format!("failed to open OCI upload data for hashing: {error}"))?;
    let mut hasher = Sha256::new();
    let mut observed_size = 0u64;
    let mut buffer = vec![0u8; BLOB_STREAM_CHUNK_SIZE];
    loop {
        let read = file
            .read(&mut buffer)
            .await
            .map_err(|error| format!("failed to hash OCI upload data: {error}"))?;
        if read == 0 {
            break;
        }
        observed_size = observed_size
            .checked_add(read as u64)
            .ok_or_else(|| "OCI upload size overflowed while hashing".to_string())?;
        if observed_size > expected_size || observed_size > MAX_OCI_BLOB_SIZE as u64 {
            return Err("OCI upload data exceeded its durable size".to_string());
        }
        hasher.update(&buffer[..read]);
    }
    if observed_size != expected_size {
        return Err("OCI upload data did not match its durable size".to_string());
    }
    Ok(hasher)
}

fn publish_staged_upload(staged: &FsPath, destination: &FsPath) -> std::io::Result<()> {
    let staged_parent = staged.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "OCI upload stage has no parent directory",
        )
    })?;
    let destination_parent = destination.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "OCI blob destination has no parent directory",
        )
    })?;
    match std::fs::symlink_metadata(destination) {
        Ok(_) => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "OCI blob destination already exists",
            ));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    std::fs::rename(staged, destination)?;
    sync_oci_directory(destination_parent)?;
    if staged_parent != destination_parent {
        sync_oci_directory(staged_parent)?;
    }
    Ok(())
}

#[cfg(unix)]
fn sync_oci_directory(path: &FsPath) -> std::io::Result<()> {
    std::fs::File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_oci_directory(_path: &FsPath) -> std::io::Result<()> {
    Ok(())
}

fn upload_progress_response(status: StatusCode, name: &str, id: &str, size: u64) -> Response {
    let mut response = status.into_response();
    insert_header(
        response.headers_mut(),
        header::LOCATION,
        &upload_location(name, id),
    );
    insert_header(
        response.headers_mut(),
        header::HeaderName::from_static("docker-upload-uuid"),
        id,
    );
    insert_header(
        response.headers_mut(),
        header::RANGE,
        &format!("0-{}", size.saturating_sub(1)),
    );
    response
}

fn parse_content_range(value: &str) -> Option<(u64, u64)> {
    let value = value.strip_prefix("bytes ").unwrap_or(value);
    let (start, end) = value.split_once('-')?;
    let start = start.parse::<u64>().ok()?;
    let end = end.parse::<u64>().ok()?;
    (end >= start).then_some((start, end))
}

fn upload_error(error: UploadAppendError, location: &str) -> Response {
    match error {
        UploadAppendError::Limit => oci_error(
            StatusCode::PAYLOAD_TOO_LARGE,
            "BLOB_UPLOAD_INVALID",
            "blob upload exceeds the configured per-upload or aggregate size limit",
            Some(location),
        ),
        UploadAppendError::Body(message) => oci_error(
            StatusCode::BAD_REQUEST,
            "BLOB_UPLOAD_INVALID",
            &message,
            Some(location),
        ),
        UploadAppendError::Storage(message) => oci_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "UNKNOWN",
            &message,
            Some(location),
        ),
    }
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
    let _transaction = match begin_upload_write(state).await {
        Ok(transaction) => transaction,
        Err(error) => return metadata_authority_error(&error),
    };
    let (active_count, active_bytes) = match prune_and_measure_uploads(state) {
        Ok(measured) => measured,
        Err(error) => return metadata_authority_error(&error),
    };
    if active_count >= MAX_ACTIVE_UPLOADS || active_bytes >= state.max_active_upload_bytes {
        return oci_error(
            StatusCode::TOO_MANY_REQUESTS,
            "TOOMANYREQUESTS",
            "too many active OCI uploads",
            None,
        );
    }

    let now = match now_unix_secs() {
        Ok(now) => now,
        Err(error) => return metadata_authority_error(&error),
    };
    let upload_id = loop {
        let candidate = new_upload_id(name);
        let metadata_exists =
            upload_metadata_path(state, &candidate).is_some_and(|path| path.exists());
        let data_exists = upload_data_path(state, &candidate).is_some_and(|path| path.exists());
        if !metadata_exists && !data_exists {
            break candidate;
        }
    };
    let data_path = upload_data_path(state, &upload_id).expect("generated upload identifier");
    if let Err(error) = crate::atomic_file::write(&data_path, &[]) {
        return metadata_authority_error(&format!("failed to create OCI upload data: {error}"));
    }
    let upload = PendingUpload {
        version: OCI_UPLOAD_METADATA_VERSION,
        repository: name.to_string(),
        created_at_unix_secs: now,
        updated_at_unix_secs: now,
        size: 0,
        expected_digest: None,
    };
    if let Err(error) = persist_upload_session(state, &upload_id, &upload) {
        let _ = std::fs::remove_file(data_path);
        return metadata_authority_error(&error);
    }
    upload_progress_response(StatusCode::ACCEPTED, name, &upload_id, 0)
}

async fn patch_upload_inner(
    state: &OciRegistryState,
    name: &str,
    id: &str,
    content_range: Option<&str>,
    declared_length: Option<u64>,
    body: Body,
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
    let _transaction = match begin_upload_write(state).await {
        Ok(transaction) => transaction,
        Err(error) => return metadata_authority_error(&error),
    };
    let (_, active_bytes) = match prune_and_measure_uploads(state) {
        Ok(measured) => measured,
        Err(error) => return metadata_authority_error(&error),
    };
    let mut upload = match read_upload_session(state, id) {
        Ok(Some(upload)) if upload.repository == name => upload,
        Ok(Some(_)) | Ok(None) => {
            return oci_error(
                StatusCode::NOT_FOUND,
                "BLOB_UPLOAD_UNKNOWN",
                "blob upload is unknown or expired",
                Some(&location),
            );
        }
        Err(error) => return metadata_authority_error(&error),
    };
    if upload.expected_digest.is_some() {
        return oci_error(
            StatusCode::CONFLICT,
            "BLOB_UPLOAD_INVALID",
            "blob upload is already being finalized",
            Some(&location),
        );
    }
    let expected_range_length = if let Some(value) = content_range {
        let Some((start, end)) = parse_content_range(value) else {
            return oci_error(
                StatusCode::RANGE_NOT_SATISFIABLE,
                "BLOB_UPLOAD_INVALID",
                "Content-Range is invalid",
                Some(&location),
            );
        };
        let Some(length) = end
            .checked_sub(start)
            .and_then(|length| length.checked_add(1))
        else {
            return oci_error(
                StatusCode::RANGE_NOT_SATISFIABLE,
                "BLOB_UPLOAD_INVALID",
                "Content-Range is invalid",
                Some(&location),
            );
        };
        if start != upload.size || declared_length.is_some_and(|declared| declared != length) {
            return oci_error(
                StatusCode::RANGE_NOT_SATISFIABLE,
                "BLOB_UPLOAD_INVALID",
                "Content-Range does not match the persisted upload offset and body length",
                Some(&location),
            );
        }
        Some(length)
    } else {
        None
    };
    let updated_at = match now_unix_secs() {
        Ok(now) => now,
        Err(error) => return metadata_authority_error(&error),
    };
    let data_path = upload_data_path(state, id).expect("validated upload identifier");
    let aggregate_remaining = state.max_active_upload_bytes.saturating_sub(active_bytes);
    let appended = match append_upload_body(
        &data_path,
        upload.size,
        aggregate_remaining,
        declared_length,
        body,
        None,
    )
    .await
    {
        Ok(appended) => appended,
        Err(error) => return upload_error(error, &location),
    };
    if expected_range_length.is_some_and(|expected| expected != appended) {
        match tokio::fs::OpenOptions::new()
            .write(true)
            .open(&data_path)
            .await
        {
            Ok(mut file) => {
                if let Err(error) = rollback_staged_file(&mut file, upload.size).await {
                    return metadata_authority_error(&error);
                }
            }
            Err(error) => {
                return metadata_authority_error(&format!(
                    "failed to reopen OCI upload after Content-Range mismatch: {error}"
                ));
            }
        }
        return oci_error(
            StatusCode::RANGE_NOT_SATISFIABLE,
            "BLOB_UPLOAD_INVALID",
            "Content-Range length does not match the streamed body",
            Some(&location),
        );
    }
    let previous_size = upload.size;
    upload.size += appended;
    upload.updated_at_unix_secs = updated_at;
    if let Err(error) = persist_upload_session(state, id, &upload) {
        match tokio::fs::OpenOptions::new()
            .write(true)
            .open(&data_path)
            .await
        {
            Ok(mut file) => {
                if let Err(rollback_error) = rollback_staged_file(&mut file, previous_size).await {
                    return metadata_authority_error(&format!(
                        "{error}; additionally {rollback_error}"
                    ));
                }
            }
            Err(rollback_error) => {
                return metadata_authority_error(&format!(
                    "{error}; failed to reopen OCI upload for rollback: {rollback_error}"
                ));
            }
        }
        return metadata_authority_error(&error);
    }
    upload_progress_response(StatusCode::ACCEPTED, name, id, upload.size)
}

async fn complete_upload_inner(
    state: &OciRegistryState,
    name: &str,
    id: &str,
    expected_digest: Option<&str>,
    declared_length: Option<u64>,
    body: Body,
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
    let _upload_transaction = match begin_upload_write(state).await {
        Ok(transaction) => transaction,
        Err(error) => return metadata_authority_error(&error),
    };
    let (_, active_bytes) = match prune_and_measure_uploads(state) {
        Ok(measured) => measured,
        Err(error) => return metadata_authority_error(&error),
    };
    let mut upload = match read_upload_session(state, id) {
        Ok(Some(upload)) if upload.repository == name => upload,
        Ok(Some(_)) | Ok(None) => {
            return oci_error(
                StatusCode::NOT_FOUND,
                "BLOB_UPLOAD_UNKNOWN",
                "blob upload is unknown or expired",
                Some(&location),
            );
        }
        Err(error) => return metadata_authority_error(&error),
    };
    let data_path = upload_data_path(state, id).expect("validated upload identifier");
    let computed_digest = if let Some(finalizing_digest) = upload.expected_digest.as_deref() {
        if finalizing_digest != expected_digest {
            return digest_invalid(
                "completion digest differs from the durable finalization digest",
                Some(&location),
            );
        }
        if declared_length.is_some_and(|length| length != 0) {
            return oci_error(
                StatusCode::CONFLICT,
                "BLOB_UPLOAD_INVALID",
                "a finalizing upload can only be resumed with an empty body",
                Some(&location),
            );
        }
        let mut stream = body.into_data_stream();
        if stream.next().await.is_some() {
            return oci_error(
                StatusCode::CONFLICT,
                "BLOB_UPLOAD_INVALID",
                "a finalizing upload can only be resumed with an empty body",
                Some(&location),
            );
        }
        finalizing_digest.to_string()
    } else {
        let updated_at = match now_unix_secs() {
            Ok(now) => now,
            Err(error) => return metadata_authority_error(&error),
        };
        let mut hasher = match hash_upload_file(&data_path, upload.size).await {
            Ok(hasher) => hasher,
            Err(error) => return metadata_authority_error(&error),
        };
        let aggregate_remaining = state.max_active_upload_bytes.saturating_sub(active_bytes);
        let original_size = upload.size;
        let appended = match append_upload_body(
            &data_path,
            original_size,
            aggregate_remaining,
            declared_length,
            body,
            Some(&mut hasher),
        )
        .await
        {
            Ok(appended) => appended,
            Err(error) => return upload_error(error, &location),
        };
        let computed_digest = format!("sha256:{}", hex::encode(hasher.finalize()));
        if expected_digest != computed_digest {
            match tokio::fs::OpenOptions::new()
                .write(true)
                .open(&data_path)
                .await
            {
                Ok(mut file) => {
                    if let Err(error) = rollback_staged_file(&mut file, original_size).await {
                        return metadata_authority_error(&error);
                    }
                }
                Err(error) => {
                    return metadata_authority_error(&format!(
                        "failed to reopen OCI upload for digest-mismatch rollback: {error}"
                    ));
                }
            }
            return digest_invalid(
                "provided digest does not match uploaded content",
                Some(&location),
            );
        }
        upload.size += appended;
        upload.updated_at_unix_secs = updated_at;
        upload.expected_digest = Some(computed_digest.clone());
        if let Err(error) = persist_upload_session(state, id, &upload) {
            match tokio::fs::OpenOptions::new()
                .write(true)
                .open(&data_path)
                .await
            {
                Ok(mut file) => {
                    if let Err(rollback_error) =
                        rollback_staged_file(&mut file, original_size).await
                    {
                        return metadata_authority_error(&format!(
                            "{error}; additionally {rollback_error}"
                        ));
                    }
                }
                Err(rollback_error) => {
                    return metadata_authority_error(&format!(
                        "{error}; failed to reopen OCI upload for rollback: {rollback_error}"
                    ));
                }
            }
            return metadata_authority_error(&error);
        }
        computed_digest
    };

    let blob_path = blob_path_for_digest(&state.blobs_dir, &computed_digest)
        .expect("computed sha256 digest is canonical");
    let data_present = std::fs::symlink_metadata(&data_path)
        .ok()
        .is_some_and(|metadata| metadata.file_type().is_file());
    let blob_metadata = match std::fs::symlink_metadata(&blob_path) {
        Ok(metadata) if metadata.file_type().is_file() => Some(metadata),
        Ok(_) => {
            return metadata_authority_error(
                "an OCI blob digest path exists but is not a regular file",
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return metadata_authority_error(&format!(
                "failed to inspect OCI blob digest path: {error}"
            ));
        }
    };
    if data_present {
        if blob_metadata.is_some() {
            let existing = match hash_upload_file(&blob_path, upload.size).await {
                Ok(hasher) => format!("sha256:{}", hex::encode(hasher.finalize())),
                Err(error) => return metadata_authority_error(&error),
            };
            if existing != computed_digest {
                return metadata_authority_error(
                    "an OCI blob digest path already contains different content",
                );
            }
        } else if let Err(error) = publish_staged_upload(&data_path, &blob_path) {
            return oci_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "UNKNOWN",
                &format!("failed to atomically publish OCI blob: {error}"),
                Some(&location),
            );
        }
    } else {
        if blob_metadata.is_none() {
            return metadata_authority_error(
                "durable OCI upload data disappeared before publication",
            );
        }
        let existing = match hash_upload_file(&blob_path, upload.size).await {
            Ok(hasher) => format!("sha256:{}", hex::encode(hasher.finalize())),
            Err(error) => return metadata_authority_error(&error),
        };
        if existing != computed_digest {
            return metadata_authority_error(
                "the durable finalizing OCI blob does not match its expected digest",
            );
        }
    }

    let (mut metadata_guard, storage_lock, mut replacement) =
        match begin_metadata_write(state).await {
            Ok(transaction) => transaction,
            Err(error) => return metadata_authority_error(&error),
        };
    replacement
        .repositories
        .entry(name.to_string())
        .or_default()
        .blobs
        .insert(computed_digest.clone());
    if let Err(error) = persist_metadata(state, &replacement) {
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
    if let Err(error) = remove_upload_session(state, id) {
        tracing::warn!(upload_id = id, error = %error, "published OCI blob but could not remove completed upload state");
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

fn supported_manifest_media_type(value: &str) -> Option<&str> {
    let media_type = value.split(';').next()?.trim();
    matches!(
        media_type,
        DEFAULT_MANIFEST_MEDIA_TYPE | DOCKER_MANIFEST_MEDIA_TYPE
    )
    .then_some(media_type)
}

fn parse_image_manifest(
    media_type: &str,
    body: &[u8],
) -> Result<ImageManifest, ManifestValidationError> {
    let Some(request_media_type) = supported_manifest_media_type(media_type) else {
        return Err(ManifestValidationError {
            status: StatusCode::BAD_REQUEST,
            code: "MANIFEST_INVALID",
            message: "unsupported OCI manifest Content-Type".to_string(),
        });
    };
    let manifest =
        serde_json::from_slice::<ImageManifest>(body).map_err(|error| ManifestValidationError {
            status: StatusCode::BAD_REQUEST,
            code: "MANIFEST_INVALID",
            message: format!("manifest is not a supported OCI/Docker image manifest: {error}"),
        })?;
    if manifest.schema_version != 2
        || manifest.layers.len() > MAX_MANIFEST_LAYERS
        || manifest
            .media_type
            .as_deref()
            .is_some_and(|body_media_type| body_media_type != request_media_type)
    {
        return Err(ManifestValidationError {
            status: StatusCode::BAD_REQUEST,
            code: "MANIFEST_INVALID",
            message: "manifest schema, media type, or layer count is unsupported".to_string(),
        });
    }
    for descriptor in std::iter::once(&manifest.config).chain(manifest.layers.iter()) {
        if descriptor.media_type.is_empty()
            || descriptor.media_type.len() > 255
            || !descriptor
                .media_type
                .bytes()
                .all(|byte| byte.is_ascii_graphic())
            || sha256_hex(&descriptor.digest).is_none()
            || descriptor.size > MAX_OCI_BLOB_SIZE as u64
        {
            return Err(ManifestValidationError {
                status: StatusCode::BAD_REQUEST,
                code: "MANIFEST_INVALID",
                message: "manifest contains an invalid config or layer descriptor".to_string(),
            });
        }
    }
    Ok(manifest)
}

async fn validate_manifest_blobs(
    state: &OciRegistryState,
    metadata: &OciMetadata,
    repository_name: &str,
    manifest: &ImageManifest,
) -> Result<(), ManifestValidationError> {
    let repository = metadata.repositories.get(repository_name);
    let mut verified = BTreeSet::new();
    for descriptor in std::iter::once(&manifest.config).chain(manifest.layers.iter()) {
        let is_member =
            repository.is_some_and(|repository| repository.blobs.contains(&descriptor.digest));
        let Some(blob_path) = blob_path_for_digest(&state.blobs_dir, &descriptor.digest) else {
            return Err(ManifestValidationError {
                status: StatusCode::BAD_REQUEST,
                code: "MANIFEST_INVALID",
                message: "manifest contains an invalid blob digest".to_string(),
            });
        };
        let file_is_exact = std::fs::symlink_metadata(&blob_path)
            .ok()
            .is_some_and(|metadata| {
                metadata.file_type().is_file() && metadata.len() == descriptor.size
            });
        if !is_member || !file_is_exact {
            return Err(ManifestValidationError {
                status: StatusCode::NOT_FOUND,
                code: "MANIFEST_BLOB_UNKNOWN",
                message: format!("manifest references unavailable blob {}", descriptor.digest),
            });
        }
        if verified.insert(descriptor.digest.clone()) {
            let observed = hash_upload_file(&blob_path, descriptor.size)
                .await
                .map_err(|error| ManifestValidationError {
                    status: StatusCode::INTERNAL_SERVER_ERROR,
                    code: "UNKNOWN",
                    message: error,
                })?;
            let observed = format!("sha256:{}", hex::encode(observed.finalize()));
            if observed != descriptor.digest {
                return Err(ManifestValidationError {
                    status: StatusCode::NOT_FOUND,
                    code: "MANIFEST_BLOB_UNKNOWN",
                    message: format!(
                        "manifest references blob {} whose content is not trustworthy",
                        descriptor.digest
                    ),
                });
            }
        }
    }
    Ok(())
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
    let manifest = match parse_image_manifest(media_type, &body) {
        Ok(manifest) => manifest,
        Err(error) => return error.response(),
    };
    let canonical_media_type = supported_manifest_media_type(media_type)
        .expect("manifest parsing already validated the media type");

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
    if let Err(error) = validate_manifest_blobs(state, &replacement, name, &manifest).await {
        return error.response();
    }
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
        media_type: canonical_media_type.to_string(),
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

    fn image_manifest_body(
        media_type: &str,
        config_digest: &str,
        config_size: usize,
        layer_digest: &str,
        layer_size: usize,
        marker: &str,
    ) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": media_type,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": config_size,
            },
            "layers": [{
                "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                "digest": layer_digest,
                "size": layer_size,
            }],
            "annotations": { "dev.kin.test-marker": marker },
        }))
        .unwrap()
    }

    async fn seed_valid_manifest(
        state: &OciRegistryState,
        repository: &str,
        reference: &str,
        media_type: &str,
        marker: &str,
    ) -> (String, Vec<u8>) {
        let config = format!("config-{marker}").into_bytes();
        let layer = format!("layer-{marker}").into_bytes();
        let config_digest = seed_blob(state, repository, &config).await;
        let layer_digest = seed_blob(state, repository, &layer).await;
        let body = image_manifest_body(
            media_type,
            &config_digest,
            config.len(),
            &layer_digest,
            layer.len(),
            marker,
        );
        let digest = seed_manifest(state, repository, reference, media_type, &body).await;
        (digest, body)
    }

    async fn durable_upload_count(state: &OciRegistryState) -> usize {
        let _transaction = begin_upload_write(state).await.unwrap();
        prune_and_measure_uploads(state).unwrap().0
    }

    fn upload_id_from_location(location: &str) -> &str {
        location.rsplit('/').next().unwrap()
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
        let (_root, state) = registry_state_with_token(Some("registry-secret"));
        let (digest, original) = seed_valid_manifest(
            &state,
            "demo",
            "latest",
            DEFAULT_MANIFEST_MEDIA_TYPE,
            "original",
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
        let (disabled_digest, _disabled_body) = seed_valid_manifest(
            &disabled,
            "demo",
            "latest",
            DEFAULT_MANIFEST_MEDIA_TYPE,
            "disabled-original",
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
            assert_eq!(durable_upload_count(&state).await, 1);
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
        assert_eq!(durable_upload_count(&state).await, 0);
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
        assert_eq!(durable_upload_count(&state).await, 1);
        assert!(blob_path.is_dir());
        let id = upload_id_from_location(&location);
        assert!(upload_data_path(&state, id).unwrap().is_file());

        // The retained upload can be retried after the storage fault clears.
        std::fs::remove_dir(&blob_path).unwrap();
        let retried = oci_routes(state.clone())
            .oneshot(authenticated_request(
                "PUT",
                &format!("{location}?digest={digest}"),
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(retried.status(), StatusCode::CREATED);
        assert_eq!(durable_upload_count(&state).await, 0);
        assert_eq!(std::fs::read(&blob_path).unwrap(), body);
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
    }

    #[tokio::test]
    async fn manifest_digest_reference_must_equal_the_uploaded_body_digest() {
        let (_root, state) = registry_state_with_token(Some("registry-secret"));
        let config = b"digest-test-config";
        let layer = b"digest-test-layer";
        let config_digest = seed_blob(&state, "demo", config).await;
        let layer_digest = seed_blob(&state, "demo", layer).await;
        let body = image_manifest_body(
            DEFAULT_MANIFEST_MEDIA_TYPE,
            &config_digest,
            config.len(),
            &layer_digest,
            layer.len(),
            "digest-reference",
        );
        let computed = format!("sha256:{}", sha2_hex(&body));
        let mismatched = format!("sha256:{}", "0".repeat(SHA256_HEX_LEN));

        let rejected = oci_routes(state.clone())
            .oneshot(authenticated_request(
                "PUT",
                &format!("/v2/demo/manifests/{mismatched}"),
                Body::from(body.clone()),
            ))
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::BAD_REQUEST);
        assert_eq!(error_code(rejected).await, "DIGEST_INVALID");
        assert!(state.metadata.read().await.repositories["demo"]
            .manifests
            .is_empty());

        let accepted = oci_routes(state.clone())
            .oneshot(authenticated_request(
                "PUT",
                &format!("/v2/demo/manifests/{computed}"),
                Body::from(body.clone()),
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
        let media_type = "application/vnd.docker.distribution.manifest.v2+json";
        let config = b"docker-config";
        let layer = b"docker-layer";
        let config_digest = seed_blob(&state, repository, config).await;
        let layer_digest = seed_blob(&state, repository, layer).await;
        let body = image_manifest_body(
            media_type,
            &config_digest,
            config.len(),
            &layer_digest,
            layer.len(),
            "restart",
        );
        let digest = format!("sha256:{}", sha2_hex(&body));

        for tag in ["latest", "stable"] {
            let response = oci_routes(state.clone())
                .oneshot(
                    Request::put(format!("/v2/{repository}/manifests/{tag}"))
                        .header(header::AUTHORIZATION, "Bearer registry-secret")
                        .header(header::CONTENT_TYPE, media_type)
                        .body(Body::from(body.clone()))
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
        let first_config = b"first-config";
        let first_layer = b"first-layer";
        let first_config_digest = seed_blob(&first, "team/first", first_config).await;
        let first_layer_digest = seed_blob(&first, "team/first", first_layer).await;
        let first_body = image_manifest_body(
            DEFAULT_MANIFEST_MEDIA_TYPE,
            &first_config_digest,
            first_config.len(),
            &first_layer_digest,
            first_layer.len(),
            "first",
        );
        let second_config = b"second-config";
        let second_layer = b"second-layer";
        let second_config_digest = seed_blob(&second, "team/second", second_config).await;
        let second_layer_digest = seed_blob(&second, "team/second", second_layer).await;
        let second_body = image_manifest_body(
            DEFAULT_MANIFEST_MEDIA_TYPE,
            &second_config_digest,
            second_config.len(),
            &second_layer_digest,
            second_layer.len(),
            "second",
        );
        let start = Arc::new(tokio::sync::Barrier::new(3));

        let publish = |state: Arc<OciRegistryState>,
                       repository: &'static str,
                       tag: &'static str,
                       body: Vec<u8>,
                       start: Arc<tokio::sync::Barrier>| {
            tokio::spawn(async move {
                start.wait().await;
                put_manifest_inner(
                    &state,
                    repository,
                    tag,
                    DEFAULT_MANIFEST_MEDIA_TYPE,
                    Bytes::from(body),
                )
                .await
                .status()
            })
        };
        let left = publish(
            first.clone(),
            "team/first",
            "stable",
            first_body,
            start.clone(),
        );
        let right = publish(
            second.clone(),
            "team/second",
            "latest",
            second_body,
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
    async fn authenticated_patch_upload_survives_restart_and_final_put() {
        let (root, state) = registry_state_with_token(Some("registry-secret"));
        let location = initiate(state.clone()).await;

        let unauthorized = oci_routes(state.clone())
            .oneshot(
                Request::patch(&location)
                    .body(Body::from("ignored"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        let chunks = futures_util::stream::iter([
            Ok::<Bytes, std::io::Error>(Bytes::from_static(b"he")),
            Ok::<Bytes, std::io::Error>(Bytes::from_static(b"llo")),
        ]);
        let first = oci_routes(state.clone())
            .oneshot(
                Request::patch(&location)
                    .header(header::AUTHORIZATION, "Bearer registry-secret")
                    .header(header::CONTENT_RANGE, "bytes 0-4")
                    .body(Body::from_stream(chunks))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::ACCEPTED);
        assert_eq!(first.headers()[header::RANGE], "0-4");
        assert_eq!(durable_upload_count(&state).await, 1);

        let restarted = Arc::new(OciRegistryState::new(
            root.path().join("oci"),
            Some("registry-secret".to_string()),
        ));
        let mismatched_range = oci_routes(restarted.clone())
            .oneshot(
                Request::patch(&location)
                    .header(header::AUTHORIZATION, "Bearer registry-secret")
                    .header(header::CONTENT_RANGE, "5-20")
                    .body(Body::from(" world"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(mismatched_range.status(), StatusCode::RANGE_NOT_SATISFIABLE);
        let second = oci_routes(restarted.clone())
            .oneshot(
                Request::patch(&location)
                    .header(header::AUTHORIZATION, "Bearer registry-secret")
                    .header(header::CONTENT_RANGE, "5-10")
                    .body(Body::from(" world"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::ACCEPTED);
        assert_eq!(second.headers()[header::RANGE], "0-10");

        let complete_body = b"hello world";
        let digest = format!("sha256:{}", sha2_hex(complete_body));
        let completed = oci_routes(restarted.clone())
            .oneshot(authenticated_request(
                "PUT",
                &format!("{location}?digest={digest}"),
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(completed.status(), StatusCode::CREATED);
        assert_eq!(completed.headers()["docker-content-digest"], digest);
        assert_eq!(durable_upload_count(&restarted).await, 0);
        assert_eq!(
            std::fs::read(blob_path_for_digest(&restarted.blobs_dir, &digest).unwrap()).unwrap(),
            complete_body
        );
    }

    #[tokio::test]
    async fn restart_discards_uncommitted_stream_bytes_at_the_durable_offset() {
        let (root, state) = registry_state_with_token(Some("registry-secret"));
        let location = initiate(state).await;
        let id = upload_id_from_location(&location);
        std::fs::write(
            root.path().join(format!("oci/uploads/{id}.data")),
            b"interrupted-request-bytes",
        )
        .unwrap();

        let restarted = Arc::new(OciRegistryState::new(
            root.path().join("oci"),
            Some("registry-secret".to_string()),
        ));
        let patched = oci_routes(restarted.clone())
            .oneshot(
                Request::patch(&location)
                    .header(header::AUTHORIZATION, "Bearer registry-secret")
                    .header(header::CONTENT_RANGE, "0-4")
                    .body(Body::from("fresh"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(patched.status(), StatusCode::ACCEPTED);
        assert_eq!(patched.headers()[header::RANGE], "0-4");
        assert_eq!(
            std::fs::read(upload_data_path(&restarted, id).unwrap()).unwrap(),
            b"fresh"
        );
    }

    #[tokio::test]
    async fn durable_uploads_share_a_cross_process_aggregate_byte_cap() {
        let root = tempfile::tempdir().unwrap();
        let blobs_dir = root.path().join("oci");
        std::fs::create_dir_all(&blobs_dir).unwrap();
        let mut state = OciRegistryState::new(blobs_dir, Some("registry-secret".to_string()));
        state.max_active_upload_bytes = 512;
        let state = Arc::new(state);
        {
            let _transaction = begin_upload_write(&state).await.unwrap();
            let now = now_unix_secs().unwrap();
            for sequence in 1u128..=4 {
                let id = format!("{sequence:032x}");
                let data_path = upload_data_path(&state, &id).unwrap();
                let file = std::fs::File::create(data_path).unwrap();
                file.set_len(128).unwrap();
                persist_upload_session(
                    &state,
                    &id,
                    &PendingUpload {
                        version: OCI_UPLOAD_METADATA_VERSION,
                        repository: "demo".to_string(),
                        created_at_unix_secs: now,
                        updated_at_unix_secs: now,
                        size: 128,
                        expected_digest: None,
                    },
                )
                .unwrap();
            }
            assert_eq!(
                prune_and_measure_uploads(&state).unwrap(),
                (4, state.max_active_upload_bytes)
            );
        }

        let rejected = oci_routes(state)
            .oneshot(authenticated_request(
                "POST",
                "/v2/demo/blobs/uploads/",
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(error_code(rejected).await, "TOOMANYREQUESTS");
    }

    #[tokio::test]
    async fn manifest_publication_requires_supported_json_and_all_referenced_blobs() {
        let (_root, state) = registry_state_with_token(Some("registry-secret"));
        let config = b"manifest-config";
        let layer = b"manifest-layer";
        let config_digest = format!("sha256:{}", sha2_hex(config));
        let layer_digest = format!("sha256:{}", sha2_hex(layer));
        let body = image_manifest_body(
            DEFAULT_MANIFEST_MEDIA_TYPE,
            &config_digest,
            config.len(),
            &layer_digest,
            layer.len(),
            "validation",
        );

        let malformed = oci_routes(state.clone())
            .oneshot(authenticated_request(
                "PUT",
                "/v2/demo/manifests/malformed",
                Body::from("not-json"),
            ))
            .await
            .unwrap();
        assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
        assert_eq!(error_code(malformed).await, "MANIFEST_INVALID");

        let unsupported = oci_routes(state.clone())
            .oneshot(
                Request::put("/v2/demo/manifests/index")
                    .header(header::AUTHORIZATION, "Bearer registry-secret")
                    .header(
                        header::CONTENT_TYPE,
                        "application/vnd.oci.image.index.v1+json",
                    )
                    .body(Body::from(body.clone()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(unsupported.status(), StatusCode::BAD_REQUEST);
        assert_eq!(error_code(unsupported).await, "MANIFEST_INVALID");

        let missing = oci_routes(state.clone())
            .oneshot(authenticated_request(
                "PUT",
                "/v2/demo/manifests/latest",
                Body::from(body.clone()),
            ))
            .await
            .unwrap();
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
        assert_eq!(error_code(missing).await, "MANIFEST_BLOB_UNKNOWN");

        assert_eq!(seed_blob(&state, "demo", config).await, config_digest);
        let missing_layer = oci_routes(state.clone())
            .oneshot(authenticated_request(
                "PUT",
                "/v2/demo/manifests/latest",
                Body::from(body.clone()),
            ))
            .await
            .unwrap();
        assert_eq!(missing_layer.status(), StatusCode::NOT_FOUND);
        assert_eq!(error_code(missing_layer).await, "MANIFEST_BLOB_UNKNOWN");

        assert_eq!(seed_blob(&state, "demo", layer).await, layer_digest);
        let layer_path = blob_path_for_digest(&state.blobs_dir, &layer_digest).unwrap();
        std::fs::write(&layer_path, vec![b'x'; layer.len()]).unwrap();
        let corrupt_layer = oci_routes(state.clone())
            .oneshot(authenticated_request(
                "PUT",
                "/v2/demo/manifests/latest",
                Body::from(body.clone()),
            ))
            .await
            .unwrap();
        assert_eq!(corrupt_layer.status(), StatusCode::NOT_FOUND);
        assert_eq!(error_code(corrupt_layer).await, "MANIFEST_BLOB_UNKNOWN");

        assert_eq!(seed_blob(&state, "demo", layer).await, layer_digest);
        let accepted = oci_routes(state.clone())
            .oneshot(authenticated_request(
                "PUT",
                "/v2/demo/manifests/latest",
                Body::from(body),
            ))
            .await
            .unwrap();
        assert_eq!(accepted.status(), StatusCode::CREATED);
        assert!(state.metadata.read().await.repositories["demo"]
            .manifests
            .contains_key("latest"));
    }

    #[tokio::test]
    async fn expired_upload_is_removed_and_cannot_be_completed() {
        let (_root, state) = registry_state_with_token(Some("registry-secret"));
        let id = "a".repeat(UPLOAD_ID_HEX_LEN);
        {
            let _transaction = begin_upload_write(&state).await.unwrap();
            let expired_at = now_unix_secs().unwrap() - UPLOAD_TTL.as_secs() - 1;
            crate::atomic_file::write(&upload_data_path(&state, &id).unwrap(), &[]).unwrap();
            persist_upload_session(
                &state,
                &id,
                &PendingUpload {
                    version: OCI_UPLOAD_METADATA_VERSION,
                    repository: "demo".to_string(),
                    created_at_unix_secs: expired_at,
                    updated_at_unix_secs: expired_at,
                    size: 0,
                    expected_digest: None,
                },
            )
            .unwrap();
        }
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
        assert_eq!(durable_upload_count(&state).await, 0);
        assert!(!upload_metadata_path(&state, &id).unwrap().exists());
        assert!(!upload_data_path(&state, &id).unwrap().exists());
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
