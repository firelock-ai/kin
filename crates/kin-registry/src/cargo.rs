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
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{header, Request, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::{get, post},
    Router,
};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use url::Url;

use crate::{Ecosystem, ManifestStore, PackageId, PackageVersion};

/// Shared state for the Cargo registry routes
pub struct CargoRegistryState {
    pub manifest_store: ManifestStore,
    pub blobs_dir: std::path::PathBuf,
    pub base_url: String,
    /// Shared secret required to authorize `publish` requests (the write path).
    ///
    /// Sourced from the `KIN_REGISTRY_CARGO_TOKEN` env var when the daemon
    /// constructs this state. Read endpoints (config, sparse index, downloads)
    /// ignore this field and stay open so `cargo` can fetch without auth.
    ///
    /// Fail-closed: when this is `None` (env unset/empty) every publish request
    /// is rejected, so a misconfigured deployment cannot silently fall open.
    pub publish_token: Option<String>,
    /// Serializes the manifest/blob commit while allowing coherent readers.
    ///
    /// Publish handlers take the write side before inspecting or mutating
    /// storage. Sparse-index and download handlers take the read side across
    /// their full manifest/blob read, so they cannot observe a half-published
    /// coordinate.
    publish_gate: RwLock<()>,
    #[cfg(test)]
    fail_next_blob_commit: std::sync::atomic::AtomicBool,
}

impl CargoRegistryState {
    pub fn new(
        manifest_store: ManifestStore,
        blobs_dir: PathBuf,
        base_url: String,
        publish_token: Option<String>,
    ) -> Self {
        let blobs_dir = crate::atomic_file::pin_authority_root(&blobs_dir).unwrap_or(blobs_dir);
        Self {
            manifest_store,
            blobs_dir,
            base_url,
            publish_token: publish_token
                .map(|token| token.trim().to_string())
                .filter(|token| !token.is_empty()),
            publish_gate: RwLock::new(()),
            #[cfg(test)]
            fail_next_blob_commit: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

const CRATES_IO_INDEX_URL: &str = "https://github.com/rust-lang/crates.io-index";

/// Maximum accepted `.crate` upload size (50 MiB), matching crates.io's cap.
const MAX_CRATE_SIZE: usize = 50 * 1024 * 1024;
const MAX_CRATE_ARCHIVE_ENTRIES: usize = 4096;
const MAX_CRATE_ARCHIVE_SCAN_SIZE: u64 = 256 * 1024 * 1024;
const MAX_CRATE_MANIFEST_SIZE: u64 = 1024 * 1024;
const MAX_CRATE_NAME_LEN: usize = 64;

/// Validate a Cargo registry package name before it can reach either the blob
/// path or the manifest store. This is deliberately at least as strict as the
/// crates.io publish boundary: a lowercase ASCII letter first, then only
/// lowercase ASCII letters, digits, `-`, or `_`, with a 64-byte maximum.
/// Rejecting uppercase avoids creating an index coordinate that Cargo later
/// lowercases and therefore cannot resolve on a case-sensitive filesystem.
fn validate_cargo_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > MAX_CRATE_NAME_LEN {
        return Err(format!(
            "crate name must contain 1 to {MAX_CRATE_NAME_LEN} ASCII characters"
        ));
    }
    let mut bytes = name.bytes();
    if !bytes.next().is_some_and(|byte| byte.is_ascii_lowercase())
        || !bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
    {
        return Err(
            "crate name must start with a lowercase ASCII letter and contain only lowercase ASCII letters, digits, '-' or '_'"
                .to_string(),
        );
    }
    Ok(())
}

fn validate_cargo_version(version: &str) -> Result<(), String> {
    semver::Version::parse(version)
        .map(|_| ())
        .map_err(|error| format!("crate version must be valid SemVer: {error}"))
}

fn validate_cargo_coordinates(name: &str, version: &str) -> Result<(), String> {
    validate_cargo_name(name)?;
    validate_cargo_version(version)
}

fn validate_cargo_manifest_path(store: &ManifestStore, name: &str) -> Result<(), String> {
    validate_cargo_name(name)?;
    let id = PackageId {
        ecosystem: Ecosystem::Cargo,
        scope: None,
        name: name.to_string(),
    };
    store
        .manifest_path_is_direct_child(&id)
        .then_some(())
        .ok_or_else(|| "crate manifest path escaped the Cargo manifest directory".to_string())
}

/// Build the only Cargo blob path shape accepted by this adapter. Coordinate
/// validation forbids separators and dot components; the parent equality check
/// is a second, structural containment proof that fails before any IO.
fn cargo_blob_path(blobs_dir: &FsPath, name: &str, version: &str) -> Result<PathBuf, String> {
    validate_cargo_coordinates(name, version)?;
    let path = blobs_dir.join(format!("{name}-{version}.crate"));
    if path.parent() != Some(blobs_dir) {
        return Err("crate blob path escaped the configured blob directory".to_string());
    }
    Ok(path)
}

fn bad_coordinate(message: String) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": message })),
    )
        .into_response()
}

/// Create axum router for Cargo registry endpoints
pub fn cargo_routes(state: Arc<CargoRegistryState>) -> Router {
    let public = Router::new()
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
        );

    // Authentication executes before the Bytes extractor can poll or buffer
    // the body. The explicit route limit raises Axum's much smaller default to
    // the registry's documented 50 MiB cap while still bounding chunked bodies.
    let writes = Router::new()
        .route(
            "/registry/cargo/api/v1/crates/publish",
            post(publish_crate).layer(DefaultBodyLimit::max(MAX_CRATE_SIZE)),
        )
        .route_layer(middleware::from_fn_with_state(
            Arc::clone(&state),
            authorize_cargo_publish,
        ));

    Router::new().merge(public).merge(writes).with_state(state)
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
    if let Err(message) = validate_cargo_manifest_path(&state.manifest_store, name) {
        return bad_coordinate(message);
    }

    let _read_guard = state.publish_gate.read().await;
    let transaction = match state
        .manifest_store
        .read_transaction_async(Ecosystem::Cargo)
        .await
    {
        Ok(transaction) => transaction,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!("Cargo index storage lock failed: {error}")
                })),
            )
                .into_response();
        }
    };

    // The manifest is the sparse index authority. Metadata extraction belongs
    // to authenticated publish/ingest; a GET must never rebuild or mutate the
    // index from ambient crate files.
    let versions = match transaction.get_versions(name) {
        Ok(v) if v.is_empty() => return StatusCode::NOT_FOUND.into_response(),
        Ok(v) => v,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!("Cargo index manifest is unreadable: {error}")
                })),
            )
                .into_response();
        }
    };

    // Cargo expects newline-delimited JSON, one entry per version
    let mut body = String::new();
    for v in &versions {
        let entry = match CargoIndexEntry::try_from_version(v) {
            Ok(entry) => entry,
            Err(error) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": error })),
                )
                    .into_response();
            }
        };
        let line = match serde_json::to_string(&entry) {
            Ok(line) => line,
            Err(error) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": format!("failed to encode Cargo index entry: {error}")
                    })),
                )
                    .into_response();
            }
        };
        body.push_str(&line);
        body.push('\n');
    }

    (StatusCode::OK, [("content-type", "text/plain")], body).into_response()
}

/// GET /registry/cargo/dl/{name}/{version} -- download .crate file
async fn download_crate(
    State(state): State<Arc<CargoRegistryState>>,
    Path((name, version)): Path<(String, String)>,
) -> Response {
    let crate_path = match cargo_blob_path(&state.blobs_dir, &name, &version) {
        Ok(path) => path,
        Err(message) => return bad_coordinate(message),
    };
    if let Err(message) = validate_cargo_manifest_path(&state.manifest_store, &name) {
        return bad_coordinate(message);
    }
    let _read_guard = state.publish_gate.read().await;
    let transaction = match state
        .manifest_store
        .read_transaction_async(Ecosystem::Cargo)
        .await
    {
        Ok(transaction) => transaction,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let versions = match transaction.get_versions(&name) {
        Ok(v) => v,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };

    let pkg_version = match versions.iter().find(|v| v.version == version) {
        Some(v) => v,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    // Read the .crate file from blob store
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

/// Constant-time comparison of two byte slices.
///
/// Returns `true` only when the slices are equal. The comparison time depends
/// on the input *lengths* but never short-circuits on the first differing byte,
/// so it does not leak how many leading bytes of a candidate token matched.
/// Implemented manually to avoid pulling in a new crate dependency.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Authenticate Cargo writes before any body extractor runs.
async fn authorize_cargo_publish(
    State(state): State<Arc<CargoRegistryState>>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let Some(expected) = state.publish_token.as_deref() else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "registry publishing is disabled: no token configured"
            })),
        )
            .into_response();
    };

    let provided = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty());

    if !provided.is_some_and(|token| constant_time_eq(token.as_bytes(), expected.as_bytes())) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": "invalid or missing publish token"
            })),
        )
            .into_response();
    }

    // Reject a declared oversize body without polling it. DefaultBodyLimit on
    // the route remains authoritative for chunked/missing/forged lengths.
    let declared = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    if declared.is_some_and(|length| length > MAX_CRATE_SIZE as u64) {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({
                "error": format!("crate body exceeds the {MAX_CRATE_SIZE} byte limit")
            })),
        )
            .into_response();
    }

    next.run(request).await
}

/// POST /registry/cargo/api/v1/crates/publish
///
/// Accepts a `.crate` file as the request body (application/octet-stream).
/// Query params: `name` and `version`.
///
/// Authorization (write path only): requires `Authorization: Bearer <token>`
/// matching `state.publish_token`. Reads stay open. Fails closed when no token
/// is configured.
///
/// Validates the body (non-empty, size cap, valid gzip-tar whose embedded
/// `Cargo.toml` `[package]` name/version match the query params), computes the
/// SHA-256 checksum, stores the .crate file, and registers the version.
/// Existing versions are immutable: re-publishing different bytes returns
/// `409` before touching the stored blob. Re-publishing identical bytes is
/// idempotent and may repair a missing or corrupted blob for the indexed
/// checksum.
async fn publish_crate(
    State(state): State<Arc<CargoRegistryState>>,
    Query(params): Query<PublishParams>,
    body: Bytes,
) -> Response {
    if let Err(message) = validate_cargo_coordinates(&params.name, &params.version) {
        return bad_coordinate(message);
    }
    if let Err(message) = validate_cargo_manifest_path(&state.manifest_store, &params.name) {
        return bad_coordinate(message);
    }

    // Reject an empty upload before touching the filesystem.
    if body.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "crate body is empty" })),
        )
            .into_response();
    }

    // Enforce the size cap.
    if body.len() > MAX_CRATE_SIZE {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({
                "error": format!(
                    "crate body of {} bytes exceeds the {MAX_CRATE_SIZE} byte limit",
                    body.len()
                )
            })),
        )
            .into_response();
    }

    // Parse the archive exactly once under explicit decompression, entry, and
    // Cargo.toml budgets. Coordinate verification and sparse-index extraction
    // consume the same parsed manifest so an authorized gzip bomb cannot make
    // the daemon walk an unbounded archive twice.
    let crate_manifest = match parse_crate_manifest(&body, &params.name, &params.version) {
        Ok(manifest) => manifest,
        Err(message) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": message })),
            )
                .into_response();
        }
    };

    // Compute SHA-256 checksum of the .crate bytes
    let checksum = hex::encode(Sha256::digest(&body));

    let crate_path = match cargo_blob_path(&state.blobs_dir, &params.name, &params.version) {
        Ok(path) => path,
        Err(message) => return bad_coordinate(message),
    };

    // Parse metadata before entering the short storage critical section. The
    // write side serializes the subsequent manifest check + blob write +
    // manifest append against every other publish in this registry. Readers
    // hold the read side across their corresponding manifest/blob reads.
    let configured_index = match configured_sparse_index_url(&state.base_url) {
        Ok(index) => index,
        Err(message) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": message })),
            )
                .into_response();
        }
    };
    let metadata = match extract_crate_metadata(&crate_manifest, &configured_index) {
        Ok(metadata) => metadata,
        Err(message) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": message })),
            )
                .into_response();
        }
    };
    let _write_guard = state.publish_gate.write().await;
    let transaction = match state
        .manifest_store
        .write_transaction_async(Ecosystem::Cargo)
        .await
    {
        Ok(transaction) => transaction,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!("failed to lock Cargo registry storage: {error}")
                })),
            )
                .into_response();
        }
    };

    let existing_versions = match transaction.get_versions(&params.name) {
        Ok(versions) => versions,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("{e}") })),
            )
                .into_response();
        }
    };

    if let Some((existing_index, existing)) = existing_versions
        .iter()
        .enumerate()
        .find(|(_, version)| version.version == params.version)
    {
        if existing.checksum != checksum {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": format!(
                        "version {} of crate {} already exists with a different checksum",
                        params.version, params.name
                    )
                })),
            )
                .into_response();
        }

        if let Err(e) = write_crate_blob(&state, &crate_path, &body) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("failed to write crate file: {e}") })),
            )
                .into_response();
        }

        // An identical immutable artifact is also the safe recovery path for
        // manifests written before Cargo dependency metadata became
        // authoritative. Replace only metadata derived from the same bytes;
        // preserve publication identity and timestamps.
        if existing.metadata != metadata {
            let mut repaired = existing_versions.clone();
            repaired[existing_index].metadata = metadata.clone();
            if let Err(error) = transaction.replace_versions(&existing.id, &repaired) {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": format!("failed to repair Cargo index metadata: {error}")
                    })),
                )
                    .into_response();
            }
        }

        return (
            StatusCode::OK,
            Json(serde_json::json!({
                "name": params.name,
                "version": params.version,
                "checksum": checksum,
                "already_published": true,
            })),
        )
            .into_response();
    }

    if let Err(e) = write_crate_blob(&state, &crate_path, &body) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("failed to write crate file: {e}") })),
        )
            .into_response();
    }

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

    match transaction.add_version(&pkg_version) {
        Ok(()) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "name": params.name,
                "version": params.version,
                "checksum": checksum,
            })),
        )
            .into_response(),
        Err(crate::RegistryError::VersionExists(_, _)) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": format!(
                    "version {} of crate {} already exists and cannot be overwritten",
                    params.version, params.name
                )
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

fn write_crate_blob(
    state: &CargoRegistryState,
    crate_path: &std::path::Path,
    body: &[u8],
) -> std::io::Result<()> {
    if crate_path.parent() != Some(state.blobs_dir.as_path()) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "crate blob path escaped the configured blob directory",
        ));
    }

    #[cfg(test)]
    if state
        .fail_next_blob_commit
        .swap(false, std::sync::atomic::Ordering::SeqCst)
    {
        return crate::atomic_file::write_with_pre_commit(crate_path, body, |_| {
            Err(std::io::Error::other(
                "injected failure before atomic crate commit",
            ))
        });
    }

    crate::atomic_file::write(crate_path, body)
}

/// Parse and verify the one authoritative Cargo.toml under bounded archive
/// traversal. The returned value is reused for sparse-index extraction.
fn parse_crate_manifest(
    crate_bytes: &[u8],
    name: &str,
    version: &str,
) -> Result<toml::Value, String> {
    use flate2::read::GzDecoder;
    use std::io::Read;

    let expected_manifest = format!("{}-{}/Cargo.toml", name, version);
    let gz = GzDecoder::new(crate_bytes);
    let mut archive = tar::Archive::new(gz);

    let entries = archive
        .entries()
        .map_err(|e| format!("crate is not a valid gzip-tar archive: {e}"))?;

    let mut cargo_toml_content = String::new();
    let mut manifest_seen = false;
    let mut scanned_size = 0u64;
    for (index, entry) in entries.enumerate() {
        if index >= MAX_CRATE_ARCHIVE_ENTRIES {
            return Err(format!(
                "crate archive exceeds the {MAX_CRATE_ARCHIVE_ENTRIES} entry scan limit"
            ));
        }
        // A malformed tar stream surfaces here (e.g. truncated/non-gzip body).
        let entry = entry.map_err(|e| format!("crate is not a valid gzip-tar archive: {e}"))?;
        let entry_size = entry
            .header()
            .size()
            .map_err(|error| format!("crate contains an invalid entry size: {error}"))?;
        scanned_size = scanned_size
            .checked_add(entry_size)
            .ok_or_else(|| "crate archive scan size overflowed".to_string())?;
        if scanned_size > MAX_CRATE_ARCHIVE_SCAN_SIZE {
            return Err(format!(
                "crate archive exceeds the {MAX_CRATE_ARCHIVE_SCAN_SIZE} byte scan limit"
            ));
        }
        let is_manifest = entry
            .path()
            .ok()
            .map(|path| path.to_str() == Some(&expected_manifest))
            .unwrap_or(false);
        if is_manifest {
            if manifest_seen {
                return Err(format!(
                    "crate contains more than one authoritative {expected_manifest}"
                ));
            }
            manifest_seen = true;
            if entry_size > MAX_CRATE_MANIFEST_SIZE {
                return Err(format!(
                    "crate Cargo.toml exceeds the {MAX_CRATE_MANIFEST_SIZE} byte limit"
                ));
            }
            entry
                .take(MAX_CRATE_MANIFEST_SIZE + 1)
                .read_to_string(&mut cargo_toml_content)
                .map_err(|e| format!("failed to read {expected_manifest} from crate: {e}"))?;
            if cargo_toml_content.len() as u64 > MAX_CRATE_MANIFEST_SIZE {
                return Err(format!(
                    "crate Cargo.toml exceeds the {MAX_CRATE_MANIFEST_SIZE} byte limit"
                ));
            }
        }
    }

    if !manifest_seen {
        return Err(format!("crate does not contain {expected_manifest}"));
    }

    let toml_value: toml::Value = toml::from_str(&cargo_toml_content)
        .map_err(|e| format!("crate {expected_manifest} is not valid TOML: {e}"))?;

    let package = toml_value
        .get("package")
        .and_then(|p| p.as_table())
        .ok_or_else(|| "crate Cargo.toml is missing a [package] section".to_string())?;

    let manifest_name = package
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "crate Cargo.toml [package] is missing a name".to_string())?;
    if manifest_name != name {
        return Err(format!(
            "crate name mismatch: query says {name:?} but Cargo.toml says {manifest_name:?}"
        ));
    }

    let manifest_version = package
        .get("version")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "crate Cargo.toml [package] is missing a version".to_string())?;
    if manifest_version != version {
        return Err(format!(
            "crate version mismatch: query says {version:?} but Cargo.toml says {manifest_version:?}"
        ));
    }

    Ok(toml_value)
}

fn normalize_registry_index_url(value: &str) -> Result<String, String> {
    let (prefix, raw) = match value.strip_prefix("sparse+") {
        Some(raw) => ("sparse+", raw),
        None => ("", value),
    };
    let mut parsed = Url::parse(raw)
        .map_err(|error| format!("registry index URL {value:?} is invalid: {error}"))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(format!(
            "registry index URL {value:?} must be an http(s) URL without credentials, query, or fragment"
        ));
    }
    let normalized_path = format!("{}/", parsed.path().trim_end_matches('/'));
    parsed.set_path(&normalized_path);
    Ok(format!("{prefix}{parsed}"))
}

fn configured_sparse_index_url(base_url: &str) -> Result<String, String> {
    normalize_registry_index_url(&format!(
        "sparse+{}/registry/cargo/",
        base_url.trim_end_matches('/')
    ))
    .map_err(|error| format!("configured Cargo registry base URL is invalid: {error}"))
}

/// Extract features and dependencies from the already verified Cargo.toml.
fn extract_crate_metadata(
    toml_value: &toml::Value,
    configured_index: &str,
) -> Result<serde_json::Value, String> {
    let mut metadata = serde_json::json!({
        "cargo_index_format": 1,
        "features": {},
        "deps": [],
    });

    // Extract [features]
    if let Some(features) = toml_value.get("features") {
        if let Ok(features_json) = serde_json::to_value(features) {
            metadata["features"] = features_json;
        }
    }

    // Extract dependencies from all sections: [dependencies], [dev-dependencies],
    // [build-dependencies], and [target.'cfg(...)'.dependencies].
    let mut deps = Vec::new();

    fn extract_dep_entry(
        dep_name: &str,
        dep_value: &toml::Value,
        target: Option<&str>,
        kind: &str,
        configured_index: &str,
    ) -> Result<Option<serde_json::Value>, String> {
        let (req, optional, default_features, dep_features, registry, package) = match dep_value {
            toml::Value::String(version_str) => (
                version_str.clone(),
                false,
                true,
                vec![],
                Some(CRATES_IO_INDEX_URL.to_string()),
                None,
            ),
            toml::Value::Table(t) => {
                // Skip path-only deps without a version (workspace-internal deps)
                if t.get("path").is_some() && t.get("version").is_none() {
                    return Ok(None);
                }
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
                // Check both `registry` (source Cargo.toml) and `registry-index`
                // (cargo-packaged Cargo.toml where named registries are expanded
                // to their full index URL).
                let registry = if let Some(reg) = t.get("registry").and_then(|v| v.as_str()) {
                    match reg {
                        "" | "crates-io" => Some(CRATES_IO_INDEX_URL.to_string()),
                        "kin" => None,
                        other => {
                            return Err(format!(
                                "dependency {dep_name:?} uses unresolved named registry {other:?}"
                            ));
                        }
                    }
                } else if let Some(idx) = t.get("registry-index").and_then(|v| v.as_str()) {
                    let normalized = normalize_registry_index_url(idx)?;
                    if normalized == configured_index {
                        None
                    } else {
                        Some(normalized)
                    }
                } else {
                    Some(CRATES_IO_INDEX_URL.to_string())
                };
                let package = t.get("package").and_then(|v| v.as_str()).map(String::from);
                (req, optional, default_features, features, registry, package)
            }
            _ => return Ok(None),
        };

        Ok(Some(serde_json::json!({
            "name": dep_name,
            "req": req,
            "features": dep_features,
            "optional": optional,
            "default_features": default_features,
            "target": target,
            "kind": kind,
            "registry": registry,
            "package": package,
        })))
    }

    // [dependencies]
    if let Some(dep_table) = toml_value.get("dependencies").and_then(|d| d.as_table()) {
        for (dep_name, dep_value) in dep_table {
            if let Some(entry) =
                extract_dep_entry(dep_name, dep_value, None, "normal", configured_index)?
            {
                deps.push(entry);
            }
        }
    }

    // [dev-dependencies]
    if let Some(dep_table) = toml_value
        .get("dev-dependencies")
        .and_then(|d| d.as_table())
    {
        for (dep_name, dep_value) in dep_table {
            if let Some(entry) =
                extract_dep_entry(dep_name, dep_value, None, "dev", configured_index)?
            {
                deps.push(entry);
            }
        }
    }

    // [build-dependencies]
    if let Some(dep_table) = toml_value
        .get("build-dependencies")
        .and_then(|d| d.as_table())
    {
        for (dep_name, dep_value) in dep_table {
            if let Some(entry) =
                extract_dep_entry(dep_name, dep_value, None, "build", configured_index)?
            {
                deps.push(entry);
            }
        }
    }

    // [target.'cfg(...)'.dependencies] / dev-dependencies / build-dependencies
    if let Some(target_table) = toml_value.get("target").and_then(|t| t.as_table()) {
        for (target_spec, target_value) in target_table {
            if let Some(target_deps) = target_value.get("dependencies").and_then(|d| d.as_table()) {
                for (dep_name, dep_value) in target_deps {
                    if let Some(entry) = extract_dep_entry(
                        dep_name,
                        dep_value,
                        Some(target_spec),
                        "normal",
                        configured_index,
                    )? {
                        deps.push(entry);
                    }
                }
            }
            if let Some(target_deps) = target_value
                .get("dev-dependencies")
                .and_then(|d| d.as_table())
            {
                for (dep_name, dep_value) in target_deps {
                    if let Some(entry) = extract_dep_entry(
                        dep_name,
                        dep_value,
                        Some(target_spec),
                        "dev",
                        configured_index,
                    )? {
                        deps.push(entry);
                    }
                }
            }
            if let Some(target_deps) = target_value
                .get("build-dependencies")
                .and_then(|d| d.as_table())
            {
                for (dep_name, dep_value) in target_deps {
                    if let Some(entry) = extract_dep_entry(
                        dep_name,
                        dep_value,
                        Some(target_spec),
                        "build",
                        configured_index,
                    )? {
                        deps.push(entry);
                    }
                }
            }
        }
    }

    metadata["deps"] = serde_json::Value::Array(deps);

    Ok(metadata)
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
    fn try_from_version(v: &PackageVersion) -> Result<Self, String> {
        if v.metadata
            .get("cargo_index_format")
            .and_then(|value| value.as_u64())
            != Some(1)
        {
            return Err(format!(
                "Cargo index metadata for {}@{} is legacy or incomplete; re-publish or migrate the manifest before serving it",
                v.id.name, v.version
            ));
        }
        let deps = v
            .metadata
            .get("deps")
            .ok_or_else(|| {
                format!(
                    "Cargo index metadata for {}@{} has no dependency authority",
                    v.id.name, v.version
                )
            })
            .and_then(|deps| {
                serde_json::from_value::<Vec<CargoIndexDep>>(deps.clone()).map_err(|error| {
                    format!(
                        "Cargo index metadata for {}@{} has invalid dependencies: {error}",
                        v.id.name, v.version
                    )
                })
            })?;
        let features = v
            .metadata
            .get("features")
            .cloned()
            .filter(serde_json::Value::is_object)
            .ok_or_else(|| {
                format!(
                    "Cargo index metadata for {}@{} has invalid features",
                    v.id.name, v.version
                )
            })?;

        Ok(Self {
            name: v.id.name.clone(),
            vers: v.version.clone(),
            deps,
            cksum: v.checksum.clone(),
            features,
            yanked: v.yanked,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    fn registry_state() -> (tempfile::TempDir, Arc<CargoRegistryState>) {
        registry_state_with_token(None)
    }

    fn registry_state_with_token(
        publish_token: Option<&str>,
    ) -> (tempfile::TempDir, Arc<CargoRegistryState>) {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(".kin")).unwrap();
        let state = Arc::new(CargoRegistryState::new(
            ManifestStore::new(&root.path().join(".kin")),
            root.path().join("cargo"),
            "https://kinlab.ai".to_string(),
            publish_token.map(String::from),
        ));
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
    async fn sparse_index_fails_loud_on_legacy_metadata_and_never_repairs_from_blob_bytes() {
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

        let manifest_before = state
            .manifest_store
            .get_versions(Ecosystem::Cargo, "kin-infer")
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
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        let error: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(error["error"]
            .as_str()
            .unwrap()
            .contains("legacy or incomplete"));

        let manifest_after = state
            .manifest_store
            .get_versions(Ecosystem::Cargo, "kin-infer")
            .unwrap();
        assert_eq!(manifest_after.len(), manifest_before.len());
        assert_eq!(manifest_after[0].version, manifest_before[0].version);
        assert_eq!(manifest_after[0].metadata, manifest_before[0].metadata);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_sparse_reads_cannot_erase_a_published_version() {
        let (_root, state) = registry_state_with_token(Some("s3cret"));
        std::fs::create_dir_all(&state.blobs_dir).unwrap();
        let first_body = build_test_crate(
            "demo",
            "0.1.0",
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1\"\n",
        );
        std::fs::write(state.blobs_dir.join("demo-0.1.0.crate"), &first_body).unwrap();
        state
            .manifest_store
            .add_version(&PackageVersion {
                id: PackageId {
                    ecosystem: Ecosystem::Cargo,
                    scope: None,
                    name: "demo".to_string(),
                },
                version: "0.1.0".to_string(),
                blob_hash: "hash".to_string(),
                blob_size: first_body.len() as u64,
                checksum: "checksum".to_string(),
                metadata: extract_crate_metadata(
                    &parse_crate_manifest(&first_body, "demo", "0.1.0").unwrap(),
                    &configured_sparse_index_url(&state.base_url).unwrap(),
                )
                .unwrap(),
                published_at: Utc::now(),
                published_by: "legacy-test".to_string(),
                yanked: false,
            })
            .unwrap();

        let reader_count = 8;
        let start = Arc::new(tokio::sync::Barrier::new(reader_count + 2));
        let mut readers = tokio::task::JoinSet::new();
        for _ in 0..reader_count {
            let state = state.clone();
            let start = start.clone();
            readers.spawn(async move {
                start.wait().await;
                for _ in 0..32 {
                    let response = cargo_routes(state.clone())
                        .oneshot(
                            Request::get("/registry/cargo/de/mo/demo")
                                .body(Body::empty())
                                .unwrap(),
                        )
                        .await
                        .unwrap();
                    assert_eq!(response.status(), StatusCode::OK);
                    tokio::task::yield_now().await;
                }
            });
        }

        let publish_state = state.clone();
        let publish_start = start.clone();
        let publisher = tokio::spawn(async move {
            publish_start.wait().await;
            publish(
                publish_state,
                "demo",
                "0.2.0",
                Some("s3cret"),
                valid_crate("demo", "0.2.0"),
            )
            .await
        });
        start.wait().await;

        let status = publisher.await.unwrap();
        assert_eq!(status, StatusCode::OK);
        while let Some(result) = readers.join_next().await {
            result.unwrap();
        }

        let versions = state
            .manifest_store
            .get_versions(Ecosystem::Cargo, "demo")
            .unwrap();
        assert_eq!(
            versions
                .iter()
                .map(|version| version.version.as_str())
                .collect::<Vec<_>>(),
            vec!["0.1.0", "0.2.0"]
        );
        assert_eq!(versions[0].metadata["cargo_index_format"].as_u64(), Some(1));
    }

    #[test]
    fn cargo_coordinates_are_semver_valid_and_paths_stay_contained() {
        let root = tempfile::tempdir().unwrap();
        let blobs = root.path().join("cargo");
        let manifests = ManifestStore::new(&root.path().join(".kin"));
        std::fs::create_dir_all(&blobs).unwrap();

        for (name, version) in [("demo", "0.1.0"), ("kin_registry", "1.2.3-alpha.1+build.9")] {
            let path = cargo_blob_path(&blobs, name, version).unwrap();
            assert_eq!(path.parent(), Some(blobs.as_path()));
            validate_cargo_manifest_path(&manifests, name).unwrap();
        }

        for name in [
            "",
            ".",
            "..",
            "Demo",
            "../outside",
            "demo/outside",
            "demo%2foutside",
            "-demo",
        ] {
            assert!(validate_cargo_name(name).is_err(), "accepted {name:?}");
        }
        for version in ["", ".", "..", "../1.0.0", "1", "1.0", "01.0.0"] {
            assert!(
                validate_cargo_version(version).is_err(),
                "accepted {version:?}"
            );
        }
    }

    #[tokio::test]
    async fn uppercase_publish_is_rejected_before_case_sensitive_index_divergence() {
        let (_root, state) = registry_state_with_token(Some("s3cret"));
        let rejected = publish(
            state.clone(),
            "Demo",
            "0.1.0",
            Some("s3cret"),
            valid_crate("Demo", "0.1.0"),
        )
        .await;
        assert_eq!(rejected, StatusCode::BAD_REQUEST);

        let lowercase_lookup = cargo_routes(state)
            .oneshot(
                Request::get("/registry/cargo/de/mo/demo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(lowercase_lookup.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn traversal_coordinates_never_touch_blob_or_manifest_paths() {
        let (root, state) = registry_state_with_token(Some("s3cret"));
        let sentinel = root.path().join("outside");
        std::fs::write(&sentinel, b"unchanged").unwrap();

        for uri in [
            "/registry/cargo/api/v1/crates/publish?name=..%2Foutside&version=0.1.0",
            "/registry/cargo/api/v1/crates/publish?name=demo&version=..%2Foutside",
        ] {
            let response = cargo_routes(state.clone())
                .oneshot(
                    Request::post(uri)
                        .header("authorization", "Bearer s3cret")
                        .body(Body::from(b"not consulted".as_slice()))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        }

        let sparse = cargo_routes(state.clone())
            .oneshot(
                Request::get("/registry/cargo/1/%2e%2e")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(sparse.status(), StatusCode::OK);

        assert_eq!(std::fs::read(&sentinel).unwrap(), b"unchanged");
        assert!(!root.path().join("outside-0.1.0.crate").exists());
        assert!(!state.blobs_dir.join("outside.crate").exists());
        assert!(!root.path().join(".kin/packages/manifests/outside").exists());
    }

    /// Build a valid `.crate` blob for a simple `[package]` manifest.
    fn valid_crate(name: &str, version: &str) -> Vec<u8> {
        let cargo_toml =
            format!("[package]\nname = \"{name}\"\nversion = \"{version}\"\nedition = \"2021\"\n");
        build_test_crate(name, version, &cargo_toml)
    }

    fn valid_crate_with_padding(name: &str, version: &str, padding_len: usize) -> Vec<u8> {
        use flate2::{write::GzEncoder, Compression};

        let encoder = GzEncoder::new(Vec::new(), Compression::none());
        let mut builder = tar::Builder::new(encoder);
        let cargo_toml =
            format!("[package]\nname = \"{name}\"\nversion = \"{version}\"\nedition = \"2021\"\n");

        let mut manifest_header = tar::Header::new_gnu();
        manifest_header.set_size(cargo_toml.len() as u64);
        manifest_header.set_mode(0o644);
        manifest_header.set_cksum();
        builder
            .append_data(
                &mut manifest_header,
                format!("{name}-{version}/Cargo.toml"),
                cargo_toml.as_bytes(),
            )
            .unwrap();

        let padding = vec![b'x'; padding_len];
        let mut padding_header = tar::Header::new_gnu();
        padding_header.set_size(padding.len() as u64);
        padding_header.set_mode(0o644);
        padding_header.set_cksum();
        builder
            .append_data(
                &mut padding_header,
                format!("{name}-{version}/payload.bin"),
                padding.as_slice(),
            )
            .unwrap();

        let encoder = builder.into_inner().unwrap();
        encoder.finish().unwrap()
    }

    /// Build a `POST .../publish` request with the given query, optional Bearer
    /// token, and raw body bytes.
    fn publish_request(
        name: &str,
        version: &str,
        token: Option<&str>,
        body: Vec<u8>,
    ) -> Request<Body> {
        let uri = format!("/registry/cargo/api/v1/crates/publish?name={name}&version={version}");
        let mut builder = Request::builder().method("POST").uri(uri);
        if let Some(token) = token {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        builder.body(Body::from(body)).unwrap()
    }

    async fn publish(
        state: Arc<CargoRegistryState>,
        name: &str,
        version: &str,
        token: Option<&str>,
        body: Vec<u8>,
    ) -> StatusCode {
        cargo_routes(state)
            .oneshot(publish_request(name, version, token, body))
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn publish_without_configured_token_is_disabled() {
        // (a) No token on state -> fail closed with 503 even with a Bearer header.
        let (_root, state) = registry_state_with_token(None);
        let status = publish(
            state,
            "demo",
            "0.1.0",
            Some("anything"),
            valid_crate("demo", "0.1.0"),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn publish_with_wrong_or_missing_token_is_unauthorized() {
        // (b) Token configured but Authorization wrong/missing -> 401.
        let (_root, state) = registry_state_with_token(Some("s3cret"));

        let missing = publish(
            state.clone(),
            "demo",
            "0.1.0",
            None,
            valid_crate("demo", "0.1.0"),
        )
        .await;
        assert_eq!(missing, StatusCode::UNAUTHORIZED);

        let wrong = publish(
            state,
            "demo",
            "0.1.0",
            Some("nope"),
            valid_crate("demo", "0.1.0"),
        )
        .await;
        assert_eq!(wrong, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn auth_precedes_extraction_and_the_50_mib_limit_bounds_chunked_bodies() {
        let (_root, state) = registry_state_with_token(Some("s3cret"));

        // No Content-Length: the body extractor's explicit DefaultBodyLimit is
        // the only size authority. Invalid auth must still win before that
        // extractor polls or buffers the oversized body.
        let unauthorized = cargo_routes(state.clone())
            .oneshot(publish_request(
                "demo",
                "0.1.0",
                Some("wrong"),
                vec![b'x'; MAX_CRATE_SIZE + 1],
            ))
            .await
            .unwrap();
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
        drop(unauthorized);

        let oversized = cargo_routes(state)
            .oneshot(publish_request(
                "demo",
                "0.1.0",
                Some("s3cret"),
                vec![b'x'; MAX_CRATE_SIZE + 1],
            ))
            .await
            .unwrap();
        assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn declared_oversize_publish_is_rejected_without_reading_the_body() {
        let (_root, state) = registry_state_with_token(Some("s3cret"));
        let response = cargo_routes(state)
            .oneshot(
                Request::post("/registry/cargo/api/v1/crates/publish?name=demo&version=0.1.0")
                    .header("authorization", "Bearer s3cret")
                    .header(header::CONTENT_LENGTH, MAX_CRATE_SIZE + 1)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn publish_above_axum_default_but_below_registry_limit_succeeds() {
        let (_root, state) = registry_state_with_token(Some("s3cret"));
        let body = valid_crate_with_padding("demo", "0.1.0", 3 * 1024 * 1024);
        assert!(body.len() > 2 * 1024 * 1024);
        assert!(body.len() < MAX_CRATE_SIZE);

        let status = publish(state, "demo", "0.1.0", Some("s3cret"), body).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn publish_with_correct_token_and_valid_crate_succeeds() {
        // (c) Correct Bearer + valid .crate -> 200, and the version is registered.
        let (_root, state) = registry_state_with_token(Some("s3cret"));
        let status = publish(
            state.clone(),
            "demo",
            "0.1.0",
            Some("s3cret"),
            valid_crate("demo", "0.1.0"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let versions = state
            .manifest_store
            .get_versions(Ecosystem::Cargo, "demo")
            .unwrap();
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].version, "0.1.0");
    }

    #[tokio::test]
    async fn republishing_existing_version_is_idempotent_for_same_checksum() {
        // (d) Re-publishing the same version with identical bytes repairs the
        // blob if needed, without adding another index entry.
        let (_root, state) = registry_state_with_token(Some("s3cret"));
        let body = valid_crate("demo", "0.1.0");

        let first = publish(state.clone(), "demo", "0.1.0", Some("s3cret"), body.clone()).await;
        assert_eq!(first, StatusCode::OK);

        let blob_path = state.blobs_dir.join("demo-0.1.0.crate");
        assert_eq!(std::fs::read(&blob_path).unwrap(), body);
        std::fs::remove_file(&blob_path).unwrap();

        let second = publish(state.clone(), "demo", "0.1.0", Some("s3cret"), body.clone()).await;
        assert_eq!(second, StatusCode::OK);
        assert_eq!(std::fs::read(&blob_path).unwrap(), body);

        // The original version must still be intact (a single entry).
        let versions = state
            .manifest_store
            .get_versions(Ecosystem::Cargo, "demo")
            .unwrap();
        assert_eq!(versions.len(), 1);
    }

    #[tokio::test]
    async fn failed_idempotent_repair_preserves_the_existing_blob_until_atomic_commit() {
        let (_root, state) = registry_state_with_token(Some("s3cret"));
        let body = valid_crate("demo", "0.1.0");
        assert_eq!(
            publish(state.clone(), "demo", "0.1.0", Some("s3cret"), body.clone(),).await,
            StatusCode::OK
        );

        let blob_path = state.blobs_dir.join("demo-0.1.0.crate");
        let prior_bytes = b"preexisting-corrupt-but-complete-bytes";
        std::fs::write(&blob_path, prior_bytes).unwrap();
        let manifest_before = state
            .manifest_store
            .get_versions(Ecosystem::Cargo, "demo")
            .unwrap();

        // Fail after the replacement is fully staged and fsynced but before
        // the atomic rename. The indexed coordinate and old blob must remain
        // exactly as they were; no temporary file may be exposed or leaked.
        state
            .fail_next_blob_commit
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let failed = publish(state.clone(), "demo", "0.1.0", Some("s3cret"), body.clone()).await;
        assert_eq!(failed, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(std::fs::read(&blob_path).unwrap(), prior_bytes);
        assert_eq!(std::fs::read_dir(&state.blobs_dir).unwrap().count(), 1);

        let manifest_after_failure = state
            .manifest_store
            .get_versions(Ecosystem::Cargo, "demo")
            .unwrap();
        assert_eq!(manifest_after_failure.len(), manifest_before.len());
        assert_eq!(
            manifest_after_failure[0].checksum,
            manifest_before[0].checksum
        );

        assert_eq!(
            publish(state.clone(), "demo", "0.1.0", Some("s3cret"), body.clone(),).await,
            StatusCode::OK
        );
        assert_eq!(std::fs::read(&blob_path).unwrap(), body);
        assert_eq!(std::fs::read_dir(&state.blobs_dir).unwrap().count(), 1);
    }

    #[tokio::test]
    async fn republishing_existing_version_with_different_checksum_does_not_overwrite_blob() {
        let (_root, state) = registry_state_with_token(Some("s3cret"));
        let original = valid_crate("demo", "0.1.0");
        let modified = build_test_crate(
            "demo",
            "0.1.0",
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\ndescription = \"different bytes\"\n",
        );
        assert_ne!(
            hex::encode(Sha256::digest(&original)),
            hex::encode(Sha256::digest(&modified))
        );

        let first = publish(
            state.clone(),
            "demo",
            "0.1.0",
            Some("s3cret"),
            original.clone(),
        )
        .await;
        assert_eq!(first, StatusCode::OK);

        let second = publish(state.clone(), "demo", "0.1.0", Some("s3cret"), modified).await;
        assert_eq!(second, StatusCode::CONFLICT);

        let blob_path = state.blobs_dir.join("demo-0.1.0.crate");
        assert_eq!(std::fs::read(blob_path).unwrap(), original);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_conflicting_publishes_commit_exactly_one_matching_artifact() {
        let (_root, state) = registry_state_with_token(Some("s3cret"));
        let first = build_test_crate(
            "demo",
            "0.1.0",
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\ndescription = \"first\"\n",
        );
        let second = build_test_crate(
            "demo",
            "0.1.0",
            "[package]\nname = \"demo\"\nversion = \"0.1.0\"\nedition = \"2021\"\ndescription = \"second\"\n",
        );
        let first_checksum = hex::encode(Sha256::digest(&first));
        let second_checksum = hex::encode(Sha256::digest(&second));
        assert_ne!(first_checksum, second_checksum);

        let start = Arc::new(tokio::sync::Barrier::new(3));
        let first_task = {
            let state = state.clone();
            let start = start.clone();
            let body = first.clone();
            tokio::spawn(async move {
                start.wait().await;
                publish(state, "demo", "0.1.0", Some("s3cret"), body).await
            })
        };
        let second_task = {
            let state = state.clone();
            let start = start.clone();
            let body = second.clone();
            tokio::spawn(async move {
                start.wait().await;
                publish(state, "demo", "0.1.0", Some("s3cret"), body).await
            })
        };
        start.wait().await;

        let statuses = [first_task.await.unwrap(), second_task.await.unwrap()];
        assert_eq!(
            statuses
                .iter()
                .filter(|status| **status == StatusCode::OK)
                .count(),
            1
        );
        assert_eq!(
            statuses
                .iter()
                .filter(|status| **status == StatusCode::CONFLICT)
                .count(),
            1
        );

        let versions = state
            .manifest_store
            .get_versions(Ecosystem::Cargo, "demo")
            .unwrap();
        assert_eq!(versions.len(), 1);
        let committed_checksum = &versions[0].checksum;
        assert!(
            committed_checksum == &first_checksum || committed_checksum == &second_checksum,
            "unexpected committed checksum {committed_checksum}"
        );

        let blob_path = state.blobs_dir.join("demo-0.1.0.crate");
        let stored = std::fs::read(&blob_path).unwrap();
        assert_eq!(hex::encode(Sha256::digest(&stored)), *committed_checksum);
        let committed_body = if committed_checksum == &first_checksum {
            &first
        } else {
            &second
        };
        assert_eq!(&stored, committed_body);

        let index_response = cargo_routes(state.clone())
            .oneshot(
                Request::get("/registry/cargo/de/mo/demo")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(index_response.status(), StatusCode::OK);
        let index_body = axum::body::to_bytes(index_response.into_body(), usize::MAX)
            .await
            .unwrap();
        let lines = String::from_utf8(index_body.to_vec()).unwrap();
        let entries = lines.lines().collect::<Vec<_>>();
        assert_eq!(entries.len(), 1);
        let entry: serde_json::Value = serde_json::from_str(entries[0]).unwrap();
        assert_eq!(entry["cksum"].as_str(), Some(committed_checksum.as_str()));

        let download_response = cargo_routes(state)
            .oneshot(
                Request::get("/registry/cargo/dl/demo/0.1.0")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(download_response.status(), StatusCode::OK);
        let downloaded = axum::body::to_bytes(download_response.into_body(), MAX_CRATE_SIZE)
            .await
            .unwrap();
        assert_eq!(downloaded.as_ref(), committed_body.as_slice());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn independent_states_preserve_concurrent_versions_and_matching_blobs() {
        let root = tempfile::tempdir().unwrap();
        let kin_dir = root.path().join(".kin");
        let blobs_dir = root.path().join("cargo");
        std::fs::create_dir_all(&kin_dir).unwrap();
        let make_state = || {
            Arc::new(CargoRegistryState::new(
                ManifestStore::new(&kin_dir),
                blobs_dir.clone(),
                "https://kinlab.ai".to_string(),
                Some("s3cret".to_string()),
            ))
        };
        let first_state = make_state();
        let second_state = make_state();
        let first_body = valid_crate("demo", "1.0.0");
        let second_body = valid_crate("demo", "2.0.0");
        let start = Arc::new(tokio::sync::Barrier::new(3));

        let first = {
            let start = start.clone();
            let body = first_body.clone();
            tokio::spawn(async move {
                start.wait().await;
                publish(first_state, "demo", "1.0.0", Some("s3cret"), body).await
            })
        };
        let second = {
            let start = start.clone();
            let body = second_body.clone();
            tokio::spawn(async move {
                start.wait().await;
                publish(second_state, "demo", "2.0.0", Some("s3cret"), body).await
            })
        };
        start.wait().await;
        assert_eq!(first.await.unwrap(), StatusCode::OK);
        assert_eq!(second.await.unwrap(), StatusCode::OK);

        let versions = ManifestStore::new(&kin_dir)
            .get_versions(Ecosystem::Cargo, "demo")
            .unwrap();
        assert_eq!(versions.len(), 2);
        for (version, expected) in [("1.0.0", first_body), ("2.0.0", second_body)] {
            let entry = versions
                .iter()
                .find(|candidate| candidate.version == version)
                .unwrap();
            let stored = std::fs::read(blobs_dir.join(format!("demo-{version}.crate"))).unwrap();
            assert_eq!(stored, expected);
            assert_eq!(entry.checksum, hex::encode(Sha256::digest(&stored)));
        }
    }

    #[tokio::test]
    async fn identical_republish_repairs_legacy_metadata_without_changing_identity() {
        let (_root, state) = registry_state_with_token(Some("s3cret"));
        let body = build_test_crate(
            "demo",
            "1.0.0",
            "[package]\nname = \"demo\"\nversion = \"1.0.0\"\n\n[dependencies]\nserde = \"1\"\n",
        );
        assert_eq!(
            publish(state.clone(), "demo", "1.0.0", Some("s3cret"), body.clone(),).await,
            StatusCode::OK
        );
        let mut legacy = state
            .manifest_store
            .get_versions(Ecosystem::Cargo, "demo")
            .unwrap();
        let published_at = legacy[0].published_at;
        let published_by = legacy[0].published_by.clone();
        legacy[0].metadata = serde_json::json!({});
        state
            .manifest_store
            .replace_versions(&legacy[0].id, &legacy)
            .unwrap();

        assert_eq!(
            publish(state.clone(), "demo", "1.0.0", Some("s3cret"), body).await,
            StatusCode::OK
        );
        let repaired = state
            .manifest_store
            .get_versions(Ecosystem::Cargo, "demo")
            .unwrap();
        assert_eq!(repaired.len(), 1);
        assert_eq!(repaired[0].published_at, published_at);
        assert_eq!(repaired[0].published_by, published_by);
        assert_eq!(repaired[0].metadata["cargo_index_format"], 1);
        assert_eq!(repaired[0].metadata["deps"][0]["name"], "serde");
    }

    #[test]
    fn dependency_registry_urls_are_classified_by_exact_normalized_authority() {
        let configured = configured_sparse_index_url("https://kinlab.ai").unwrap();
        let manifest: toml::Value = toml::from_str(
            r#"
[package]
name = "demo"
version = "1.0.0"

[dependencies]
local = { version = "1", registry-index = "sparse+https://kinlab.ai/registry/cargo" }
attacker = { version = "1", registry-index = "sparse+https://kinlab.ai.evil/registry/cargo" }
"#,
        )
        .unwrap();
        let metadata = extract_crate_metadata(&manifest, &configured).unwrap();
        let deps = metadata["deps"].as_array().unwrap();
        assert_eq!(deps[0]["name"], "attacker");
        assert_eq!(
            deps[0]["registry"],
            "sparse+https://kinlab.ai.evil/registry/cargo/"
        );
        assert_eq!(deps[1]["name"], "local");
        assert!(deps[1]["registry"].is_null());

        let unresolved: toml::Value = toml::from_str(
            r#"
[package]
name = "demo"
version = "1.0.0"
[dependencies]
private = { version = "1", registry = "corp" }
"#,
        )
        .unwrap();
        assert!(extract_crate_metadata(&unresolved, &configured).is_err());
    }

    #[test]
    fn crate_archive_budgets_reject_declared_bombs_before_decompression() {
        use flate2::{write::GzEncoder, Compression};
        use std::io::Write;

        let archive_with_declared_entry = |path: &str, size: u64| {
            let mut header = tar::Header::new_gnu();
            header.set_path(path).unwrap();
            header.set_size(size);
            header.set_mode(0o644);
            header.set_cksum();
            let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
            encoder.write_all(header.as_bytes()).unwrap();
            encoder.finish().unwrap()
        };
        let oversized_manifest =
            archive_with_declared_entry("demo-1.0.0/Cargo.toml", MAX_CRATE_MANIFEST_SIZE + 1);
        let error = parse_crate_manifest(&oversized_manifest, "demo", "1.0.0").unwrap_err();
        assert!(
            error.contains("Cargo.toml") && error.contains("limit"),
            "{error}"
        );

        let oversized_scan =
            archive_with_declared_entry("demo-1.0.0/padding", MAX_CRATE_ARCHIVE_SCAN_SIZE + 1);
        let error = parse_crate_manifest(&oversized_scan, "demo", "1.0.0").unwrap_err();
        assert!(error.contains("scan limit"), "{error}");

        let manifest = b"[package]\nname = \"demo\"\nversion = \"1.0.0\"\n";
        let mut uncompressed = Vec::new();
        let mut manifest_header = tar::Header::new_gnu();
        manifest_header.set_path("demo-1.0.0/Cargo.toml").unwrap();
        manifest_header.set_size(manifest.len() as u64);
        manifest_header.set_mode(0o644);
        manifest_header.set_cksum();
        uncompressed.extend_from_slice(manifest_header.as_bytes());
        uncompressed.extend_from_slice(manifest);
        uncompressed.resize(uncompressed.len().next_multiple_of(512), 0);
        let mut trailing_header = tar::Header::new_gnu();
        trailing_header
            .set_path("demo-1.0.0/trailing-bomb")
            .unwrap();
        trailing_header.set_size(MAX_CRATE_ARCHIVE_SCAN_SIZE + 1);
        trailing_header.set_mode(0o644);
        trailing_header.set_cksum();
        uncompressed.extend_from_slice(trailing_header.as_bytes());
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&uncompressed).unwrap();
        let manifest_first_bomb = encoder.finish().unwrap();
        let error = parse_crate_manifest(&manifest_first_bomb, "demo", "1.0.0").unwrap_err();
        assert!(error.contains("scan limit"), "{error}");
    }

    #[test]
    fn crate_archive_rejects_duplicate_authoritative_manifests() {
        use flate2::{write::GzEncoder, Compression};

        let manifest = b"[package]\nname = \"demo\"\nversion = \"1.0.0\"\n";
        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = tar::Builder::new(encoder);
        for _ in 0..2 {
            let mut header = tar::Header::new_gnu();
            header.set_size(manifest.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, "demo-1.0.0/Cargo.toml", manifest.as_slice())
                .unwrap();
        }
        let encoder = builder.into_inner().unwrap();
        let body = encoder.finish().unwrap();
        let error = parse_crate_manifest(&body, "demo", "1.0.0").unwrap_err();
        assert!(error.contains("more than one authoritative"), "{error}");
    }

    #[tokio::test]
    async fn publish_empty_body_is_rejected() {
        // (e) Empty body -> 400 (with a valid token so we exercise the body check).
        let (_root, state) = registry_state_with_token(Some("s3cret"));
        let status = publish(state, "demo", "0.1.0", Some("s3cret"), Vec::new()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn publish_with_mismatched_manifest_is_rejected() {
        // A valid gzip-tar whose embedded Cargo.toml disagrees with the query
        // coordinates must be refused (400), not stored under the claimed name.
        let (_root, state) = registry_state_with_token(Some("s3cret"));
        // Crate body is internally named other-crate@0.1.0 but published as demo.
        let body = valid_crate("other-crate", "0.1.0");
        let status = publish(state.clone(), "demo", "0.1.0", Some("s3cret"), body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        assert!(state
            .manifest_store
            .get_versions(Ecosystem::Cargo, "demo")
            .unwrap()
            .is_empty());
    }

    #[tokio::test]
    async fn publish_with_non_crate_body_is_rejected() {
        // Arbitrary non-gzip bytes are not a valid .crate -> 400.
        let (_root, state) = registry_state_with_token(Some("s3cret"));
        let status = publish(
            state,
            "demo",
            "0.1.0",
            Some("s3cret"),
            b"this is not a gzip tarball".to_vec(),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn reads_remain_open_without_token() {
        // Read endpoints must stay reachable without any Authorization header,
        // even when a publish token is configured.
        let (_root, state) = registry_state_with_token(Some("s3cret"));
        let response = cargo_routes(state)
            .oneshot(
                Request::builder()
                    .uri("/registry/cargo/config.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[test]
    fn constant_time_eq_matches_only_equal_slices() {
        assert!(constant_time_eq(b"token", b"token"));
        assert!(!constant_time_eq(b"token", b"toke"));
        assert!(!constant_time_eq(b"token", b"tokeN"));
        assert!(constant_time_eq(b"", b""));
    }
}
