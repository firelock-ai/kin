// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! npm registry protocol adapter.
//!
//! Supports scoped and unscoped packages across the core npm flows:
//! - GET /registry/npm/{package}
//! - GET /registry/npm/{package}/{version}
//! - GET /registry/npm/{package}/-/{tarball}
//! - PUT /registry/npm/{package}

use axum::{
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, Extension, OriginalUri, Request, State},
    http::{header, Method, StatusCode, Uri},
    middleware::{self, Next},
    response::{IntoResponse, Json, Response},
    routing::get,
    Router,
};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chrono::{SecondsFormat, Utc};
use percent_encoding::percent_decode_str;
use serde::Deserialize;
use serde_json::{Map, Value};
use sha1::Sha1;
use sha2::{Digest, Sha512};
use std::{collections::BTreeMap, path::Path as FsPath, sync::Arc};

use crate::{Ecosystem, ManifestStore, PackageId, PackageVersion, RegistryError};

const INTERNAL_REGISTRY_KEY: &str = "_kin_registry";
const MAX_NPM_PACKAGE_LEN: usize = 214;
const MAX_NPM_VERSION_LEN: usize = 128;
const MAX_NPM_TARBALL_SIZE: usize = 100 * 1024 * 1024;
const MAX_NPM_PUBLISH_BODY_SIZE: usize = 140 * 1024 * 1024;
const MAX_NPM_ARCHIVE_ENTRIES: u64 = 100_000;
const MAX_NPM_UNPACKED_SIZE: u64 = 1024 * 1024 * 1024;

/// Shared state for the npm registry routes
pub struct NpmRegistryState {
    pub manifest_store: ManifestStore,
    pub blobs_dir: std::path::PathBuf,
    pub base_url: String,
}

impl NpmRegistryState {
    pub fn new(
        manifest_store: ManifestStore,
        blobs_dir: std::path::PathBuf,
        base_url: String,
    ) -> Self {
        let blobs_dir = crate::atomic_file::pin_authority_root(&blobs_dir).unwrap_or(blobs_dir);
        Self {
            manifest_store,
            blobs_dir,
            base_url,
        }
    }
}

/// Authenticated caller metadata injected by the daemon-side registry auth
/// middleware when KinLab token enforcement is enabled.
#[derive(Clone, Debug, Default, serde::Deserialize, serde::Serialize)]
pub struct RegistryAccessIdentity {
    pub user_id: String,
    pub email: String,
    pub display_name: String,
    pub actor_kind: String,
    #[serde(default)]
    pub org_ids: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    pub credential_type: Option<String>,
}

/// Create axum router for npm registry endpoints.
///
/// npm uses a mix of encoded package IDs (`@scope%2Fname`) and scoped tarball
/// paths (`@scope/name/-/name-version.tgz`). A catch-all route lets us parse
/// both forms correctly instead of trying to encode that variability into a
/// fixed axum route tree.
pub fn npm_routes(state: Arc<NpmRegistryState>) -> Router {
    Router::new()
        .route("/registry/npm/{*path}", get(handle_get).put(handle_put))
        .layer(DefaultBodyLimit::max(MAX_NPM_PUBLISH_BODY_SIZE))
        .route_layer(middleware::from_fn(authorize_npm_publish))
        .with_state(state)
}

/// Refuse writes without the daemon-injected identity before Axum polls the
/// request body. This keeps a disabled or unauthenticated registry from
/// buffering the 140 MiB publish envelope merely to return a 503.
async fn authorize_npm_publish(request: Request<Body>, next: Next) -> Response {
    if request.method() != Method::PUT {
        return next.run(request).await;
    }
    if request
        .extensions()
        .get::<RegistryAccessIdentity>()
        .is_none()
    {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": "npm publishing is disabled: no authenticated registry identity",
            })),
        )
            .into_response();
    }
    let declared = request
        .headers()
        .get(header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok());
    if declared.is_some_and(|length| length > MAX_NPM_PUBLISH_BODY_SIZE as u64) {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({
                "error": "npm publish body exceeds the configured size limit",
            })),
        )
            .into_response();
    }
    next.run(request).await
}

async fn handle_get(
    State(state): State<Arc<NpmRegistryState>>,
    OriginalUri(uri): OriginalUri,
) -> Response {
    let route = match parse_route(&uri) {
        Some(route) => route,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    match route {
        ParsedRoute::PackageMetadata { package } => {
            if validate_npm_package(&package).is_err() {
                return invalid_npm_coordinate();
            }
            package_metadata(&state, &package).await
        }
        ParsedRoute::VersionMetadata { package, version } => {
            if validate_npm_package(&package).is_err() || !valid_npm_version(&version) {
                return invalid_npm_coordinate();
            }
            version_metadata(&state, &package, &version).await
        }
        ParsedRoute::Tarball { package, tarball } => {
            if validate_npm_package(&package).is_err() || !valid_npm_tarball_name(&tarball) {
                return invalid_npm_coordinate();
            }
            download_tarball(&state, &package, &tarball).await
        }
    }
}

async fn handle_put(
    State(state): State<Arc<NpmRegistryState>>,
    OriginalUri(uri): OriginalUri,
    identity: Option<Extension<RegistryAccessIdentity>>,
    body: Bytes,
) -> Response {
    let route = match parse_route(&uri) {
        Some(route) => route,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    let package = match route {
        ParsedRoute::PackageMetadata { package } => package,
        _ => return StatusCode::METHOD_NOT_ALLOWED.into_response(),
    };

    let identity = match identity {
        Some(Extension(identity)) => identity,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "npm publishing is disabled: no authenticated registry identity",
                })),
            )
                .into_response();
        }
    };

    if validate_npm_package(&package).is_err() {
        return invalid_npm_coordinate();
    }

    publish_package(&state, &package, identity, body).await
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ParsedRoute {
    PackageMetadata { package: String },
    VersionMetadata { package: String, version: String },
    Tarball { package: String, tarball: String },
}

fn parse_route(uri: &Uri) -> Option<ParsedRoute> {
    let suffix = uri.path().strip_prefix("/registry/npm/")?;
    if suffix.is_empty() {
        return None;
    }

    let raw_segments: Vec<&str> = suffix
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    if raw_segments.is_empty() {
        return None;
    }

    if let Some(dash_index) = raw_segments.iter().position(|segment| *segment == "-") {
        if dash_index == 0 || dash_index + 1 != raw_segments.len() - 1 {
            return None;
        }
        let package = decode_package_path(&raw_segments[..dash_index].join("/"))?;
        let tarball = percent_decode_segment(raw_segments[dash_index + 1])?;
        return Some(ParsedRoute::Tarball { package, tarball });
    }

    match raw_segments.len() {
        1 => {
            let package = decode_package_path(raw_segments[0])?;
            Some(ParsedRoute::PackageMetadata { package })
        }
        2 => {
            if raw_segments[0].starts_with('@') && !contains_encoded_slash(raw_segments[0]) {
                let package = format!(
                    "{}/{}",
                    raw_segments[0],
                    percent_decode_segment(raw_segments[1])?
                );
                return Some(ParsedRoute::PackageMetadata { package });
            }

            let package = decode_package_path(raw_segments[0])?;
            let version = percent_decode_segment(raw_segments[1])?;
            Some(ParsedRoute::VersionMetadata { package, version })
        }
        3 => {
            if !raw_segments[0].starts_with('@') {
                return None;
            }
            let package = format!(
                "{}/{}",
                raw_segments[0],
                percent_decode_segment(raw_segments[1])?
            );
            let version = percent_decode_segment(raw_segments[2])?;
            Some(ParsedRoute::VersionMetadata { package, version })
        }
        _ => None,
    }
}

fn contains_encoded_slash(segment: &str) -> bool {
    segment.contains("%2f") || segment.contains("%2F")
}

fn percent_decode_segment(segment: &str) -> Option<String> {
    percent_decode_str(segment)
        .decode_utf8()
        .ok()
        .map(|value| value.into_owned())
}

fn decode_package_path(raw: &str) -> Option<String> {
    let decoded = percent_decode_segment(raw)?;
    if decoded.is_empty() {
        return None;
    }
    Some(decoded)
}

fn valid_npm_name_segment(segment: &str) -> bool {
    if segment.is_empty() || segment == "." || segment == ".." {
        return false;
    }
    let bytes = segment.as_bytes();
    bytes
        .first()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
}

fn validate_npm_package(package: &str) -> Result<PackageId, String> {
    if package.is_empty() || package.len() > MAX_NPM_PACKAGE_LEN {
        return Err("npm package name is empty or too long".to_string());
    }
    if let Some(scoped) = package.strip_prefix('@') {
        let Some((scope, name)) = scoped.split_once('/') else {
            return Err("scoped npm package must contain one scope and one name".to_string());
        };
        if name.contains('/') || !valid_npm_name_segment(scope) || !valid_npm_name_segment(name) {
            return Err("scoped npm package contains an invalid segment".to_string());
        }
        return Ok(PackageId {
            ecosystem: Ecosystem::Npm,
            scope: Some(scope.to_string()),
            name: name.to_string(),
        });
    }
    if package.contains('/') || !valid_npm_name_segment(package) {
        return Err("npm package contains an invalid segment".to_string());
    }
    Ok(PackageId {
        ecosystem: Ecosystem::Npm,
        scope: None,
        name: package.to_string(),
    })
}

fn valid_npm_version(version: &str) -> bool {
    !version.is_empty()
        && version.len() <= MAX_NPM_VERSION_LEN
        && semver::Version::parse(version).is_ok()
}

fn valid_npm_tarball_name(tarball: &str) -> bool {
    !tarball.is_empty()
        && tarball.len() <= MAX_NPM_PACKAGE_LEN + MAX_NPM_VERSION_LEN + 5
        && tarball.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
        && !tarball.contains("..")
}

fn invalid_npm_coordinate() -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({ "error": "invalid npm package coordinate" })),
    )
        .into_response()
}

async fn package_metadata(state: &NpmRegistryState, package: &str) -> Response {
    let transaction = match state
        .manifest_store
        .read_transaction_async(Ecosystem::Npm)
        .await
    {
        Ok(transaction) => transaction,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let versions = match transaction.get_versions(package) {
        Ok(v) if v.is_empty() => return StatusCode::NOT_FOUND.into_response(),
        Ok(v) => v,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };

    let mut version_map = Map::new();
    let mut dist_tags = Map::new();
    let mut time = Map::new();

    let created = versions
        .iter()
        .map(|version| version.published_at)
        .min()
        .unwrap_or_else(Utc::now);
    let modified = versions
        .iter()
        .map(|version| version.published_at)
        .max()
        .unwrap_or_else(Utc::now);

    time.insert(
        "created".to_string(),
        Value::String(format_npm_time(created)),
    );
    time.insert(
        "modified".to_string(),
        Value::String(format_npm_time(modified)),
    );

    for version in &versions {
        let entry = match npm_version_document(state, package, version) {
            Ok(document) => document,
            Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
        version_map.insert(version.version.clone(), entry);
        time.insert(
            version.version.clone(),
            Value::String(format_npm_time(version.published_at)),
        );

        if let Some(tags) = registry_metadata(version).and_then(|meta| meta.dist_tags) {
            for (tag, value) in tags {
                dist_tags.insert(tag, Value::String(value));
            }
        }
    }

    if dist_tags.is_empty() {
        if let Some(latest) = versions.last() {
            dist_tags.insert("latest".to_string(), Value::String(latest.version.clone()));
        }
    }

    let latest = match versions.last() {
        Some(latest) => latest,
        None => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let latest_document = match npm_version_document(state, package, latest) {
        Ok(document) => document,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let readme = latest_document.get("readme").cloned().or_else(|| {
        registry_metadata(latest).and_then(|meta| meta.readme.clone().map(Value::String))
    });

    let description = latest_document.get("description").cloned();

    let mut response = serde_json::json!({
        "_id": package,
        "name": package,
        "dist-tags": dist_tags,
        "versions": version_map,
        "time": time,
    });

    if let Some(readme) = readme {
        response["readme"] = readme;
    }
    if let Some(description) = description {
        response["description"] = description;
    }

    Json(response).into_response()
}

async fn version_metadata(state: &NpmRegistryState, package: &str, version: &str) -> Response {
    let transaction = match state
        .manifest_store
        .read_transaction_async(Ecosystem::Npm)
        .await
    {
        Ok(transaction) => transaction,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let versions = match transaction.get_versions(package) {
        Ok(v) => v,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };

    match versions.iter().find(|entry| entry.version == version) {
        Some(entry) => match npm_version_document(state, package, entry) {
            Ok(response) => Json(response).into_response(),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        },
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn download_tarball(state: &NpmRegistryState, package: &str, tarball: &str) -> Response {
    let transaction = match state
        .manifest_store
        .read_transaction_async(Ecosystem::Npm)
        .await
    {
        Ok(transaction) => transaction,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let versions = match transaction.get_versions(package) {
        Ok(v) => v,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };

    let pkg_version = match versions.iter().find(|version| {
        registry_metadata(version)
            .map(|meta| meta.tarball_filename == tarball)
            .unwrap_or(false)
    }) {
        Some(version) => version,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    let metadata = match registry_metadata(pkg_version) {
        Some(metadata) => metadata,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    let tarball_path =
        match stored_npm_blob_path(&state.blobs_dir, package, &pkg_version.version, &metadata) {
            Some(path) => path,
            None => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        };
    match std::fs::read(&tarball_path) {
        Ok(bytes) => (
            StatusCode::OK,
            [
                (
                    "content-type",
                    metadata
                        .content_type
                        .as_deref()
                        .unwrap_or("application/octet-stream"),
                ),
                ("etag", &format!("\"{}\"", pkg_version.checksum)),
            ],
            bytes,
        )
            .into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

#[derive(Debug, Deserialize)]
struct NpmPublishRequest {
    #[serde(rename = "_id")]
    _id: String,
    name: String,
    #[serde(rename = "dist-tags", default)]
    dist_tags: Map<String, Value>,
    #[serde(default)]
    versions: Map<String, Value>,
    #[serde(default)]
    access: Option<String>,
    #[serde(rename = "_attachments", default)]
    attachments: BTreeMap<String, NpmAttachment>,
}

#[derive(Debug, Deserialize)]
struct NpmAttachment {
    #[serde(default)]
    content_type: Option<String>,
    data: String,
    #[serde(default)]
    length: Option<u64>,
}

async fn publish_package(
    state: &NpmRegistryState,
    package: &str,
    identity: RegistryAccessIdentity,
    body: Bytes,
) -> Response {
    let publish_request: NpmPublishRequest = match serde_json::from_slice(&body) {
        Ok(request) => request,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!("invalid npm publish payload: {error}"),
                })),
            )
                .into_response();
        }
    };

    if publish_request.name != package || publish_request._id != package {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "package path does not match publish payload",
            })),
        )
            .into_response();
    }

    if publish_request.versions.len() != 1 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "npm publish payload must contain exactly one version",
            })),
        )
            .into_response();
    }
    let (version, mut version_document) = match publish_request.versions.into_iter().next() {
        Some((version, Value::Object(document))) => (version, Value::Object(document)),
        Some(_) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "npm publish payload must contain an object version document",
                })),
            )
                .into_response();
        }
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "npm publish payload did not include any versions",
                })),
            )
                .into_response();
        }
    };

    if !valid_npm_version(&version) {
        return invalid_npm_coordinate();
    }
    if version_document.get("name").and_then(Value::as_str) != Some(package)
        || version_document.get("version").and_then(Value::as_str) != Some(version.as_str())
    {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "npm version document does not match the published coordinate",
            })),
        )
            .into_response();
    }

    let package_id = match validate_npm_package(package) {
        Ok(package_id) => package_id,
        Err(_) => return invalid_npm_coordinate(),
    };

    let tarball_filename = tarball_filename(&package_id, &version);

    let attachment = match select_attachment(&publish_request.attachments, &package_id, &version) {
        Some(attachment) => attachment,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "npm publish payload is missing a tarball attachment",
                })),
            )
                .into_response();
        }
    };

    let tarball_bytes = match STANDARD.decode(attachment.data.as_bytes()) {
        Ok(bytes) => bytes,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": format!("invalid attachment encoding: {error}"),
                })),
            )
                .into_response();
        }
    };
    if tarball_bytes.is_empty() || tarball_bytes.len() > MAX_NPM_TARBALL_SIZE {
        return (
            StatusCode::PAYLOAD_TOO_LARGE,
            Json(serde_json::json!({
                "error": "npm tarball is empty or exceeds the configured size limit",
            })),
        )
            .into_response();
    }

    if let Some(expected_length) = attachment.length {
        if expected_length != tarball_bytes.len() as u64 {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "attachment length does not match payload",
                })),
            )
                .into_response();
        }
    }

    let shasum = hex::encode(Sha1::digest(&tarball_bytes));
    let blob_hash = hex::encode(sha2::Sha256::digest(&tarball_bytes));
    let integrity = format!("sha512-{}", STANDARD.encode(Sha512::digest(&tarball_bytes)));
    let (file_count, unpacked_size) = match tarball_stats(&tarball_bytes) {
        Ok(stats) => stats,
        Err(error) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": error })),
            )
                .into_response();
        }
    };

    let (tarball_rel_path, tarball_path) =
        match npm_blob_path(&state.blobs_dir, &package_id, &version) {
            Some(paths) => paths,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": "invalid npm package name",
                    })),
                )
                    .into_response();
            }
        };
    let transaction = match state
        .manifest_store
        .write_transaction_async(Ecosystem::Npm)
        .await
    {
        Ok(transaction) => transaction,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("{error}") })),
            )
                .into_response();
        }
    };
    let existing = match transaction.get_versions(package) {
        Ok(existing) => existing,
        Err(error) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("{error}") })),
            )
                .into_response();
        }
    };
    if existing.iter().any(|entry| entry.version == version) {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": format!("version already exists: {package}@{version}"),
            })),
        )
            .into_response();
    }
    if let Err(error) = crate::atomic_file::write(&tarball_path, &tarball_bytes) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({
                "error": format!("failed to store npm tarball: {error}"),
            })),
        )
            .into_response();
    }

    let mut registry_metadata = Map::new();
    registry_metadata.insert(
        "tarball_filename".to_string(),
        Value::String(tarball_filename.clone()),
    );
    registry_metadata.insert(
        "blob_rel_path".to_string(),
        Value::String(tarball_rel_path.to_string_lossy().into_owned()),
    );
    registry_metadata.insert(
        "content_type".to_string(),
        Value::String(
            attachment
                .content_type
                .clone()
                .unwrap_or_else(|| "application/octet-stream".to_string()),
        ),
    );
    registry_metadata.insert("shasum".to_string(), Value::String(shasum.clone()));
    registry_metadata.insert("integrity".to_string(), Value::String(integrity.clone()));
    registry_metadata.insert("file_count".to_string(), Value::from(file_count));
    registry_metadata.insert("unpacked_size".to_string(), Value::from(unpacked_size));
    if !publish_request.dist_tags.is_empty() {
        registry_metadata.insert(
            "dist_tags".to_string(),
            Value::Object(
                publish_request
                    .dist_tags
                    .iter()
                    .filter_map(|(key, value)| {
                        value
                            .as_str()
                            .map(|value| (key.clone(), Value::String(value.to_string())))
                    })
                    .collect(),
            ),
        );
    }
    if let Some(access) = &publish_request.access {
        registry_metadata.insert("access".to_string(), Value::String(access.clone()));
    }

    if let Some(document) = version_document.as_object_mut() {
        document.insert(
            INTERNAL_REGISTRY_KEY.to_string(),
            Value::Object(registry_metadata),
        );
    }

    let published_by = identity.email;

    let package_version = PackageVersion {
        id: package_id,
        version: version.clone(),
        blob_hash,
        blob_size: tarball_bytes.len() as u64,
        checksum: shasum.clone(),
        metadata: version_document,
        published_at: Utc::now(),
        published_by,
        yanked: false,
    };

    match transaction.add_version(&package_version) {
        Ok(()) => (
            StatusCode::CREATED,
            Json(serde_json::json!({
                "ok": "created",
                "id": package,
                "name": package,
                "version": version,
            })),
        )
            .into_response(),
        Err(RegistryError::VersionExists(name, version)) => (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "error": format!("version already exists: {name}@{version}"),
            })),
        )
            .into_response(),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": format!("{error}") })),
        )
            .into_response(),
    }
}

fn select_attachment<'a>(
    attachments: &'a BTreeMap<String, NpmAttachment>,
    package_id: &PackageId,
    version: &str,
) -> Option<&'a NpmAttachment> {
    if attachments.is_empty() {
        return None;
    }

    let canonical = format!("{}-{}.tgz", package_id.canonical_name(), version);
    let encoded_scope = match &package_id.scope {
        Some(scope) => format!("@{scope}%2F{}-{}.tgz", package_id.name, version),
        None => format!("{}-{}.tgz", package_id.name, version),
    };
    let packed = match &package_id.scope {
        Some(scope) => format!("{scope}-{}-{}.tgz", package_id.name, version),
        None => format!("{}-{}.tgz", package_id.name, version),
    };
    let leaf = tarball_filename(package_id, version);

    attachments
        .get(&canonical)
        .or_else(|| attachments.get(&encoded_scope))
        .or_else(|| attachments.get(&packed))
        .or_else(|| attachments.get(&leaf))
        .or_else(|| attachments.values().next())
}

fn tarball_filename(package_id: &PackageId, version: &str) -> String {
    format!("{}-{}.tgz", package_id.name, version)
}

fn tarball_dir(package_id: &PackageId) -> Option<std::path::PathBuf> {
    let mut path = std::path::PathBuf::new();
    if let Some(scope) = &package_id.scope {
        if scope.is_empty() {
            return None;
        }
        path.push(format!("@{scope}"));
    }
    path.push(&package_id.name);
    Some(path)
}

fn npm_blob_path(
    blobs_dir: &FsPath,
    package_id: &PackageId,
    version: &str,
) -> Option<(std::path::PathBuf, std::path::PathBuf)> {
    let validated = validate_npm_package(&package_id.canonical_name()).ok()?;
    if package_id.ecosystem != Ecosystem::Npm
        || !valid_npm_version(version)
        || validated.scope != package_id.scope
        || validated.name != package_id.name
    {
        return None;
    }
    let directory = tarball_dir(package_id)?;
    let relative = directory.join(tarball_filename(package_id, version));
    if relative
        .components()
        .any(|component| !matches!(component, std::path::Component::Normal(_)))
    {
        return None;
    }
    let package_directory = blobs_dir.join(&directory);
    let path = blobs_dir.join(&relative);
    (path.parent() == Some(package_directory.as_path())).then_some((relative, path))
}

fn stored_npm_blob_path(
    blobs_dir: &FsPath,
    package: &str,
    version: &str,
    metadata: &ParsedRegistryMetadata,
) -> Option<std::path::PathBuf> {
    let package_id = validate_npm_package(package).ok()?;
    let (expected_relative, expected_path) = npm_blob_path(blobs_dir, &package_id, version)?;
    if metadata.tarball_filename != tarball_filename(&package_id, version)
        || FsPath::new(&metadata.blob_rel_path) != expected_relative
    {
        return None;
    }
    Some(expected_path)
}

fn npm_version_document(
    state: &NpmRegistryState,
    package: &str,
    version: &PackageVersion,
) -> Result<Value, RegistryError> {
    let mut document = version.metadata.clone();
    let registry_metadata =
        registry_metadata(version).ok_or_else(|| RegistryError::NotFound(package.to_string()))?;

    if let Some(map) = document.as_object_mut() {
        map.remove(INTERNAL_REGISTRY_KEY);

        let tarball = format!(
            "{}/registry/npm/{}/-/{}",
            state.base_url.trim_end_matches('/'),
            package,
            registry_metadata.tarball_filename,
        );

        let mut dist = map
            .remove("dist")
            .and_then(|value| value.as_object().cloned())
            .unwrap_or_default();
        dist.insert("tarball".to_string(), Value::String(tarball));
        dist.insert(
            "shasum".to_string(),
            Value::String(registry_metadata.shasum.to_string()),
        );
        dist.insert(
            "integrity".to_string(),
            Value::String(registry_metadata.integrity.to_string()),
        );
        dist.insert(
            "fileCount".to_string(),
            Value::from(registry_metadata.file_count),
        );
        dist.insert(
            "unpackedSize".to_string(),
            Value::from(registry_metadata.unpacked_size),
        );
        map.insert("dist".to_string(), Value::Object(dist));
    }

    Ok(document)
}

fn format_npm_time(timestamp: chrono::DateTime<Utc>) -> String {
    timestamp.to_rfc3339_opts(SecondsFormat::Millis, true)
}

fn tarball_stats(tarball_bytes: &[u8]) -> Result<(u64, u64), String> {
    use flate2::read::GzDecoder;

    let gz = GzDecoder::new(tarball_bytes);
    let mut archive = tar::Archive::new(gz);
    let mut file_count = 0u64;
    let mut unpacked_size = 0u64;

    let entries = archive
        .entries()
        .map_err(|error| format!("npm attachment is not a valid gzip-tar archive: {error}"))?;
    for entry in entries {
        let entry = entry
            .map_err(|error| format!("npm attachment is not a valid gzip-tar archive: {error}"))?;
        file_count = file_count
            .checked_add(1)
            .ok_or_else(|| "npm archive entry count overflowed".to_string())?;
        if file_count > MAX_NPM_ARCHIVE_ENTRIES {
            return Err(format!(
                "npm archive exceeds the {MAX_NPM_ARCHIVE_ENTRIES} entry limit"
            ));
        }
        let size = entry
            .header()
            .size()
            .map_err(|error| format!("npm archive entry has an invalid size: {error}"))?;
        unpacked_size = unpacked_size
            .checked_add(size)
            .ok_or_else(|| "npm archive unpacked size overflowed".to_string())?;
        if unpacked_size > MAX_NPM_UNPACKED_SIZE {
            return Err(format!(
                "npm archive exceeds the {MAX_NPM_UNPACKED_SIZE} byte unpacked limit"
            ));
        }
    }

    Ok((file_count, unpacked_size))
}

#[derive(Debug, Clone)]
struct ParsedRegistryMetadata {
    tarball_filename: String,
    blob_rel_path: String,
    content_type: Option<String>,
    shasum: String,
    integrity: String,
    file_count: u64,
    unpacked_size: u64,
    dist_tags: Option<BTreeMap<String, String>>,
    readme: Option<String>,
}

fn registry_metadata(version: &PackageVersion) -> Option<ParsedRegistryMetadata> {
    let internal = version.metadata.get(INTERNAL_REGISTRY_KEY)?.as_object()?;
    let dist_tags = internal.get("dist_tags").and_then(|value| {
        value.as_object().map(|tags| {
            tags.iter()
                .filter_map(|(key, value)| {
                    value.as_str().map(|value| (key.clone(), value.to_string()))
                })
                .collect()
        })
    });

    Some(ParsedRegistryMetadata {
        tarball_filename: internal.get("tarball_filename")?.as_str()?.to_string(),
        blob_rel_path: internal.get("blob_rel_path")?.as_str()?.to_string(),
        content_type: internal
            .get("content_type")
            .and_then(|value| value.as_str())
            .map(|value| value.to_string()),
        shasum: internal.get("shasum")?.as_str()?.to_string(),
        integrity: internal.get("integrity")?.as_str()?.to_string(),
        file_count: internal
            .get("file_count")
            .and_then(|value| value.as_u64())
            .unwrap_or(0),
        unpacked_size: internal
            .get("unpacked_size")
            .and_then(|value| value.as_u64())
            .unwrap_or(0),
        dist_tags,
        readme: version
            .metadata
            .get("readme")
            .and_then(|value| value.as_str())
            .map(|value| value.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use tower::ServiceExt;

    fn registry_state() -> (tempfile::TempDir, Arc<NpmRegistryState>) {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(".kin")).unwrap();
        let state = Arc::new(NpmRegistryState::new(
            ManifestStore::new(&root.path().join(".kin")),
            root.path().join("npm"),
            "https://kinlab.ai".to_string(),
        ));
        (root, state)
    }

    fn publish_identity() -> RegistryAccessIdentity {
        RegistryAccessIdentity {
            email: "builder@firelock.ai".to_string(),
            display_name: "Builder".to_string(),
            user_id: "user_123".to_string(),
            actor_kind: "human".to_string(),
            org_ids: vec![],
            scopes: vec!["packages:write".to_string()],
            credential_type: Some("pat".to_string()),
        }
    }

    fn build_test_tarball(marker: &str) -> Vec<u8> {
        use flate2::{write::GzEncoder, Compression};

        let encoder = GzEncoder::new(Vec::new(), Compression::default());
        let mut builder = tar::Builder::new(encoder);
        let contents = format!("module.exports = {marker:?};\n");
        let mut header = tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "package/index.js", contents.as_bytes())
            .unwrap();
        builder.into_inner().unwrap().finish().unwrap()
    }

    fn publish_payload(package: &str, version: &str, tarball: &[u8]) -> Value {
        let attachment = format!("{package}-{version}.tgz");
        serde_json::json!({
            "_id": package,
            "name": package,
            "dist-tags": { "latest": version },
            "versions": {
                version: {
                    "name": package,
                    "version": version,
                }
            },
            "_attachments": {
                attachment: {
                    "content_type": "application/octet-stream",
                    "data": STANDARD.encode(tarball),
                    "length": tarball.len(),
                }
            }
        })
    }

    #[test]
    fn parses_encoded_scoped_package_routes() {
        let package_uri = Uri::from_static("/registry/npm/@kin%2Fboundary-contracts");
        let version_uri = Uri::from_static("/registry/npm/@kin%2Fboundary-contracts/0.1.0");
        let tarball_uri = Uri::from_static(
            "/registry/npm/@kin/boundary-contracts/-/boundary-contracts-0.1.0.tgz",
        );

        assert_eq!(
            parse_route(&package_uri),
            Some(ParsedRoute::PackageMetadata {
                package: "@kin/boundary-contracts".to_string(),
            })
        );
        assert_eq!(
            parse_route(&version_uri),
            Some(ParsedRoute::VersionMetadata {
                package: "@kin/boundary-contracts".to_string(),
                version: "0.1.0".to_string(),
            })
        );
        assert_eq!(
            parse_route(&tarball_uri),
            Some(ParsedRoute::Tarball {
                package: "@kin/boundary-contracts".to_string(),
                tarball: "boundary-contracts-0.1.0.tgz".to_string(),
            })
        );
    }

    #[tokio::test]
    async fn publishes_and_reads_back_scoped_package_metadata() {
        let (_root, state) = registry_state();
        let app = npm_routes(state.clone());
        let tarball_bytes = build_test_tarball("boundary-contracts");
        let payload = serde_json::json!({
            "_id": "@kin/boundary-contracts",
            "name": "@kin/boundary-contracts",
            "dist-tags": { "latest": "0.1.0" },
            "versions": {
                "0.1.0": {
                    "name": "@kin/boundary-contracts",
                    "version": "0.1.0",
                    "description": "Boundary contracts",
                    "readme": "# Boundary Contracts",
                    "dependencies": {
                        "zod": "^4.0.0"
                    }
                }
            },
            "_attachments": {
                "@kin/boundary-contracts-0.1.0.tgz": {
                    "content_type": "application/octet-stream",
                    "data": STANDARD.encode(&tarball_bytes),
                    "length": tarball_bytes.len()
                }
            }
        });

        let publish = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri("/registry/npm/@kin%2Fboundary-contracts")
                    .extension(publish_identity())
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(publish.status(), StatusCode::CREATED);

        let package = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/registry/npm/@kin%2Fboundary-contracts")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(package.status(), StatusCode::OK);
        let package_body = axum::body::to_bytes(package.into_body(), usize::MAX)
            .await
            .unwrap();
        let package_json: Value = serde_json::from_slice(&package_body).unwrap();
        assert_eq!(package_json["name"], "@kin/boundary-contracts");
        assert_eq!(package_json["dist-tags"]["latest"], "0.1.0");
        assert_eq!(
            package_json["versions"]["0.1.0"]["dist"]["tarball"],
            "https://kinlab.ai/registry/npm/@kin/boundary-contracts/-/boundary-contracts-0.1.0.tgz"
        );
        assert_eq!(
            package_json["versions"]["0.1.0"]["dependencies"]["zod"],
            "^4.0.0"
        );

        let version = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/registry/npm/@kin%2Fboundary-contracts/0.1.0")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(version.status(), StatusCode::OK);
        let version_body = axum::body::to_bytes(version.into_body(), usize::MAX)
            .await
            .unwrap();
        let version_json: Value = serde_json::from_slice(&version_body).unwrap();
        assert_eq!(version_json["name"], "@kin/boundary-contracts");
        assert_eq!(version_json["version"], "0.1.0");

        let tarball = app
            .oneshot(
                Request::builder()
                    .uri("/registry/npm/@kin/boundary-contracts/-/boundary-contracts-0.1.0.tgz")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(tarball.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn rejects_immutable_version_republish() {
        let (_root, state) = registry_state();
        let app = npm_routes(state);
        let tarball_bytes = build_test_tarball("immutable");
        let payload = serde_json::json!({
            "_id": "@kin/boundary-contracts",
            "name": "@kin/boundary-contracts",
            "dist-tags": { "latest": "0.1.0" },
            "versions": {
                "0.1.0": {
                    "name": "@kin/boundary-contracts",
                    "version": "0.1.0"
                }
            },
            "_attachments": {
                "@kin/boundary-contracts-0.1.0.tgz": {
                    "content_type": "application/octet-stream",
                    "data": STANDARD.encode(&tarball_bytes),
                    "length": tarball_bytes.len()
                }
            }
        });

        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri("/registry/npm/@kin%2Fboundary-contracts")
                    .extension(publish_identity())
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(first.status(), StatusCode::CREATED);

        let second = app
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri("/registry/npm/@kin%2Fboundary-contracts")
                    .extension(publish_identity())
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn publishing_fails_closed_without_an_authenticated_identity() {
        let (_root, state) = registry_state();
        let response = npm_routes(state)
            .oneshot(
                Request::put("/registry/npm/demo")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn unauthenticated_publish_is_rejected_without_polling_the_body() {
        use std::task::Poll;

        let (_root, state) = registry_state();
        let body = Body::from_stream(futures_util::stream::poll_fn(
            |_| -> Poll<Option<Result<Bytes, std::io::Error>>> {
                panic!("unauthenticated npm request body was polled")
            },
        ));
        let response = npm_routes(state)
            .oneshot(
                Request::put("/registry/npm/demo")
                    .header("content-type", "application/json")
                    .body(body)
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn stored_tarball_metadata_cannot_redirect_reads_outside_the_blob_root() {
        let root = tempfile::tempdir().unwrap();
        let metadata = ParsedRegistryMetadata {
            tarball_filename: "demo-1.0.0.tgz".to_string(),
            blob_rel_path: "../outside".to_string(),
            content_type: None,
            shasum: "checksum".to_string(),
            integrity: "integrity".to_string(),
            file_count: 0,
            unpacked_size: 0,
            dist_tags: None,
            readme: None,
        };
        assert!(stored_npm_blob_path(root.path(), "demo", "1.0.0", &metadata).is_none());
        for invalid in [
            "../demo",
            "@scope/../demo",
            "@../demo",
            "demo/../../outside",
        ] {
            assert!(
                validate_npm_package(invalid).is_err(),
                "accepted {invalid:?}"
            );
        }
    }

    #[test]
    fn archive_stats_reject_invalid_and_declared_oversize_tarballs() {
        assert!(tarball_stats(b"not-a-tarball").is_err());

        use flate2::{write::GzEncoder, Compression};
        use std::io::Write;
        let mut header = tar::Header::new_gnu();
        header.set_size(MAX_NPM_UNPACKED_SIZE + 1);
        header.set_mode(0o644);
        header.set_cksum();
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(header.as_bytes()).unwrap();
        let declared_oversize = encoder.finish().unwrap();
        let error = tarball_stats(&declared_oversize).unwrap_err();
        assert!(error.contains("unpacked limit"), "{error}");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn independent_states_preserve_concurrent_versions_and_matching_blobs() {
        let root = tempfile::tempdir().unwrap();
        let kin_dir = root.path().join(".kin");
        let blobs_dir = root.path().join("npm");
        std::fs::create_dir_all(&kin_dir).unwrap();
        let make_state = || {
            Arc::new(NpmRegistryState::new(
                ManifestStore::new(&kin_dir),
                blobs_dir.clone(),
                "https://kinlab.ai".to_string(),
            ))
        };
        let first_state = make_state();
        let second_state = make_state();
        let first_tarball = build_test_tarball("first");
        let second_tarball = build_test_tarball("second");
        let start = Arc::new(tokio::sync::Barrier::new(3));

        let publish = |state: Arc<NpmRegistryState>,
                       version: &'static str,
                       tarball: Vec<u8>,
                       start: Arc<tokio::sync::Barrier>| {
            tokio::spawn(async move {
                let payload = publish_payload("demo", version, &tarball);
                start.wait().await;
                npm_routes(state)
                    .oneshot(
                        Request::put("/registry/npm/demo")
                            .extension(publish_identity())
                            .header("content-type", "application/json")
                            .body(Body::from(payload.to_string()))
                            .unwrap(),
                    )
                    .await
                    .unwrap()
                    .status()
            })
        };
        let first = publish(first_state, "1.0.0", first_tarball.clone(), start.clone());
        let second = publish(second_state, "2.0.0", second_tarball.clone(), start.clone());
        start.wait().await;
        assert_eq!(first.await.unwrap(), StatusCode::CREATED);
        assert_eq!(second.await.unwrap(), StatusCode::CREATED);

        let versions = ManifestStore::new(&kin_dir)
            .get_versions(Ecosystem::Npm, "demo")
            .unwrap();
        assert_eq!(versions.len(), 2);
        for (version, expected) in [("1.0.0", first_tarball), ("2.0.0", second_tarball)] {
            let entry = versions
                .iter()
                .find(|candidate| candidate.version == version)
                .unwrap();
            let metadata = registry_metadata(entry).unwrap();
            let path = stored_npm_blob_path(&blobs_dir, "demo", version, &metadata).unwrap();
            assert_eq!(std::fs::read(path).unwrap(), expected);
        }
    }
}
