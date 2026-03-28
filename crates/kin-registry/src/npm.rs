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
    body::Bytes,
    extract::{Extension, OriginalUri, State},
    http::{StatusCode, Uri},
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
use std::{collections::BTreeMap, sync::Arc};

use crate::{Ecosystem, ManifestStore, PackageId, PackageVersion, RegistryError};

const INTERNAL_REGISTRY_KEY: &str = "_kin_registry";

/// Shared state for the npm registry routes
pub struct NpmRegistryState {
    pub manifest_store: ManifestStore,
    pub blobs_dir: std::path::PathBuf,
    pub base_url: String,
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
        .with_state(state)
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
        ParsedRoute::PackageMetadata { package } => package_metadata(&state, &package),
        ParsedRoute::VersionMetadata { package, version } => {
            version_metadata(&state, &package, &version)
        }
        ParsedRoute::Tarball { package, tarball } => download_tarball(&state, &package, &tarball),
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

    publish_package(
        &state,
        &package,
        identity.map(|extension| extension.0),
        body,
    )
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

fn package_metadata(state: &NpmRegistryState, package: &str) -> Response {
    let versions = match state.manifest_store.get_versions(Ecosystem::Npm, package) {
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

    let latest = versions.last().expect("versions is not empty");
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

fn version_metadata(state: &NpmRegistryState, package: &str, version: &str) -> Response {
    let versions = match state.manifest_store.get_versions(Ecosystem::Npm, package) {
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

fn download_tarball(state: &NpmRegistryState, package: &str, tarball: &str) -> Response {
    let versions = match state.manifest_store.get_versions(Ecosystem::Npm, package) {
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

    let tarball_path = state.blobs_dir.join(&metadata.blob_rel_path);
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

fn publish_package(
    state: &NpmRegistryState,
    package: &str,
    identity: Option<RegistryAccessIdentity>,
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

    let existing = match state.manifest_store.get_versions(Ecosystem::Npm, package) {
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

    let package_id = PackageId::from_registry_name(Ecosystem::Npm, package);
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
    let (file_count, unpacked_size) = tarball_stats(&tarball_bytes);

    let package_dir = match tarball_dir(&package_id) {
        Some(dir) => dir,
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
    let tarball_rel_path = package_dir.join(&tarball_filename);
    let tarball_path = state.blobs_dir.join(&tarball_rel_path);

    if let Some(parent) = tarball_path.parent() {
        if let Err(error) = std::fs::create_dir_all(parent) {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!("failed to create npm blob directory: {error}"),
                })),
            )
                .into_response();
        }
    }

    if let Err(error) = std::fs::write(&tarball_path, &tarball_bytes) {
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

    let published_by = identity
        .as_ref()
        .map(|caller| caller.email.clone())
        .unwrap_or_else(|| "anonymous".to_string());

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

    match state.manifest_store.add_version(&package_version) {
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

fn tarball_stats(tarball_bytes: &[u8]) -> (u64, u64) {
    use flate2::read::GzDecoder;

    let gz = GzDecoder::new(tarball_bytes);
    let mut archive = tar::Archive::new(gz);
    let mut file_count = 0u64;
    let mut unpacked_size = 0u64;

    if let Ok(entries) = archive.entries() {
        for entry in entries.flatten() {
            file_count += 1;
            unpacked_size += entry.header().size().unwrap_or(0);
        }
    }

    (file_count, unpacked_size)
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

    fn registry_state() -> Arc<NpmRegistryState> {
        let root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(root.path().join(".kin")).unwrap();
        Arc::new(NpmRegistryState {
            manifest_store: ManifestStore::new(&root.path().join(".kin")),
            blobs_dir: root.path().join("npm"),
            base_url: "https://kinlab.ai".to_string(),
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
        let state = registry_state();
        let app = npm_routes(state.clone());
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
                    "data": STANDARD.encode(b"fake-tarball"),
                    "length": 12
                }
            }
        });

        let publish = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri("/registry/npm/@kin%2Fboundary-contracts")
                    .extension(RegistryAccessIdentity {
                        email: "builder@firelock.ai".to_string(),
                        display_name: "Builder".to_string(),
                        user_id: "user_123".to_string(),
                        actor_kind: "human".to_string(),
                        org_ids: vec![],
                        scopes: vec!["packages:write".to_string()],
                        credential_type: Some("pat".to_string()),
                    })
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
        let state = registry_state();
        let app = npm_routes(state);
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
                    "data": STANDARD.encode(b"fake-tarball"),
                    "length": 12
                }
            }
        });

        let first = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(Method::PUT)
                    .uri("/registry/npm/@kin%2Fboundary-contracts")
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
                    .header("content-type", "application/json")
                    .body(Body::from(payload.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::CONFLICT);
    }
}
