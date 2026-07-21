// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Go module proxy (GOPROXY) protocol adapter.
//!
//! Implements: <https://go.dev/ref/mod#goproxy-protocol>
//!
//! Endpoints:
//! - GET /registry/go/{module}/@v/list -- list available versions
//! - GET /registry/go/{module}/@v/{version}.info -- version metadata (JSON)
//! - GET /registry/go/{module}/@v/{version}.mod -- go.mod file
//! - GET /registry/go/{module}/@v/{version}.zip -- module source zip

use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Json, Response},
    routing::get,
    Router,
};
use sha2::{Digest, Sha256};
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;

use crate::{Ecosystem, ManifestStore};

/// Shared state for the Go module proxy routes
pub struct GoProxyState {
    pub manifest_store: ManifestStore,
    pub blobs_dir: std::path::PathBuf,
}

const MAX_GO_MODULE_LEN: usize = 255;
const MAX_GO_VERSION_LEN: usize = 128;

fn valid_go_module(module: &str) -> bool {
    if module.is_empty() || module.len() > MAX_GO_MODULE_LEN {
        return false;
    }
    module.split('/').all(|segment| {
        let bytes = segment.as_bytes();
        !segment.is_empty()
            && segment != "."
            && segment != ".."
            && bytes
                .first()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
            && bytes
                .last()
                .is_some_and(|byte| byte.is_ascii_alphanumeric())
            && bytes.iter().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'!')
            })
    })
}

fn valid_go_version(version: &str) -> bool {
    if version.is_empty() || version.len() > MAX_GO_VERSION_LEN || !version.starts_with('v') {
        return false;
    }
    version
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'+' | b'!'))
        && !version.contains("..")
}

fn go_zip_path(blobs_dir: &FsPath, module: &str, version: &str) -> Option<PathBuf> {
    if !valid_go_module(module) || !valid_go_version(version) {
        return None;
    }
    // Module paths contain `/`; hash the validated logical coordinate into one
    // fixed filename rather than projecting caller-controlled segments onto
    // the host filesystem.
    let coordinate = format!("{module}\0{version}");
    let key = hex::encode(Sha256::digest(coordinate.as_bytes()));
    let path = blobs_dir.join(format!("module_{key}.zip"));
    (path.parent() == Some(blobs_dir)).then_some(path)
}

fn invalid_coordinate() -> Response {
    (StatusCode::BAD_REQUEST, "invalid Go module coordinate").into_response()
}

/// Create axum router for Go module proxy endpoints
pub fn go_routes(state: Arc<GoProxyState>) -> Router {
    Router::new()
        .route("/registry/go/{*path}", get(dispatch))
        .with_state(state)
}

/// Parse the fixed `/@v/` protocol marker from the right so normal multi-segment
/// module paths remain one validated logical coordinate.
async fn dispatch(State(state): State<Arc<GoProxyState>>, Path(path): Path<String>) -> Response {
    let Some((module, version_file)) = path.rsplit_once("/@v/") else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if !valid_go_module(module) {
        return invalid_coordinate();
    }
    if version_file == "list" {
        return list_versions_inner(&state, module);
    }
    let (version, ext) = match version_file.rsplit_once('.') {
        Some((v, e)) => (v, e),
        None => return StatusCode::NOT_FOUND.into_response(),
    };
    if !valid_go_version(version) {
        return invalid_coordinate();
    }
    match ext {
        "info" => version_info_inner(&state, module, version),
        "mod" => version_mod_inner(&state, module, version),
        "zip" => version_zip_inner(&state, module, version),
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

fn list_versions_inner(state: &GoProxyState, module: &str) -> Response {
    let versions = match state.manifest_store.get_versions(Ecosystem::Go, module) {
        Ok(v) => v,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let body = versions
        .iter()
        .map(|v| v.version.clone())
        .collect::<Vec<_>>()
        .join("\n");
    (StatusCode::OK, [("content-type", "text/plain")], body).into_response()
}

fn version_info_inner(state: &GoProxyState, module: &str, version: &str) -> Response {
    let versions = match state.manifest_store.get_versions(Ecosystem::Go, module) {
        Ok(v) => v,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    match versions.iter().find(|v| v.version == version) {
        Some(v) => Json(serde_json::json!({
            "Version": v.version,
            "Time": v.published_at.to_rfc3339(),
        }))
        .into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

fn version_mod_inner(state: &GoProxyState, module: &str, version: &str) -> Response {
    let versions = match state.manifest_store.get_versions(Ecosystem::Go, module) {
        Ok(v) => v,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    match versions.iter().find(|v| v.version == version) {
        Some(v) => {
            let default_mod = format!("module {}\n\ngo 1.21\n", module);
            let go_mod = v
                .metadata
                .get("go_mod")
                .and_then(|m| m.as_str())
                .unwrap_or(&default_mod);
            (
                StatusCode::OK,
                [("content-type", "text/plain")],
                go_mod.to_string(),
            )
                .into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

fn version_zip_inner(state: &GoProxyState, module: &str, version: &str) -> Response {
    let Some(zip_path) = go_zip_path(&state.blobs_dir, module, version) else {
        return invalid_coordinate();
    };
    match std::fs::read(&zip_path) {
        Ok(bytes) => (StatusCode::OK, [("content-type", "application/zip")], bytes).into_response(),
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{body::Body, http::Request};
    use tower::ServiceExt;

    fn state() -> (tempfile::TempDir, Arc<GoProxyState>) {
        let root = tempfile::tempdir().unwrap();
        let kin_dir = root.path().join(".kin");
        let blobs_dir = root.path().join("go");
        std::fs::create_dir_all(&kin_dir).unwrap();
        std::fs::create_dir_all(&blobs_dir).unwrap();
        (
            root,
            Arc::new(GoProxyState {
                manifest_store: ManifestStore::new(&kin_dir),
                blobs_dir,
            }),
        )
    }

    #[test]
    fn zip_path_rejects_traversal_and_remains_a_direct_child() {
        let root = tempfile::tempdir().unwrap();
        let blobs = root.path().join("go");
        std::fs::create_dir_all(&blobs).unwrap();

        let valid = go_zip_path(&blobs, "example.com/team/module", "v1.2.3").unwrap();
        assert_eq!(valid.parent(), Some(blobs.as_path()));
        assert_eq!(valid.file_name().unwrap().to_string_lossy().len(), 75);

        for (module, version) in [
            ("..", "v1.2.3"),
            ("../outside", "v1.2.3"),
            ("example.com", "../../outside"),
            ("example.com", "v1.2.3/../../outside"),
            ("example.com", "v1.2.3\\outside"),
            ("example.com", "v1..2"),
        ] {
            assert!(
                go_zip_path(&blobs, module, version).is_none(),
                "accepted {module:?}@{version:?}"
            );
        }
    }

    #[tokio::test]
    async fn catch_all_version_route_cannot_read_outside_the_blob_directory() {
        let (root, state) = state();
        let sentinel = root.path().join("outside.zip");
        std::fs::write(&sentinel, b"must-not-be-served").unwrap();

        for uri in [
            "/registry/go/example.com/@v/..%2F..%2Foutside.zip",
            "/registry/go/example.com/@v/v1.2.3%5C..%5Coutside.zip",
            "/registry/go/%2e%2e/@v/v1.2.3.zip",
        ] {
            let response = go_routes(state.clone())
                .oneshot(Request::get(uri).body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_ne!(response.status(), StatusCode::OK, "served {uri}");
        }

        assert_eq!(std::fs::read(sentinel).unwrap(), b"must-not-be-served");
        assert!(std::fs::read_dir(&state.blobs_dir)
            .unwrap()
            .next()
            .is_none());
    }

    #[tokio::test]
    async fn validated_go_zip_reads_remain_public() {
        let (_root, state) = state();
        let bytes = b"valid-public-module-zip";
        let module = "github.com/firelock-ai/kin";
        let path = go_zip_path(&state.blobs_dir, module, "v1.2.3").unwrap();
        std::fs::write(path, bytes).unwrap();

        let response = go_routes(state)
            .oneshot(
                Request::get("/registry/go/github.com/firelock-ai/kin/@v/v1.2.3.zip")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let observed = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(observed.as_ref(), bytes);
    }

    #[tokio::test]
    async fn standard_multisegment_module_path_lists_versions() {
        let (_root, state) = state();
        let module = "github.com/firelock-ai/kin";
        state
            .manifest_store
            .add_version(&crate::PackageVersion {
                id: crate::PackageId {
                    ecosystem: Ecosystem::Go,
                    scope: None,
                    name: module.to_string(),
                },
                version: "v1.2.3".to_string(),
                blob_hash: "hash".to_string(),
                blob_size: 0,
                checksum: "checksum".to_string(),
                metadata: serde_json::json!({}),
                published_at: chrono::Utc::now(),
                published_by: "test".to_string(),
                yanked: false,
            })
            .unwrap();

        let response = go_routes(state)
            .oneshot(
                Request::get("/registry/go/github.com/firelock-ai/kin/@v/list")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let observed = axum::body::to_bytes(response.into_body(), 1024)
            .await
            .unwrap();
        assert_eq!(observed.as_ref(), b"v1.2.3");
    }
}
