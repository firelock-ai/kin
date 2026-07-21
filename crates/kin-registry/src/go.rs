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
    let bytes = module.as_bytes();
    bytes
        .first()
        .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && bytes
            .last()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'!'))
        && module != "."
        && module != ".."
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
    let path = blobs_dir.join(format!("{module}-{version}.zip"));
    (path.parent() == Some(blobs_dir)).then_some(path)
}

fn invalid_coordinate() -> Response {
    (StatusCode::BAD_REQUEST, "invalid Go module coordinate").into_response()
}

/// Create axum router for Go module proxy endpoints
pub fn go_routes(state: Arc<GoProxyState>) -> Router {
    Router::new()
        .route("/registry/go/{module}/@v/list", get(list_versions))
        .route(
            "/registry/go/{module}/@v/{*version_file}",
            get(version_dispatch),
        )
        .with_state(state)
}

/// Dispatch /registry/go/{module}/@v/{version}.{ext} to the correct handler
async fn version_dispatch(
    state: State<Arc<GoProxyState>>,
    Path((module, version_file)): Path<(String, String)>,
) -> Response {
    if !valid_go_module(&module) {
        return invalid_coordinate();
    }
    let (version, ext) = match version_file.rsplit_once('.') {
        Some((v, e)) => (v.to_string(), e),
        None => return StatusCode::NOT_FOUND.into_response(),
    };
    if !valid_go_version(&version) {
        return invalid_coordinate();
    }
    match ext {
        "info" => version_info_inner(state, &module, &version).await,
        "mod" => version_mod_inner(state, &module, &version).await,
        "zip" => version_zip_inner(state, &module, &version).await,
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

/// GET /registry/go/{module}/@v/list -- list all available versions (plain text, one per line)
async fn list_versions(
    State(state): State<Arc<GoProxyState>>,
    Path(module): Path<String>,
) -> Response {
    if !valid_go_module(&module) {
        return invalid_coordinate();
    }
    let versions = match state.manifest_store.get_versions(Ecosystem::Go, &module) {
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

async fn version_info_inner(
    State(state): State<Arc<GoProxyState>>,
    module: &str,
    version: &str,
) -> Response {
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

async fn version_mod_inner(
    State(state): State<Arc<GoProxyState>>,
    module: &str,
    version: &str,
) -> Response {
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

async fn version_zip_inner(
    State(state): State<Arc<GoProxyState>>,
    module: &str,
    version: &str,
) -> Response {
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

        let valid = go_zip_path(&blobs, "example.com", "v1.2.3").unwrap();
        assert_eq!(valid, blobs.join("example.com-v1.2.3.zip"));
        assert_eq!(valid.parent(), Some(blobs.as_path()));

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
        let path = go_zip_path(&state.blobs_dir, "example.com", "v1.2.3").unwrap();
        std::fs::write(path, bytes).unwrap();

        let response = go_routes(state)
            .oneshot(
                Request::get("/registry/go/example.com/@v/v1.2.3.zip")
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
}
