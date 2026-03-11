use crate::client::DaemonClient;
use crate::pages;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{Html, IntoResponse, Json};
use axum::routing::get;
use axum::Router;
use std::path::PathBuf;

/// Shared application state.
#[derive(Clone)]
pub struct AppState {
    pub daemon_url: String,
    pub client: reqwest::Client,
}

impl AppState {
    fn daemon_client(&self) -> DaemonClient {
        DaemonClient::new(self.daemon_url.clone(), self.client.clone())
    }
}

/// Build the full axum router.
pub fn router(state: AppState) -> Router {
    Router::new()
        // HTML pages
        .route("/", get(dashboard))
        .route("/graph", get(graph))
        .route("/review", get(review))
        .route("/benchmarks", get(benchmarks))
        .route("/traffic", get(traffic))
        .route("/work", get(work))
        .route("/verification", get(verification))
        .route("/provenance", get(provenance))
        // API proxy endpoints
        .route("/api/health", get(api_health))
        .route("/api/status", get(api_status))
        .route("/api/sessions", get(api_sessions))
        .route("/api/traffic", get(api_traffic))
        .route("/api/benchmarks", get(api_benchmarks))
        .route("/api/dashboard", get(api_dashboard))
        .with_state(state)
}

// -- Page handlers --

async fn dashboard() -> Html<String> {
    pages::dashboard_page()
}

async fn graph() -> Html<String> {
    pages::graph_page()
}

async fn review() -> Html<String> {
    pages::review_page()
}

async fn benchmarks() -> Html<String> {
    pages::benchmarks_page()
}

async fn traffic() -> Html<String> {
    pages::traffic_page()
}

async fn work() -> Html<String> {
    pages::work_page()
}

async fn verification() -> Html<String> {
    pages::verification_page()
}

async fn provenance() -> Html<String> {
    pages::provenance_page()
}

// -- API proxy handlers --

async fn api_health(State(state): State<AppState>) -> Result<impl IntoResponse, StatusCode> {
    let client = state.daemon_client();
    match client.health().await {
        Ok(data) => Ok(Json(data)),
        Err(_) => Err(StatusCode::BAD_GATEWAY),
    }
}

async fn api_status(State(state): State<AppState>) -> Result<impl IntoResponse, StatusCode> {
    let client = state.daemon_client();
    match client.status().await {
        Ok(data) => Ok(Json(data)),
        Err(_) => Err(StatusCode::BAD_GATEWAY),
    }
}

async fn api_sessions(State(state): State<AppState>) -> Result<impl IntoResponse, StatusCode> {
    let client = state.daemon_client();
    match client.sessions().await {
        Ok(data) => Ok(Json(data)),
        Err(_) => Err(StatusCode::BAD_GATEWAY),
    }
}

async fn api_traffic(State(state): State<AppState>) -> Result<impl IntoResponse, StatusCode> {
    let client = state.daemon_client();
    match client.traffic().await {
        Ok(data) => Ok(Json(data)),
        Err(_) => Err(StatusCode::BAD_GATEWAY),
    }
}

async fn api_benchmarks() -> impl IntoResponse {
    let bench_dir = find_bench_dir();
    let data = match bench_dir {
        Some(dir) => read_latest_bench_json(&dir),
        None => None,
    };
    match data {
        Some(json) => Json(json),
        None => Json(serde_json::Value::Object(serde_json::Map::new())),
    }
}

async fn api_dashboard() -> impl IntoResponse {
    let bench_dir = find_bench_dir();
    let data = match bench_dir {
        Some(dir) => read_latest_dashboard_json(&dir),
        None => None,
    };
    match data {
        Some(json) => Json(json),
        None => Json(serde_json::Value::Object(serde_json::Map::new())),
    }
}

/// Read the most recent `bench-dashboard-*.json` file from the bench directory.
fn read_latest_dashboard_json(dir: &PathBuf) -> Option<serde_json::Value> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy();
            name.starts_with("bench-dashboard-") && name.ends_with(".json")
        })
        .collect();

    entries.sort_by(|a, b| b.file_name().cmp(&a.file_name()));

    let latest = entries.first()?;
    let contents = std::fs::read_to_string(latest.path()).ok()?;
    serde_json::from_str(&contents).ok()
}

/// Walk up from cwd to find `.kin/bench/`.
fn find_bench_dir() -> Option<PathBuf> {
    let mut current = std::env::current_dir().ok()?;
    loop {
        let candidate = current.join(".kin").join("bench");
        if candidate.is_dir() {
            return Some(candidate);
        }
        if !current.pop() {
            return None;
        }
    }
}

/// Read the most recent `bench-*.json` file from the bench directory.
fn read_latest_bench_json(dir: &PathBuf) -> Option<serde_json::Value> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .ok()?
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name();
            let name = name.to_string_lossy();
            name.starts_with("bench-") && name.ends_with(".json")
        })
        .collect();

    // Sort by filename descending (timestamps sort lexicographically).
    entries.sort_by(|a, b| b.file_name().cmp(&a.file_name()));

    let latest = entries.first()?;
    let contents = std::fs::read_to_string(latest.path()).ok()?;
    serde_json::from_str(&contents).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn test_state() -> AppState {
        AppState {
            daemon_url: "http://127.0.0.1:0".into(),
            client: reqwest::Client::new(),
        }
    }

    #[tokio::test]
    async fn dashboard_returns_html() {
        let app = router(test_state());
        let req = Request::builder().uri("/").body(Body::empty()).unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 1024 * 64)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Dashboard"));
    }

    #[tokio::test]
    async fn graph_returns_html() {
        let app = router(test_state());
        let req = Request::builder()
            .uri("/graph")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn review_returns_html() {
        let app = router(test_state());
        let req = Request::builder()
            .uri("/review")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn benchmarks_returns_html() {
        let app = router(test_state());
        let req = Request::builder()
            .uri("/benchmarks")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn traffic_returns_html() {
        let app = router(test_state());
        let req = Request::builder()
            .uri("/traffic")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 1024 * 64)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Live Traffic"));
    }

    #[tokio::test]
    async fn work_returns_html() {
        let app = router(test_state());
        let req = Request::builder()
            .uri("/work")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 1024 * 64)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Work Items"));
    }

    #[tokio::test]
    async fn verification_returns_html() {
        let app = router(test_state());
        let req = Request::builder()
            .uri("/verification")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 1024 * 64)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Verification"));
    }

    #[tokio::test]
    async fn provenance_returns_html() {
        let app = router(test_state());
        let req = Request::builder()
            .uri("/provenance")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 1024 * 64)
            .await
            .unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(html.contains("Provenance"));
    }

    #[tokio::test]
    async fn api_health_returns_bad_gateway_when_daemon_down() {
        let app = router(test_state());
        let req = Request::builder()
            .uri("/api/health")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        // Daemon is not running, expect 502
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
    }
}
