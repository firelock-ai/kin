use std::net::SocketAddr;

use tracing::info;
use tracing_subscriber;

mod api;
mod client;
mod pages;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let daemon_url =
        std::env::var("KIN_DAEMON_URL").unwrap_or_else(|_| "http://127.0.0.1:4219".to_string());

    let state = api::AppState {
        daemon_url,
        client: reqwest::Client::new(),
    };

    let app = api::router(state);

    let port: u16 = std::env::var("KIN_UI_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(4220);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    info!("kin-local-ui listening on http://{}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
