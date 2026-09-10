// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin graph viz` — serve the live graph as an interactive page.
//!
//! The page draws the payload `GET /graph/export` serves, which is the same
//! projection and the same sample every other drawing consumer gets. It used to
//! ask `/graph/bootstrap` instead and shape a payload of its own, and both
//! halves of that were wrong at repository scale.
//!
//! `/graph/bootstrap` exports the whole binary snapshot with no cap. This
//! repository's own measurement of the two routes, recorded beside the export
//! handler, is 119.6 MiB against 1.0 MiB on a 23,098-entity repository, and the
//! CLI gave that transfer a 30-second budget. On the 20,298-entity store this
//! was reported against, the request failed before a pixel was drawn. Nothing
//! about a bigger timeout or a streaming body makes moving 119.6 MiB to draw
//! 1,400 nodes the right shape, so it asks for the drawable projection: capped and
//! sampled server side, off the request thread, and outside the one-at-a-time
//! whole-snapshot semaphore `/graph/bootstrap` holds.
//!
//! The cap is why the page says what it is showing. A sampled export that
//! reported only its own size would read as the whole graph, so the payload
//! carries the population it was drawn from and the page renders that line.
//! `--limit 0` asks for every entity, for a caller willing to wait.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::extract::State;
use axum::http::{header, HeaderValue};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use tokio::net::TcpListener;

use crate::commands::graph_export::{self, GraphExportPayload};

const INDEX_HTML: &str = include_str!("../../assets/graph_viz/index.html");
const APP_JS: &str = include_str!("../../assets/graph_viz/app.js");
const STYLE_CSS: &str = include_str!("../../assets/graph_viz/style.css");

async fn serve_index() -> Response {
    static_response(INDEX_HTML.as_bytes().to_vec(), "text/html; charset=utf-8")
}

async fn serve_app_js() -> Response {
    static_response(
        APP_JS.as_bytes().to_vec(),
        "application/javascript; charset=utf-8",
    )
}

async fn serve_style_css() -> Response {
    static_response(STYLE_CSS.as_bytes().to_vec(), "text/css; charset=utf-8")
}

fn static_response(body: Vec<u8>, content_type: &'static str) -> Response {
    let mut resp = Response::new(body.into());
    resp.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    resp
}

async fn serve_graph_json(State(json): State<Arc<String>>) -> Response {
    let mut resp = Response::new((*json).clone().into());
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    resp
}

/// Build the export payload from local storage, for the offline/admin arm.
///
/// The same projection and the same sampling rule the daemon applies, run in
/// this process against the store's own graph, so the page cannot draw one
/// picture through the daemon and a different one beside it.
fn payload_from_local_store(
    layout: &kin_core::KinLayout,
    options: &graph_export::ExportOptions,
) -> Result<GraphExportPayload> {
    let snap = crate::backend::open_snapshot_local(layout)?;
    let graph = snap.graph();
    let root_hash = hex::encode(graph.compute_root_hash());
    let (node_meta, all_entity_ids, edges) = graph_export::read_graph(graph.as_ref())?;
    // Sequence zero rather than a borrowed cursor. An offline read holds no
    // position in the daemon's event stream, and a client discards every event
    // at or below this number; zero discards none, so a page that later
    // subscribes re-applies what it already has instead of skipping what it
    // does not. An invented cursor would silently lose the difference.
    Ok(graph_export::assemble_payload(
        root_hash,
        0,
        node_meta,
        &all_entity_ids,
        edges,
        options,
    ))
}

/// Resolve the payload the page will draw.
///
/// The authority order every read-only graph command follows: the daemon first,
/// then an explicit offline/admin local read behind
/// `KIN_ALLOW_DAEMON_BOOTSTRAP_ADMIN`, then an actionable refusal. Neither arm
/// may answer with an empty graph it did not actually read. That is what the old
/// local arm did, opening a retired file name, finding nothing, and serving a
/// blank canvas at exit 0 against a store holding 20,298 entities.
async fn resolve_payload(
    layout: &kin_core::KinLayout,
    options: &graph_export::ExportOptions,
    query: &str,
) -> Result<GraphExportPayload> {
    let daemon_error =
        match crate::daemon_client::DaemonClient::connect_for_command("graph viz", layout).await {
            Ok(client) => match client.graph_export(query).await {
                Ok(payload) => return Ok(payload),
                Err(error) => error,
            },
            Err(error) => error,
        };

    if crate::backend::daemon_bootstrap_admin_allowed() {
        tracing::warn!(
            command = "kin graph viz",
            error = %daemon_error,
            "daemon unavailable; drawing from the local store directly (KIN_ALLOW_DAEMON_BOOTSTRAP_ADMIN)"
        );
        return payload_from_local_store(layout, options);
    }

    Err(daemon_error.context(
        "kin graph viz needs the Kin daemon, which could not be reached.\n\
         Start it with `kin status` (it auto-starts the daemon), then retry.\n\
         For offline/admin use only, set KIN_ALLOW_DAEMON_BOOTSTRAP_ADMIN=1 to read the local store directly.",
    ))
}

/// `kin graph viz` — serve an interactive force-directed graph over HTTP.
///
/// `limit` caps the drawn node count: `None` uses the export's default cap and
/// `Some(0)` asks for every entity. The server binds only after a payload has
/// actually been resolved, so a failure to read the graph refuses the command
/// rather than serving a page with nothing on it.
pub async fn run(port: u16, open_browser: bool, limit: Option<usize>) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    let args = graph_export::ExportArgs {
        limit,
        ..Default::default()
    };
    let options = graph_export::ExportOptions {
        limit: graph_export::resolve_limit(limit),
        ..Default::default()
    };
    let payload =
        resolve_payload(&layout, &options, &graph_export::export_query_string(&args)).await?;

    // The same line `kin graph export` prints, on the terminal that started the
    // server, so what the page claims and what the command reported are one
    // sentence rather than two that can drift.
    println!("{}", graph_export::export_summary_line(&payload, None));
    if payload.nodes.is_empty() {
        println!(
            "This repository's graph holds no entities matching the request, so the page will be blank."
        );
    }

    let json_body = serde_json::to_string(&payload).context("failed to serialize graph JSON")?;
    let shared: Arc<String> = Arc::new(json_body);

    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let listener = TcpListener::bind(addr)
        .await
        .with_context(|| format!("failed to bind 127.0.0.1:{port}"))?;

    let app = Router::new()
        .route("/", get(serve_index))
        .route("/app.js", get(serve_app_js))
        .route("/style.css", get(serve_style_css))
        .route("/api/graph.json", get(serve_graph_json))
        .with_state(shared);

    let url = format!("http://127.0.0.1:{port}/");
    println!("Serving kin graph at {url}");

    if open_browser {
        let url_for_open = url.clone();
        tokio::task::spawn_blocking(move || {
            if let Err(e) = open::that(&url_for_open) {
                eprintln!("failed to open browser: {e}");
            }
        });
    }

    axum::serve(listener, app)
        .await
        .context("kin graph viz server error")?;
    Ok(())
}
