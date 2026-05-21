// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use anyhow::{Context, Result};
use axum::extract::State;
use axum::http::{header, HeaderValue};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use kin_model::{EntityStore, GraphNodeId};
use serde::Serialize;
use tokio::net::TcpListener;

const INDEX_HTML: &str = include_str!("../../assets/graph_viz/index.html");
const APP_JS: &str = include_str!("../../assets/graph_viz/app.js");
const STYLE_CSS: &str = include_str!("../../assets/graph_viz/style.css");

#[derive(Serialize)]
struct GraphNode {
    id: String,
    name: String,
    kind: String,
    file: Option<String>,
    degree: usize,
}

#[derive(Serialize)]
struct GraphLink {
    source: String,
    target: String,
    kind: String,
}

#[derive(Serialize)]
struct GraphPayload {
    nodes: Vec<GraphNode>,
    links: Vec<GraphLink>,
}

fn build_payload_from_snapshot(snap: &kin_db::SnapshotManager) -> Result<GraphPayload> {
    let graph = snap.graph();
    let entities = graph.list_all_entities()?;

    let mut nodes: Vec<GraphNode> = Vec::with_capacity(entities.len());
    let mut degrees: HashMap<String, usize> = HashMap::with_capacity(entities.len());

    let mut link_keys: BTreeSet<(String, String, String)> = BTreeSet::new();

    for e in &entities {
        let src_id = e.id.to_string();
        let rels = graph.get_all_relations_for_entity(&e.id)?;
        for rel in rels {
            let other_id = match (&rel.src, &rel.dst) {
                (GraphNodeId::Entity(s), GraphNodeId::Entity(d)) => {
                    if *s == e.id {
                        d.to_string()
                    } else {
                        s.to_string()
                    }
                }
                _ => continue,
            };
            let kind_str = format!("{:?}", rel.kind);
            let (a, b) = if src_id <= other_id {
                (src_id.clone(), other_id)
            } else {
                (other_id, src_id.clone())
            };
            link_keys.insert((a, b, kind_str));
        }
    }

    for (a, b, _kind) in &link_keys {
        *degrees.entry(a.clone()).or_insert(0) += 1;
        *degrees.entry(b.clone()).or_insert(0) += 1;
    }

    for e in &entities {
        let id_str = e.id.to_string();
        let degree = degrees.get(&id_str).copied().unwrap_or(0);
        nodes.push(GraphNode {
            id: id_str,
            name: e.name.clone(),
            kind: format!("{:?}", e.kind),
            file: e.file_origin.as_ref().map(|f| f.0.clone()),
            degree,
        });
    }

    let links: Vec<GraphLink> = link_keys
        .into_iter()
        .map(|(a, b, kind)| GraphLink {
            source: a,
            target: b,
            kind,
        })
        .collect();

    Ok(GraphPayload { nodes, links })
}

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

/// `kin graph viz` — serve an interactive force-directed graph over HTTP.
pub async fn run(port: u16, open_browser: bool) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let snap = crate::backend::open_snapshot_daemon_first_read_only(&layout).await?;
    let payload = build_payload_from_snapshot(&snap)?;
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
