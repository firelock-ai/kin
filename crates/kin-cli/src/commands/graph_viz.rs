// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{BTreeSet, HashMap, HashSet};
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

#[derive(Debug, Serialize)]
struct GraphNode {
    id: String,
    name: String,
    kind: String,
    file: Option<String>,
    degree: usize,
}

#[derive(Debug, Serialize)]
struct GraphLink {
    source: String,
    target: String,
    kind: String,
}

#[derive(Debug, Serialize)]
struct GraphPayload {
    nodes: Vec<GraphNode>,
    links: Vec<GraphLink>,
    /// Relations whose other endpoint is not itself an entity in this graph,
    /// counted rather than emitted. A link naming an absent node is not a
    /// drawable edge, and emitting one made the whole render die.
    unresolved_links: usize,
}

/// One node's graph-owned identity, split out from the store so payload
/// assembly is a pure function over what the graph reported.
struct NodeMeta {
    id: String,
    name: String,
    kind: String,
    file: Option<String>,
}

/// Assemble the render payload, dropping every edge whose endpoints are not
/// both present in the node set.
///
/// Relations legitimately point outside the entity set — an import of an
/// external crate resolves to a placeholder destination that is no entity in
/// this graph. The renderer joins edges to nodes by id and throws on the first
/// unmatched one, so a single such relation used to abort the whole layout and
/// leave a blank canvas. Withheld edges are counted and reported instead of
/// dropped silently, so the page can say the graph is partial rather than
/// implying every relation is drawn.
fn assemble_payload(
    node_meta: Vec<NodeMeta>,
    edges: impl IntoIterator<Item = (String, String, String)>,
) -> GraphPayload {
    let node_ids: HashSet<&str> = node_meta.iter().map(|meta| meta.id.as_str()).collect();

    let mut link_keys: BTreeSet<(String, String, String)> = BTreeSet::new();
    let mut unresolved_links = 0usize;
    for (a, b, kind) in edges {
        if !node_ids.contains(a.as_str()) || !node_ids.contains(b.as_str()) {
            unresolved_links += 1;
            continue;
        }
        let (a, b) = if a <= b { (a, b) } else { (b, a) };
        link_keys.insert((a, b, kind));
    }

    let mut degrees: HashMap<&str, usize> = HashMap::with_capacity(node_meta.len());
    for (a, b, _kind) in &link_keys {
        *degrees.entry(a.as_str()).or_insert(0) += 1;
        *degrees.entry(b.as_str()).or_insert(0) += 1;
    }

    let nodes: Vec<GraphNode> = node_meta
        .iter()
        .map(|meta| GraphNode {
            id: meta.id.clone(),
            name: meta.name.clone(),
            kind: meta.kind.clone(),
            file: meta.file.clone(),
            degree: degrees.get(meta.id.as_str()).copied().unwrap_or(0),
        })
        .collect();

    let links: Vec<GraphLink> = link_keys
        .into_iter()
        .map(|(source, target, kind)| GraphLink {
            source,
            target,
            kind,
        })
        .collect();

    GraphPayload {
        nodes,
        links,
        unresolved_links,
    }
}

fn build_payload_from_snapshot(snap: &kin_db::SnapshotManager) -> Result<GraphPayload> {
    let graph = snap.graph();
    let entities = graph.list_all_entities()?;

    let mut edges: Vec<(String, String, String)> = Vec::new();
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
            edges.push((src_id.clone(), other_id, format!("{:?}", rel.kind)));
        }
    }

    let node_meta = entities
        .iter()
        .map(|e| NodeMeta {
            id: e.id.to_string(),
            name: e.name.clone(),
            kind: format!("{:?}", e.kind),
            file: e.file_origin.as_ref().map(|f| f.0.clone()),
        })
        .collect();

    Ok(assemble_payload(node_meta, edges))
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
    let layout = crate::commands::require_repository_layout()?;
    let snap =
        crate::backend::open_snapshot_explicit_admin_read_only(&layout, "kin graph viz").await?;
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

#[cfg(test)]
mod tests {
    use super::{assemble_payload, NodeMeta};

    fn node(id: &str) -> NodeMeta {
        NodeMeta {
            id: id.to_string(),
            name: format!("entity_{id}"),
            kind: "Function".to_string(),
            file: Some("src/lib.rs".to_string()),
        }
    }

    fn edge(a: &str, b: &str, kind: &str) -> (String, String, String) {
        (a.to_string(), b.to_string(), kind.to_string())
    }

    /// The empty-canvas defect in miniature. A relation pointing at an id that
    /// is no entity in this graph must never reach the payload: the renderer
    /// joins links to nodes by id and aborts the whole layout on the first
    /// unmatched one.
    #[test]
    fn links_naming_an_absent_node_are_withheld_and_counted() {
        let payload = assemble_payload(
            vec![node("a"), node("b")],
            vec![
                edge("a", "b", "Calls"),
                edge("a", "external-placeholder", "Imports"),
                edge("missing", "b", "Calls"),
            ],
        );

        assert_eq!(payload.links.len(), 1);
        assert_eq!(payload.links[0].source, "a");
        assert_eq!(payload.links[0].target, "b");
        assert_eq!(payload.unresolved_links, 2);

        let ids: Vec<&str> = payload.nodes.iter().map(|n| n.id.as_str()).collect();
        for link in &payload.links {
            assert!(
                ids.contains(&link.source.as_str()),
                "{link:?} source absent"
            );
            assert!(
                ids.contains(&link.target.as_str()),
                "{link:?} target absent"
            );
        }
    }

    /// Falsification: a graph whose relations all resolve must withhold
    /// nothing, so a passing test above cannot be explained by the filter
    /// simply dropping everything.
    #[test]
    fn a_fully_resolvable_graph_withholds_no_links() {
        let payload = assemble_payload(
            vec![node("a"), node("b"), node("c")],
            vec![edge("a", "b", "Calls"), edge("b", "c", "Contains")],
        );

        assert_eq!(payload.unresolved_links, 0);
        assert_eq!(payload.links.len(), 2);
    }

    /// Degree drives node radius, so it must count the edges actually drawn.
    /// Counting withheld relations would inflate a node the layout never
    /// connects to anything.
    #[test]
    fn degree_counts_only_drawn_edges() {
        let payload = assemble_payload(
            vec![node("a"), node("b")],
            vec![
                edge("a", "b", "Calls"),
                edge("a", "gone", "Imports"),
                edge("a", "also-gone", "Imports"),
            ],
        );

        let degree_of = |id: &str| {
            payload
                .nodes
                .iter()
                .find(|n| n.id == id)
                .map(|n| n.degree)
                .expect("node present")
        };
        assert_eq!(degree_of("a"), 1);
        assert_eq!(degree_of("b"), 1);
    }

    /// The same relation observed from both endpoints is one edge, and an
    /// undirected key must not depend on which endpoint reported it.
    #[test]
    fn reciprocal_observations_collapse_to_one_link() {
        let payload = assemble_payload(
            vec![node("a"), node("b")],
            vec![edge("a", "b", "Calls"), edge("b", "a", "Calls")],
        );

        assert_eq!(payload.links.len(), 1);
        assert_eq!(payload.unresolved_links, 0);
    }

    /// The page reports the withheld count, so it must survive serialization
    /// under the name the page reads.
    #[test]
    fn payload_serializes_the_withheld_count_for_the_page() {
        let payload = assemble_payload(vec![node("a")], vec![edge("a", "gone", "Imports")]);
        let json = serde_json::to_value(&payload).unwrap();

        assert_eq!(json["unresolved_links"], 1);
        assert_eq!(json["links"].as_array().unwrap().len(), 0);
        assert_eq!(json["nodes"].as_array().unwrap().len(), 1);
    }
}
