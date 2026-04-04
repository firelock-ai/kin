// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::Path;

use crate::{McpError, Result};
use kin_model::entity::Entity;
use kin_model::graph::EntityStore;
use kin_model::ids::FilePathId;

const MCP_BOOTSTRAP_PRIMARY_COUNT_HEADER: &str = "x-kin-primary-entity-count";
const MCP_BOOTSTRAP_SIBLING_COUNT_HEADER: &str = "x-kin-sibling-repo-count";

/// Loaded stdio graph state for `kin mcp start`.
pub struct StdioGraphLoad {
    pub graph: kin_db::InMemoryGraph,
    pub primary_entity_count: usize,
    pub sibling_repo_count: usize,
}

/// Load the current working repo graph and merge sibling registry graphs.
pub fn load_stdio_graph(cwd: &Path) -> Result<StdioGraphLoad> {
    let primary_graph = load_cwd_graph(cwd)?;
    let primary_entity_count = primary_graph
        .as_ref()
        .map(|graph: &kin_db::InMemoryGraph| graph.entity_count())
        .unwrap_or(0);

    let cwd_canonical = cwd.canonicalize().unwrap_or_else(|_| cwd.to_path_buf());
    let sibling_graphs = load_sibling_graphs(&cwd_canonical)?;
    let sibling_repo_count = sibling_graphs.len();
    let graph = merge_graphs(primary_graph, &sibling_graphs)?;

    Ok(StdioGraphLoad {
        graph,
        primary_entity_count,
        sibling_repo_count,
    })
}

/// Load the daemon-authoritative MCP bootstrap graph.
pub async fn load_stdio_graph_from_daemon() -> Result<StdioGraphLoad> {
    let base_url =
        std::env::var("KIN_DAEMON_URL").unwrap_or_else(|_| "http://127.0.0.1:4219".to_string());
    let url = format!("{}/mcp/bootstrap", base_url.trim_end_matches('/'));
    let response = reqwest::Client::new()
        .get(url)
        .send()
        .await
        .map_err(|e| McpError::Other(format!("failed to fetch daemon MCP bootstrap: {e}")))?;

    if !response.status().is_success() {
        return Err(McpError::Other(format!(
            "daemon MCP bootstrap failed: HTTP {}",
            response.status()
        )));
    }

    let headers = response.headers().clone();
    let bytes = response
        .bytes()
        .await
        .map_err(|e| McpError::Other(format!("failed to read daemon MCP bootstrap body: {e}")))?;
    let snapshot = kin_db::GraphSnapshot::from_bytes(&bytes).map_err(|e| {
        McpError::Other(format!(
            "failed to decode daemon MCP bootstrap snapshot: {e}"
        ))
    })?;
    let graph = kin_db::InMemoryGraph::from_snapshot(snapshot);

    Ok(StdioGraphLoad {
        primary_entity_count: parse_count_header(&headers, MCP_BOOTSTRAP_PRIMARY_COUNT_HEADER)
            .unwrap_or_else(|| graph.entity_count()),
        sibling_repo_count: parse_count_header(&headers, MCP_BOOTSTRAP_SIBLING_COUNT_HEADER)
            .unwrap_or(0),
        graph,
    })
}

fn parse_count_header(headers: &reqwest::header::HeaderMap, name: &str) -> Option<usize> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<usize>().ok())
}

fn load_cwd_graph(cwd: &Path) -> Result<Option<kin_db::InMemoryGraph>> {
    let layout = match kin_core::KinLayout::discover(cwd) {
        Some(layout) => layout,
        None => match kin_core::registry::KinRegistry::load() {
            Ok(registry) if !registry.repos.is_empty() => {
                eprintln!(
                    "Kin MCP: no .kin/ in CWD, using {} registered repo(s) from global registry",
                    registry.repos.len()
                );
                return Ok(None);
            }
            _ => {
                let init_result = kin_core::init(cwd).map_err(|e| {
                    McpError::Other(format!(
                        "not a Kin repository and auto-init failed: {}\nhint: run `kin init .` to initialize manually",
                        e
                    ))
                })?;
                eprintln!(
                    "Auto-initialized Kin repository. Run `kin init .` in the terminal for full semantic graph initialization."
                );
                init_result.layout
            }
        },
    };

    let snap =
        kin_db::SnapshotManager::open(layout.kindb_snapshot_path()).map_err(McpError::graph)?;
    let arc = snap.graph();
    drop(snap);
    let graph = std::sync::Arc::try_unwrap(arc)
        .map_err(|_| McpError::Other("KinDB graph has outstanding references".to_string()))?;
    Ok(Some(graph))
}

fn load_sibling_graphs(cwd_canonical: &Path) -> Result<Vec<(String, kin_db::InMemoryGraph)>> {
    let mut sibling_graphs = Vec::new();

    if let Ok(registry) = kin_core::registry::KinRegistry::load() {
        for repo in &registry.repos {
            let repo_canonical = repo
                .path
                .canonicalize()
                .unwrap_or_else(|_| repo.path.clone());

            if repo_canonical == cwd_canonical || cwd_canonical.starts_with(&repo_canonical) {
                continue;
            }

            let kindb_path = repo.path.join(".kin").join("kindb").join("graph.kndb");
            if !kindb_path.exists() {
                continue;
            }

            let kindb_clone = kindb_path.clone();
            let load_result = std::thread::Builder::new()
                .name(format!("load-{}", repo.id))
                .spawn(move || -> Option<kin_db::InMemoryGraph> {
                    let snap = kin_db::SnapshotManager::open(&kindb_clone).ok()?;
                    let arc = snap.graph();
                    drop(snap);
                    std::sync::Arc::try_unwrap(arc).ok()
                });

            match load_result {
                Ok(handle) => match handle.join() {
                    Ok(Some(graph)) => sibling_graphs.push((repo.id.clone(), graph)),
                    Ok(None) => eprintln!("Kin MCP: warning: could not load sibling '{}'", repo.id),
                    Err(_) => eprintln!("Kin MCP: warning: sibling '{}' load panicked", repo.id),
                },
                Err(e) => eprintln!(
                    "Kin MCP: warning: could not spawn loader for '{}': {}",
                    repo.id, e
                ),
            }
        }
    }

    Ok(sibling_graphs)
}

fn merge_graphs(
    primary: Option<kin_db::InMemoryGraph>,
    siblings: &[(String, kin_db::InMemoryGraph)],
) -> Result<kin_db::InMemoryGraph> {
    let merged = primary.unwrap_or_else(kin_db::InMemoryGraph::new);

    for (repo_name, sibling) in siblings {
        let entities: Vec<Entity> = sibling.list_all_entities().map_err(|e| {
            McpError::Other(format!(
                "failed to list entities from '{}': {}",
                repo_name, e
            ))
        })?;

        for entity in &entities {
            let mut tagged = entity.clone();
            if let Some(ref origin) = tagged.file_origin {
                tagged.file_origin = Some(FilePathId::new(format!("[{}] {}", repo_name, origin.0)));
            }
            if let Err(e) = merged.upsert_entity(&tagged) {
                eprintln!(
                    "Kin MCP: warning: failed to merge entity '{}' from '{}': {}",
                    entity.name, repo_name, e
                );
            }
        }

        for entity in &entities {
            let relations = sibling
                .get_all_relations_for_entity(&entity.id)
                .unwrap_or_default();
            for relation in &relations {
                if let Err(e) = merged.upsert_relation(relation) {
                    eprintln!(
                        "Kin MCP: warning: failed to merge relation from '{}': {}",
                        repo_name, e
                    );
                }
            }
        }
    }

    Ok(merged)
}
