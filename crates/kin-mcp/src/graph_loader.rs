// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashSet;
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
                let auto_init = std::env::var("KIN_MCP_AUTO_INIT")
                    .ok()
                    .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
                    .unwrap_or(false);
                if !auto_init {
                    return Err(McpError::Other(
                        "Kin MCP: no .kin/ in CWD\nhint: run `kin init .` first, or set KIN_MCP_AUTO_INIT=1 to allow MCP startup to initialize this repo"
                            .to_string(),
                    ));
                }
                eprintln!("Kin MCP: no .kin/ in CWD, running `kin init` automatically...");
                let kin_bin = std::env::var("KIN_BINARY_PATH")
                    .or_else(|_| std::env::var("KIN_MCP_KIN_BINARY"))
                    .unwrap_or_else(|_| "kin".to_string());
                let status = std::process::Command::new(&kin_bin)
                    .args(["init", "--force", "--json", "."])
                    .current_dir(cwd)
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::inherit())
                    .status();
                match status {
                    Ok(s) if s.success() => {
                        eprintln!("Kin MCP: auto-init succeeded, loading graph...");
                    }
                    Ok(s) => {
                        return Err(McpError::Other(format!(
                            "kin init failed with exit code {}\nhint: run `kin init .` in the terminal manually",
                            s.code().unwrap_or(-1)
                        )));
                    }
                    Err(e) => {
                        return Err(McpError::Other(format!(
                            "failed to run kin init: {}\nhint: ensure `kin` is on PATH or set KIN_BINARY_PATH",
                            e
                        )));
                    }
                }
                let layout = kin_core::KinLayout::discover(cwd).ok_or_else(|| {
                    McpError::Other(
                        "kin init succeeded but .kin/ not found\nhint: run `kin init .` manually"
                            .to_string(),
                    )
                })?;
                layout
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
        let mut tagged_entities = Vec::with_capacity(entities.len());

        for entity in &entities {
            let mut tagged = entity.clone();
            if let Some(ref origin) = tagged.file_origin {
                tagged.file_origin = Some(FilePathId::new(format!("[{}] {}", repo_name, origin.0)));
            }
            tagged_entities.push(tagged);
        }

        if let Err(e) = merged.upsert_entities_batch(&tagged_entities) {
            eprintln!(
                "Kin MCP: warning: failed to merge entities from '{}': {}",
                repo_name, e
            );
        }

        let mut seen_relation_ids = HashSet::new();
        let mut relations = Vec::new();
        for entity in &entities {
            for relation in sibling
                .get_all_relations_for_entity(&entity.id)
                .unwrap_or_default()
            {
                if seen_relation_ids.insert(relation.id.clone()) {
                    relations.push(relation);
                }
            }
        }

        if let Err(e) = merged.upsert_relations_batch(&relations) {
            eprintln!(
                "Kin MCP: warning: failed to merge relations from '{}': {}",
                repo_name, e
            );
        }
    }

    Ok(merged)
}
