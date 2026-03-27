// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_model::graph::{EntityStore, GraphStore};
use kin_model::ids::FilePathId;
use std::collections::HashSet;
use std::path::Path;

/// `kin mcp start` — Start the MCP stdio server.
///
/// Loads the CWD repo's graph as primary, then merges entities and relations
/// from all sibling repos in `~/.kin/registry.toml` for cross-repo context.
pub async fn start() -> Result<()> {
    let cwd = std::env::current_dir()?;

    // Step 1: Load primary (CWD) graph
    let primary_graph = load_cwd_graph(&cwd)?;
    let primary_entity_count = primary_graph
        .as_ref()
        .map(|g| g.entity_count())
        .unwrap_or(0);

    // Step 2: Load sibling graphs from registry
    let cwd_canonical = cwd.canonicalize().unwrap_or_else(|_| cwd.clone());
    let mut sibling_graphs: Vec<(String, kin_db::InMemoryGraph)> = Vec::new();

    if let Ok(registry) = kin_core::registry::KinRegistry::load() {
        for repo in &registry.repos {
            let repo_canonical = repo
                .path
                .canonicalize()
                .unwrap_or_else(|_| repo.path.clone());

            // Skip the primary (CWD) repo
            if repo_canonical == cwd_canonical || cwd_canonical.starts_with(&repo_canonical) {
                continue;
            }

            let kindb_path = repo.path.join(".kin").join("kindb").join("graph.kndb");
            if !kindb_path.exists() {
                continue;
            }

            // Load sibling graph with a timeout to prevent hangs from stale locks.
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
                    Ok(Some(graph)) => {
                        sibling_graphs.push((repo.id.clone(), graph));
                    }
                    Ok(None) => {
                        eprintln!(
                            "Kin MCP: warning: could not load sibling '{}'",
                            repo.id
                        );
                    }
                    Err(_) => {
                        eprintln!(
                            "Kin MCP: warning: sibling '{}' load panicked",
                            repo.id
                        );
                    }
                },
                Err(e) => {
                    eprintln!(
                        "Kin MCP: warning: could not spawn loader for '{}': {}",
                        repo.id, e
                    );
                }
            }
        }
    }

    // Step 3: Merge siblings into primary
    let merged = merge_graphs(primary_graph, &sibling_graphs)?;

    eprintln!(
        "Kin MCP: {} primary entities, {} sibling repo(s), {} total entities",
        primary_entity_count,
        sibling_graphs.len(),
        merged.entity_count(),
    );

    // Step 4: Configure and run
    let mut config = kin_mcp::McpServerConfig::default();
    if matches!(
        std::env::var("KIN_MCP_TOOL_PROFILE").ok().as_deref(),
        Some("benchmark")
    ) {
        config.allowed_tools = Some(
            kin_mcp::benchmark_tool_names()
                .iter()
                .map(|name| (*name).to_string())
                .collect::<HashSet<_>>(),
        );
    }

    kin_mcp::run_stdio(merged, config)
        .await
        .map_err(|e| anyhow::anyhow!("MCP server error: {}", e))?;

    Ok(())
}

/// Try to load the graph from the CWD's `.kin/` directory.
/// Returns `None` if no `.kin/` exists.
fn load_cwd_graph(cwd: &Path) -> Result<Option<kin_db::InMemoryGraph>> {
    let layout = match kin_core::KinLayout::discover(cwd) {
        Some(l) => l,
        None => {
            // Check if registry has repos — if so, no need to auto-init the parent dir
            if let Ok(reg) = kin_core::registry::KinRegistry::load() {
                if !reg.repos.is_empty() {
                    eprintln!(
                        "Kin MCP: no .kin/ in CWD, using {} registered repo(s) from global registry",
                        reg.repos.len()
                    );
                    return Ok(None);
                }
            }
            // No registry repos — auto-initialize
            let init_result = kin_core::init(cwd).map_err(|e| {
                anyhow::anyhow!(
                    "not a Kin repository and auto-init failed: {}\nhint: run `kin init .` to initialize manually",
                    e
                )
            })?;
            eprintln!("Auto-initialized Kin repository. Run `kin commit` to extract entities from source.");
            init_result.layout
        }
    };

    let snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout))?;
    let arc = snap.graph();
    drop(snap);
    let graph = std::sync::Arc::try_unwrap(arc)
        .map_err(|_| anyhow::anyhow!("KinDB graph has outstanding references"))?;
    Ok(Some(graph))
}

/// Merge sibling graphs into a primary graph.
/// Entities from siblings get their `file_origin` prefixed with `[repo_name]`.
fn merge_graphs(
    primary: Option<kin_db::InMemoryGraph>,
    siblings: &[(String, kin_db::InMemoryGraph)],
) -> Result<kin_db::InMemoryGraph> {
    let merged = primary.unwrap_or_else(kin_db::InMemoryGraph::new);

    for (repo_name, sibling) in siblings {
        let entities = sibling
            .list_all_entities()
            .map_err(|e| anyhow::anyhow!("failed to list entities from '{}': {}", repo_name, e))?;

        for entity in &entities {
            let mut tagged = entity.clone();
            if let Some(ref origin) = tagged.file_origin {
                tagged.file_origin =
                    Some(FilePathId::new(format!("[{}] {}", repo_name, origin.0)));
            }
            if let Err(e) = merged.upsert_entity(&tagged) {
                eprintln!(
                    "Kin MCP: warning: failed to merge entity '{}' from '{}': {}",
                    entity.name, repo_name, e
                );
            }
        }

        for entity in &entities {
            let relations = sibling.get_all_relations_for_entity(&entity.id).unwrap_or_default();
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
