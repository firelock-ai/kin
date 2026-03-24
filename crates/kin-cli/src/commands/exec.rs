// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_core::{ExternalToolExecutionPolicy, KinConfig};
use kin_model::{EntityFilter, EntityId, GraphStore};

/// Full version of `kin exec` with all options.
pub async fn run_full(
    command: String,
    keep: bool,
    strategy: Option<String>,
    scope: Option<String>,
) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let _snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout))?;
    let graph = &*_snap.graph();
    let config = KinConfig::load_or_default(&layout.config_path())?;

    let source = kin_core::source_dir(&layout);
    let resolved_scope = resolve_materialization_scope(graph, scope)?;
    let planned_scope = plan_materialization_scope(&command, resolved_scope, &config)?;

    let parsed_strategy = match &strategy {
        Some(s) => {
            let strat: kin_runtime::MaterializeStrategy =
                s.parse().map_err(|e: String| anyhow::anyhow!(e))?;
            Some(strat)
        }
        None => None,
    };

    let config = kin_runtime::exec::MaterializeConfig {
        strategy: parsed_strategy,
        keep,
        scope: planned_scope.clone(),
    };

    println!("Materializing workspace...");
    match &planned_scope {
        Some(s) => println!("  Scope: {s}"),
        None => println!("  Scope: full workspace"),
    }
    let result = kin_runtime::exec::exec_in_workspace(&source, &command, &config)?;

    // Print output
    if !result.stdout.is_empty() {
        print!("{}", result.stdout);
    }
    if !result.stderr.is_empty() {
        eprint!("{}", result.stderr);
    }

    println!(
        "\nExecution complete (exit code: {}, {}ms, strategy: {})",
        result.exit_code, result.duration_ms, result.strategy_used
    );

    if keep {
        println!("Workspace kept at: {}", result.workspace_path.display());
    } else {
        kin_runtime::exec::cleanup_workspace(&result.workspace_path)?;
    }

    if result.exit_code != 0 {
        std::process::exit(result.exit_code);
    }

    Ok(())
}

fn resolve_materialization_scope(
    graph: &kin_db::InMemoryGraph,
    scope: Option<String>,
) -> Result<Option<String>> {
    let Some(scope) = scope else {
        return Ok(None);
    };

    if let Some(raw) = scope.strip_prefix("entity:") {
        if let Ok(uuid) = uuid::Uuid::parse_str(raw) {
            let entity_id = EntityId(uuid);
            let entity = graph
                .get_entity(&entity_id)?
                .ok_or_else(|| anyhow::anyhow!("entity '{}' not found", raw))?;
            let file = entity
                .file_origin
                .ok_or_else(|| anyhow::anyhow!("entity '{}' has no file origin", raw))?;
            return Ok(Some(format!("file:{}", file.0)));
        }

        let matches = graph.query_entities(&EntityFilter {
            name_pattern: Some(raw.to_string()),
            ..Default::default()
        })?;

        let exact: Vec<_> = matches.into_iter().filter(|e| e.name == raw).collect();
        let entity = match exact.as_slice() {
            [entity] => entity,
            [] => return Err(anyhow::anyhow!("entity '{}' not found", raw)),
            _ => {
                return Err(anyhow::anyhow!(
                    "entity '{}' is ambiguous; use entity:<uuid>",
                    raw
                ))
            }
        };

        let file = entity
            .file_origin
            .clone()
            .ok_or_else(|| anyhow::anyhow!("entity '{}' has no file origin", raw))?;
        return Ok(Some(format!("file:{}", file.0)));
    }

    if let Some(raw) = scope.strip_prefix("artifact:") {
        let path = raw.trim();
        if path.is_empty() {
            return Err(anyhow::anyhow!("artifact scope cannot be empty"));
        }
        return Ok(Some(format!("file:{path}")));
    }

    Ok(Some(scope))
}

fn plan_materialization_scope(
    command: &str,
    scope: Option<String>,
    config: &KinConfig,
) -> Result<Option<String>> {
    let Some(tool) = detect_external_tool(command) else {
        return Ok(scope);
    };

    let Some(active_scope) = scope else {
        return Ok(None);
    };

    match config.execution.external_tools {
        ExternalToolExecutionPolicy::Workspace => {
            eprintln!(
                "Execution policy widened `{}` from `{}` to a full compatibility workspace.",
                tool.display_name(),
                active_scope
            );
            Ok(None)
        }
        ExternalToolExecutionPolicy::Strict => Err(anyhow::anyhow!(
            "execution policy `strict` will not auto-widen `{}` from `{}`. Run without `--scope` for a full workspace or switch to `kin mode preset compatibility`.",
            tool.display_name(),
            active_scope,
        )),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExternalToolKind {
    DockerCompose,
    DockerBuild,
    Make,
}

impl ExternalToolKind {
    fn display_name(self) -> &'static str {
        match self {
            Self::DockerCompose => "docker compose",
            Self::DockerBuild => "docker build",
            Self::Make => "make",
        }
    }
}

fn detect_external_tool(command: &str) -> Option<ExternalToolKind> {
    let parts: Vec<_> = command.split_whitespace().collect();
    match parts.as_slice() {
        ["docker-compose", ..] | ["podman-compose", ..] => Some(ExternalToolKind::DockerCompose),
        ["docker", "compose", ..] | ["podman", "compose", ..] => {
            Some(ExternalToolKind::DockerCompose)
        }
        ["docker", "build", ..]
        | ["podman", "build", ..]
        | ["docker", "bake", ..]
        | ["docker", "buildx", "bake", ..]
        | ["podman", "bake", ..] => Some(ExternalToolKind::DockerBuild),
        ["make", ..] | ["gmake", ..] => Some(ExternalToolKind::Make),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        detect_external_tool, plan_materialization_scope, resolve_materialization_scope,
        ExternalToolKind,
    };
    use kin_core::{ExternalToolExecutionPolicy, KinConfig, WorldPreset};
    use kin_model::{
        Entity, EntityId, EntityKind, EntityMetadata, FilePathId, FingerprintAlgorithm, GraphStore,
        Hash256, LanguageId, SemanticFingerprint, SourceSpan, Visibility,
    };

    fn test_entity(name: &str, file: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([1; 32]),
                signature_hash: Hash256::from_bytes([2; 32]),
                behavior_hash: Hash256::from_bytes([3; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(file)),
            span: Some(SourceSpan {
                file: FilePathId::new(file),
                start_byte: 0,
                end_byte: 10,
                start_line: 1,
                start_col: 0,
                end_line: 1,
                end_col: 10,
            }),
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    #[test]
    fn resolves_entity_id_scope_to_file_scope() {
        let graph = kin_db::InMemoryGraph::new();
        let entity = test_entity("render", "src/render.rs");
        graph.upsert_entity(&entity).unwrap();

        let scope =
            resolve_materialization_scope(&graph, Some(format!("entity:{}", entity.id))).unwrap();

        assert_eq!(scope, Some("file:src/render.rs".to_string()));
    }

    #[test]
    fn resolves_exact_entity_name_scope_to_file_scope() {
        let graph = kin_db::InMemoryGraph::new();
        let entity = test_entity("render", "src/render.rs");
        graph.upsert_entity(&entity).unwrap();

        let scope =
            resolve_materialization_scope(&graph, Some("entity:render".to_string())).unwrap();

        assert_eq!(scope, Some("file:src/render.rs".to_string()));
    }

    #[test]
    fn resolves_artifact_scope_to_file_scope() {
        let graph = kin_db::InMemoryGraph::new();

        let scope =
            resolve_materialization_scope(&graph, Some("artifact:docker-compose.yml".to_string()))
                .unwrap();

        assert_eq!(scope, Some("file:docker-compose.yml".to_string()));
    }

    #[test]
    fn detects_docker_compose_variants() {
        assert_eq!(
            detect_external_tool("docker compose up"),
            Some(ExternalToolKind::DockerCompose)
        );
        assert_eq!(
            detect_external_tool("docker-compose up"),
            Some(ExternalToolKind::DockerCompose)
        );
        assert_eq!(
            detect_external_tool("make test"),
            Some(ExternalToolKind::Make)
        );
    }

    #[test]
    fn detects_docker_build_variants() {
        assert_eq!(
            detect_external_tool("docker build -f Dockerfile ."),
            Some(ExternalToolKind::DockerBuild)
        );
        assert_eq!(
            detect_external_tool("podman build -f Containerfile ."),
            Some(ExternalToolKind::DockerBuild)
        );
        assert_eq!(
            detect_external_tool("docker buildx bake"),
            Some(ExternalToolKind::DockerBuild)
        );
    }

    #[test]
    fn workspace_policy_widens_scoped_external_tools() {
        let mut config = KinConfig::default();
        config.apply_world_preset(WorldPreset::Compatibility);

        let scope = plan_materialization_scope(
            "docker compose up",
            Some("file:docker-compose.yml".to_string()),
            &config,
        )
        .unwrap();

        assert_eq!(scope, None);
        assert_eq!(
            config.execution.external_tools,
            ExternalToolExecutionPolicy::Workspace
        );
    }

    #[test]
    fn strict_policy_blocks_scoped_external_tools() {
        let mut config = KinConfig::default();
        config.apply_world_preset(WorldPreset::Native);

        let err =
            plan_materialization_scope("make test", Some("artifact:Makefile".to_string()), &config)
                .unwrap_err();

        assert!(err.to_string().contains("will not auto-widen"));
        assert_eq!(
            config.execution.external_tools,
            ExternalToolExecutionPolicy::Strict
        );
    }
}
