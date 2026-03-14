use anyhow::Result;
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
    let _snap = kin_db::SnapshotManager::open(layout.graph_dir().join("kindb"))?;
    let graph = &*_snap.graph();

    let source = kin_core::source_dir(&layout);
    let resolved_scope = resolve_materialization_scope(&graph, scope)?;

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
        scope: resolved_scope.clone(),
    };

    println!("Materializing workspace...");
    match &resolved_scope {
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

    Ok(Some(scope))
}

#[cfg(test)]
mod tests {
    use super::resolve_materialization_scope;
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
}
