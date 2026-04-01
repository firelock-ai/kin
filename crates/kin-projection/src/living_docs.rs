// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::Path;

use kin_model::{Entity, EntityKind, GraphStore};
use tracing::info;

use crate::error::{ProjectionError, Result};

/// Generate living documentation files in `.kin/docs/`.
///
/// These docs are regenerated from graph state whenever code changes.
/// They are not committed to version control by default.
pub fn generate_living_docs<G>(graph: &G, docs_dir: &Path) -> Result<()>
where
    G: GraphStore,
{
    std::fs::create_dir_all(docs_dir).map_err(|e| ProjectionError::io(docs_dir, e))?;

    let entities = graph
        .list_all_entities()
        .map_err(|e| ProjectionError::Graph(e.to_string()))?;

    generate_architecture_md(&entities, docs_dir)?;
    generate_agents_md(&entities, docs_dir)?;
    generate_context_md(&entities, docs_dir)?;

    info!(path = %docs_dir.display(), "generated living docs");
    Ok(())
}

/// Generate ARCHITECTURE.md — high-level module/package overview.
fn generate_architecture_md(entities: &[Entity], docs_dir: &Path) -> Result<()> {
    let mut doc = String::new();
    doc.push_str("# Architecture\n\n");
    doc.push_str("*Auto-generated from Kin semantic graph. Do not edit manually.*\n\n");

    // List modules and packages.
    let modules: Vec<_> = entities
        .iter()
        .filter(|e| matches!(e.kind, EntityKind::Module | EntityKind::Package))
        .collect();

    if !modules.is_empty() {
        doc.push_str("## Modules\n\n");
        for entity in &modules {
            doc.push_str(&format!("- **{}** ({})", entity.name, entity.language));
            if let Some(ref summary) = entity.doc_summary {
                doc.push_str(&format!(" — {summary}"));
            }
            doc.push('\n');
        }
        doc.push('\n');
    }

    // List top-level types.
    let types: Vec<_> = entities
        .iter()
        .filter(|e| {
            matches!(
                e.kind,
                EntityKind::Class
                    | EntityKind::Interface
                    | EntityKind::TraitDef
                    | EntityKind::TypeAlias
            )
        })
        .collect();

    if !types.is_empty() {
        doc.push_str("## Types\n\n");
        for entity in &types {
            doc.push_str(&format!(
                "- `{}` ({:?}, {})\n",
                entity.name, entity.kind, entity.language
            ));
        }
        doc.push('\n');
    }

    let path = docs_dir.join("ARCHITECTURE.md");
    std::fs::write(&path, doc).map_err(|e| ProjectionError::io(&path, e))?;
    Ok(())
}

/// Generate AGENTS.md — information for AI assistants working in this repo.
fn generate_agents_md(entities: &[Entity], docs_dir: &Path) -> Result<()> {
    let mut doc = String::new();
    doc.push_str("# Agent Context\n\n");
    doc.push_str("*Auto-generated from Kin semantic graph. Do not edit manually.*\n\n");

    let function_count = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Function)
        .count();
    let test_count = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Test)
        .count();
    let total = entities.len();

    doc.push_str("## Summary\n\n");
    doc.push_str(&format!("- **Total entities:** {total}\n"));
    doc.push_str(&format!("- **Functions:** {function_count}\n"));
    doc.push_str(&format!("- **Tests:** {test_count}\n"));
    doc.push('\n');

    // Group by language.
    let mut by_language: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    for entity in entities {
        *by_language.entry(entity.language.to_string()).or_default() += 1;
    }

    if !by_language.is_empty() {
        doc.push_str("## Languages\n\n");
        for (lang, count) in &by_language {
            doc.push_str(&format!("- {lang}: {count} entities\n"));
        }
        doc.push('\n');
    }

    let path = docs_dir.join("AGENTS.md");
    std::fs::write(&path, doc).map_err(|e| ProjectionError::io(&path, e))?;
    Ok(())
}

/// Generate CONTEXT.md — key entry points and dependency summary.
fn generate_context_md(entities: &[Entity], docs_dir: &Path) -> Result<()> {
    let mut doc = String::new();
    doc.push_str("# Context Guide\n\n");
    doc.push_str("*Auto-generated from Kin semantic graph. Do not edit manually.*\n\n");

    // List API endpoints.
    let endpoints: Vec<_> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::ApiEndpoint)
        .collect();

    if !endpoints.is_empty() {
        doc.push_str("## API Endpoints\n\n");
        for entity in &endpoints {
            doc.push_str(&format!("- `{}`", entity.signature));
            if let Some(ref summary) = entity.doc_summary {
                doc.push_str(&format!(" — {summary}"));
            }
            doc.push('\n');
        }
        doc.push('\n');
    }

    // List schemas.
    let schemas: Vec<_> = entities
        .iter()
        .filter(|e| e.kind == EntityKind::Schema)
        .collect();

    if !schemas.is_empty() {
        doc.push_str("## Schemas\n\n");
        for entity in &schemas {
            doc.push_str(&format!("- `{}`\n", entity.name));
        }
        doc.push('\n');
    }

    let path = docs_dir.join("CONTEXT.md");
    std::fs::write(&path, doc).map_err(|e| ProjectionError::io(&path, e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::*;

    fn make_entity(name: &str, kind: EntityKind) -> Entity {
        Entity {
            id: EntityId::new(),
            kind,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: None,
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: Some(format!("Does {name} things")),
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    #[test]
    fn generate_architecture_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let entities = vec![
            make_entity("core", EntityKind::Module),
            make_entity("MyStruct", EntityKind::Class),
        ];

        generate_architecture_md(&entities, dir.path()).unwrap();

        let content = std::fs::read_to_string(dir.path().join("ARCHITECTURE.md")).unwrap();
        assert!(content.contains("# Architecture"));
        assert!(content.contains("core"));
        assert!(content.contains("MyStruct"));
    }

    #[test]
    fn generate_agents_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let entities = vec![
            make_entity("foo", EntityKind::Function),
            make_entity("test_foo", EntityKind::Test),
        ];

        generate_agents_md(&entities, dir.path()).unwrap();

        let content = std::fs::read_to_string(dir.path().join("AGENTS.md")).unwrap();
        assert!(content.contains("# Agent Context"));
        assert!(content.contains("**Functions:** 1"));
        assert!(content.contains("**Tests:** 1"));
    }

    #[test]
    fn generate_context_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let entities: Vec<Entity> = vec![];

        generate_context_md(&entities, dir.path()).unwrap();

        let content = std::fs::read_to_string(dir.path().join("CONTEXT.md")).unwrap();
        assert!(content.contains("# Context Guide"));
    }
}
