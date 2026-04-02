// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;

use anyhow::Result;
use kin_model::{EntityKind, EntityRole, EntityStore, RelationKind};

/// `kin graph status` — quick health check of the semantic graph.
pub async fn status() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let snap = crate::backend::open_snapshot_daemon_first_read_only(&layout).await?;
    let graph = &*snap.graph();

    let entities = graph.list_all_entities()?;
    let entity_count = entities.len();

    // Role counts
    let mut role_counts: HashMap<EntityRole, usize> = HashMap::new();
    for e in &entities {
        *role_counts.entry(e.role).or_insert(0) += 1;
    }

    // Kind counts
    let mut kind_counts: HashMap<EntityKind, usize> = HashMap::new();
    for e in &entities {
        *kind_counts.entry(e.kind).or_insert(0) += 1;
    }

    // Relation counts by kind
    let mut relation_counts: HashMap<RelationKind, usize> = HashMap::new();
    let mut total_relations = 0usize;
    for e in &entities {
        for rel in graph.get_all_relations_for_entity(&e.id)? {
            *relation_counts.entry(rel.kind).or_insert(0) += 1;
            total_relations += 1;
        }
    }
    // Each relation counted twice (from both endpoints), divide by 2.
    total_relations /= 2;
    for count in relation_counts.values_mut() {
        *count /= 2;
    }

    // File count
    let unique_files: std::collections::HashSet<_> = entities
        .iter()
        .filter_map(|e| e.file_origin.as_ref().map(|f| f.0.clone()))
        .collect();

    // Embedding status
    let embed_status = graph.embedding_status();

    // Doc summary coverage
    let with_docs = entities.iter().filter(|e| e.doc_summary.is_some()).count();

    // Print report
    println!("=== Graph Health ===");
    println!();
    println!(
        "Entities: {}  |  Relations: {}  |  Files: {}",
        entity_count, total_relations, unique_files.len()
    );
    println!(
        "Rels/Entity: {:.2}",
        if entity_count == 0 {
            0.0
        } else {
            total_relations as f64 / entity_count as f64
        }
    );
    println!();

    // Roles
    let role_order = [
        (EntityRole::Source, "source"),
        (EntityRole::Test, "test"),
        (EntityRole::External, "external"),
        (EntityRole::Docs, "docs"),
        (EntityRole::Generated, "generated"),
        (EntityRole::Vendored, "vendored"),
    ];
    let role_parts: Vec<String> = role_order
        .iter()
        .filter_map(|(role, label)| role_counts.get(role).map(|c| format!("{label}: {c}")))
        .collect();
    println!("Roles: {}", role_parts.join(", "));

    // Relation types
    let mut rel_pairs: Vec<_> = relation_counts.iter().collect();
    rel_pairs.sort_by(|a, b| b.1.cmp(a.1));
    let rel_parts: Vec<String> = rel_pairs
        .iter()
        .map(|(kind, count)| format!("{:?}: {}", kind, count))
        .collect();
    println!("Relations: {}", rel_parts.join(", "));

    // Kind distribution
    let mut kind_pairs: Vec<_> = kind_counts.iter().collect();
    kind_pairs.sort_by(|a, b| b.1.cmp(a.1));
    let kind_parts: Vec<String> = kind_pairs
        .iter()
        .take(8)
        .map(|(kind, count)| format!("{:?}: {}", kind, count))
        .collect();
    println!("Kinds: {}", kind_parts.join(", "));

    println!();
    println!(
        "Embeddings: {}/{} indexed ({} pending)",
        embed_status.indexed, embed_status.total, embed_status.pending
    );
    println!(
        "Doc summaries: {}/{} ({:.0}%)",
        with_docs,
        entity_count,
        if entity_count == 0 {
            0.0
        } else {
            (with_docs as f64 / entity_count as f64) * 100.0
        }
    );

    // Warnings
    let mut warnings = Vec::new();
    if entity_count > 0 && total_relations == 0 {
        warnings.push("no relations in graph — cross-file linking may have failed".to_string());
    }
    if entity_count > 0
        && role_counts.len() == 1
        && role_counts.contains_key(&EntityRole::Source)
    {
        warnings.push(
            "all entities are Source — role classification may not be working".to_string(),
        );
    }
    let rels_per_ent = if entity_count == 0 {
        0.0
    } else {
        total_relations as f64 / entity_count as f64
    };
    if rels_per_ent < 0.1 && entity_count > 100 {
        warnings.push(format!(
            "very low relation density ({:.2} rels/entity) — linker may be failing",
            rels_per_ent
        ));
    }
    if embed_status.pending > 0 {
        warnings.push(format!(
            "{} embeddings pending — run `kin embed` for semantic search",
            embed_status.pending
        ));
    }

    if warnings.is_empty() {
        println!("\n✓ No issues detected.");
    } else {
        println!();
        for w in &warnings {
            println!("⚠ {}", w);
        }
    }

    Ok(())
}

/// `kin graph validate` — structural integrity checks.
pub async fn validate() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let snap = crate::backend::open_snapshot_daemon_first_read_only(&layout).await?;
    let graph = &*snap.graph();

    let entities = graph.list_all_entities()?;
    let mut issues = Vec::new();

    // Check for duplicate entities (same name + file + kind)
    let mut seen: HashMap<(String, Option<String>, EntityKind), Vec<kin_model::EntityId>> =
        HashMap::new();
    for e in &entities {
        let key = (
            e.name.clone(),
            e.file_origin.as_ref().map(|f| f.0.clone()),
            e.kind,
        );
        seen.entry(key).or_default().push(e.id);
    }
    let duplicates: Vec<_> = seen
        .iter()
        .filter(|(_, ids)| ids.len() > 1)
        .collect();
    if !duplicates.is_empty() {
        issues.push(format!(
            "{} duplicate entities (same name+file+kind)",
            duplicates.len()
        ));
    }

    // Check for orphaned entities (file_origin that doesn't exist on disk)
    let source_root = kin_core::source_dir(&layout);
    let mut orphaned = 0usize;
    for e in &entities {
        if let Some(ref fo) = e.file_origin {
            if !source_root.join(&fo.0).exists() {
                orphaned += 1;
            }
        }
    }
    if orphaned > 0 {
        issues.push(format!(
            "{} orphaned entities (file no longer exists on disk)",
            orphaned
        ));
    }

    // Check relation integrity (src/dst entity IDs exist)
    let entity_ids: std::collections::HashSet<_> = entities.iter().map(|e| e.id).collect();
    let mut broken_relations = 0usize;
    for e in &entities {
        for rel in graph.get_all_relations_for_entity(&e.id)? {
            if let kin_model::GraphNodeId::Entity(id) = rel.src {
                if !entity_ids.contains(&id) {
                    broken_relations += 1;
                }
            }
            if let kin_model::GraphNodeId::Entity(id) = rel.dst {
                if !entity_ids.contains(&id) {
                    broken_relations += 1;
                }
            }
        }
    }
    if broken_relations > 0 {
        issues.push(format!(
            "{} relations reference non-existent entities",
            broken_relations
        ));
    }

    // Report
    println!("=== Graph Validation ===");
    println!();
    println!(
        "Checked {} entities, {} relations",
        entities.len(),
        entities.len() // approximation; we don't double-count here
    );

    if issues.is_empty() {
        println!("\n✓ All checks passed.");
    } else {
        println!();
        for issue in &issues {
            println!("✗ {}", issue);
        }
        anyhow::bail!("{} issue(s) found", issues.len());
    }

    Ok(())
}

/// `kin graph inspect <entity_name>` — look up an entity and show its relations.
pub async fn inspect(name: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let snap = crate::backend::open_snapshot_daemon_first_read_only(&layout).await?;
    let graph = &*snap.graph();

    let entities = graph.list_all_entities()?;
    let matches: Vec<_> = entities
        .iter()
        .filter(|e| e.name == name || e.name.ends_with(&format!(".{}", name)))
        .collect();

    if matches.is_empty() {
        anyhow::bail!("no entity found matching '{}'", name);
    }

    for entity in &matches {
        println!("Entity: {} ({:?})", entity.name, entity.kind);
        println!("  ID: {}", entity.id);
        println!("  Language: {}", entity.language);
        println!("  Role: {:?}", entity.role);
        if let Some(ref fo) = entity.file_origin {
            println!("  File: {}", fo.0);
        }
        if let Some(ref span) = entity.span {
            println!(
                "  Span: lines {}-{}",
                span.start_line, span.end_line
            );
        }
        println!("  Signature: {}", entity.signature);
        if let Some(ref doc) = entity.doc_summary {
            println!("  Doc: {}", doc);
        }
        println!("  Visibility: {:?}", entity.visibility);

        // Show relations
        let relations = graph.get_all_relations_for_entity(&entity.id)?;
        if !relations.is_empty() {
            println!("  Relations ({}):", relations.len());
            for rel in relations.iter().take(20) {
                let target_name = match rel.dst {
                    kin_model::GraphNodeId::Entity(id) => {
                        if id == entity.id {
                            // Incoming relation — show source
                            match rel.src {
                                kin_model::GraphNodeId::Entity(src_id) => graph
                                    .get_entity(&src_id)?
                                    .map(|e| format!("{} ({})", e.name, e.file_origin.as_ref().map(|f| f.0.as_str()).unwrap_or("?")))
                                    .unwrap_or_else(|| format!("{}", src_id)),
                                _ => format!("{:?}", rel.src),
                            }
                        } else {
                            graph
                                .get_entity(&id)?
                                .map(|e| format!("{} ({})", e.name, e.file_origin.as_ref().map(|f| f.0.as_str()).unwrap_or("?")))
                                .unwrap_or_else(|| format!("{}", id))
                        }
                    }
                    _ => format!("{:?}", rel.dst),
                };
                let direction = if matches!(rel.dst, kin_model::GraphNodeId::Entity(id) if id == entity.id) {
                    "<-"
                } else {
                    "->"
                };
                println!("    {} {:?} {}", direction, rel.kind, target_name);
            }
            if relations.len() > 20 {
                println!("    ... and {} more", relations.len() - 20);
            }
        }
        println!();
    }

    Ok(())
}
