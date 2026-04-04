// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_model::EntityStore;
use std::collections::HashMap;

pub async fn run_json() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let _snap = crate::backend::open_snapshot_daemon_first_read_only(&layout).await?;
    let graph = &*_snap.graph();

    let entities = graph.list_all_entities()?;
    let unique_files: std::collections::HashSet<_> = entities
        .iter()
        .filter_map(|e| e.file_origin.as_ref().map(|f| f.0.clone()))
        .collect();
    let mut relation_ids = std::collections::HashSet::new();
    let mut kinds = HashMap::<String, usize>::new();

    for entity in &entities {
        *kinds.entry(format!("{:?}", entity.kind)).or_default() += 1;
        for rel in graph.get_all_relations_for_entity(&entity.id)? {
            relation_ids.insert(rel.id);
        }
    }

    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "entities": entities.len(),
            "edges": relation_ids.len(),
            "files": unique_files.len(),
            "kinds": kinds,
        }))?
    );
    Ok(())
}

pub async fn run(compact: bool) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let _snap = crate::backend::open_snapshot_daemon_first_read_only(&layout).await?;
    let graph = &*_snap.graph();

    let entities = graph.list_all_entities()?;

    let repo_name = std::env::current_dir()?
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Count unique files
    let unique_files: std::collections::HashSet<_> = entities
        .iter()
        .filter_map(|e| e.file_origin.as_ref().map(|f| f.0.clone()))
        .collect();

    println!("=== Kin Overview ===");
    println!(
        "Repository: {}  |  Entities: {}  |  Files: {}",
        repo_name,
        entities.len(),
        unique_files.len()
    );
    println!();

    // Group by language
    let mut by_lang: HashMap<String, (usize, std::collections::HashSet<String>)> = HashMap::new();
    for e in &entities {
        let lang_str = e.language.to_string();
        let entry = by_lang
            .entry(lang_str)
            .or_insert((0, std::collections::HashSet::new()));
        entry.0 += 1;
        if let Some(ref fo) = e.file_origin {
            entry.1.insert(fo.0.clone());
        }
    }
    println!("--- Languages ---");
    let mut langs: Vec<_> = by_lang.iter().collect();
    langs.sort_by(|a, b| b.1 .0.cmp(&a.1 .0));
    for (lang, (count, files)) in &langs {
        println!(
            "  {}: {} entities across {} files",
            lang,
            count,
            files.len()
        );
    }
    println!();

    // Group by kind
    let mut by_kind: HashMap<String, Vec<&kin_model::Entity>> = HashMap::new();
    for e in &entities {
        by_kind.entry(format!("{:?}", e.kind)).or_default().push(e);
    }

    if compact {
        // Compact mode: just counts per kind, no entity listings
        println!("--- Entity Kinds ---");
        let mut kinds: Vec<_> = by_kind.iter().collect();
        kinds.sort_by(|a, b| b.1.len().cmp(&a.1.len()));
        for (kind, ents) in &kinds {
            println!("  {}: {}", kind, ents.len());
        }
    } else {
        // Full mode: show top entities per kind
        let top_n = 5;
        println!("--- Top Entities by Kind ---");
        let mut kinds: Vec<_> = by_kind.iter().collect();
        kinds.sort_by(|a, b| b.1.len().cmp(&a.1.len()));
        for (kind, ents) in &kinds {
            println!("{} ({}):", kind, ents.len());
            for e in ents.iter().take(top_n) {
                let file = e.file_origin.as_ref().map(|f| f.0.as_str()).unwrap_or("?");
                let line = e.span.as_ref().map(|s| s.start_line).unwrap_or(0);
                println!("  {}  {}:{}", e.name, file, line);
            }
            if ents.len() > top_n {
                println!("  ... and {} more", ents.len() - top_n);
            }
            println!();
        }
    }

    Ok(())
}
