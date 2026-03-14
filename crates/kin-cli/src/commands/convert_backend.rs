//! Convert graph data from KuzuDB to KinDB backend.

use anyhow::Result;
use kin_model::graph::GraphStore;
use std::collections::HashMap;

pub fn run() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let _snap = kin_db::SnapshotManager::open(layout.graph_dir().join("kindb"))?;
    let kuzu = &*_snap.graph();

    eprintln!("Reading KuzuDB graph...");
    let entities = kuzu.list_all_entities()?;
    eprintln!("  {} entities", entities.len());

    let kindb = kin_db::InMemoryGraph::new();
    let mut rel_count = 0usize;

    for entity in &entities {
        kindb.upsert_entity(entity)?;
        let relations = kuzu.get_all_relations_for_entity(&entity.id)?;
        for rel in &relations {
            // Avoid duplicate relations (they appear on both src and dst)
            if rel.src == entity.id {
                kindb.upsert_relation(rel)?;
                rel_count += 1;
            }
        }
    }

    // Also copy branches
    let branches = kuzu.list_branches()?;
    for branch in &branches {
        kindb.create_branch(branch)?;
    }
    eprintln!("  {} branches", branches.len());

    // Copy shallow files
    let shallow = kuzu.list_shallow_files()?;
    for sf in &shallow {
        kindb.upsert_shallow_file(sf)?;
    }
    eprintln!("  {} shallow files", shallow.len());

    eprintln!(
        "KinDB graph: {} entities, {} relations",
        kindb.entity_count(),
        rel_count
    );

    let kindb_path = crate::backend::kindb_snapshot_path(&layout);
    if let Some(parent) = kindb_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let snap = kin_db::SnapshotManager::new(&kindb_path);
    snap.swap(kindb);
    snap.save()?;

    eprintln!("Saved KinDB snapshot to {}", kindb_path.display());

    // Generate embeddings for all entities
    eprintln!("Generating embeddings...");
    let mut embedder = kin_db::CodeEmbedder::new()?;
    let mut vectors: HashMap<String, Vec<f32>> = HashMap::with_capacity(entities.len());

    for entity in &entities {
        let text =
            kin_db::embed::format_entity_text(&entity.name, &entity.signature, "");
        if text.is_empty() {
            continue;
        }
        let embedding = embedder.embed_entity(&entity.name, &entity.signature, "")?;
        vectors.insert(entity.id.to_string(), embedding);
    }
    eprintln!("  {} embeddings generated", vectors.len());

    let vectors_path = crate::backend::kindb_vectors_path(&layout);
    let vectors_json = serde_json::to_vec(&vectors)?;
    std::fs::write(&vectors_path, &vectors_json)?;
    eprintln!("Saved vectors to {}", vectors_path.display());

    eprintln!("Use KIN_BACKEND=kindb to switch to KinDB backend.");
    Ok(())
}
