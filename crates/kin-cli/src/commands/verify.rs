use anyhow::Result;
use kin_model::GraphStore;

/// `kin verify <entity>` — Check verification / test coverage for an entity.
///
/// Shows per-entity test linkage and overall coverage summary.
pub async fn run(entity: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let graph = kin_graph::KuzuGraphStore::open(&layout.graph_dir())?;

    // Find entity by name
    let filter = kin_model::EntityFilter {
        name_pattern: Some(entity.clone()),
        ..Default::default()
    };
    let entities = graph.query_entities(&filter)?;

    if entities.is_empty() {
        println!("No entity matching '{}' found.", entity);
        return Ok(());
    }

    let mut covered_count = 0usize;
    let mut uncovered_count = 0usize;

    for ent in &entities {
        let tests = graph.get_tests_for_entity(&ent.id)?;
        if tests.is_empty() {
            uncovered_count += 1;
            println!("  MISSING  {} ({:?})", ent.name, ent.kind);
        } else {
            covered_count += 1;
            println!("  COVERED  {} ({:?}) — {} test(s)", ent.name, ent.kind, tests.len());
            for test in &tests {
                println!("           - {} [{}] runner={}", test.name, test.kind, test.runner);
            }
        }
    }

    println!();
    println!(
        "Matched {} entity(ies): {} covered, {} missing proof",
        entities.len(),
        covered_count,
        uncovered_count,
    );

    // Show overall coverage summary
    let summary = graph.get_coverage_summary()?;
    println!();
    println!("Repository Coverage:");
    println!(
        "  {}/{} entities covered ({:.1}%)",
        summary.covered_entities,
        summary.total_entities,
        summary.coverage_ratio * 100.0
    );
    if !summary.missing_proof.is_empty() {
        println!("  {} entities missing proof", summary.missing_proof.len());
    }

    Ok(())
}

/// `kin verify --summary` — Show repository-wide coverage summary only.
pub async fn summary() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let graph = kin_graph::KuzuGraphStore::open(&layout.graph_dir())?;

    let summary = graph.get_coverage_summary()?;

    println!("Repository Coverage:");
    println!(
        "  {}/{} entities covered ({:.1}%)",
        summary.covered_entities,
        summary.total_entities,
        summary.coverage_ratio * 100.0
    );

    if summary.missing_proof.is_empty() {
        println!("  All entities have linked proof.");
    } else {
        println!("  {} entities missing proof:", summary.missing_proof.len());
        // Show uncovered entity names (look up each).
        for eid in &summary.missing_proof {
            if let Some(entity) = graph.get_entity(eid)? {
                println!("    - {} ({:?})", entity.name, entity.kind);
            } else {
                println!("    - {}", eid);
            }
        }
    }

    Ok(())
}

/// `kin verify --missing` — Show only entities without any linked test.
pub async fn missing() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let graph = kin_graph::KuzuGraphStore::open(&layout.graph_dir())?;

    let summary = graph.get_coverage_summary()?;

    if summary.missing_proof.is_empty() {
        println!("All {} entities have linked proof.", summary.total_entities);
        return Ok(());
    }

    println!(
        "Entities missing proof ({}/{}):",
        summary.missing_proof.len(),
        summary.total_entities
    );

    for eid in &summary.missing_proof {
        if let Some(entity) = graph.get_entity(eid)? {
            let file = entity
                .file_origin
                .as_ref()
                .map(|f| f.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            println!("  - {} ({:?}) in {}", entity.name, entity.kind, file);
        } else {
            println!("  - {}", eid);
        }
    }

    Ok(())
}
