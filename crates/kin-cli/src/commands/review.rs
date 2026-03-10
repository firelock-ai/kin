use anyhow::Result;

pub async fn run(change: Option<String>) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let graph = kin_graph::KuzuGraphStore::open(&layout.graph_dir())?;

    use kin_model::GraphStore;

    let change_id = match change {
        Some(h) => kin_model::SemanticChangeId::from_hash(
            kin_model::Hash256::from_hex(&h)
                .map_err(|e| anyhow::anyhow!("invalid hash: {}", e))?,
        ),
        None => {
            let current = kin_core::read_current_branch(&layout)?;
            let branch = graph
                .get_branch(&current)?
                .ok_or_else(|| anyhow::anyhow!("branch '{}' not found", current))?;
            branch.head
        }
    };

    println!("Reviewing semantic change: {}", change_id);

    if let Some(change) = graph.get_change(&change_id)? {
        println!("  Message: {}", change.message);
        println!("  Author: {}", change.author);
        println!("  Entity deltas: {}", change.entity_deltas.len());
        println!("  Relation deltas: {}", change.relation_deltas.len());
        println!("  Artifact deltas: {}", change.artifact_deltas.len());

        if let Some(ref risk) = change.risk_summary {
            println!("  Risk: {:?}", risk.overall_risk);
            for note in &risk.notes {
                println!("    - {}", note);
            }
        } else {
            println!("  Risk: not yet assessed");
        }
    } else {
        println!("  Change not found");
    }

    Ok(())
}
