use anyhow::Result;

pub async fn run(count: usize) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let graph = kin_graph::KuzuGraphStore::open_read_only(&layout.graph_dir())?;
    let current = kin_core::read_current_branch(&layout)?;

    use kin_model::GraphStore;
    let branch = graph
        .get_branch(&current)?
        .ok_or_else(|| anyhow::anyhow!("branch '{}' not found", current))?;

    println!("Semantic change log (branch: {}):", branch.name);
    println!("  Head: {}", branch.head);

    // Walk the change DAG from head
    let mut current_id = Some(branch.head);
    let mut shown = 0usize;

    while let Some(id) = current_id {
        if shown >= count {
            break;
        }
        if let Some(change) = graph.get_change(&id)? {
            println!("\n  {} - {}", change.id, change.message);
            println!("    Author: {}", change.author);
            println!("    Time: {}", change.timestamp);
            println!(
                "    Entities: {} added/modified/removed",
                change.entity_deltas.len()
            );
            shown += 1;
            current_id = change.parents.first().copied();
        } else {
            break;
        }
    }

    if shown == 0 {
        println!("\n  (no changes found)");
    }

    Ok(())
}
