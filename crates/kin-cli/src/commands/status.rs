use anyhow::Result;

pub async fn run() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let graph = kin_graph::KuzuGraphStore::open(&layout.graph_dir())?;
    let current = kin_core::read_current_branch(&layout)?;

    use kin_model::GraphStore;
    if let Some(branch) = graph.get_branch(&current)? {
        println!("On branch: {}", branch.name);
        println!("Head: {}", branch.head);
    } else {
        println!("On branch: {} (not found in graph)", current);
    }

    // Show entity count
    let entities = graph.list_all_entities()?;
    println!("Entities: {}", entities.len());

    Ok(())
}
