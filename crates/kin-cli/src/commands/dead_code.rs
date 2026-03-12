use anyhow::Result;
use kin_model::GraphStore;

pub async fn run() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let graph = kin_graph::KuzuGraphStore::open_read_only(&layout.graph_dir())?;

    println!("Scanning for dead code...");

    let dead = graph.find_dead_code()?;
    if dead.is_empty() {
        println!("No dead code found.");
    } else {
        println!("Found {} unreferenced entities:", dead.len());
        for e in &dead {
            println!(
                "  {} ({:?}, {}) - {}",
                e.name,
                e.kind,
                e.language,
                e.file_origin
                    .as_ref()
                    .map(|f| f.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            );
        }
    }

    Ok(())
}
