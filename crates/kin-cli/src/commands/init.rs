use anyhow::Result;
use std::path::PathBuf;

pub async fn run(path: Option<String>) -> Result<()> {
    let dir = path
        .map(PathBuf::from)
        .unwrap_or_else(|| std::env::current_dir().expect("cannot determine current directory"));

    let result = kin_core::init(&dir)?;
    println!(
        "Initialized Kin repository at {}",
        result.layout.root().display()
    );
    println!("  KinDB: {}", result.layout.kindb_snapshot_path().display());
    println!("  Blobs: {}", result.layout.objects_dir().display());
    println!("  Genesis change: {}", result.genesis_id);

    Ok(())
}
