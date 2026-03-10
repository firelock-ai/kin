use std::fs;
use std::path::PathBuf;

use anyhow::Result;

/// `kin workspace list` — List known workspaces.
pub async fn list() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let ws_dir = layout.root().join(".kin/workspaces");
    let entries = list_workspace_entries(&ws_dir)?;

    if entries.is_empty() {
        println!("No workspaces. Use 'kin workspace create <name>' to create one.");
        return Ok(());
    }

    println!("{:<20}  {:<40}  {}", "NAME", "ID", "CREATED");
    println!("{}", "-".repeat(80));

    for entry in &entries {
        let content = fs::read_to_string(entry)?;
        let ws: serde_json::Value = serde_json::from_str(&content)?;
        let name = entry
            .file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();
        let id = ws["id"].as_str().unwrap_or("unknown");
        let created = ws["created_at"].as_str().unwrap_or("unknown");
        println!("{:<20}  {:<40}  {}", name, id, created);
    }

    Ok(())
}

/// `kin workspace create <name>` — Create a new workspace.
pub async fn create(name: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let ws_dir = layout.root().join(".kin/workspaces");
    fs::create_dir_all(&ws_dir)?;

    let ws_file = ws_dir.join(format!("{}.json", name));
    if ws_file.exists() {
        anyhow::bail!("workspace '{}' already exists", name);
    }

    let workspace = kin_runtime::create_workspace(layout.root())?;

    let ws_json = serde_json::json!({
        "id": workspace.id,
        "name": name,
        "root": workspace.root.display().to_string(),
        "created_at": workspace.created_at.to_rfc3339(),
        "snapshot_id": workspace.snapshot_id,
    });

    fs::write(&ws_file, serde_json::to_string_pretty(&ws_json)?)?;

    println!("Created workspace '{}'", name);
    println!("  ID: {}", workspace.id);
    println!("  Root: {}", workspace.root.display());

    Ok(())
}

/// `kin workspace switch <name>` — Switch to a workspace.
pub async fn switch(name: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let ws_dir = layout.root().join(".kin/workspaces");
    let ws_file = ws_dir.join(format!("{}.json", name));

    if !ws_file.exists() {
        anyhow::bail!("workspace '{}' not found", name);
    }

    let content = fs::read_to_string(&ws_file)?;
    let ws: serde_json::Value = serde_json::from_str(&content)?;

    // Write the active workspace marker.
    let active_file = layout.root().join(".kin/active-workspace");
    fs::write(&active_file, &name)?;

    let id = ws["id"].as_str().unwrap_or("unknown");
    println!("Switched to workspace '{}' ({})", name, id);

    Ok(())
}

// ── Helpers ──────────────────────────────────────────────────────────

fn list_workspace_entries(ws_dir: &PathBuf) -> Result<Vec<PathBuf>> {
    if !ws_dir.exists() {
        return Ok(vec![]);
    }

    let mut entries: Vec<PathBuf> = fs::read_dir(ws_dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().map_or(false, |ext| ext == "json"))
        .collect();

    entries.sort();
    Ok(entries)
}
