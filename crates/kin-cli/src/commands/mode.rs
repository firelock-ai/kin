// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Firelock, LLC

use std::path::Path;

use anyhow::Result;

use kin_core::{
    generate_bootstrap_docs, import_legacy_docs, AssistantKind, KinConfig, KinLayout, RepoMode,
    WorldPreset,
};

/// Files/directories to keep in the control root (not moved to source-root).
const CONTROL_ROOT_KEEP: &[&str] = &[
    "README.md",
    "AGENTS.md",
    "CLAUDE.md",
    "CODEX.md",
    "GEMINI.md",
    ".mcp.json",
    "kin.toml",
    ".kin",
    ".git",
    ".gitignore",
    "LICENSE",
    "LICENSE.md",
];

/// Hidden files/dirs that must remain in the control root.
/// Everything else (like .env, .cargo/, .python-version, .npmrc, .tool-versions)
/// moves to source-root so session workspaces can access them.
const HIDDEN_CONTROL_KEEP: &[&str] = &[
    ".git",
    ".gitignore",
    ".gitmodules",
    ".gitattributes",
    ".kin",
    ".mcp.json",
    ".claude",
];

/// `kin mode show` — Display the current repository mode.
pub async fn show() -> Result<()> {
    let layout = KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let config = KinConfig::load_or_default(&layout.config_path())?;

    let mode = kin_core::read_repo_mode(&layout);
    println!("Repository mode: {}", mode);
    println!("World preset: {}", config.world.preset);
    println!("Non-code artifacts: {}", config.artifacts.non_code);
    println!("External tools: {}", config.execution.external_tools);

    match mode {
        RepoMode::Native => {
            let source_root = layout.source_root_dir();
            if source_root.exists() {
                println!("Source root: {}", source_root.display());
            } else {
                println!("Source root: {} (missing!)", source_root.display());
            }
        }
        RepoMode::Compat => {
            println!("Source files are at the repository root.");
        }
    }

    Ok(())
}

/// `kin mode preset <name>` — Apply a worldview preset.
pub async fn preset(preset: String) -> Result<()> {
    let layout = KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let config_path = layout.config_path();
    let mut config = KinConfig::load_or_default(&config_path)?;
    let parsed = WorldPreset::from_str(&preset).ok_or_else(|| {
        anyhow::anyhow!(
            "unknown preset '{}'; expected one of: hybrid, radical, brownfield",
            preset
        )
    })?;

    config.apply_world_preset(parsed);
    config.save(&config_path)?;

    println!("Applied world preset: {}", parsed);
    println!("  Non-code artifacts: {}", config.artifacts.non_code);
    println!("  External tools: {}", config.execution.external_tools);

    Ok(())
}

/// `kin mode native` — Switch to Kin-native mode.
pub async fn native() -> Result<()> {
    let layout = KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let current = kin_core::read_repo_mode(&layout);
    if current == RepoMode::Native {
        println!("Already in native mode.");
        return Ok(());
    }

    // 1. Verify the KinDB snapshot exists
    if !crate::backend::kindb_snapshot_path(&layout).exists() {
        return Err(anyhow::anyhow!(
            "no KinDB snapshot found. Run `kin init` first."
        ));
    }

    let working_dir = layout.working_dir().to_path_buf();

    // 2. Import legacy docs
    let imported = import_legacy_docs(&layout)?;
    for path in &imported {
        println!("  Imported: {}", path.display());
    }

    // 3. Move source files to .kin/source-root/
    let source_root = layout.source_root_dir();
    std::fs::create_dir_all(&source_root)
        .map_err(|e| anyhow::anyhow!("failed to create source-root: {}", e))?;

    move_source_files(&working_dir, &source_root)?;

    // 4. Generate bootstrap docs for known assistants
    for kind in &[
        AssistantKind::ClaudeCode,
        AssistantKind::Codex,
        AssistantKind::GeminiCli,
    ] {
        let doc_name = match kind {
            AssistantKind::ClaudeCode => "CLAUDE.md",
            AssistantKind::Codex => "CODEX.md",
            AssistantKind::GeminiCli => "GEMINI.md",
            _ => continue,
        };
        // Only generate if the file existed (was imported) or should be created
        let doc = generate_bootstrap_docs(&layout, *kind);
        std::fs::write(working_dir.join(doc_name), &doc)
            .map_err(|e| anyhow::anyhow!("failed to write {}: {}", doc_name, e))?;
        println!("  Generated: {}", doc_name);
    }

    // Also generate AGENTS.md bootstrap
    let agents_doc = generate_bootstrap_docs(&layout, AssistantKind::Generic);
    std::fs::write(working_dir.join("AGENTS.md"), &agents_doc)
        .map_err(|e| anyhow::anyhow!("failed to write AGENTS.md: {}", e))?;
    println!("  Generated: AGENTS.md");

    // 5. Generate PATH shims so commands like cat/rg/find transparently
    //    resolve against source-root when launched from the control root.
    let shim_dir = kin_core::shims::ensure_shim_dir(&layout)?;
    println!("  Generated: shims at {}", shim_dir.display());

    // 6. Write mode flag
    kin_core::write_repo_mode(&layout, RepoMode::Native)?;

    // 7. Update config
    let config_path = layout.config_path();
    let mut config = KinConfig::load_or_default(&config_path)?;
    config.mode = "native".into();
    config.save(&config_path)?;

    println!("\nSwitched to native mode.");
    println!("Source files are now at: {}", source_root.display());
    println!("Use `kin exec`, `kin shell`, or `kin with` to work with source files.");
    println!("To revert: `kin mode compat`");

    Ok(())
}

/// `kin mode compat` — Switch back to compatibility mode.
pub async fn compat() -> Result<()> {
    let layout = KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let current = kin_core::read_repo_mode(&layout);
    if current == RepoMode::Compat {
        println!("Already in compat mode.");
        return Ok(());
    }

    let working_dir = layout.working_dir().to_path_buf();
    let source_root = layout.source_root_dir();

    if !source_root.exists() {
        return Err(anyhow::anyhow!(
            "source-root directory not found at {}",
            source_root.display()
        ));
    }

    // 1. Restore source files from source-root to working dir
    restore_source_files(&source_root, &working_dir)?;

    // 2. Restore original docs from imported/
    let import_dir = layout.docs_dir().join("imported");
    if import_dir.exists() {
        for entry in std::fs::read_dir(&import_dir)
            .map_err(|e| anyhow::anyhow!("failed to read imported dir: {}", e))?
        {
            let entry = entry?;
            let name = entry.file_name();
            let name_str = name.to_string_lossy();
            if let Some(original_name) = name_str.strip_suffix(".original.md") {
                let dest = working_dir.join(format!("{}.md", original_name));
                std::fs::copy(entry.path(), &dest)
                    .map_err(|e| anyhow::anyhow!("failed to restore {}: {}", name_str, e))?;
                println!("  Restored: {}", dest.display());
            }
        }
    }

    // 3. Clean up source-root
    std::fs::remove_dir_all(&source_root)
        .map_err(|e| anyhow::anyhow!("failed to remove source-root: {}", e))?;

    // 4. Write mode flag
    kin_core::write_repo_mode(&layout, RepoMode::Compat)?;

    // 5. Update config
    let config_path = layout.config_path();
    let mut config = KinConfig::load_or_default(&config_path)?;
    config.mode = "compat".into();
    config.save(&config_path)?;

    println!("\nSwitched to compat mode.");
    println!("Source files restored to repository root.");

    Ok(())
}

/// Move source files from working_dir into source_root, keeping control-root files in place.
fn move_source_files(working_dir: &Path, source_root: &Path) -> Result<()> {
    for entry in std::fs::read_dir(working_dir)
        .map_err(|e| anyhow::anyhow!("failed to read working dir: {}", e))?
    {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Skip control root items
        if CONTROL_ROOT_KEEP
            .iter()
            .any(|k| name_str.eq_ignore_ascii_case(k))
        {
            continue;
        }

        // Only skip hidden entries on the control-root allowlist; let .env, .cargo/, etc. move
        if name_str.starts_with('.') && HIDDEN_CONTROL_KEEP.iter().any(|k| *k == name_str.as_ref())
        {
            continue;
        }

        let src = entry.path();
        let dst = source_root.join(&name);

        std::fs::rename(&src, &dst).map_err(|e| {
            anyhow::anyhow!(
                "failed to move {} -> {}: {}",
                src.display(),
                dst.display(),
                e
            )
        })?;
        println!("  Moved: {} -> source-root/{}", name_str, name_str);
    }

    Ok(())
}

/// Restore source files from source_root back to working_dir.
fn restore_source_files(source_root: &Path, working_dir: &Path) -> Result<()> {
    for entry in std::fs::read_dir(source_root)
        .map_err(|e| anyhow::anyhow!("failed to read source-root: {}", e))?
    {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        let src = entry.path();
        let dst = working_dir.join(&name);

        // Don't overwrite existing files in working dir
        if dst.exists() {
            eprintln!(
                "  Warning: {} already exists at root, skipping restore",
                name_str
            );
            continue;
        }

        std::fs::rename(&src, &dst).map_err(|e| {
            anyhow::anyhow!(
                "failed to restore {} -> {}: {}",
                src.display(),
                dst.display(),
                e
            )
        })?;
        println!("  Restored: {} -> {}", name_str, name_str);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    /// Helper: create a realistic layout where source-root is under .kin/
    /// (mirroring KinLayout::source_root_dir() = .kin/source-root).
    fn setup_working_dir() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let dir = tempdir().unwrap();
        let working = dir.path().to_path_buf();
        let kin_dir = working.join(".kin");
        fs::create_dir(&kin_dir).unwrap();
        let source_root = kin_dir.join("source-root");
        fs::create_dir(&source_root).unwrap();
        (dir, working, source_root)
    }

    #[test]
    fn move_source_files_keeps_control_root_items() {
        let (_dir, working, source_root) = setup_working_dir();

        // Create control root items that should stay
        fs::write(working.join("README.md"), "readme").unwrap();
        fs::write(working.join("AGENTS.md"), "agents").unwrap();
        fs::write(working.join("kin.toml"), "config").unwrap();
        fs::create_dir(working.join(".git")).unwrap();

        // Create source files that should move
        fs::create_dir(working.join("src")).unwrap();
        fs::write(working.join("src").join("main.rs"), "fn main() {}").unwrap();
        fs::write(working.join("Cargo.toml"), "[package]").unwrap();

        move_source_files(&working, &source_root).unwrap();

        // Control root items stayed
        assert!(working.join("README.md").exists());
        assert!(working.join("AGENTS.md").exists());
        assert!(working.join(".kin").exists());

        // Source files moved
        assert!(!working.join("src").exists());
        assert!(!working.join("Cargo.toml").exists());
        assert!(source_root.join("src").join("main.rs").exists());
        assert!(source_root.join("Cargo.toml").exists());
    }

    #[test]
    fn move_source_files_moves_hidden_config_files() {
        let (_dir, working, source_root) = setup_working_dir();

        // Hidden config files that SHOULD move to source-root
        fs::write(working.join(".env"), "SECRET=x").unwrap();
        fs::create_dir(working.join(".cargo")).unwrap();
        fs::write(working.join(".cargo").join("config.toml"), "[build]").unwrap();
        fs::write(working.join(".python-version"), "3.11").unwrap();
        fs::write(working.join(".npmrc"), "registry=...").unwrap();
        fs::write(working.join(".tool-versions"), "node 20").unwrap();

        // Hidden infra that should NOT move
        fs::create_dir(working.join(".git")).unwrap();
        fs::write(working.join(".gitignore"), "target/").unwrap();

        move_source_files(&working, &source_root).unwrap();

        // Config files moved to source-root
        assert!(source_root.join(".env").exists());
        assert!(source_root.join(".cargo").join("config.toml").exists());
        assert!(source_root.join(".python-version").exists());
        assert!(source_root.join(".npmrc").exists());
        assert!(source_root.join(".tool-versions").exists());

        // Git/kin infra stayed
        assert!(working.join(".git").exists());
        assert!(working.join(".kin").exists());
        assert!(working.join(".gitignore").exists());
    }

    #[test]
    fn move_source_files_keeps_license_files() {
        let (_dir, working, source_root) = setup_working_dir();

        fs::write(working.join("LICENSE"), "MIT").unwrap();
        fs::write(working.join("LICENSE.md"), "MIT detailed").unwrap();
        fs::write(working.join("CLAUDE.md"), "claude docs").unwrap();
        fs::write(working.join("CODEX.md"), "codex docs").unwrap();
        fs::write(working.join("GEMINI.md"), "gemini docs").unwrap();

        move_source_files(&working, &source_root).unwrap();

        assert!(working.join("LICENSE").exists());
        assert!(working.join("LICENSE.md").exists());
        assert!(working.join("CLAUDE.md").exists());
        assert!(working.join("CODEX.md").exists());
        assert!(working.join("GEMINI.md").exists());
    }

    #[test]
    fn move_source_files_keeps_mcp_json_and_claude_dir() {
        let (_dir, working, source_root) = setup_working_dir();

        // .mcp.json and .claude/ are control root items that should stay
        fs::write(working.join(".mcp.json"), r#"{"mcpServers":{}}"#).unwrap();
        fs::create_dir(working.join(".claude")).unwrap();
        fs::write(working.join(".claude").join("settings.json"), "{}").unwrap();

        // Source file that should move
        fs::write(working.join("main.py"), "print('hi')").unwrap();

        move_source_files(&working, &source_root).unwrap();

        // Control root items stayed
        assert!(working.join(".mcp.json").exists());
        assert!(working.join(".claude").join("settings.json").exists());

        // Source file moved
        assert!(!working.join("main.py").exists());
        assert!(source_root.join("main.py").exists());
    }

    #[test]
    fn restore_source_files_moves_everything_back() {
        let dir = tempdir().unwrap();
        let working = dir.path();
        let source_root = dir.path().join("sr");
        fs::create_dir(&source_root).unwrap();

        // Create files in source-root
        fs::create_dir(source_root.join("src")).unwrap();
        fs::write(source_root.join("src").join("main.rs"), "fn main() {}").unwrap();
        fs::write(source_root.join("Cargo.toml"), "[package]").unwrap();
        fs::write(source_root.join(".env"), "SECRET=x").unwrap();

        restore_source_files(&source_root, working).unwrap();

        assert!(working.join("src").join("main.rs").exists());
        assert!(working.join("Cargo.toml").exists());
        assert!(working.join(".env").exists());
    }

    #[test]
    fn restore_skips_existing_files() {
        let dir = tempdir().unwrap();
        let working = dir.path();
        let source_root = dir.path().join("sr");
        fs::create_dir(&source_root).unwrap();

        // File exists at both locations
        fs::write(working.join("conflict.txt"), "root version").unwrap();
        fs::write(source_root.join("conflict.txt"), "source version").unwrap();

        restore_source_files(&source_root, working).unwrap();

        // Root version should be preserved (not overwritten)
        assert_eq!(
            fs::read_to_string(working.join("conflict.txt")).unwrap(),
            "root version"
        );
    }

    #[test]
    fn move_then_restore_roundtrip() {
        let (_dir, working, source_root) = setup_working_dir();

        // Create a realistic project layout
        fs::create_dir(working.join(".git")).unwrap();
        fs::write(working.join("README.md"), "readme").unwrap();
        fs::create_dir_all(working.join("src")).unwrap();
        fs::write(working.join("src").join("lib.rs"), "pub fn foo() {}").unwrap();
        fs::write(working.join("Cargo.toml"), "[package]\nname = \"test\"").unwrap();
        fs::write(working.join(".env"), "KEY=val").unwrap();

        move_source_files(&working, &source_root).unwrap();

        // Source files gone from working dir
        assert!(!working.join("src").exists());
        assert!(!working.join("Cargo.toml").exists());
        assert!(!working.join(".env").exists());

        // Control items remain
        assert!(working.join("README.md").exists());
        assert!(working.join(".git").exists());
        assert!(working.join(".kin").exists());

        // Now restore
        restore_source_files(&source_root, &working).unwrap();

        // Everything back
        assert!(working.join("src").join("lib.rs").exists());
        assert_eq!(
            fs::read_to_string(working.join("Cargo.toml")).unwrap(),
            "[package]\nname = \"test\""
        );
        assert_eq!(fs::read_to_string(working.join(".env")).unwrap(), "KEY=val");
    }

    #[test]
    fn show_compatible_config_defaults_survive_mode_updates() {
        let (_dir, working, _source_root) = setup_working_dir();
        fs::write(working.join(".kin").join("graph.kndb"), "stub").unwrap();
        let layout = KinLayout::discover(&working).unwrap();

        let mut config = KinConfig::default();
        config.apply_world_preset(WorldPreset::Radical);
        config.save(&layout.config_path()).unwrap();
        kin_core::write_repo_mode(&layout, RepoMode::Compat).unwrap();

        let mut loaded = KinConfig::load_or_default(&layout.config_path()).unwrap();
        loaded.mode = "native".into();
        loaded.save(&layout.config_path()).unwrap();

        let reloaded = KinConfig::load(&layout.config_path()).unwrap();
        assert_eq!(reloaded.world.preset, WorldPreset::Radical);
        assert_eq!(reloaded.artifacts.non_code.as_str(), "semantic");
        assert_eq!(reloaded.execution.external_tools.as_str(), "strict");
    }
}
