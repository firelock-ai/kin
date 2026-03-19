// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Firelock, LLC

use std::fs;

use anyhow::Result;

pub async fn create(intent: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let spec = kin_model::Spec {
        id: kin_model::SpecId::new(),
        intent,
        scope: Vec::new(),
        constraints: Vec::new(),
        acceptance_criteria: Vec::new(),
        affected_systems: Vec::new(),
        validation_requirements: Vec::new(),
    };

    // Store spec as JSON in .kin/specs/
    let specs_dir = layout.root().join("specs");
    fs::create_dir_all(&specs_dir)?;

    let spec_file = specs_dir.join(format!("{}.json", spec.id));
    let json = serde_json::to_string_pretty(&spec)?;
    fs::write(&spec_file, &json)?;

    println!("Created spec: {}", spec.id);
    println!("  Intent: {}", spec.intent);
    println!("  Stored: {}", spec_file.display());

    Ok(())
}

pub async fn list() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let specs_dir = layout.root().join("specs");
    if !specs_dir.exists() {
        println!("No specs found.");
        return Ok(());
    }

    let mut entries: Vec<_> = fs::read_dir(&specs_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "json"))
        .collect();

    if entries.is_empty() {
        println!("No specs found.");
        return Ok(());
    }

    entries.sort_by_key(|e| e.file_name());

    for entry in &entries {
        let content = fs::read_to_string(entry.path())?;
        let spec: kin_model::Spec = serde_json::from_str(&content)?;
        println!("  {} - {}", spec.id, spec.intent);
    }

    Ok(())
}

pub async fn show(id: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let specs_dir = layout.root().join("specs");
    let spec_file = specs_dir.join(format!("{}.json", id));

    if !spec_file.exists() {
        anyhow::bail!("spec '{}' not found", id);
    }

    let content = fs::read_to_string(&spec_file)?;
    let spec: kin_model::Spec = serde_json::from_str(&content)?;

    println!("Spec: {}", spec.id);
    println!("  Intent: {}", spec.intent);
    if !spec.scope.is_empty() {
        println!("  Scope: {}", spec.scope.join(", "));
    }
    if !spec.constraints.is_empty() {
        println!("  Constraints:");
        for c in &spec.constraints {
            println!("    - {}", c);
        }
    }
    if !spec.acceptance_criteria.is_empty() {
        println!("  Acceptance criteria:");
        for ac in &spec.acceptance_criteria {
            println!("    - {}", ac);
        }
    }
    if !spec.affected_systems.is_empty() {
        println!("  Affected systems: {}", spec.affected_systems.join(", "));
    }
    if !spec.validation_requirements.is_empty() {
        println!("  Validation requirements:");
        for vr in &spec.validation_requirements {
            println!("    - {}", vr);
        }
    }

    Ok(())
}
