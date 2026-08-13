// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::fs;
use std::path::Path;

use anyhow::Result;
use serde::Serialize;

/// Schema token stamped on every `kin spec list --json` answer.
pub const SPEC_LIST_SCHEMA: &str = "kin.spec.list.v1";

pub async fn create(intent: String) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;

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

/// One stored spec, as both the list and the JSON surface describe it.
#[derive(Debug, Serialize)]
pub struct SpecEntry {
    pub id: String,
    pub intent: String,
}

#[derive(Debug, Serialize)]
pub struct SpecListJson {
    pub schema: &'static str,
    pub count: usize,
    pub specs: Vec<SpecEntry>,
}

/// Every spec stored under `<root>/specs`, ordered by filename.
///
/// A missing directory yields an empty list rather than an error: a repository
/// that has never created a spec is a repository with no specs, which is an
/// answer both surfaces can state.
fn collect_specs(specs_dir: &Path) -> Result<Vec<SpecEntry>> {
    if !specs_dir.exists() {
        return Ok(Vec::new());
    }

    let mut entries: Vec<_> = fs::read_dir(specs_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().is_some_and(|ext| ext == "json"))
        .collect();
    entries.sort_by_key(|e| e.file_name());

    let mut specs = Vec::new();
    for entry in &entries {
        let content = fs::read_to_string(entry.path())?;
        let spec: kin_model::Spec = serde_json::from_str(&content)?;
        specs.push(SpecEntry {
            id: spec.id.to_string(),
            intent: spec.intent,
        });
    }
    Ok(specs)
}

pub async fn list(json: bool) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;

    let specs_dir = layout.root().join("specs");
    let specs = collect_specs(&specs_dir)?;

    // An empty set is an answer, so the stamped envelope goes out with a zero
    // count rather than the prose the text path prints.
    if json {
        let payload = SpecListJson {
            schema: SPEC_LIST_SCHEMA,
            count: specs.len(),
            specs,
        };
        println!("{}", serde_json::to_string_pretty(&payload)?);
        return Ok(());
    }

    if specs.is_empty() {
        println!("No specs found.");
        return Ok(());
    }

    for spec in &specs {
        println!("  {} - {}", spec.id, spec.intent);
    }

    Ok(())
}

pub async fn show(id: String) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;

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

#[cfg(test)]
mod tests {
    use super::*;

    /// The filename and the stored id are set independently on purpose: the
    /// walk orders by filename and reads the id out of the file, so a test that
    /// tied them together could not tell the two apart.
    fn write_spec(specs_dir: &Path, file_stem: &str, id: &str, intent: &str) {
        let spec = serde_json::json!({
            "id": id,
            "intent": intent,
            "scope": [],
            "constraints": [],
            "acceptance_criteria": [],
            "affected_systems": [],
            "validation_requirements": [],
        });
        fs::write(
            specs_dir.join(format!("{file_stem}.json")),
            serde_json::to_string_pretty(&spec).unwrap(),
        )
        .unwrap();
    }

    /// A repository that never created a spec has no specs, which is an answer.
    ///
    /// The directory is absent in that case, and the text path prints prose for
    /// it. The machine surface must still emit a parseable stamped envelope.
    #[test]
    fn a_missing_specs_directory_answers_with_a_stamped_zero() {
        let dir = tempfile::tempdir().unwrap();
        let specs = collect_specs(&dir.path().join("specs")).unwrap();
        assert!(specs.is_empty());

        let payload = SpecListJson {
            schema: SPEC_LIST_SCHEMA,
            count: specs.len(),
            specs,
        };
        let value = serde_json::to_value(&payload).unwrap();
        assert_eq!(value["schema"], SPEC_LIST_SCHEMA);
        assert_eq!(value["count"].as_u64().unwrap(), 0);
        assert!(
            value["specs"].is_array(),
            "the list must be present and empty, never absent"
        );
    }

    /// Specs come back ordered by filename, carrying the id and intent the text
    /// path prints, and non-JSON files in the directory are not specs.
    #[test]
    fn the_json_surface_carries_every_stored_spec_in_filename_order() {
        const FIRST_ID: &str = "11111111-1111-4111-8111-111111111111";
        const SECOND_ID: &str = "22222222-2222-4222-8222-222222222222";

        let dir = tempfile::tempdir().unwrap();
        let specs_dir = dir.path().join("specs");
        fs::create_dir_all(&specs_dir).unwrap();
        write_spec(&specs_dir, "b", SECOND_ID, "tighten the reconcile loop");
        write_spec(&specs_dir, "a", FIRST_ID, "name the embedding gap");
        fs::write(specs_dir.join("notes.md"), b"not a spec").unwrap();

        let specs = collect_specs(&specs_dir).unwrap();
        let ids: Vec<&str> = specs.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, vec![FIRST_ID, SECOND_ID]);
        assert_eq!(specs[0].intent, "name the embedding gap");
        assert_eq!(specs[1].intent, "tighten the reconcile loop");

        let payload = SpecListJson {
            schema: SPEC_LIST_SCHEMA,
            count: specs.len(),
            specs,
        };
        let value = serde_json::to_value(&payload).unwrap();
        assert_eq!(
            value["count"].as_u64().unwrap() as usize,
            value["specs"].as_array().unwrap().len()
        );
        assert!(value["specs"][0]["id"].is_string());
        assert!(value["specs"][0]["intent"].is_string());
    }
}
