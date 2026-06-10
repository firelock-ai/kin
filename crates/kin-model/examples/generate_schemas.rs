// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Generates JSON Schema files from kin-model types.
//!
//! Usage: cargo run --example generate_schemas -- [output_dir]
//! Default output_dir: schemas/

use schemars::schema_for;
use std::fs;
use std::path::Path;

fn main() {
    let out_dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "schemas".to_string());
    let out = Path::new(&out_dir);
    fs::create_dir_all(out).expect("failed to create output directory");

    let schemas: Vec<(&str, String)> = vec![
        // Core graph types
        (
            "Entity",
            serde_json::to_string_pretty(&schema_for!(kin_model::Entity)).unwrap(),
        ),
        (
            "EntityKind",
            serde_json::to_string_pretty(&schema_for!(kin_model::EntityKind)).unwrap(),
        ),
        (
            "Relation",
            serde_json::to_string_pretty(&schema_for!(kin_model::Relation)).unwrap(),
        ),
        (
            "RelationKind",
            serde_json::to_string_pretty(&schema_for!(kin_model::RelationKind)).unwrap(),
        ),
        // Semantic changes
        (
            "SemanticChange",
            serde_json::to_string_pretty(&schema_for!(kin_model::SemanticChange)).unwrap(),
        ),
        // Work graph
        (
            "WorkItem",
            serde_json::to_string_pretty(&schema_for!(kin_model::WorkItem)).unwrap(),
        ),
        (
            "WorkStatus",
            serde_json::to_string_pretty(&schema_for!(kin_model::WorkStatus)).unwrap(),
        ),
        (
            "WorkKind",
            serde_json::to_string_pretty(&schema_for!(kin_model::WorkKind)).unwrap(),
        ),
        (
            "Annotation",
            serde_json::to_string_pretty(&schema_for!(kin_model::Annotation)).unwrap(),
        ),
        // Review
        (
            "RiskSummary",
            serde_json::to_string_pretty(&schema_for!(kin_model::RiskSummary)).unwrap(),
        ),
        (
            "RiskLevel",
            serde_json::to_string_pretty(&schema_for!(kin_model::RiskLevel)).unwrap(),
        ),
    ];

    for (name, schema) in &schemas {
        let path = out.join(format!("{}.json", name));
        fs::write(&path, schema)
            .unwrap_or_else(|e| panic!("failed to write {}: {}", path.display(), e));
    }

    println!("Generated {} schemas to {}", schemas.len(), out.display());
}
