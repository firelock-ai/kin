// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use serde_json::Value;
use std::process::Command;
use tempfile::tempdir;

#[test]
fn bench_meta_json_reports_cache_key_dimensions() {
    let repo = tempdir().expect("temp repo");
    let output = Command::new(env!("CARGO_BIN_EXE_kin"))
        .arg("bench-meta")
        .arg("--json")
        .current_dir(repo.path())
        .output()
        .expect("run kin bench-meta");
    assert!(
        output.status.success(),
        "kin bench-meta failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let payload: Value =
        serde_json::from_slice(&output.stdout).expect("bench-meta stdout should be valid json");
    assert_eq!(payload["schema"], "kin.bench-meta.v1");
    assert!(payload["init_pipeline_epoch"].is_string());
    assert!(payload["parser_schema_epoch"].is_string());
    assert!(payload["layout_schema_version"].is_u64());
    assert!(payload["graph_snapshot_version"].is_u64());
    assert!(payload["text_index_format_version"].is_u64());
    assert!(payload["kin_binary_sha256"].is_string());

    let embeddings = payload["embeddings"].as_object().expect("embeddings object");
    assert!(embeddings.contains_key("vector_enabled"));
    assert!(embeddings.contains_key("embeddings_enabled"));
    assert!(embeddings.contains_key("metal_enabled"));
    assert!(payload["feature_flags"].is_array());
}
