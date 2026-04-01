// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result, bail};
use serde::Serialize;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

const PREPARED_PUBLISH_SCHEMA: &str = "kin.prepared-state.publish.v1";
const PREPARED_MATERIALIZE_SCHEMA: &str = "kin.prepared-state.materialize.v1";
const PREPARED_MANIFEST_SCHEMA: &str = "kin.prepared-state.v1";

const VALIDATION_KEYS: &[&str] = &[
    "cache_key",
    "repo_identity",
    "git_head",
    "git_tree",
    "init_pipeline_epoch",
    "parser_schema_epoch",
    "layout_schema_version",
    "graph_snapshot_version",
    "text_index_format_version",
    "vector_index_metadata_version",
    "feature_flags",
    "embedding_model_id",
    "embedding_model_revision",
    "embedding_pipeline_epoch",
    "embeddings_enabled",
    "vector_enabled",
    "metal_enabled",
    "kin_binary_sha256",
];

#[derive(Debug, Serialize)]
struct PublishResult {
    schema: &'static str,
    prepared_dir: String,
    manifest_path: String,
    cache_key: String,
    repo_identity: String,
    text_index_present: bool,
    vector_index_present: bool,
}

#[derive(Debug, Serialize)]
struct MaterializeResult {
    schema: &'static str,
    source_dir: String,
    repo_path: String,
    manifest_path: String,
    cache_key: String,
    repo_identity: String,
    validated: bool,
    text_index_present: bool,
    vector_index_present: bool,
}

pub async fn publish(target: PathBuf, json: bool) -> Result<()> {
    let repo_path = std::env::current_dir()?;
    let kin_dir = repo_path.join(".kin");
    if !kin_dir.exists() {
        bail!("not a Kin repository (no .kin/ found)");
    }

    let manifest = expected_manifest(&repo_path)?;
    publish_prepared_state_from_kin_dir(&kin_dir, &target, &manifest)?;

    let result = PublishResult {
        schema: PREPARED_PUBLISH_SCHEMA,
        prepared_dir: target.display().to_string(),
        manifest_path: target.join("manifest.json").display().to_string(),
        cache_key: manifest_string(&manifest, "cache_key")?,
        repo_identity: manifest_string(&manifest, "repo_identity")?,
        text_index_present: target.join(".kin/kindb/text-index").exists(),
        vector_index_present: target.join(".kin/kindb/graph.kvec").exists()
            && target.join(".kin/kindb/graph.kvec.meta.json").exists(),
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("published prepared state to {}", result.prepared_dir);
        println!("cache_key: {}", result.cache_key);
        println!("repo_identity: {}", result.repo_identity);
    }

    Ok(())
}

pub async fn materialize(source: PathBuf, json: bool) -> Result<()> {
    let repo_path = std::env::current_dir()?;
    let expected_manifest = expected_manifest(&repo_path)?;
    let actual_manifest = validate_prepared_state(&source, &expected_manifest)?;
    materialize_prepared_state(&source, &repo_path)?;

    let result = MaterializeResult {
        schema: PREPARED_MATERIALIZE_SCHEMA,
        source_dir: source.display().to_string(),
        repo_path: repo_path.display().to_string(),
        manifest_path: source.join("manifest.json").display().to_string(),
        cache_key: manifest_string(&actual_manifest, "cache_key")?,
        repo_identity: manifest_string(&actual_manifest, "repo_identity")?,
        validated: true,
        text_index_present: source.join(".kin/kindb/text-index").exists(),
        vector_index_present: source.join(".kin/kindb/graph.kvec").exists()
            && source.join(".kin/kindb/graph.kvec.meta.json").exists(),
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("materialized prepared state from {}", result.source_dir);
        println!("cache_key: {}", result.cache_key);
        println!("repo_identity: {}", result.repo_identity);
    }

    Ok(())
}

fn expected_manifest(repo_path: &Path) -> Result<Value> {
    let meta = crate::commands::bench_meta::build_meta()?;
    let (prepared_manifest, _) =
        crate::commands::bench_meta::build_prepared_manifests(&meta, repo_path)?;
    serde_json::to_value(&prepared_manifest).context("serialize prepared-state manifest")
}

fn validate_prepared_state(prepared_dir: &Path, expected_manifest: &Value) -> Result<Value> {
    let manifest_path = prepared_dir.join("manifest.json");
    if !prepared_dir.exists() {
        bail!("missing prepared state");
    }
    if !manifest_path.exists() {
        bail!("prepared manifest missing");
    }

    let actual_manifest: Value = serde_json::from_str(
        &fs::read_to_string(&manifest_path)
            .with_context(|| format!("read prepared manifest {}", manifest_path.display()))?,
    )
    .with_context(|| format!("parse prepared manifest {}", manifest_path.display()))?;

    if actual_manifest
        .get("schema")
        .and_then(Value::as_str)
        .unwrap_or_default()
        != PREPARED_MANIFEST_SCHEMA
    {
        bail!("schema version mismatch");
    }

    for key in VALIDATION_KEYS {
        if actual_manifest.get(*key) != expected_manifest.get(*key) {
            bail!("{} mismatch", key.replace('_', " "));
        }
    }

    for relative_path in required_prepared_entries() {
        if !prepared_dir.join(relative_path).exists() {
            bail!("prepared artifact missing {}", relative_path.display());
        }
    }

    Ok(actual_manifest)
}

fn required_prepared_entries() -> &'static [PathBuf] {
    use std::sync::OnceLock;

    static REQUIRED: OnceLock<Vec<PathBuf>> = OnceLock::new();
    REQUIRED
        .get_or_init(|| {
            vec![
                PathBuf::from(".kin"),
                PathBuf::from(".kin/version"),
                PathBuf::from(".kin/kindb/graph.kndb"),
                PathBuf::from(".kin/kindb/text-index"),
            ]
        })
        .as_slice()
}

fn publish_prepared_state_from_kin_dir(
    source_kin_dir: &Path,
    target_dir: &Path,
    manifest: &Value,
) -> Result<()> {
    let parent = target_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    fs::create_dir_all(&parent)?;
    let file_name = target_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("prepared");
    let staging_dir = parent.join(format!(
        ".{file_name}.tmp.{}.{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    remove_path_if_exists(&staging_dir)?;
    fs::create_dir_all(&staging_dir)?;
    copy_dir_recursive(source_kin_dir, &staging_dir.join(".kin"))?;
    fs::write(
        staging_dir.join("manifest.json"),
        serde_json::to_string_pretty(manifest)?,
    )?;

    if target_dir.exists() {
        remove_path_if_exists(target_dir)?;
    }
    fs::rename(&staging_dir, target_dir)
        .with_context(|| format!("replace prepared dir {}", target_dir.display()))?;
    Ok(())
}

fn materialize_prepared_state(source_dir: &Path, repo_path: &Path) -> Result<()> {
    let kin_dir = repo_path.join(".kin");
    remove_path_if_exists(&kin_dir)?;
    copy_dir_recursive(&source_dir.join(".kin"), &kin_dir)
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src).with_context(|| format!("read {}", src.display()))? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else if file_type.is_file() {
            if let Some(parent) = dst_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(&src_path, &dst_path).with_context(|| {
                format!("copy {} -> {}", src_path.display(), dst_path.display())
            })?;
        }
    }
    Ok(())
}

fn remove_path_if_exists(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_dir() {
        fs::remove_dir_all(path)?;
    } else {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn manifest_string(manifest: &Value, key: &str) -> Result<String> {
    manifest
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .with_context(|| format!("prepared manifest missing string field {key}"))
}
