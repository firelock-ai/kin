// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_core::layout::KIN_LAYOUT_VERSION;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Serialize)]
pub(crate) struct BenchMeta {
    schema: &'static str,
    kin_version: &'static str,
    init_pipeline_epoch: &'static str,
    parser_schema_epoch: &'static str,
    layout_schema_version: u32,
    graph_snapshot_version: u32,
    text_index_format_version: u32,
    vector_index_metadata_version: Option<u32>,
    feature_flags: Vec<&'static str>,
    embeddings: EmbeddingMeta,
    kin_commit: &'static str,
    kin_dirty: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct EmbeddingMeta {
    vector_enabled: bool,
    embeddings_enabled: bool,
    metal_enabled: bool,
    model_id: Option<String>,
    model_revision: Option<String>,
    pipeline_epoch: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct PreparedManifest {
    schema: &'static str,
    cache_key: String,
    repo_base_key: String,
    repo_identity: String,
    git_head: String,
    git_tree: String,
    init_pipeline_epoch: &'static str,
    parser_schema_epoch: &'static str,
    layout_schema_version: u32,
    graph_snapshot_version: u32,
    text_index_format_version: u32,
    vector_index_metadata_version: Option<u32>,
    feature_flags: Vec<&'static str>,
    embedding_model_id: Option<String>,
    embedding_model_revision: Option<String>,
    embedding_pipeline_epoch: Option<String>,
    embeddings_enabled: bool,
    vector_enabled: bool,
    metal_enabled: bool,
    kin_commit: &'static str,
    kin_dirty: bool,
    kin_version: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct RepoBaseManifest {
    schema: &'static str,
    repo_base_key: String,
    repo_identity: String,
    init_pipeline_epoch: &'static str,
    parser_schema_epoch: &'static str,
    layout_schema_version: u32,
    graph_snapshot_version: u32,
    text_index_format_version: u32,
    vector_index_metadata_version: Option<u32>,
    feature_flags: Vec<&'static str>,
    embedding_model_id: Option<String>,
    embedding_model_revision: Option<String>,
    embedding_pipeline_epoch: Option<String>,
    embeddings_enabled: bool,
    vector_enabled: bool,
    metal_enabled: bool,
    kin_commit: &'static str,
    kin_dirty: bool,
    kin_version: &'static str,
    source_git_head: String,
    source_git_tree: String,
}

#[derive(Debug, Clone, Serialize)]
struct BenchMetaWithPreparedState {
    #[serde(flatten)]
    meta: BenchMeta,
    prepared_manifest: PreparedManifest,
    repo_base_manifest: RepoBaseManifest,
}

pub async fn run(json: bool, prepared_state: bool) -> Result<()> {
    let meta = build_meta()?;

    if prepared_state {
        let (prepared_manifest, repo_base_manifest) =
            build_prepared_manifests(&meta, &std::env::current_dir()?)?;
        let payload = BenchMetaWithPreparedState {
            meta,
            prepared_manifest,
            repo_base_manifest,
        };
        if json {
            println!("{}", serde_json::to_string_pretty(&payload)?);
        } else {
            println!("{}", serde_json::to_string_pretty(&payload)?);
        }
        return Ok(());
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&meta)?);
    } else {
        println!("schema: {}", meta.schema);
        println!("kin_version: {}", meta.kin_version);
        println!("init_pipeline_epoch: {}", meta.init_pipeline_epoch);
        println!("parser_schema_epoch: {}", meta.parser_schema_epoch);
        println!("layout_schema_version: {}", meta.layout_schema_version);
        println!("graph_snapshot_version: {}", meta.graph_snapshot_version);
        println!(
            "text_index_format_version: {}",
            meta.text_index_format_version
        );
        if let Some(version) = meta.vector_index_metadata_version {
            println!("vector_index_metadata_version: {}", version);
        } else {
            println!("vector_index_metadata_version: disabled");
        }
        println!("feature_flags: {}", meta.feature_flags.join(","));
        println!("kin_commit: {}", meta.kin_commit);
        println!("kin_dirty: {}", meta.kin_dirty);
        if let Some(model_id) = meta.embeddings.model_id.as_deref() {
            println!("embedding_model_id: {}", model_id);
        }
        if let Some(revision) = meta.embeddings.model_revision.as_deref() {
            println!("embedding_model_revision: {}", revision);
        }
        if let Some(epoch) = meta.embeddings.pipeline_epoch.as_deref() {
            println!("embedding_pipeline_epoch: {}", epoch);
        }
    }

    Ok(())
}

pub(crate) fn build_meta() -> Result<BenchMeta> {
    let build = kin_buildinfo::get();
    Ok(BenchMeta {
        schema: "kin.bench-meta.v1",
        kin_version: env!("CARGO_PKG_VERSION"),
        init_pipeline_epoch: crate::commands::init::INIT_WARM_CACHE_PIPELINE_EPOCH,
        parser_schema_epoch: kin_parser::PARSER_SCHEMA_EPOCH,
        layout_schema_version: KIN_LAYOUT_VERSION,
        graph_snapshot_version: kin_db::GraphSnapshot::CURRENT_VERSION,
        text_index_format_version: kin_db::TEXT_INDEX_FORMAT_VERSION,
        vector_index_metadata_version: vector_index_metadata_version(),
        feature_flags: feature_flags(),
        embeddings: embedding_meta(),
        kin_commit: build.sha,
        kin_dirty: build.dirty,
    })
}

/// Whether the Metal embedding backend is *actually* compiled into this binary.
///
/// The real `kin-db/metal` -> `kin-infer/metal` backend is pulled in by the
/// `[target.'cfg(target_os = "macos")'.dependencies] kin-db = { features = ["metal"] }`
/// block in kin-cli/Cargo.toml. Cargo target-dependency sections are gated by the build
/// *target* only — never by the crate's own cargo features (`feature = ...` isn't even
/// allowed in a `[target.'cfg(...)']` key) — so that block is UNCONDITIONAL on macOS:
/// Metal is built for every macOS build, even under `--no-default-features`. The `metal`
/// cargo feature is therefore vestigial for "is Metal built"; the honest predicate is the
/// target OS alone. (`cfg!(feature = "metal")` would be wrong both ways: true on Linux where
/// Metal isn't compiled, and false for a macOS `--no-default-features` build where it is.)
const fn metal_active() -> bool {
    cfg!(target_os = "macos")
}

fn feature_flags() -> Vec<&'static str> {
    let mut flags = Vec::new();
    if cfg!(feature = "vector") {
        flags.push("vector");
    }
    if cfg!(feature = "embeddings") {
        flags.push("embeddings");
    }
    if metal_active() {
        flags.push("metal");
    }
    flags.sort_unstable();
    flags
}

fn embedding_meta() -> EmbeddingMeta {
    #[cfg(feature = "embeddings")]
    {
        let runtime = kin_db::embed::configured_embedding_runtime();
        EmbeddingMeta {
            vector_enabled: cfg!(feature = "vector"),
            embeddings_enabled: true,
            metal_enabled: metal_active(),
            model_id: Some(runtime.model_id),
            model_revision: Some(runtime.revision),
            pipeline_epoch: Some(runtime.pipeline_epoch),
        }
    }

    #[cfg(not(feature = "embeddings"))]
    {
        EmbeddingMeta {
            vector_enabled: cfg!(feature = "vector"),
            embeddings_enabled: false,
            metal_enabled: metal_active(),
            model_id: None,
            model_revision: None,
            pipeline_epoch: None,
        }
    }
}

fn vector_index_metadata_version() -> Option<u32> {
    #[cfg(feature = "vector")]
    {
        Some(kin_db::VECTOR_INDEX_METADATA_VERSION)
    }

    #[cfg(not(feature = "vector"))]
    {
        None
    }
}

pub(crate) fn build_prepared_manifests(
    meta: &BenchMeta,
    repo_path: &Path,
) -> Result<(PreparedManifest, RepoBaseManifest)> {
    let repo_identity = detect_repo_identity(repo_path);
    let git_head = git_output(repo_path, ["rev-parse", "HEAD"])?;
    let git_tree = git_output(repo_path, ["rev-parse", "HEAD^{tree}"])?;
    let cache_key = hash_json(&serde_json::json!({
        "repo_identity": &repo_identity,
        "git_head": &git_head,
        "git_tree": &git_tree,
        "init_pipeline_epoch": meta.init_pipeline_epoch,
        "parser_schema_epoch": meta.parser_schema_epoch,
        "layout_schema_version": meta.layout_schema_version,
        "graph_snapshot_version": meta.graph_snapshot_version,
        "text_index_format_version": meta.text_index_format_version,
        "vector_index_metadata_version": meta.vector_index_metadata_version,
        "feature_flags": &meta.feature_flags,
        "embedding_model_id": &meta.embeddings.model_id,
        "embedding_model_revision": &meta.embeddings.model_revision,
        "embedding_pipeline_epoch": &meta.embeddings.pipeline_epoch,
        "embeddings_enabled": meta.embeddings.embeddings_enabled,
        "vector_enabled": meta.embeddings.vector_enabled,
        "metal_enabled": meta.embeddings.metal_enabled,
        "kin_commit": meta.kin_commit,
        "kin_dirty": meta.kin_dirty,
    }));
    let repo_base_key = hash_json(&serde_json::json!({
        "repo_identity": &repo_identity,
        "init_pipeline_epoch": meta.init_pipeline_epoch,
        "parser_schema_epoch": meta.parser_schema_epoch,
        "layout_schema_version": meta.layout_schema_version,
        "graph_snapshot_version": meta.graph_snapshot_version,
        "text_index_format_version": meta.text_index_format_version,
        "vector_index_metadata_version": meta.vector_index_metadata_version,
        "feature_flags": &meta.feature_flags,
        "embedding_model_id": &meta.embeddings.model_id,
        "embedding_model_revision": &meta.embeddings.model_revision,
        "embedding_pipeline_epoch": &meta.embeddings.pipeline_epoch,
        "embeddings_enabled": meta.embeddings.embeddings_enabled,
        "vector_enabled": meta.embeddings.vector_enabled,
        "metal_enabled": meta.embeddings.metal_enabled,
        "kin_commit": meta.kin_commit,
        "kin_dirty": meta.kin_dirty,
    }));

    let prepared = PreparedManifest {
        schema: "kin.prepared-state.v1",
        cache_key,
        repo_identity,
        git_head,
        git_tree,
        init_pipeline_epoch: meta.init_pipeline_epoch,
        parser_schema_epoch: meta.parser_schema_epoch,
        layout_schema_version: meta.layout_schema_version,
        graph_snapshot_version: meta.graph_snapshot_version,
        text_index_format_version: meta.text_index_format_version,
        vector_index_metadata_version: meta.vector_index_metadata_version,
        feature_flags: meta.feature_flags.clone(),
        embedding_model_id: meta.embeddings.model_id.clone(),
        embedding_model_revision: meta.embeddings.model_revision.clone(),
        embedding_pipeline_epoch: meta.embeddings.pipeline_epoch.clone(),
        embeddings_enabled: meta.embeddings.embeddings_enabled,
        vector_enabled: meta.embeddings.vector_enabled,
        metal_enabled: meta.embeddings.metal_enabled,
        kin_commit: meta.kin_commit,
        kin_dirty: meta.kin_dirty,
        kin_version: meta.kin_version,
        repo_base_key: repo_base_key.clone(),
    };
    let repo_base = RepoBaseManifest {
        schema: "kin.prepared-base.v1",
        repo_base_key,
        repo_identity: prepared.repo_identity.clone(),
        init_pipeline_epoch: meta.init_pipeline_epoch,
        parser_schema_epoch: meta.parser_schema_epoch,
        layout_schema_version: meta.layout_schema_version,
        graph_snapshot_version: meta.graph_snapshot_version,
        text_index_format_version: meta.text_index_format_version,
        vector_index_metadata_version: meta.vector_index_metadata_version,
        feature_flags: meta.feature_flags.clone(),
        embedding_model_id: meta.embeddings.model_id.clone(),
        embedding_model_revision: meta.embeddings.model_revision.clone(),
        embedding_pipeline_epoch: meta.embeddings.pipeline_epoch.clone(),
        embeddings_enabled: meta.embeddings.embeddings_enabled,
        vector_enabled: meta.embeddings.vector_enabled,
        metal_enabled: meta.embeddings.metal_enabled,
        kin_commit: meta.kin_commit,
        kin_dirty: meta.kin_dirty,
        kin_version: meta.kin_version,
        source_git_head: prepared.git_head.clone(),
        source_git_tree: prepared.git_tree.clone(),
    };
    Ok((prepared, repo_base))
}

fn detect_repo_identity(repo_path: &Path) -> String {
    git_output_optional(repo_path, &["remote", "get-url", "origin"])
        .map(|remote| format!("git:{remote}"))
        .unwrap_or_else(|| {
            format!(
                "path:{}",
                repo_path
                    .canonicalize()
                    .unwrap_or_else(|_| repo_path.to_path_buf())
                    .display()
            )
        })
}

fn git_output(repo_path: &Path, args: [&str; 2]) -> Result<String> {
    git_output_inner(repo_path, &args)
}

fn git_output_optional(repo_path: &Path, args: &[&str]) -> Option<String> {
    git_output_inner(repo_path, args).ok()
}

fn git_output_inner(repo_path: &Path, args: &[&str]) -> Result<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(repo_path)
        .output()?;
    if !output.status.success() {
        return Err(anyhow::anyhow!(
            "git {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let stdout = String::from_utf8(output.stdout)?;
    let value = stdout.trim();
    if value.is_empty() {
        return Err(anyhow::anyhow!(
            "git {} returned empty output",
            args.join(" ")
        ));
    }
    Ok(value.to_string())
}

fn hash_json(value: &serde_json::Value) -> String {
    let bytes = serde_json::to_vec(value).expect("json serialization should succeed");
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::{
        build_meta, build_prepared_manifests, embedding_meta, feature_flags, metal_active,
        vector_index_metadata_version,
    };
    use std::fs;
    use std::process::Command;
    use tempfile::tempdir;

    #[test]
    fn feature_flags_reflect_compile_configuration() {
        let flags = feature_flags();
        if cfg!(feature = "vector") {
            assert!(flags.contains(&"vector"));
        } else {
            assert!(!flags.contains(&"vector"));
        }
        if cfg!(feature = "embeddings") {
            assert!(flags.contains(&"embeddings"));
        } else {
            assert!(!flags.contains(&"embeddings"));
        }
    }

    #[test]
    fn embedding_meta_matches_feature_flags() {
        let meta = embedding_meta();
        assert_eq!(meta.vector_enabled, cfg!(feature = "vector"));
        assert_eq!(meta.embeddings_enabled, cfg!(feature = "embeddings"));
        // metal_enabled must track the ACTUAL compiled backend (macOS-only), not the
        // no-op `metal` marker feature which stays on for every target.
        assert_eq!(meta.metal_enabled, metal_active());
        if cfg!(feature = "embeddings") {
            assert!(meta.model_id.is_some());
            assert!(meta.model_revision.is_some());
            assert!(meta.pipeline_epoch.is_some());
        } else {
            assert!(meta.model_id.is_none());
            assert!(meta.model_revision.is_none());
            assert!(meta.pipeline_epoch.is_none());
        }
    }

    #[test]
    fn vector_metadata_version_tracks_vector_feature() {
        assert_eq!(
            vector_index_metadata_version().is_some(),
            cfg!(feature = "vector")
        );
    }

    #[test]
    fn prepared_manifest_tracks_repo_state() {
        let repo = tempdir().unwrap();
        fs::write(repo.path().join("README.md"), "hello\n").unwrap();
        Command::new("git")
            .args(["init"])
            .current_dir(repo.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.email", "kin@example.com"])
            .current_dir(repo.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.name", "Kin"])
            .current_dir(repo.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["add", "README.md"])
            .current_dir(repo.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "init"])
            .env("GIT_AUTHOR_DATE", "1000000000 +0000")
            .env("GIT_COMMITTER_DATE", "1000000000 +0000")
            .current_dir(repo.path())
            .output()
            .unwrap();

        let meta = build_meta().unwrap();
        let (prepared, repo_base) = build_prepared_manifests(&meta, repo.path()).unwrap();

        assert_eq!(prepared.schema, "kin.prepared-state.v1");
        assert!(!prepared.cache_key.is_empty());
        assert!(!prepared.repo_base_key.is_empty());
        assert!(prepared.repo_identity.starts_with("path:"));
        assert_eq!(prepared.init_pipeline_epoch, meta.init_pipeline_epoch);
        assert_eq!(prepared.parser_schema_epoch, meta.parser_schema_epoch);
        assert_eq!(repo_base.schema, "kin.prepared-base.v1");
        assert_eq!(repo_base.repo_base_key, prepared.repo_base_key);
        assert_eq!(repo_base.source_git_head, prepared.git_head);
    }

    #[test]
    fn prepared_manifest_cache_keys_track_kin_commit_and_dirty() {
        let repo = tempdir().unwrap();
        fs::write(repo.path().join("README.md"), "hello\n").unwrap();
        Command::new("git")
            .args(["init"])
            .current_dir(repo.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.email", "kin@example.com"])
            .current_dir(repo.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["config", "user.name", "Kin"])
            .current_dir(repo.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["add", "README.md"])
            .current_dir(repo.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "init"])
            .env("GIT_AUTHOR_DATE", "1000000100 +0000")
            .env("GIT_COMMITTER_DATE", "1000000100 +0000")
            .current_dir(repo.path())
            .output()
            .unwrap();

        let meta = build_meta().unwrap();
        let (prepared_a, repo_base_a) = build_prepared_manifests(&meta, repo.path()).unwrap();

        let (prepared_a2, repo_base_a2) = build_prepared_manifests(&meta, repo.path()).unwrap();
        assert_eq!(
            prepared_a.cache_key, prepared_a2.cache_key,
            "prepared-state cache key must be STABLE across rebuilds of the same commit"
        );
        assert_eq!(
            repo_base_a.repo_base_key, repo_base_a2.repo_base_key,
            "warm init cache key must be STABLE across rebuilds of the same commit"
        );

        let mut meta_commit = meta.clone();
        meta_commit.kin_commit = "ffffffffffff";
        let (prepared_b, repo_base_b) =
            build_prepared_manifests(&meta_commit, repo.path()).unwrap();
        assert_ne!(
            prepared_a.cache_key, prepared_b.cache_key,
            "prepared-state cache must miss when the Kin commit changes"
        );
        assert_ne!(
            repo_base_a.repo_base_key, repo_base_b.repo_base_key,
            "warm init cache must miss when the Kin commit changes"
        );

        let mut meta_dirty = meta.clone();
        meta_dirty.kin_dirty = !meta.kin_dirty;
        let (prepared_c, repo_base_c) = build_prepared_manifests(&meta_dirty, repo.path()).unwrap();
        assert_ne!(
            prepared_a.cache_key, prepared_c.cache_key,
            "prepared-state cache must miss when the dirty flag changes"
        );
        assert_ne!(
            repo_base_a.repo_base_key, repo_base_c.repo_base_key,
            "warm init cache must miss when the dirty flag changes"
        );
    }
}
