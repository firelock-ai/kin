// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_core::layout::KIN_LAYOUT_VERSION;
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Debug, Serialize)]
struct BenchMeta {
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
    kin_binary_sha256: String,
}

#[derive(Debug, Serialize)]
struct EmbeddingMeta {
    vector_enabled: bool,
    embeddings_enabled: bool,
    metal_enabled: bool,
    model_id: Option<String>,
    model_revision: Option<String>,
    pipeline_epoch: Option<String>,
}

pub async fn run(json: bool) -> Result<()> {
    let meta = BenchMeta {
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
        kin_binary_sha256: current_binary_sha256()?,
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&meta)?);
    } else {
        println!("schema: {}", meta.schema);
        println!("kin_version: {}", meta.kin_version);
        println!("init_pipeline_epoch: {}", meta.init_pipeline_epoch);
        println!("parser_schema_epoch: {}", meta.parser_schema_epoch);
        println!("layout_schema_version: {}", meta.layout_schema_version);
        println!("graph_snapshot_version: {}", meta.graph_snapshot_version);
        println!("text_index_format_version: {}", meta.text_index_format_version);
        if let Some(version) = meta.vector_index_metadata_version {
            println!("vector_index_metadata_version: {}", version);
        } else {
            println!("vector_index_metadata_version: disabled");
        }
        println!("feature_flags: {}", meta.feature_flags.join(","));
        println!("kin_binary_sha256: {}", meta.kin_binary_sha256);
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

fn current_binary_sha256() -> Result<String> {
    let exe = std::env::current_exe()?;
    let bytes = std::fs::read(exe)?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn feature_flags() -> Vec<&'static str> {
    let mut flags = Vec::new();
    if cfg!(feature = "vector") {
        flags.push("vector");
    }
    if cfg!(feature = "embeddings") {
        flags.push("embeddings");
    }
    if cfg!(feature = "metal") {
        flags.push("metal");
    }
    flags.sort_unstable();
    flags
}

fn embedding_meta() -> EmbeddingMeta {
    #[cfg(feature = "embeddings")]
    {
        let runtime = kin_db::embed::configured_embedding_runtime();
        return EmbeddingMeta {
            vector_enabled: cfg!(feature = "vector"),
            embeddings_enabled: true,
            metal_enabled: cfg!(feature = "metal"),
            model_id: Some(runtime.model_id),
            model_revision: Some(runtime.revision),
            pipeline_epoch: Some(runtime.pipeline_epoch),
        };
    }

    #[cfg(not(feature = "embeddings"))]
    {
        EmbeddingMeta {
            vector_enabled: cfg!(feature = "vector"),
            embeddings_enabled: false,
            metal_enabled: cfg!(feature = "metal"),
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

#[cfg(test)]
mod tests {
    use super::{embedding_meta, feature_flags, vector_index_metadata_version};

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
        assert_eq!(meta.metal_enabled, cfg!(feature = "metal"));
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
        assert_eq!(vector_index_metadata_version().is_some(), cfg!(feature = "vector"));
    }
}
