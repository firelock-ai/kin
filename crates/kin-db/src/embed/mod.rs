// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

#[cfg(feature = "embeddings")]
mod inference;

#[cfg(feature = "embeddings")]
use directories::BaseDirs;
#[cfg(feature = "embeddings")]
use hf_hub::{api::sync::Api, Repo, RepoType};
#[cfg(feature = "embeddings")]
use kin_infer::gpu::GpuBackend;
#[cfg(feature = "embeddings")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "embeddings")]
use sha2::{Digest, Sha256};
#[cfg(feature = "embeddings")]
use std::collections::HashMap;
#[cfg(feature = "embeddings")]
use std::path::{Path, PathBuf};
#[cfg(feature = "embeddings")]
use tokenizers::tokenizer::{
    PaddingDirection, PaddingParams, PaddingStrategy, TruncationDirection, TruncationParams,
    TruncationStrategy,
};
#[cfg(feature = "embeddings")]
use tokenizers::Tokenizer;

#[cfg(feature = "embeddings")]
use self::inference::{BertConfig, BertModel};

use crate::error::KinDbError;
use kin_model::{Entity, EntityKind};

/// Default HuggingFace model ID.
///
/// BGE small keeps semantic search local while bringing embedding build time
/// down enough for repo-scale indexing to stay practical on developer
/// machines.
const DEFAULT_MODEL_ID: &str = "BAAI/bge-small-en-v1.5";

/// Default model revision.
const DEFAULT_REVISION: &str = "main";
#[cfg(feature = "embeddings")]
const DEFAULT_MAX_BATCH_TOKENS: usize = 12_288;
#[cfg(feature = "embeddings")]
const CUDA_MAX_BATCH_TOKENS: usize = 24_576;
#[cfg(feature = "embeddings")]
const METAL_MAX_BATCH_TOKENS: usize = 4_096;
#[cfg(feature = "embeddings")]
const EMBEDDING_CACHE_SCHEMA_VERSION: &str = "v2";
#[cfg(feature = "embeddings")]
const EMBEDDING_CACHE_PIPELINE_EPOCH: &str = "embed-pipeline-2026-03-28";
pub const EMBEDDING_BODY_PREVIEW_KEY: &str = "embedding_body_preview";
const FILE_IMPORT_CONTEXT_KEY: &str = "file_import_context";
const FILE_SURFACE_CONTEXT_KEY: &str = "file_surface_context";

#[cfg(feature = "embeddings")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbeddingRuntimeConfig {
    pub model_id: String,
    pub revision: String,
    pub pipeline_epoch: String,
}

/// Generates code embeddings using a local BERT model via a custom inference
/// runtime. Pure Rust, zero framework dependencies (ndarray + safetensors).
///
/// Uses BGE-small-en-v1.5 by default (384 dimensions, ~130 MB).
/// The model is downloaded from HuggingFace Hub on first use and cached locally.
pub struct CodeEmbedder {
    #[cfg(feature = "embeddings")]
    model: BertModel,
    #[cfg(feature = "embeddings")]
    tokenizer: Tokenizer,
    #[cfg(feature = "embeddings")]
    dimensions: usize,
    #[cfg(feature = "embeddings")]
    cache: Option<EmbeddingCache>,
}

impl std::fmt::Debug for CodeEmbedder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodeEmbedder")
            .field("dimensions", {
                #[cfg(feature = "embeddings")]
                {
                    &self.dimensions
                }
                #[cfg(not(feature = "embeddings"))]
                {
                    &0usize
                }
            })
            .finish()
    }
}

impl CodeEmbedder {
    /// Create a new embedder with the default code model.
    pub fn new() -> Result<Self, KinDbError> {
        let _span = tracing::info_span!("kindb.embedder.new").entered();
        let model_id = std::env::var("KIN_EMBED_MODEL_ID")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_MODEL_ID.to_string());
        let revision = std::env::var("KIN_EMBED_MODEL_REVISION")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_REVISION.to_string());
        Self::with_model(&model_id, &revision)
    }

    /// Create with a specific HuggingFace model.
    #[cfg(feature = "embeddings")]
    pub fn with_model(model_id: &str, revision: &str) -> Result<Self, KinDbError> {
        let _span = tracing::info_span!(
            "kindb.embedder.with_model",
            model_id = %model_id,
            revision = %revision
        )
        .entered();
        let repo = Repo::with_revision(model_id.to_string(), RepoType::Model, revision.to_string());
        let api = Api::new().map_err(|e| {
            KinDbError::IndexError(format!("failed to initialise HuggingFace API: {e}"))
        })?;
        let api = api.repo(repo);

        let config_path = api
            .get("config.json")
            .map_err(|e| KinDbError::IndexError(format!("failed to download model config: {e}")))?;
        let tokenizer_path = api
            .get("tokenizer.json")
            .map_err(|e| KinDbError::IndexError(format!("failed to download tokenizer: {e}")))?;
        let weights_path = api.get("model.safetensors").map_err(|e| {
            KinDbError::IndexError(format!("failed to download model weights: {e}"))
        })?;

        let config_data = std::fs::read_to_string(&config_path)
            .map_err(|e| KinDbError::IndexError(format!("failed to read config: {e}")))?;
        let config: BertConfig = serde_json::from_str(&config_data)
            .map_err(|e| KinDbError::IndexError(format!("failed to parse model config: {e}")))?;

        let dimensions = config.hidden_size;

        let mut tokenizer = Tokenizer::from_file(&tokenizer_path)
            .map_err(|e| KinDbError::IndexError(format!("failed to load tokenizer: {e}")))?;

        let pad_id = tokenizer
            .token_to_id("<pad>")
            .or_else(|| tokenizer.get_padding().map(|padding| padding.pad_id))
            .or(config.pad_token_id)
            .unwrap_or(0);
        let pad_token = tokenizer
            .id_to_token(pad_id)
            .unwrap_or_else(|| "<pad>".to_string());

        tokenizer
            .with_truncation(Some(TruncationParams {
                direction: TruncationDirection::Right,
                max_length: config.max_position_embeddings,
                strategy: TruncationStrategy::LongestFirst,
                stride: 0,
            }))
            .map_err(|e| KinDbError::IndexError(format!("failed to configure truncation: {e}")))?;
        tokenizer.with_padding(Some(PaddingParams {
            strategy: PaddingStrategy::BatchLongest,
            direction: PaddingDirection::Right,
            pad_to_multiple_of: None,
            pad_id,
            pad_type_id: 0,
            pad_token,
        }));

        let model = BertModel::load(&weights_path, config)
            .map_err(|e| KinDbError::IndexError(format!("failed to load BERT model: {e}")))?;

        let cache_namespace = model_namespace(
            model_id,
            revision,
            dimensions,
            [&config_path, &tokenizer_path, &weights_path],
        );

        Ok(Self {
            model,
            tokenizer,
            dimensions,
            cache: EmbeddingCache::new(cache_namespace, dimensions),
        })
    }

    /// Create with a specific HuggingFace model.
    #[cfg(not(feature = "embeddings"))]
    pub fn with_model(_model_id: &str, _revision: &str) -> Result<Self, KinDbError> {
        Err(disabled_error())
    }

    /// Generate an embedding for a single entity.
    ///
    /// The input text is composed as `"{name} {signature} {body_preview}"`.
    #[cfg(feature = "embeddings")]
    pub fn embed_entity(
        &self,
        name: &str,
        signature: &str,
        body: &str,
    ) -> Result<Vec<f32>, KinDbError> {
        let _span = tracing::info_span!(
            "kindb.embedder.embed_entity",
            name = %name
        )
        .entered();
        let text = format_entity_text(name, signature, body);
        let mut vecs = self.embed_batch(&[text])?;
        vecs.pop()
            .ok_or_else(|| KinDbError::IndexError("embedding returned empty result".into()))
    }

    /// Generate an embedding for a single entity.
    ///
    /// The input text is composed as `"{name} {signature} {body_preview}"`.
    #[cfg(not(feature = "embeddings"))]
    pub fn embed_entity(
        &self,
        _name: &str,
        _signature: &str,
        _body: &str,
    ) -> Result<Vec<f32>, KinDbError> {
        Err(disabled_error())
    }

    /// Embed a raw query string (for semantic search).
    #[cfg(feature = "embeddings")]
    pub fn embed_text(&self, text: &str) -> Result<Vec<f32>, KinDbError> {
        let _span =
            tracing::info_span!("kindb.embedder.embed_text", text_len = text.len()).entered();
        let mut vecs = self.embed_batch(&[text.to_string()])?;
        vecs.pop()
            .ok_or_else(|| KinDbError::IndexError("embedding returned empty result".into()))
    }

    /// Embed a raw query string (for semantic search).
    #[cfg(not(feature = "embeddings"))]
    pub fn embed_text(&self, _text: &str) -> Result<Vec<f32>, KinDbError> {
        Err(disabled_error())
    }

    /// Batch-embed multiple pre-formatted text strings.
    #[cfg(feature = "embeddings")]
    pub fn embed_batch(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, KinDbError> {
        let _span =
            tracing::info_span!("kindb.embedder.embed_batch", texts = texts.len()).entered();
        if texts.is_empty() {
            return Ok(Vec::new());
        }

        let mut cached_results: Vec<Option<Vec<f32>>> = vec![None; texts.len()];
        let mut missing_texts = Vec::new();
        let mut missing_slots: Vec<Vec<usize>> = Vec::new();
        let mut missing_keys = Vec::new();

        if let Some(cache) = self.cache.as_ref() {
            let mut missing_by_key: HashMap<String, usize> = HashMap::new();
            for (idx, text) in texts.iter().enumerate() {
                let key = cache.key_for_text(text);
                if let Some(vector) = cache.get_by_key(&key) {
                    cached_results[idx] = Some(vector);
                    continue;
                }

                match missing_by_key.get(&key).copied() {
                    Some(miss_idx) => missing_slots[miss_idx].push(idx),
                    None => {
                        missing_by_key.insert(key.clone(), missing_texts.len());
                        missing_keys.push(key);
                        missing_texts.push(text.clone());
                        missing_slots.push(vec![idx]);
                    }
                }
            }
        } else {
            for (idx, text) in texts.iter().enumerate() {
                missing_texts.push(text.clone());
                missing_slots.push(vec![idx]);
            }
        }

        if missing_texts.is_empty() {
            return cached_results
                .into_iter()
                .map(|vector| {
                    vector.ok_or_else(|| {
                        KinDbError::IndexError("embedding cache returned incomplete batch".into())
                    })
                })
                .collect();
        }

        let encodings = {
            let _span =
                tracing::info_span!("kindb.embedder.tokenize_batch", texts = missing_texts.len())
                    .entered();
            self.tokenizer
                .encode_batch(missing_texts.clone(), true)
                .map_err(|e| KinDbError::IndexError(format!("tokenization failed: {e}")))?
        };

        let mut encoded: Vec<(usize, Vec<u32>, Vec<u32>)> = encodings
            .iter()
            .enumerate()
            .map(|(idx, encoding)| {
                (
                    idx,
                    encoding.get_ids().to_vec(),
                    encoding.get_attention_mask().to_vec(),
                )
            })
            .collect();
        encoded.sort_by_key(|(_, ids, _)| ids.len());

        let max_batch_tokens = std::env::var("KIN_EMBED_MAX_BATCH_TOKENS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| *value > 0)
            .unwrap_or_else(|| default_max_batch_tokens(self.model.backend()));

        let mut missing_results: Vec<Option<Vec<f32>>> = vec![None; missing_texts.len()];
        let mut start = 0usize;
        while start < encoded.len() {
            let mut end = start;
            let mut longest = 0usize;

            while end < encoded.len() {
                let candidate_len = encoded[end].1.len().max(1);
                let projected_longest = longest.max(candidate_len);
                let projected_tokens = projected_longest * (end - start + 1);
                if end > start && projected_tokens > max_batch_tokens {
                    break;
                }
                longest = projected_longest;
                end += 1;
            }

            let batch = &encoded[start..end];
            let token_ids: Vec<Vec<u32>> = batch.iter().map(|(_, ids, _)| ids.clone()).collect();
            let attention_masks: Vec<Vec<u32>> =
                batch.iter().map(|(_, _, mask)| mask.clone()).collect();
            let vectors = {
                let _span = tracing::info_span!(
                    "kindb.embedder.forward_batch",
                    batch = batch.len(),
                    longest = longest
                )
                .entered();
                self.model
                    .forward_batched(&token_ids, &attention_masks)
                    .map_err(|e| KinDbError::IndexError(format!("inference failed: {e}")))?
            };

            for ((original_idx, _, _), vector) in batch.iter().zip(vectors.into_iter()) {
                missing_results[*original_idx] = Some(vector);
            }
            start = end;
        }

        for (miss_idx, vector) in missing_results.into_iter().enumerate() {
            let vector = vector.ok_or_else(|| {
                KinDbError::IndexError("embedding batch result order mismatch".into())
            })?;

            if let Some(cache) = self.cache.as_ref() {
                if let Some(key) = missing_keys.get(miss_idx) {
                    cache.put_by_key(key, &vector);
                }
            }

            for original_idx in &missing_slots[miss_idx] {
                cached_results[*original_idx] = Some(vector.clone());
            }
        }

        cached_results
            .into_iter()
            .map(|vector| {
                vector.ok_or_else(|| {
                    KinDbError::IndexError("embedding batch result order mismatch".into())
                })
            })
            .collect()
    }

    /// Batch-embed multiple pre-formatted text strings.
    #[cfg(not(feature = "embeddings"))]
    pub fn embed_batch(&self, _texts: &[String]) -> Result<Vec<Vec<f32>>, KinDbError> {
        Err(disabled_error())
    }

    /// The number of dimensions produced by this model.
    #[cfg(feature = "embeddings")]
    pub fn dimensions(&self) -> usize {
        self.dimensions
    }
}

#[cfg(feature = "embeddings")]
pub fn configured_embedding_runtime() -> EmbeddingRuntimeConfig {
    let model_id = std::env::var("KIN_EMBED_MODEL_ID")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_MODEL_ID.to_string());
    let revision = std::env::var("KIN_EMBED_MODEL_REVISION")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| DEFAULT_REVISION.to_string());
    EmbeddingRuntimeConfig {
        model_id,
        revision,
        pipeline_epoch: EMBEDDING_CACHE_PIPELINE_EPOCH.to_string(),
    }
}

#[cfg(feature = "embeddings")]
fn default_max_batch_tokens(backend: GpuBackend) -> usize {
    match backend {
        GpuBackend::Metal => METAL_MAX_BATCH_TOKENS,
        GpuBackend::Cuda => CUDA_MAX_BATCH_TOKENS,
        GpuBackend::Cpu => DEFAULT_MAX_BATCH_TOKENS,
    }
}

/// Build the text representation fed to the embedding model.
pub fn format_entity_text(name: &str, signature: &str, body: &str) -> String {
    let mut parts = Vec::with_capacity(3);
    if !name.is_empty() {
        parts.push(name);
    }
    if !signature.is_empty() {
        parts.push(signature);
    }
    if !body.is_empty() {
        parts.push(body);
    }
    parts.join(" ")
}

/// Build the text representation for a persisted graph entity.
pub fn format_graph_entity_text(entity: &Entity) -> String {
    format_graph_entity_text_with_context(entity, &[])
}

/// Build the text representation for a persisted graph entity with additional
/// graph-derived neighborhood context lines.
pub fn format_graph_entity_text_with_context(entity: &Entity, context_lines: &[String]) -> String {
    let mut parts = Vec::with_capacity(8 + context_lines.len());

    parts.push(entity_kind_label(entity.kind).to_string());

    if let Some(file_origin) = &entity.file_origin {
        parts.push(file_origin.0.clone());
    }
    if !entity.name.is_empty() {
        parts.push(entity.name.clone());
    }
    if !entity.signature.is_empty() {
        parts.push(entity.signature.clone());
    }
    if let Some(doc_summary) = entity.doc_summary.as_deref() {
        if !doc_summary.is_empty() {
            parts.push(doc_summary.to_string());
        }
    }
    if let Some(body_preview) = entity
        .metadata
        .extra
        .get(EMBEDDING_BODY_PREVIEW_KEY)
        .and_then(|value| value.as_str())
    {
        if !body_preview.is_empty() {
            parts.push(body_preview.to_string());
        }
    }
    if let Some(file_import_context) = entity
        .metadata
        .extra
        .get(FILE_IMPORT_CONTEXT_KEY)
        .and_then(|value| value.as_str())
    {
        if !file_import_context.is_empty() {
            parts.push(file_import_context.to_string());
        }
    }
    if let Some(file_surface_context) = entity
        .metadata
        .extra
        .get(FILE_SURFACE_CONTEXT_KEY)
        .and_then(|value| value.as_str())
    {
        if !file_surface_context.is_empty() {
            parts.push(file_surface_context.to_string());
        }
    }
    parts.extend(context_lines.iter().cloned());

    parts.join("\n")
}

fn entity_kind_label(kind: EntityKind) -> &'static str {
    match kind {
        EntityKind::Function => "function",
        EntityKind::Class => "class",
        EntityKind::Interface => "interface",
        EntityKind::TraitDef => "trait",
        EntityKind::TypeAlias => "type_alias",
        EntityKind::Module => "module",
        EntityKind::Package => "package",
        EntityKind::Test => "test",
        EntityKind::Schema => "schema",
        EntityKind::ApiEndpoint => "api_endpoint",
        EntityKind::EventContract => "event_contract",
        EntityKind::File => "file",
        EntityKind::DocumentNode => "document_node",
        EntityKind::Method => "method",
        EntityKind::EnumDef => "enum",
        EntityKind::EnumVariant => "enum_variant",
        EntityKind::Constant => "constant",
        EntityKind::StaticVar => "static_var",
    }
}

#[cfg(not(feature = "embeddings"))]
fn disabled_error() -> KinDbError {
    KinDbError::IndexError(
        "embeddings support is disabled in this build. Rebuild with `--features embeddings`."
            .into(),
    )
}

#[cfg(feature = "embeddings")]
#[derive(Debug, Clone)]
struct EmbeddingCache {
    root: PathBuf,
    dimensions: usize,
}

#[cfg(feature = "embeddings")]
impl EmbeddingCache {
    fn new(namespace: String, dimensions: usize) -> Option<Self> {
        if std::env::var("KIN_EMBED_CACHE")
            .ok()
            .is_some_and(|value| value == "0")
        {
            return None;
        }

        let base_dir = std::env::var_os("KIN_EMBED_CACHE_DIR")
            .map(PathBuf::from)
            .or_else(|| {
                BaseDirs::new().map(|dirs| dirs.home_dir().join(".kin/cache/embeddings"))
            })?;
        Self::new_in(base_dir, namespace, dimensions)
    }

    fn new_in(base_dir: PathBuf, namespace: String, dimensions: usize) -> Option<Self> {
        let root = base_dir
            .join(EMBEDDING_CACHE_SCHEMA_VERSION)
            .join(namespace);
        std::fs::create_dir_all(&root).ok()?;
        Some(Self { root, dimensions })
    }

    fn key_for_text(&self, text: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(text.as_bytes());
        hex::encode(hasher.finalize())
    }

    fn get_by_key(&self, key: &str) -> Option<Vec<f32>> {
        read_cached_vector(&self.path_for_key(key), self.dimensions)
    }

    fn put_by_key(&self, key: &str, vector: &[f32]) {
        if vector.len() != self.dimensions {
            return;
        }
        let _ = write_cached_vector(&self.path_for_key(key), vector);
    }

    fn path_for_key(&self, key: &str) -> PathBuf {
        let prefix = &key[..2];
        self.root.join(prefix).join(format!("{key}.bin"))
    }
}

#[cfg(feature = "embeddings")]
fn model_namespace<const N: usize>(
    model_id: &str,
    revision: &str,
    dimensions: usize,
    artifact_paths: [&Path; N],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(EMBEDDING_CACHE_PIPELINE_EPOCH.as_bytes());
    hasher.update([0]);
    hasher.update(model_id.as_bytes());
    hasher.update([0]);
    hasher.update(revision.as_bytes());
    hasher.update([0]);
    hasher.update(dimensions.to_le_bytes());
    hasher.update([0]);
    for path in artifact_paths {
        hasher.update(path.to_string_lossy().as_bytes());
        hasher.update([0]);
    }
    let digest = hex::encode(hasher.finalize());
    format!("{}-{}", sanitize_component(model_id), &digest[..16])
}

#[cfg(feature = "embeddings")]
fn sanitize_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    out
}

#[cfg(feature = "embeddings")]
fn read_cached_vector(path: &Path, dimensions: usize) -> Option<Vec<f32>> {
    let bytes = std::fs::read(path).ok()?;
    if bytes.len() != dimensions * std::mem::size_of::<f32>() {
        return None;
    }

    let mut values = Vec::with_capacity(dimensions);
    for chunk in bytes.chunks_exact(std::mem::size_of::<f32>()) {
        values.push(f32::from_le_bytes(chunk.try_into().ok()?));
    }
    Some(values)
}

#[cfg(feature = "embeddings")]
fn write_cached_vector(path: &Path, vector: &[f32]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut bytes = Vec::with_capacity(std::mem::size_of_val(vector));
    for value in vector {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{
        EntityId, EntityMetadata, FilePathId, FingerprintAlgorithm, Hash256, LanguageId,
        SemanticFingerprint, Visibility,
    };

    /// Default embedding dimensions for BGE-small-en-v1.5.
    const DEFAULT_EMBED_DIMS: usize = 384;

    #[test]
    fn format_entity_text_joins_parts() {
        assert_eq!(
            format_entity_text("foo", "fn foo()", "{ 1 }"),
            "foo fn foo() { 1 }"
        );
        assert_eq!(format_entity_text("foo", "", ""), "foo");
        assert_eq!(format_entity_text("", "", ""), "");
    }

    #[test]
    fn format_graph_entity_text_includes_semantic_context() {
        let mut entity = Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: "parse_config".into(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256([0; 32]),
                signature_hash: Hash256([0; 32]),
                behavior_hash: Hash256([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new("src/config.rs")),
            span: None,
            signature: "fn parse_config(path: &str) -> Config".into(),
            visibility: Visibility::Public,
            doc_summary: Some("Parse a config file".into()),
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };
        entity.metadata.extra.insert(
            EMBEDDING_BODY_PREVIEW_KEY.into(),
            serde_json::Value::String("fn parse_config(path: &str) -> Config { ... }".into()),
        );
        entity.metadata.extra.insert(
            FILE_IMPORT_CONTEXT_KEY.into(),
            serde_json::Value::String(
                "module @vue/runtime-core names createRenderer hydrate".into(),
            ),
        );
        entity.metadata.extra.insert(
            FILE_SURFACE_CONTEXT_KEY.into(),
            serde_json::Value::String("surface runtime-dom surface runtime dom".into()),
        );

        let formatted = format_graph_entity_text(&entity);
        assert!(formatted.contains("function"));
        assert!(formatted.contains("src/config.rs"));
        assert!(formatted.contains("parse_config"));
        assert!(formatted.contains("fn parse_config(path: &str) -> Config"));
        assert!(formatted.contains("Parse a config file"));
        assert!(formatted.contains("fn parse_config(path: &str) -> Config { ... }"));
        assert!(formatted.contains("@vue/runtime-core"));
        assert!(formatted.contains("runtime dom"));
    }

    #[test]
    fn format_graph_entity_text_with_context_appends_graph_neighborhood() {
        let entity = Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: "load_registry".into(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256([0; 32]),
                signature_hash: Hash256([0; 32]),
                behavior_hash: Hash256([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new("src/registry.rs")),
            span: None,
            signature: "fn load_registry() -> Registry".into(),
            visibility: Visibility::Public,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };

        let formatted = format_graph_entity_text_with_context(
            &entity,
            &[
                "calls parse_manifest".into(),
                "import_source serde_json".into(),
            ],
        );

        assert!(formatted.contains("load_registry"));
        assert!(formatted.contains("calls parse_manifest"));
        assert!(formatted.contains("import_source serde_json"));
    }

    #[test]
    fn default_dimensions_match_default_model() {
        #[cfg(feature = "embeddings")]
        {
            let embedder = CodeEmbedder::new().unwrap();
            assert_eq!(embedder.dimensions(), DEFAULT_EMBED_DIMS);
        }
    }

    #[cfg(feature = "embeddings")]
    #[test]
    fn backend_specific_default_batch_token_budget_matches_runtime() {
        assert_eq!(
            default_max_batch_tokens(GpuBackend::Cpu),
            DEFAULT_MAX_BATCH_TOKENS
        );
        assert_eq!(
            default_max_batch_tokens(GpuBackend::Cuda),
            CUDA_MAX_BATCH_TOKENS
        );
        assert_eq!(
            default_max_batch_tokens(GpuBackend::Metal),
            METAL_MAX_BATCH_TOKENS
        );
    }

    #[cfg(feature = "embeddings")]
    #[test]
    fn embedding_cache_round_trips_vectors() {
        let dir = tempfile::tempdir().unwrap();
        let cache =
            EmbeddingCache::new_in(dir.path().to_path_buf(), "test_model-namespace".into(), 4)
                .expect("cache should initialize");
        let key = cache.key_for_text("hello");

        assert!(cache.get_by_key(&key).is_none());

        cache.put_by_key(&key, &[1.0, 2.0, 3.0, 4.0]);
        assert_eq!(cache.get_by_key(&key).unwrap(), vec![1.0, 2.0, 3.0, 4.0]);
    }
}
