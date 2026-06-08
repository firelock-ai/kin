// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

#[cfg(feature = "embeddings")]
mod inference;
#[cfg(feature = "embeddings")]
pub mod rerank;

#[cfg(feature = "embeddings")]
use directories::BaseDirs;
#[cfg(feature = "embeddings")]
use hf_hub::{api::sync::Api, Repo, RepoType};
#[cfg(feature = "embeddings")]
use kin_infer::gpu::GpuBackend;
#[cfg(feature = "embeddings")]
use reqwest::blocking::Client as BlockingHttpClient;
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
use kin_model::{
    ArtifactKind, Entity, EntityKind, OpaqueArtifact, ShallowTrackedFile, StructuredArtifact,
};

/// Default HuggingFace model ID.
///
/// SweRank small keeps semantic search local while bringing embedding build time
/// down enough for repo-scale indexing to stay practical on developer
/// machines.
const DEFAULT_MODEL_ID: &str = "nomic-ai/nomic-embed-text-v1.5";
/// Asymmetric query instruction for SweRankEmbed / nomic_bert code retrievers.
///
/// SweRankEmbed-Small prepends this exact string (trailing space included) to
/// queries and encodes documents raw. BGE stays symmetric, so this only fires
/// when the loaded model reports a nomic_bert architecture.
#[cfg(feature = "embeddings")]
const SWERANK_QUERY_PREFIX: &str = "Represent this query for searching relevant code: ";
#[cfg(feature = "embeddings")]
const DEFAULT_LMSTUDIO_EMBED_MODEL_ID: &str = "text-embedding-nomic-embed-text-v1.5";
#[cfg(feature = "embeddings")]
const DEFAULT_OPENAI_EMBED_MODEL_ID: &str = "text-embedding-3-small";

/// Default model revision.
const DEFAULT_REVISION: &str = "main";
#[cfg(feature = "embeddings")]
const DEFAULT_MAX_BATCH_TOKENS: usize = 32_768;
#[cfg(feature = "embeddings")]
const CUDA_MAX_BATCH_TOKENS: usize = 65_536;
#[cfg(feature = "embeddings")]
const METAL_MAX_BATCH_TOKENS: usize = 65_536;
#[cfg(feature = "embeddings")]
const EMBEDDING_CACHE_SCHEMA_VERSION: &str = "v2";
#[cfg(feature = "embeddings")]
const EMBEDDING_CACHE_PIPELINE_EPOCH: &str = "embed-pipeline-2026-05-31-swerank";
pub const EMBEDDING_BODY_PREVIEW_KEY: &str = "embedding_body_preview";
const FILE_IMPORT_CONTEXT_KEY: &str = "file_import_context";
const FILE_SURFACE_CONTEXT_KEY: &str = "file_surface_context";

/// Practical per-entity tokenization ceiling for embeddings. Bounded *below* the
/// model's trained range so a single entity can never dominate GPU cost: the
/// naive scalar Metal attention is O(seq²), so a 2982-token entity (e.g. a
/// scikit-learn class whose numpy docstring alone is ~3700 tokens) costs ~30×
/// a typical ~500-token entity for negligible retrieval gain. The entity embed
/// text is front-loaded with the discriminating signal (kind, path, name,
/// signature, doc summary, body preview), so right-truncation past this length
/// drops boilerplate (Parameters/Examples/References prose), not semantics.
const EMBED_MAX_SEQ_LEN: usize = 8192;

/// Maximum characters of an entity's docstring (`doc_summary`) folded into its
/// embedding text. NumPy/PEP-257 docstrings are front-loaded — the summary line
/// and first paragraph carry the semantics; the long Parameters/Attributes/
/// Examples/References sections add tokens (and O(seq²) GPU cost) without
/// retrieval signal. The full docstring stays in graph truth for display/blame;
/// only the embed projection is bounded. Mirrors the 800-char body preview.
const EMBED_DOC_SUMMARY_MAX_CHARS: usize = 8000;

#[cfg(feature = "embeddings")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbeddingRuntimeConfig {
    pub provider: String,
    pub model_id: String,
    pub revision: String,
    pub dimensions: Option<usize>,
    pub pipeline_epoch: String,
}

/// Generates code embeddings using a local BERT model via a custom inference
/// runtime. Pure Rust, zero framework dependencies (ndarray + safetensors).
///
/// Uses SweRankEmbed-Small by default (768 dimensions).
/// The model is downloaded from HuggingFace Hub on first use and cached locally.
pub struct CodeEmbedder {
    #[cfg(feature = "embeddings")]
    backend: CodeEmbedderBackend,
    #[cfg(feature = "embeddings")]
    dimensions: usize,
    #[cfg(feature = "embeddings")]
    cache: Option<EmbeddingCache>,
}

#[cfg(feature = "embeddings")]
enum CodeEmbedderBackend {
    Bert(BertEmbedder),
    OpenAiCompat(OpenAiCompatEmbedder),
}

#[cfg(feature = "embeddings")]
struct BertEmbedder {
    model: BertModel,
    /// CPU-only BertModel, loaded lazily the first time the dispatcher
    /// routes a batch through the CPU path. Held behind a Mutex + OnceLock
    /// pattern because BertModel is `!Sync` for `forward` (mutable buffers
    /// internally) and we only need one-time construction. Heap-weighted:
    /// holding two models doubles resident weights (~260MB for BGE-small).
    #[cfg(feature = "embeddings")]
    cpu_model: std::sync::OnceLock<BertModel>,
    /// Captured arguments needed to build `cpu_model` on demand.
    #[cfg(feature = "embeddings")]
    cpu_model_source: std::sync::Mutex<Option<CpuModelSource>>,
    tokenizer: Tokenizer,
    /// Instruction prepended to queries for asymmetric retrievers (SweRank /
    /// nomic_bert). Empty for symmetric models like BGE.
    query_prefix: String,
}

#[cfg(feature = "embeddings")]
struct OpenAiCompatEmbedder {
    client: BlockingHttpClient,
    endpoint: String,
    model_id: String,
    api_key: Option<String>,
    dimensions: usize,
    request_overrides: serde_json::Map<String, serde_json::Value>,
    query_prefix: String,
    document_prefix: String,
}

#[cfg(feature = "embeddings")]
#[derive(Debug, Clone, PartialEq, Eq)]
enum EmbeddingInputRole {
    Query,
    Document,
}

/// Paths captured at model load time so the CPU twin can be constructed
/// lazily without re-downloading weights from HuggingFace. Config is stored
/// as the original JSON bytes because `BertConfig` is not `Clone`.
#[cfg(feature = "embeddings")]
#[derive(Debug)]
struct CpuModelSource {
    weights_path: PathBuf,
    config_json: String,
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
        #[cfg(feature = "embeddings")]
        {
            let provider = configured_embedding_provider();
            return match provider {
                EmbeddingProvider::Local => {
                    let model_id = env_nonempty("KIN_EMBED_MODEL_ID")
                        .unwrap_or_else(|| DEFAULT_MODEL_ID.to_string());
                    let revision = env_nonempty("KIN_EMBED_MODEL_REVISION")
                        .unwrap_or_else(|| DEFAULT_REVISION.to_string());
                    Self::with_model(&model_id, &revision)
                }
                EmbeddingProvider::OpenAiCompat { profile } => {
                    Self::with_openai_compat(OpenAiCompatConfig::from_profile(profile)?)
                }
            };
        }

        #[cfg(not(feature = "embeddings"))]
        {
            Err(disabled_error())
        }
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
        let (config_path, tokenizer_path, weights_path) =
            if let Some(dir) = local_model_dir(model_id) {
                resolve_local_model_artifacts(&dir)?
            } else {
                let repo = Repo::with_revision(
                    model_id.to_string(),
                    RepoType::Model,
                    revision.to_string(),
                );
                let api = Api::new().map_err(|e| {
                    KinDbError::IndexError(format!("failed to initialise HuggingFace API: {e}"))
                })?;
                let api = api.repo(repo);

                let config_path = api.get("config.json").map_err(|e| {
                    KinDbError::IndexError(format!("failed to download model config: {e}"))
                })?;
                let tokenizer_path = api.get("tokenizer.json").map_err(|e| {
                    KinDbError::IndexError(format!("failed to download tokenizer: {e}"))
                })?;
                let weights_path = api.get("model.safetensors").map_err(|e| {
                    KinDbError::IndexError(format!("failed to download model weights: {e}"))
                })?;
                (config_path, tokenizer_path, weights_path)
            };

        let config_data = std::fs::read_to_string(&config_path)
            .map_err(|e| KinDbError::IndexError(format!("failed to read config: {e}")))?;
        let config: BertConfig = serde_json::from_str(&config_data)
            .map_err(|e| KinDbError::IndexError(format!("failed to parse model config: {e}")))?;

        let dimensions = config.hidden_size;
        let query_prefix = local_query_prefix(model_id, config.model_type.as_deref());

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

        let max_length = config.effective_max_seq_len().min(EMBED_MAX_SEQ_LEN);
        tokenizer
            .with_truncation(Some(TruncationParams {
                direction: TruncationDirection::Right,
                max_length,
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

        let backend = BertEmbedder {
            model,
            cpu_model: std::sync::OnceLock::new(),
            cpu_model_source: std::sync::Mutex::new(Some(CpuModelSource {
                weights_path: weights_path.clone(),
                config_json: config_data,
            })),
            tokenizer,
            query_prefix,
        };

        Ok(Self {
            backend: CodeEmbedderBackend::Bert(backend),
            dimensions,
            cache: EmbeddingCache::new(cache_namespace, dimensions),
        })
    }

    /// Create with a specific HuggingFace model.
    #[cfg(not(feature = "embeddings"))]
    pub fn with_model(_model_id: &str, _revision: &str) -> Result<Self, KinDbError> {
        Err(disabled_error())
    }

    /// Create with an OpenAI-compatible embeddings endpoint.
    #[cfg(feature = "embeddings")]
    fn with_openai_compat(config: OpenAiCompatConfig) -> Result<Self, KinDbError> {
        let embedder = OpenAiCompatEmbedder::new(config)?;
        let dimensions = embedder.dimensions;
        let cache_namespace = embedder.cache_namespace();
        Ok(Self {
            backend: CodeEmbedderBackend::OpenAiCompat(embedder),
            dimensions,
            cache: EmbeddingCache::new(cache_namespace, dimensions),
        })
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
        let mut vecs = self.embed_batch_for_role(&[text.to_string()], EmbeddingInputRole::Query)?;
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
        self.embed_batch_for_role(texts, EmbeddingInputRole::Document)
    }

    #[cfg(feature = "embeddings")]
    fn embed_batch_for_role(
        &self,
        texts: &[String],
        role: EmbeddingInputRole,
    ) -> Result<Vec<Vec<f32>>, KinDbError> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }

        let prepared_texts = self.prepare_inputs(texts, role);
        let mut cached_results: Vec<Option<Vec<f32>>> = vec![None; texts.len()];
        let mut missing_texts = Vec::new();
        let mut missing_slots: Vec<Vec<usize>> = Vec::new();
        let mut missing_keys = Vec::new();

        if let Some(cache) = self.cache.as_ref() {
            let mut missing_by_key: HashMap<String, usize> = HashMap::new();
            for (idx, text) in prepared_texts.iter().enumerate() {
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
            for (idx, text) in prepared_texts.iter().enumerate() {
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

        let missing_results = self.embed_uncached_batch(&missing_texts)?;
        if missing_results.len() != missing_texts.len() {
            return Err(KinDbError::IndexError(format!(
                "embedding endpoint returned {} vectors for {} inputs",
                missing_results.len(),
                missing_texts.len()
            )));
        }

        for (miss_idx, vector) in missing_results.into_iter().enumerate() {
            let vector = sanitize_embedding(vector, self.dimensions, || {
                missing_texts
                    .get(miss_idx)
                    .map(String::as_str)
                    .unwrap_or("")
            });
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

    #[cfg(feature = "embeddings")]
    fn prepare_inputs(&self, texts: &[String], role: EmbeddingInputRole) -> Vec<String> {
        match &self.backend {
            CodeEmbedderBackend::Bert(embedder) => embedder.prepare_inputs(texts, role),
            CodeEmbedderBackend::OpenAiCompat(embedder) => embedder.prepare_inputs(texts, role),
        }
    }

    #[cfg(feature = "embeddings")]
    fn embed_uncached_batch(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, KinDbError> {
        match &self.backend {
            CodeEmbedderBackend::Bert(embedder) => {
                embedder.embed_uncached_batch(texts, self.dimensions)
            }
            CodeEmbedderBackend::OpenAiCompat(embedder) => embedder.embed_batch(texts),
        }
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
impl BertEmbedder {
    fn prepare_inputs(&self, texts: &[String], role: EmbeddingInputRole) -> Vec<String> {
        if self.query_prefix.is_empty() || role != EmbeddingInputRole::Query {
            return texts.to_vec();
        }
        texts
            .iter()
            .map(|text| format!("{}{}", self.query_prefix, text))
            .collect()
    }

    fn embed_uncached_batch(
        &self,
        texts: &[String],
        dimensions: usize,
    ) -> Result<Vec<Vec<f32>>, KinDbError> {
        let encodings = {
            let _span =
                tracing::info_span!("kindb.embedder.tokenize_batch", texts = texts.len()).entered();
            self.tokenizer
                .encode_batch(texts.to_vec(), true)
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

        let mode = hybrid_mode();
        if mode != HybridMode::Off {
            return self.embed_hybrid(encoded, dimensions, max_batch_tokens, texts.len(), mode);
        }

        let mut results: Vec<Option<Vec<f32>>> = vec![None; texts.len()];
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

            // TODO(metal): seq_len > ~500 produces NaN in kin-infer Metal attention
            // kernels for the batched code path (fused_attention_batched —
            // scale_mask_alibi_grouped.metal / softmax_rows.metal — likely softmax
            // max-subtract missing). See embedder agent diagnosis 2026-04-14 and
            // planning/metal-bert-nan-bug.md.
            let backend_choice = resolve_embed_backend(longest);
            let vectors = match backend_choice {
                EmbedBackendChoice::Metal { reason } => {
                    tracing::info!(
                        target: "kindb.embed.dispatch",
                        batch_size = batch.len(),
                        max_seq = longest,
                        backend = "metal",
                        reason = reason,
                        "embed_dispatch"
                    );
                    let _span = tracing::info_span!(
                        "kindb.embedder.forward_batch",
                        batch = batch.len(),
                        longest = longest
                    )
                    .entered();
                    let metal_forward = if metal_oom_injection_armed() {
                        Err(kin_infer::InferError::OutOfMemory(
                            "synthetic Metal OOM (KIN_EMBED_TEST_FORCE_METAL_OOM)".to_string(),
                        ))
                    } else {
                        self.model.forward_batched(&token_ids, &attention_masks)
                    };
                    match metal_forward {
                        Ok(v) => v,
                        Err(kin_infer::InferError::OutOfMemory(msg)) => {
                            // Metal ran out of device memory mid-forward. Rather
                            // than failing the index, degrade this batch to the
                            // CPU twin (which create_compute builds under
                            // KIN_INFER_FORCE_CPU) and retry once.
                            tracing::warn!(
                                target: "kindb.embed.dispatch",
                                error = %msg,
                                batch_size = batch.len(),
                                max_seq = longest,
                                "metal embed out-of-memory; retrying batch on CPU"
                            );
                            let cpu_model = match self.cpu_model() {
                                Ok(m) => Some(m),
                                Err(e) => {
                                    tracing::warn!(
                                        error = %e,
                                        "cpu_model unavailable after metal OOM; retrying on primary model"
                                    );
                                    None
                                }
                            };
                            let model = cpu_model.unwrap_or(&self.model);
                            model
                                .forward_batched(&token_ids, &attention_masks)
                                .map_err(|e| {
                                    KinDbError::IndexError(format!(
                                        "inference failed (cpu retry after metal OOM): {e}"
                                    ))
                                })?
                        }
                        Err(e) => {
                            return Err(KinDbError::IndexError(format!(
                                "inference failed: {e}"
                            )));
                        }
                    }
                }
                EmbedBackendChoice::Cpu { reason } => {
                    tracing::info!(
                        target: "kindb.embed.dispatch",
                        batch_size = batch.len(),
                        max_seq = longest,
                        backend = "cpu",
                        reason = reason,
                        "embed_dispatch"
                    );
                    let _span = tracing::info_span!(
                        "kindb.embedder.forward_cpu_path",
                        batch = batch.len(),
                        longest = longest
                    )
                    .entered();
                    let cpu_model = match self.cpu_model() {
                        Ok(m) => Some(m),
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "cpu_model unavailable; falling back to primary model for this chunk"
                            );
                            None
                        }
                    };
                    let model = cpu_model.unwrap_or(&self.model);
                    model
                        .forward_batched(&token_ids, &attention_masks)
                        .map_err(|e| KinDbError::IndexError(format!("inference failed: {e}")))?
                }
            };

            // Defense in depth: if the dispatched path still returned any
            // non-finite vectors, retry per-sample through the single-input
            // forward path before the outer sanitizer handles any remaining
            // bad vectors.
            let vectors = if vectors.iter().any(|v| !v.iter().all(|x| x.is_finite())) {
                tracing::warn!(
                    batch = batch.len(),
                    longest = longest,
                    "dispatched path produced non-finite vectors; retrying via single-input forward path"
                );
                let mut retried = Vec::with_capacity(batch.len());
                for (ids, mask) in token_ids.iter().zip(attention_masks.iter()) {
                    let out = self
                        .model
                        .forward(std::slice::from_ref(ids), std::slice::from_ref(mask))
                        .map_err(|e| KinDbError::IndexError(format!("inference failed: {e}")))?;
                    retried.push(out.into_iter().next().ok_or_else(|| {
                        KinDbError::IndexError("forward returned empty batch".into())
                    })?);
                }
                retried
            } else {
                vectors
            };

            for ((original_idx, _, _), vector) in batch.iter().zip(vectors.into_iter()) {
                if vector.len() != dimensions {
                    return Err(KinDbError::IndexError(format!(
                        "embedding returned {} dimensions, expected {}",
                        vector.len(),
                        dimensions
                    )));
                }
                results[*original_idx] = Some(vector);
            }
            start = end;
        }

        results
            .into_iter()
            .map(|vector| {
                vector.ok_or_else(|| {
                    KinDbError::IndexError("embedding batch result order mismatch".into())
                })
            })
            .collect()
    }

    fn embed_hybrid(
        &self,
        encoded: Vec<Encoded>,
        dimensions: usize,
        max_batch_tokens: usize,
        total: usize,
        mode: HybridMode,
    ) -> Result<Vec<Vec<f32>>, KinDbError> {
        let placed = match mode {
            HybridMode::Off => unreachable!("embed_hybrid is only called for enabled modes"),
            HybridMode::SeqFloor => {
                let split =
                    encoded.partition_point(|(_, ids, _)| ids.len() <= EMBED_CPU_SEQ_THRESHOLD);
                let (short, long) = encoded.split_at(split);
                self.dispatch_concurrent(short, long, dimensions, max_batch_tokens)?
            }
            HybridMode::Balanced { gpu_tput_ratio } => {
                let (metal_subset, cpu_subset) = balanced_partition(&encoded, gpu_tput_ratio);
                let metal_tokens: usize = metal_subset.iter().map(|(_, ids, _)| ids.len()).sum();
                let cpu_tokens: usize = cpu_subset.iter().map(|(_, ids, _)| ids.len()).sum();
                tracing::info!(
                    target: "kindb.embed.dispatch",
                    metal_entities = metal_subset.len(),
                    cpu_entities = cpu_subset.len(),
                    metal_tokens = metal_tokens,
                    cpu_tokens = cpu_tokens,
                    gpu_tput_ratio = gpu_tput_ratio,
                    cpu_threads = rayon::current_num_threads(),
                    "embed_hybrid_balance"
                );
                self.dispatch_concurrent(&metal_subset, &cpu_subset, dimensions, max_batch_tokens)?
            }
        };

        let mut results: Vec<Option<Vec<f32>>> = vec![None; total];
        for (original_idx, vector) in placed {
            results[original_idx] = Some(vector);
        }
        results
            .into_iter()
            .map(|vector| {
                vector.ok_or_else(|| {
                    KinDbError::IndexError("embedding batch result order mismatch".into())
                })
            })
            .collect()
    }

    fn process_encoded_subset(
        &self,
        encoded: &[(usize, Vec<u32>, Vec<u32>)],
        dimensions: usize,
        max_batch_tokens: usize,
        backend_override: Option<EmbedBackendChoice>,
    ) -> Result<Vec<(usize, Vec<f32>)>, KinDbError> {
        let mut placed: Vec<(usize, Vec<f32>)> = Vec::with_capacity(encoded.len());
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

            let backend_choice = backend_override.unwrap_or_else(|| resolve_embed_backend(longest));
            let vectors = match backend_choice {
                EmbedBackendChoice::Metal { reason } => {
                    tracing::info!(
                        target: "kindb.embed.dispatch",
                        batch_size = batch.len(),
                        max_seq = longest,
                        backend = "metal",
                        reason = reason,
                        "embed_dispatch"
                    );
                    let _span = tracing::info_span!(
                        "kindb.embedder.forward_batch",
                        batch = batch.len(),
                        longest = longest
                    )
                    .entered();
                    match self.model.forward_batched(&token_ids, &attention_masks) {
                        Ok(v) => v,
                        Err(kin_infer::InferError::OutOfMemory(msg)) => {
                            // Metal ran out of device memory mid-forward. Rather
                            // than failing the index, degrade this batch to the
                            // CPU twin (which create_compute builds under
                            // KIN_INFER_FORCE_CPU) and retry once.
                            tracing::warn!(
                                target: "kindb.embed.dispatch",
                                error = %msg,
                                batch_size = batch.len(),
                                max_seq = longest,
                                "metal embed out-of-memory; retrying batch on CPU"
                            );
                            let cpu_model = match self.cpu_model() {
                                Ok(m) => Some(m),
                                Err(e) => {
                                    tracing::warn!(
                                        error = %e,
                                        "cpu_model unavailable after metal OOM; retrying on primary model"
                                    );
                                    None
                                }
                            };
                            let model = cpu_model.unwrap_or(&self.model);
                            model
                                .forward_batched(&token_ids, &attention_masks)
                                .map_err(|e| {
                                    KinDbError::IndexError(format!(
                                        "inference failed (cpu retry after metal OOM): {e}"
                                    ))
                                })?
                        }
                        Err(e) => {
                            return Err(KinDbError::IndexError(format!(
                                "inference failed: {e}"
                            )));
                        }
                    }
                }
                EmbedBackendChoice::Cpu { reason } => {
                    tracing::info!(
                        target: "kindb.embed.dispatch",
                        batch_size = batch.len(),
                        max_seq = longest,
                        backend = "cpu",
                        reason = reason,
                        "embed_dispatch"
                    );
                    let _span = tracing::info_span!(
                        "kindb.embedder.forward_cpu_path",
                        batch = batch.len(),
                        longest = longest
                    )
                    .entered();
                    let cpu_model = match self.cpu_model() {
                        Ok(m) => Some(m),
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "cpu_model unavailable; falling back to primary model for this chunk"
                            );
                            None
                        }
                    };
                    let model = cpu_model.unwrap_or(&self.model);
                    model
                        .forward_batched(&token_ids, &attention_masks)
                        .map_err(|e| KinDbError::IndexError(format!("inference failed: {e}")))?
                }
            };

            let vectors = if vectors.iter().any(|v| !v.iter().all(|x| x.is_finite())) {
                tracing::warn!(
                    batch = batch.len(),
                    longest = longest,
                    "dispatched path produced non-finite vectors; retrying via single-input forward path"
                );
                let mut retried = Vec::with_capacity(batch.len());
                for (ids, mask) in token_ids.iter().zip(attention_masks.iter()) {
                    let out = self
                        .model
                        .forward(std::slice::from_ref(ids), std::slice::from_ref(mask))
                        .map_err(|e| KinDbError::IndexError(format!("inference failed: {e}")))?;
                    retried.push(out.into_iter().next().ok_or_else(|| {
                        KinDbError::IndexError("forward returned empty batch".into())
                    })?);
                }
                retried
            } else {
                vectors
            };

            for ((original_idx, _, _), vector) in batch.iter().zip(vectors.into_iter()) {
                if vector.len() != dimensions {
                    return Err(KinDbError::IndexError(format!(
                        "embedding returned {} dimensions, expected {}",
                        vector.len(),
                        dimensions
                    )));
                }
                placed.push((*original_idx, vector));
            }
            start = end;
        }

        Ok(placed)
    }

    fn dispatch_concurrent(
        &self,
        metal_side: &[Encoded],
        cpu_side: &[Encoded],
        dimensions: usize,
        max_batch_tokens: usize,
    ) -> Result<Vec<(usize, Vec<f32>)>, KinDbError> {
        if metal_side.is_empty() {
            return self.process_encoded_subset(cpu_side, dimensions, max_batch_tokens, None);
        }
        if cpu_side.is_empty() {
            return self.process_encoded_subset(metal_side, dimensions, max_batch_tokens, None);
        }

        // Hybrid concurrency is only safe when the CPU arm runs on its OWN model
        // (the CPU twin) — a different backend than the primary Metal model. If the
        // twin is unavailable, process_encoded_subset's CPU path falls back to
        // &self.model, so BOTH rayon::join arms would submit to the single Metal
        // model concurrently; on unified memory that races the shared command queue
        // and buffer pool and corrupts embeddings. In that case process the whole
        // set SERIALLY on the primary model instead (slower, but correct).
        if let Err(e) = self.cpu_model() {
            tracing::warn!(
                error = %e,
                "cpu twin unavailable; processing hybrid set serially on the primary model to avoid concurrent shared-model submission"
            );
            let mut merged = self.process_encoded_subset(
                metal_side,
                dimensions,
                max_batch_tokens,
                Some(EmbedBackendChoice::Metal {
                    reason: "hybrid_serial_primary",
                }),
            )?;
            merged.extend(self.process_encoded_subset(
                cpu_side,
                dimensions,
                max_batch_tokens,
                Some(EmbedBackendChoice::Metal {
                    reason: "hybrid_serial_primary",
                }),
            )?);
            return Ok(merged);
        }

        let (metal_res, cpu_res) = rayon::join(
            || {
                self.process_encoded_subset(
                    metal_side,
                    dimensions,
                    max_batch_tokens,
                    Some(EmbedBackendChoice::Metal {
                        reason: "hybrid_metal",
                    }),
                )
            },
            || {
                self.process_encoded_subset(
                    cpu_side,
                    dimensions,
                    max_batch_tokens,
                    Some(EmbedBackendChoice::Cpu {
                        reason: "hybrid_cpu",
                    }),
                )
            },
        );
        let mut merged = metal_res?;
        merged.extend(cpu_res?);
        Ok(merged)
    }

    /// Lazily construct (or return) the CPU-only BertModel twin.
    ///
    /// Construction sets `KIN_INFER_FORCE_CPU=1` around the single
    /// `BertModel::load` call so `kin_infer::gpu::create_compute` returns
    /// `CpuCompute` regardless of build-time Metal/CUDA features, then
    /// restores the prior env value. Called from the dispatcher when
    /// `KIN_EMBED_BACKEND` resolves to CPU.
    #[cfg(feature = "embeddings")]
    fn cpu_model(&self) -> Result<&BertModel, KinDbError> {
        if let Some(model) = self.cpu_model.get() {
            return Ok(model);
        }

        // Take the source out of the Mutex; we only need it once. After
        // successful init, the OnceLock holds the model and the source is
        // dropped.
        let source = {
            let mut guard = self
                .cpu_model_source
                .lock()
                .map_err(|_| KinDbError::IndexError("cpu_model_source mutex poisoned".into()))?;
            guard.take()
        };

        let built = if let Some(source) = source {
            let config: BertConfig = serde_json::from_str(&source.config_json).map_err(|e| {
                KinDbError::IndexError(format!("cpu twin config parse failed: {e}"))
            })?;

            // Force kin_infer::gpu::create_compute to pick the CPU backend
            // for this one load call only. Restore prior value afterward so
            // the primary (GPU) model loaded earlier is unaffected and any
            // unrelated inference elsewhere keeps its backend selection.
            let prev = std::env::var_os("KIN_INFER_FORCE_CPU");
            std::env::set_var("KIN_INFER_FORCE_CPU", "1");
            let result = BertModel::load(&source.weights_path, config);
            match prev {
                Some(v) => std::env::set_var("KIN_INFER_FORCE_CPU", v),
                None => std::env::remove_var("KIN_INFER_FORCE_CPU"),
            }
            let cpu_model = result.map_err(|e| {
                KinDbError::IndexError(format!("failed to load CPU BERT twin: {e}"))
            })?;
            tracing::info!(
                backend = %cpu_model.backend(),
                "kindb.embed: CPU BertModel twin loaded for long-sequence fallback"
            );
            cpu_model
        } else {
            return Err(KinDbError::IndexError(
                "cpu_model_source already consumed without a successful init".into(),
            ));
        };

        // Race: another thread may have beaten us; `set` will return Err on
        // that second attempt. Either way, `get` afterward yields the
        // winning instance.
        let _ = self.cpu_model.set(built);
        self.cpu_model
            .get()
            .ok_or_else(|| KinDbError::IndexError("cpu_model init failed".into()))
    }
}

#[cfg(feature = "embeddings")]
#[derive(Debug, Clone, PartialEq, Eq)]
enum EmbeddingProvider {
    Local,
    OpenAiCompat { profile: OpenAiCompatProfile },
}

#[cfg(feature = "embeddings")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpenAiCompatProfile {
    OpenAi,
    LmStudio,
    Compatible,
}

#[cfg(feature = "embeddings")]
#[derive(Debug, Clone)]
struct OpenAiCompatConfig {
    provider_label: String,
    base_url: String,
    model_id: String,
    api_key: Option<String>,
    dimensions: Option<usize>,
    send_dimensions: bool,
    timeout_secs: u64,
    request_overrides: serde_json::Map<String, serde_json::Value>,
    query_prefix: String,
    document_prefix: String,
}

#[cfg(feature = "embeddings")]
impl OpenAiCompatConfig {
    fn from_profile(profile: OpenAiCompatProfile) -> Result<Self, KinDbError> {
        let provider_label = match profile {
            OpenAiCompatProfile::OpenAi => "openai",
            OpenAiCompatProfile::LmStudio => "lmstudio",
            OpenAiCompatProfile::Compatible => "openai-compatible",
        }
        .to_string();

        let default_base_url = match profile {
            OpenAiCompatProfile::OpenAi => "https://api.openai.com/v1",
            OpenAiCompatProfile::LmStudio | OpenAiCompatProfile::Compatible => {
                "http://localhost:1234/v1"
            }
        };
        let default_model = match profile {
            OpenAiCompatProfile::OpenAi => DEFAULT_OPENAI_EMBED_MODEL_ID,
            OpenAiCompatProfile::LmStudio | OpenAiCompatProfile::Compatible => {
                DEFAULT_LMSTUDIO_EMBED_MODEL_ID
            }
        };
        let base_url = env_nonempty("KIN_EMBED_OPENAI_BASE_URL")
            .or_else(|| env_nonempty("KIN_EMBED_BASE_URL"))
            .unwrap_or_else(|| default_base_url.to_string());
        let model_id = env_nonempty("KIN_EMBED_OPENAI_MODEL")
            .or_else(|| env_nonempty("KIN_EMBED_MODEL_ID"))
            .unwrap_or_else(|| default_model.to_string());
        let api_key = env_nonempty("KIN_EMBED_OPENAI_API_KEY").or_else(|| {
            if matches!(profile, OpenAiCompatProfile::OpenAi) {
                env_nonempty("OPENAI_API_KEY")
            } else {
                None
            }
        });
        let dimensions = env_nonempty("KIN_EMBED_OPENAI_DIMENSIONS")
            .map(|value| parse_positive_usize("KIN_EMBED_OPENAI_DIMENSIONS", &value))
            .transpose()?;
        let timeout_secs = env_nonempty("KIN_EMBED_OPENAI_TIMEOUT_SECS")
            .map(|value| parse_positive_u64("KIN_EMBED_OPENAI_TIMEOUT_SECS", &value))
            .transpose()?
            .unwrap_or(120);
        let send_dimensions = env_flag("KIN_EMBED_OPENAI_SEND_DIMENSIONS");
        let request_overrides = match env_nonempty("KIN_EMBED_OPENAI_REQUEST_JSON") {
            Some(value) => parse_json_object_env("KIN_EMBED_OPENAI_REQUEST_JSON", &value)?,
            None => serde_json::Map::new(),
        };
        let (default_query_prefix, default_document_prefix) =
            default_openai_embedding_prefixes(&model_id);
        let query_prefix =
            env_nonempty("KIN_EMBED_OPENAI_QUERY_PREFIX").unwrap_or(default_query_prefix);
        let document_prefix =
            env_nonempty("KIN_EMBED_OPENAI_DOCUMENT_PREFIX").unwrap_or(default_document_prefix);

        Ok(Self {
            provider_label,
            base_url,
            model_id,
            api_key,
            dimensions,
            send_dimensions,
            timeout_secs,
            request_overrides,
            query_prefix,
            document_prefix,
        })
    }

    fn endpoint(&self) -> String {
        let trimmed = self.base_url.trim_end_matches('/');
        if trimmed.ends_with("/embeddings") {
            trimmed.to_string()
        } else {
            format!("{trimmed}/embeddings")
        }
    }

    fn provider_identity(&self) -> String {
        format!(
            "{}:{}",
            self.provider_label,
            self.base_url.trim_end_matches('/')
        )
    }

    fn request_overrides_fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        if let Ok(encoded) = serde_json::to_vec(&self.request_overrides) {
            hasher.update(encoded);
        }
        let digest = hex::encode(hasher.finalize());
        digest[..16].to_string()
    }

    fn runtime_revision(&self) -> String {
        format!(
            "openai-compatible;query_prefix={};document_prefix={};send_dimensions={};request={}",
            self.query_prefix,
            self.document_prefix,
            self.send_dimensions,
            self.request_overrides_fingerprint()
        )
    }
}

#[cfg(feature = "embeddings")]
impl OpenAiCompatEmbedder {
    fn new(config: OpenAiCompatConfig) -> Result<Self, KinDbError> {
        let client = BlockingHttpClient::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(|e| {
                KinDbError::IndexError(format!("failed to build embeddings HTTP client: {e}"))
            })?;
        let mut embedder = Self {
            client,
            endpoint: config.endpoint(),
            model_id: config.model_id,
            api_key: config.api_key,
            dimensions: config.dimensions.unwrap_or(0),
            request_overrides: config.request_overrides,
            query_prefix: config.query_prefix,
            document_prefix: config.document_prefix,
        };
        if config.send_dimensions {
            if let Some(dimensions) = config.dimensions {
                embedder
                    .request_overrides
                    .insert("dimensions".to_string(), serde_json::json!(dimensions));
            }
        }
        if embedder.dimensions == 0 {
            let probe = embedder.embed_batch_raw(&["kin embedding dimension probe".to_string()])?;
            embedder.dimensions = probe.first().map(Vec::len).ok_or_else(|| {
                KinDbError::IndexError("embedding probe returned no vectors".into())
            })?;
        }
        Ok(embedder)
    }

    fn prepare_inputs(&self, texts: &[String], role: EmbeddingInputRole) -> Vec<String> {
        let prefix = match role {
            EmbeddingInputRole::Query => &self.query_prefix,
            EmbeddingInputRole::Document => &self.document_prefix,
        };
        if prefix.is_empty() {
            return texts.to_vec();
        }
        texts.iter().map(|text| format!("{prefix}{text}")).collect()
    }

    fn embed_batch(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, KinDbError> {
        let vectors = self.embed_batch_raw(texts)?;
        for vector in &vectors {
            if vector.len() != self.dimensions {
                return Err(KinDbError::IndexError(format!(
                    "embedding endpoint returned {} dimensions, expected {}",
                    vector.len(),
                    self.dimensions
                )));
            }
        }
        Ok(vectors)
    }

    fn embed_batch_raw(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, KinDbError> {
        let mut body = serde_json::Map::new();
        body.insert(
            "model".to_string(),
            serde_json::Value::String(self.model_id.clone()),
        );
        body.insert("input".to_string(), serde_json::json!(texts));
        for (key, value) in &self.request_overrides {
            if matches!(key.as_str(), "model" | "input") {
                return Err(KinDbError::IndexError(format!(
                    "KIN_EMBED_OPENAI_REQUEST_JSON cannot override reserved embeddings field '{key}'"
                )));
            }
            body.insert(key.clone(), value.clone());
        }

        let mut req = self
            .client
            .post(&self.endpoint)
            .json(&serde_json::Value::Object(body));
        if let Some(api_key) = self.api_key.as_ref() {
            req = req.bearer_auth(api_key);
        }

        let resp = req
            .send()
            .map_err(|e| KinDbError::IndexError(format!("embedding request failed: {e}")))?;
        let status = resp.status();
        let text = resp
            .text()
            .map_err(|e| KinDbError::IndexError(format!("embedding response read failed: {e}")))?;
        if !status.is_success() {
            return Err(KinDbError::IndexError(format!(
                "embedding endpoint error (HTTP {status}): {text}"
            )));
        }
        parse_openai_embedding_response(&text, texts.len())
    }

    fn cache_namespace(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(EMBEDDING_CACHE_PIPELINE_EPOCH.as_bytes());
        hasher.update([0]);
        hasher.update(self.endpoint.as_bytes());
        hasher.update([0]);
        hasher.update(self.model_id.as_bytes());
        hasher.update([0]);
        hasher.update(self.dimensions.to_le_bytes());
        hasher.update([0]);
        hasher.update(self.query_prefix.as_bytes());
        hasher.update([0]);
        hasher.update(self.document_prefix.as_bytes());
        hasher.update([0]);
        if !self.request_overrides.is_empty() {
            if let Ok(encoded) = serde_json::to_vec(&self.request_overrides) {
                hasher.update(encoded);
            }
        }
        let digest = hex::encode(hasher.finalize());
        format!(
            "{}-{}",
            sanitize_component(&format!("{}-{}", self.endpoint, self.model_id)),
            &digest[..16]
        )
    }
}

#[cfg(feature = "embeddings")]
#[derive(Debug, Deserialize)]
struct OpenAiEmbeddingResponse {
    data: Vec<OpenAiEmbeddingData>,
}

#[cfg(feature = "embeddings")]
#[derive(Debug, Deserialize)]
struct OpenAiEmbeddingData {
    embedding: Vec<f32>,
    #[serde(default)]
    index: Option<usize>,
}

#[cfg(feature = "embeddings")]
fn parse_openai_embedding_response(
    text: &str,
    expected: usize,
) -> Result<Vec<Vec<f32>>, KinDbError> {
    let response: OpenAiEmbeddingResponse = serde_json::from_str(text)
        .map_err(|e| KinDbError::IndexError(format!("invalid embeddings JSON: {e}")))?;
    if response.data.len() != expected {
        return Err(KinDbError::IndexError(format!(
            "embedding endpoint returned {} vectors for {} inputs",
            response.data.len(),
            expected
        )));
    }
    let mut ordered: Vec<Option<Vec<f32>>> = vec![None; expected];
    for (fallback_idx, item) in response.data.into_iter().enumerate() {
        let index = item.index.unwrap_or(fallback_idx);
        if index >= expected {
            return Err(KinDbError::IndexError(format!(
                "embedding response index {index} out of range for {expected} inputs"
            )));
        }
        if ordered[index].replace(item.embedding).is_some() {
            return Err(KinDbError::IndexError(format!(
                "embedding response duplicated index {index}"
            )));
        }
    }
    ordered
        .into_iter()
        .enumerate()
        .map(|(index, vector)| {
            vector.ok_or_else(|| {
                KinDbError::IndexError(format!("embedding response missing index {index}"))
            })
        })
        .collect()
}

#[cfg(feature = "embeddings")]
fn configured_embedding_provider() -> EmbeddingProvider {
    match env_nonempty("KIN_EMBED_PROVIDER")
        .unwrap_or_else(|| "local".to_string())
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "local" | "hf" | "huggingface" | "bge" => EmbeddingProvider::Local,
        "openai" => EmbeddingProvider::OpenAiCompat {
            profile: OpenAiCompatProfile::OpenAi,
        },
        "lmstudio" | "lm-studio" => EmbeddingProvider::OpenAiCompat {
            profile: OpenAiCompatProfile::LmStudio,
        },
        "openai-compat" | "openai-compatible" | "compatible" => EmbeddingProvider::OpenAiCompat {
            profile: OpenAiCompatProfile::Compatible,
        },
        other => {
            tracing::warn!(
                provider = %other,
                "unknown KIN_EMBED_PROVIDER value, falling back to local embeddings"
            );
            EmbeddingProvider::Local
        }
    }
}

#[cfg(feature = "embeddings")]
fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(feature = "embeddings")]
fn env_flag(name: &str) -> bool {
    env_nonempty(name)
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

#[cfg(feature = "embeddings")]
fn parse_positive_usize(name: &str, value: &str) -> Result<usize, KinDbError> {
    let parsed = value
        .parse::<usize>()
        .map_err(|e| KinDbError::IndexError(format!("{name} must be a positive integer: {e}")))?;
    if parsed == 0 {
        return Err(KinDbError::IndexError(format!(
            "{name} must be a positive integer"
        )));
    }
    Ok(parsed)
}

#[cfg(feature = "embeddings")]
fn parse_positive_u64(name: &str, value: &str) -> Result<u64, KinDbError> {
    let parsed = value
        .parse::<u64>()
        .map_err(|e| KinDbError::IndexError(format!("{name} must be a positive integer: {e}")))?;
    if parsed == 0 {
        return Err(KinDbError::IndexError(format!(
            "{name} must be a positive integer"
        )));
    }
    Ok(parsed)
}

#[cfg(feature = "embeddings")]
fn parse_json_object_env(
    name: &str,
    value: &str,
) -> Result<serde_json::Map<String, serde_json::Value>, KinDbError> {
    let parsed: serde_json::Value = serde_json::from_str(value)
        .map_err(|e| KinDbError::IndexError(format!("{name} must be JSON: {e}")))?;
    parsed
        .as_object()
        .cloned()
        .ok_or_else(|| KinDbError::IndexError(format!("{name} must be a JSON object")))
}

/// When `model_id` resolves to an existing local directory, return it so model
/// artifacts load from disk instead of HuggingFace Hub. Lets the bench point at
/// a local SweRank checkout via `KIN_EMBED_MODEL_ID=/path/to/model` while a bare
/// repo id (e.g. `BAAI/bge-small-en-v1.5`) still downloads as before.
#[cfg(feature = "embeddings")]
fn local_model_dir(model_id: &str) -> Option<PathBuf> {
    let path = Path::new(model_id);
    if path.is_dir() {
        Some(path.to_path_buf())
    } else {
        None
    }
}

#[cfg(feature = "embeddings")]
fn resolve_local_model_artifacts(dir: &Path) -> Result<(PathBuf, PathBuf, PathBuf), KinDbError> {
    let require = |name: &str| -> Result<PathBuf, KinDbError> {
        let candidate = dir.join(name);
        if candidate.is_file() {
            Ok(candidate)
        } else {
            Err(KinDbError::IndexError(format!(
                "local model directory {} is missing {name}",
                dir.display()
            )))
        }
    };
    Ok((
        require("config.json")?,
        require("tokenizer.json")?,
        require("model.safetensors")?,
    ))
}

#[cfg(feature = "embeddings")]
fn local_query_prefix(model_id: &str, model_type: Option<&str>) -> String {
    let lower_id = model_id.to_ascii_lowercase();
    if lower_id.contains("swerank") {
        SWERANK_QUERY_PREFIX.to_string()
    } else {
        match model_type.map(str::trim) {
            Some("nomic_bert") | Some("nomic-bert") => SWERANK_QUERY_PREFIX.to_string(),
            _ => String::new(),
        }
    }
}

#[cfg(feature = "embeddings")]
fn default_openai_embedding_prefixes(model_id: &str) -> (String, String) {
    let lower = model_id.to_ascii_lowercase();
    if lower.contains("nomic-embed") || lower.contains("nomic_embed") {
        (
            "search_query: ".to_string(),
            "search_document: ".to_string(),
        )
    } else {
        (String::new(), String::new())
    }
}

#[cfg(feature = "embeddings")]
pub fn configured_embedding_runtime() -> EmbeddingRuntimeConfig {
    match configured_embedding_provider() {
        EmbeddingProvider::Local => EmbeddingRuntimeConfig {
            provider: "local".to_string(),
            model_id: env_nonempty("KIN_EMBED_MODEL_ID")
                .unwrap_or_else(|| DEFAULT_MODEL_ID.to_string()),
            revision: env_nonempty("KIN_EMBED_MODEL_REVISION")
                .unwrap_or_else(|| DEFAULT_REVISION.to_string()),
            dimensions: None,
            pipeline_epoch: EMBEDDING_CACHE_PIPELINE_EPOCH.to_string(),
        },
        EmbeddingProvider::OpenAiCompat { profile } => {
            let config =
                OpenAiCompatConfig::from_profile(profile).unwrap_or_else(|_| OpenAiCompatConfig {
                    provider_label: "openai-compatible".to_string(),
                    base_url: env_nonempty("KIN_EMBED_OPENAI_BASE_URL")
                        .unwrap_or_else(|| "http://localhost:1234/v1".to_string()),
                    model_id: env_nonempty("KIN_EMBED_OPENAI_MODEL")
                        .or_else(|| env_nonempty("KIN_EMBED_MODEL_ID"))
                        .unwrap_or_else(|| DEFAULT_LMSTUDIO_EMBED_MODEL_ID.to_string()),
                    api_key: None,
                    dimensions: None,
                    send_dimensions: false,
                    timeout_secs: 120,
                    request_overrides: serde_json::Map::new(),
                    query_prefix: String::new(),
                    document_prefix: String::new(),
                });
            let revision = config.runtime_revision();
            EmbeddingRuntimeConfig {
                provider: config.provider_identity(),
                model_id: config.model_id,
                revision,
                dimensions: config.dimensions,
                pipeline_epoch: EMBEDDING_CACHE_PIPELINE_EPOCH.to_string(),
            }
        }
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

/// Seq_len partition used only by opt-in hybrid dispatch.
///
/// Plain `auto` no longer CPU-falls back above this threshold. The nlohmann/json
/// backfill probe showed forced Metal cleanly embedding max_seq=2048 batches
/// while the previous threshold routed those same long, context-augmented
/// entities through the slow CPU path.
#[cfg(feature = "embeddings")]
const EMBED_CPU_SEQ_THRESHOLD: usize = 1024;

/// When auto dispatch resolves, should it prefer CPU unconditionally?
///
/// The Metal BERT NaN was root-caused to GELU's tanh argument overflowing
/// (`sinh/cosh` → inf → NaN) at long sequences; the fix clamps the argument
/// in `gelu_activation` (kin-infer commit d8df3cc). With that landed, the
/// `metal_seq_len_regression` suite is green end-to-end (BGE-small Metal-vs-CPU
/// parity, cosine ≈ 1.0, zero NaN from seq_len 7..1024), the SwiGLU/SiLU path is
/// verified clean by `swerank_self_retrieval` (top-1 correct, margin 0.19), and
/// the ContextBench nlohmann/json backfill probe validated max_seq=2048 forced
/// Metal batches. Auto dispatch should therefore stay on Metal by default; CPU
/// remains available through `KIN_EMBED_BACKEND=cpu`.
#[cfg(feature = "embeddings")]
const EMBED_AUTO_PREFERS_CPU: bool = false;

#[cfg(feature = "embeddings")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EmbedBackendChoice {
    Metal { reason: &'static str },
    Cpu { reason: &'static str },
}

#[cfg(feature = "embeddings")]
const HYBRID_DEFAULT_GPU_TPUT_RATIO: f64 = 4.0;

#[cfg(feature = "embeddings")]
#[derive(Debug, Clone, Copy, PartialEq)]
enum HybridMode {
    Off,
    SeqFloor,
    Balanced { gpu_tput_ratio: f64 },
}

#[cfg(feature = "embeddings")]
fn hybrid_mode() -> HybridMode {
    let raw = match std::env::var("KIN_EMBED_HYBRID") {
        Ok(v) => v.trim().to_ascii_lowercase(),
        Err(_) => return HybridMode::Off,
    };
    let enabled = !matches!(raw.as_str(), "" | "0" | "false" | "off" | "no");
    if !enabled || EMBED_AUTO_PREFERS_CPU {
        return HybridMode::Off;
    }
    let backend = std::env::var("KIN_EMBED_BACKEND")
        .ok()
        .map(|v| v.trim().to_ascii_lowercase())
        .unwrap_or_else(|| "auto".to_string());
    if !matches!(backend.as_str(), "auto" | "") {
        return HybridMode::Off;
    }
    if matches!(raw.as_str(), "seq" | "floor" | "seqfloor" | "seq_floor") {
        return HybridMode::SeqFloor;
    }
    let gpu_tput_ratio = std::env::var("KIN_EMBED_HYBRID_GPU_TPUT_RATIO")
        .ok()
        .and_then(|v| v.trim().parse::<f64>().ok())
        .filter(|v| v.is_finite() && *v > 0.0)
        .unwrap_or(HYBRID_DEFAULT_GPU_TPUT_RATIO);
    HybridMode::Balanced { gpu_tput_ratio }
}

#[cfg(feature = "embeddings")]
type Encoded = (usize, Vec<u32>, Vec<u32>);

#[cfg(feature = "embeddings")]
fn balanced_partition(encoded: &[Encoded], gpu_tput_ratio: f64) -> (Vec<Encoded>, Vec<Encoded>) {
    let ceiling_split = encoded.partition_point(|(_, ids, _)| ids.len() <= EMBED_CPU_SEQ_THRESHOLD);
    let short = &encoded[..ceiling_split];
    let long = &encoded[ceiling_split..];

    let work = |ids: &[u32]| ids.len().max(1) as f64;
    let w_short: f64 = short.iter().map(|(_, ids, _)| work(ids)).sum();
    let w_long: f64 = long.iter().map(|(_, ids, _)| work(ids)).sum();

    let target_metal =
        ((gpu_tput_ratio * w_short - w_long) / (gpu_tput_ratio + 1.0)).clamp(0.0, w_short);

    let mut order: Vec<usize> = (0..short.len()).collect();
    order.sort_by(|&a, &b| {
        short[b]
            .1
            .len()
            .cmp(&short[a].1.len())
            .then(short[a].0.cmp(&short[b].0))
    });

    let mut to_metal = vec![false; short.len()];
    let mut metal_work = 0.0;
    let mut metal_count = 0usize;
    for pos in order {
        let w = work(&short[pos].1);
        if target_metal > 0.0 && (metal_work + w <= target_metal || metal_count == 0) {
            metal_work += w;
            metal_count += 1;
            to_metal[pos] = true;
        }
    }

    let mut metal_subset: Vec<Encoded> = Vec::with_capacity(metal_count);
    let mut cpu_subset: Vec<Encoded> = Vec::with_capacity(encoded.len() - metal_count);
    for (pos, entry) in short.iter().enumerate() {
        if to_metal[pos] {
            metal_subset.push(entry.clone());
        } else {
            cpu_subset.push(entry.clone());
        }
    }
    cpu_subset.extend(long.iter().cloned());

    (metal_subset, cpu_subset)
}

/// Pick the inference path for a chunk based on `KIN_EMBED_BACKEND` and the
/// chunk's longest sequence length.
///
/// - `metal` (forced): always route through `forward_batched`. Useful to
///   verify the Metal kernel fix once it lands.
/// - `cpu` (forced): always route through per-sample `forward`, which on
///   Metal uses the non-broken fused_attention kernel and on pure-CPU builds
///   is the SIMD path. Debug escape hatch.
/// - `auto` (default): use batched Metal. CPU is an explicit escape hatch via
///   `KIN_EMBED_BACKEND=cpu`, not a hidden fallback for long code entities.
#[cfg(feature = "embeddings")]
fn resolve_embed_backend(max_seq: usize) -> EmbedBackendChoice {
    let mode = std::env::var("KIN_EMBED_BACKEND")
        .ok()
        .map(|v| v.trim().to_ascii_lowercase())
        .unwrap_or_else(|| "auto".to_string());

    match mode.as_str() {
        "metal" | "gpu" => EmbedBackendChoice::Metal {
            reason: "env_forced",
        },
        "cpu" => EmbedBackendChoice::Cpu {
            reason: "env_forced",
        },
        "auto" | "" => auto_choice(max_seq),
        other => {
            tracing::warn!(
                backend = %other,
                "unknown KIN_EMBED_BACKEND value, falling back to auto"
            );
            auto_choice(max_seq)
        }
    }
}

#[cfg(feature = "embeddings")]
fn auto_choice(_max_seq: usize) -> EmbedBackendChoice {
    if EMBED_AUTO_PREFERS_CPU {
        EmbedBackendChoice::Cpu {
            reason: "auto_metal_unreliable",
        }
    } else {
        EmbedBackendChoice::Metal {
            reason: "auto_metal_default",
        }
    }
}

/// Test-only fault injection for the Metal embedding dispatch arm.
///
/// When `KIN_EMBED_TEST_FORCE_METAL_OOM` is set to a positive integer `N`, the
/// first `N` Metal `forward_batched` dispatches in this process are replaced
/// with a synthetic `kin_infer::InferError::OutOfMemory`, so the CPU-degrade
/// retry path can be exercised end-to-end without putting the device under real
/// memory pressure. The kin-infer side already proves `try_new_buffer` surfaces
/// a real `OutOfMemory`; this lets the kin-db side prove the dispatcher handles
/// that error value by retrying the batch on the CPU twin.
///
/// In production the variable is unset: the budget initializes to `0` exactly
/// once and every subsequent check is a single relaxed atomic load that returns
/// `false`, so the embedding hot path is unaffected.
#[cfg(feature = "embeddings")]
fn metal_oom_injection_armed() -> bool {
    use std::sync::atomic::{AtomicI64, Ordering};
    use std::sync::OnceLock;

    static BUDGET: OnceLock<AtomicI64> = OnceLock::new();
    let budget = BUDGET.get_or_init(|| {
        let remaining = std::env::var("KIN_EMBED_TEST_FORCE_METAL_OOM")
            .ok()
            .and_then(|value| value.trim().parse::<i64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(0);
        AtomicI64::new(remaining)
    });

    if budget.load(Ordering::Relaxed) <= 0 {
        return false;
    }
    // fetch_sub returns the PREVIOUS value; inject while it was still positive.
    budget.fetch_sub(1, Ordering::Relaxed) > 0
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

/// Bound a single embed-text field to `max_chars`, on a UTF-8 char boundary.
/// Right-truncation keeps the front of the field, which for docstrings is the
/// summary line and first paragraph (the discriminating signal); the trailing
/// boilerplate that is dropped carries little retrieval value but heavy cost.
fn bounded_embed_field(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        text.to_string()
    } else {
        text.chars().take(max_chars).collect()
    }
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
        let doc_summary = doc_summary.trim();
        if !doc_summary.is_empty() {
            parts.push(bounded_embed_field(doc_summary, EMBED_DOC_SUMMARY_MAX_CHARS));
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

/// Build the text representation for a structured artifact.
pub fn format_artifact_text(artifact: &StructuredArtifact) -> String {
    let mut parts = Vec::with_capacity(4);
    parts.push("structured_artifact".to_string());
    parts.push(format!("kind={}", artifact_kind_label(artifact.kind)));
    parts.push(format!("file={}", artifact.file_id.0));
    if let Some(text_preview) = artifact.text_preview.as_deref() {
        let text_preview = text_preview.trim();
        if !text_preview.is_empty() {
            parts.push(text_preview.to_string());
        }
    }
    parts.join("\n")
}

/// Build the text representation for an opaque artifact.
pub fn format_opaque_text(artifact: &OpaqueArtifact) -> String {
    let mut parts = Vec::with_capacity(4);
    parts.push("opaque_artifact".to_string());
    parts.push(format!("file={}", artifact.file_id.0));
    if let Some(mime_type) = artifact.mime_type.as_deref() {
        let mime_type = mime_type.trim();
        if !mime_type.is_empty() {
            parts.push(format!("mime_type={mime_type}"));
        }
    }
    if let Some(text_preview) = artifact.text_preview.as_deref() {
        let text_preview = text_preview.trim();
        if !text_preview.is_empty() {
            parts.push(text_preview.to_string());
        }
    }
    parts.join("\n")
}

/// Build the text representation for a shallow-tracked file.
pub fn format_shallow_text(file: &ShallowTrackedFile) -> String {
    let mut parts = Vec::with_capacity(8);
    parts.push("shallow_file".to_string());
    parts.push(format!("file={}", file.file_id.0));
    parts.push(format!("language_hint={}", file.language_hint));
    parts.push(format!("declaration_count={}", file.declaration_count));
    parts.push(format!("import_count={}", file.import_count));
    if let Some(signature_hash) = file.signature_hash.as_ref() {
        parts.push(format!("signature_hash={signature_hash:?}"));
    }
    if !file.declaration_names.is_empty() {
        parts.push(format!("declarations={}", file.declaration_names.join(" ")));
    }
    if !file.import_paths.is_empty() {
        parts.push(format!("imports={}", file.import_paths.join(" ")));
    }
    parts.join("\n")
}

fn artifact_kind_label(kind: ArtifactKind) -> &'static str {
    match kind {
        ArtifactKind::PackageManifest => "package_manifest",
        ArtifactKind::SqlMigration => "sql_migration",
        ArtifactKind::CiConfig => "ci_config",
        ArtifactKind::Dockerfile => "dockerfile",
        ArtifactKind::ComposeFile => "compose_file",
        ArtifactKind::Makefile => "makefile",
    }
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
        EntityKind::Macro => "macro",
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
        if !vector.iter().all(|v| v.is_finite()) {
            return;
        }
        // Zero vectors are what `sanitize_embedding` emits in place of NaN;
        // persisting them would poison future runs the same way the prior
        // NaN cache did. A genuine embedding from BGE is L2-normalized so
        // its norm is ~1.0 — a zero vector is always sentinel output.
        if vector.iter().all(|v| *v == 0.0) {
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
    // Poisoned cache entries from prior builds must not be returned: treat them
    // as a miss so the caller re-embeds with current defensive guards in place.
    if !values.iter().all(|v| v.is_finite()) {
        let _ = std::fs::remove_file(path);
        return None;
    }
    // Zero vectors in the cache are the sentinel emitted by `sanitize_embedding`
    // when the inference kernel produced NaN. A real BGE embedding is
    // L2-normalized (norm ~1.0), so a zero vector is never a legitimate
    // cache hit — evict and re-embed.
    if values.iter().all(|v| *v == 0.0) {
        let _ = std::fs::remove_file(path);
        return None;
    }
    Some(values)
}

/// Replace non-finite embeddings with a zero vector of the correct dimension.
/// Cosine distance's zero-norm guard then produces a sentinel distance of 1.0
/// rather than propagating NaN through the search index.
#[cfg(feature = "embeddings")]
fn sanitize_embedding<'a, F>(vector: Vec<f32>, dimensions: usize, describe: F) -> Vec<f32>
where
    F: FnOnce() -> &'a str,
{
    let needs_fix = vector.len() != dimensions || !vector.iter().all(|v| v.is_finite());
    if !needs_fix {
        return vector;
    }
    let text = describe();
    let preview: String = text.chars().take(64).collect();
    tracing::error!(
        dims = vector.len(),
        expected_dims = dimensions,
        nan_count = vector.iter().filter(|v| v.is_nan()).count(),
        inf_count = vector.iter().filter(|v| v.is_infinite()).count(),
        text_len = text.len(),
        text_preview = %preview,
        "embedder produced non-finite vector; substituting zero vector"
    );
    vec![0.0f32; dimensions]
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
        EntityId, EntityMetadata, EntityRole, FilePathId, FingerprintAlgorithm, Hash256,
        LanguageId, SemanticFingerprint, Visibility,
    };

    /// Default embedding dimensions for SweRankEmbed-Small.
    const DEFAULT_EMBED_DIMS: usize = 768;

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
            role: EntityRole::Source,
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
    fn format_graph_entity_text_caps_long_doc_summary() {
        // A numpy-style docstring far exceeds the embed cap (cf. scikit-learn's
        // RandomForestClassifier, whose docstring alone is ~3700 tokens). Only
        // the front — the semantic summary — should be folded into embed text;
        // the trailing Parameters/Examples prose is dropped.
        let head = "A random forest classifier. ";
        let long_doc = format!(
            "{head}{}",
            "Parameters ---------- n_estimators int default 100. ".repeat(200)
        );
        assert!(long_doc.chars().count() > EMBED_DOC_SUMMARY_MAX_CHARS);

        let entity = Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: "RandomForestClassifier".into(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256([0; 32]),
                signature_hash: Hash256([0; 32]),
                behavior_hash: Hash256([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new("sklearn/ensemble/_forest.py")),
            span: None,
            signature: "class RandomForestClassifier".into(),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: Some(long_doc.clone()),
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };

        let formatted = format_graph_entity_text(&entity);
        // The summary head is retained.
        assert!(formatted.contains("A random forest classifier."));
        // The full docstring is NOT folded in verbatim.
        assert!(!formatted.contains(&long_doc));
        // Total embed text stays within the cap plus the short header fields
        // (kind/path/name/signature), proving the docstring no longer dominates.
        assert!(
            formatted.chars().count() <= EMBED_DOC_SUMMARY_MAX_CHARS + 256,
            "doc summary not capped: {} chars",
            formatted.chars().count()
        );
    }

    #[test]
    fn bounded_embed_field_passes_through_short_text() {
        assert_eq!(bounded_embed_field("short text", 100), "short text");
    }

    #[test]
    fn bounded_embed_field_truncates_on_char_boundary() {
        // Multi-byte chars must not panic at the truncation boundary.
        let text: String = "é".repeat(50);
        let bounded = bounded_embed_field(&text, 10);
        assert_eq!(bounded.chars().count(), 10);
        assert!(bounded.chars().all(|c| c == 'é'));
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
            role: EntityRole::Source,
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
    fn format_artifact_text_includes_kind_path_and_preview() {
        let artifact = StructuredArtifact {
            file_id: FilePathId::new("Makefile"),
            kind: ArtifactKind::Makefile,
            content_hash: Hash256([1; 32]),
            text_preview: Some("build target install test".into()),
        };

        let formatted = format_artifact_text(&artifact);
        assert_eq!(
            formatted,
            "structured_artifact\nkind=makefile\nfile=Makefile\nbuild target install test"
        );
    }

    #[test]
    fn format_opaque_text_includes_mime_and_preview() {
        let artifact = OpaqueArtifact {
            file_id: FilePathId::new("assets/logo.svg"),
            content_hash: Hash256([2; 32]),
            mime_type: Some("image/svg+xml".into()),
            text_preview: Some("svg logo icon".into()),
        };

        let formatted = format_opaque_text(&artifact);
        assert_eq!(
            formatted,
            "opaque_artifact\nfile=assets/logo.svg\nmime_type=image/svg+xml\nsvg logo icon"
        );
    }

    #[test]
    fn format_shallow_text_includes_surface_context() {
        let file = ShallowTrackedFile {
            file_id: FilePathId::new("src/lib.rs"),
            language_hint: "rust".into(),
            declaration_count: 2,
            import_count: 1,
            syntax_hash: Hash256([3; 32]),
            signature_hash: Some(Hash256([4; 32])),
            declaration_names: vec!["parse_config".into(), "load_registry".into()],
            import_paths: vec!["crate::config".into()],
        };

        let formatted = format_shallow_text(&file);
        assert!(formatted.starts_with(
            "shallow_file\nfile=src/lib.rs\nlanguage_hint=rust\ndeclaration_count=2\nimport_count=1"
        ));
        assert!(formatted.contains("signature_hash=Hash256"));
        assert!(formatted.contains("declarations=parse_config load_registry"));
        assert!(formatted.contains("imports=crate::config"));
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
    fn resolve_embed_backend_honors_env_and_metal_default() {
        // Use a unique env var sequence; reset at the end to avoid bleed
        // into sibling tests that share process env.
        let prev = std::env::var("KIN_EMBED_BACKEND").ok();

        std::env::set_var("KIN_EMBED_BACKEND", "auto");
        // `EMBED_AUTO_PREFERS_CPU` is `false`: auto stays on Metal. CPU is an
        // explicit debug escape hatch via KIN_EMBED_BACKEND=cpu.
        assert!(matches!(
            resolve_embed_backend(8),
            EmbedBackendChoice::Metal { .. }
        ));
        assert!(matches!(
            resolve_embed_backend(128),
            EmbedBackendChoice::Metal { .. }
        ));
        assert!(matches!(
            resolve_embed_backend(EMBED_CPU_SEQ_THRESHOLD + 1),
            EmbedBackendChoice::Metal { .. }
        ));

        std::env::set_var("KIN_EMBED_BACKEND", "cpu");
        assert!(matches!(
            resolve_embed_backend(64),
            EmbedBackendChoice::Cpu { .. }
        ));
        assert!(matches!(
            resolve_embed_backend(1024),
            EmbedBackendChoice::Cpu { .. }
        ));

        std::env::set_var("KIN_EMBED_BACKEND", "metal");
        assert!(matches!(
            resolve_embed_backend(1024),
            EmbedBackendChoice::Metal { .. }
        ));

        // An unrecognized value falls through to the auto path, which now keeps
        // long code entities on Metal.
        std::env::set_var("KIN_EMBED_BACKEND", "nonsense-value");
        assert!(matches!(
            resolve_embed_backend(EMBED_CPU_SEQ_THRESHOLD + 1),
            EmbedBackendChoice::Metal { .. }
        ));

        match prev {
            Some(v) => std::env::set_var("KIN_EMBED_BACKEND", v),
            None => std::env::remove_var("KIN_EMBED_BACKEND"),
        }
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

    #[cfg(feature = "embeddings")]
    #[test]
    fn openai_embedding_response_is_ordered_by_index() {
        let body = r#"{
            "object": "list",
            "data": [
                {"object": "embedding", "index": 1, "embedding": [0.0, 1.0]},
                {"object": "embedding", "index": 0, "embedding": [1.0, 0.0]}
            ],
            "model": "test"
        }"#;

        let vectors = parse_openai_embedding_response(body, 2).unwrap();
        assert_eq!(vectors, vec![vec![1.0, 0.0], vec![0.0, 1.0]]);
    }

    #[cfg(feature = "embeddings")]
    #[test]
    fn openai_embedding_response_rejects_count_mismatch() {
        let body = r#"{"data":[{"index":0,"embedding":[1.0]}]}"#;
        let err = parse_openai_embedding_response(body, 2).unwrap_err();
        assert!(err.to_string().contains("returned 1 vectors for 2 inputs"));
    }

    #[cfg(feature = "embeddings")]
    #[test]
    fn nomic_defaults_use_search_prefixes() {
        let (query, document) =
            default_openai_embedding_prefixes("text-embedding-nomic-embed-text-v1.5");
        assert_eq!(query, "search_query: ");
        assert_eq!(document, "search_document: ");

        let (query, document) = default_openai_embedding_prefixes("text-embedding-3-small");
        assert_eq!(query, "");
        assert_eq!(document, "");
    }

    #[cfg(feature = "embeddings")]
    #[test]
    fn openai_runtime_revision_includes_request_overrides() {
        let base = OpenAiCompatConfig {
            provider_label: "openai-compatible".into(),
            base_url: "http://localhost:1234/v1".into(),
            model_id: "test-embed".into(),
            api_key: None,
            dimensions: Some(3),
            send_dimensions: false,
            timeout_secs: 30,
            request_overrides: serde_json::Map::new(),
            query_prefix: String::new(),
            document_prefix: String::new(),
        };
        let mut tuned = base.clone();
        tuned.request_overrides.insert(
            "encoding_format".into(),
            serde_json::Value::String("float".into()),
        );

        assert_ne!(base.runtime_revision(), tuned.runtime_revision());
    }
}
