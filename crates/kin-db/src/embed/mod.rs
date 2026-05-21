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
use kin_model::{
    ArtifactKind, Entity, EntityKind, OpaqueArtifact, ShallowTrackedFile, StructuredArtifact,
};

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
const METAL_MAX_BATCH_TOKENS: usize = 16_384;
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
    #[cfg(feature = "embeddings")]
    tokenizer: Tokenizer,
    #[cfg(feature = "embeddings")]
    dimensions: usize,
    #[cfg(feature = "embeddings")]
    cache: Option<EmbeddingCache>,
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
            cpu_model: std::sync::OnceLock::new(),
            cpu_model_source: std::sync::Mutex::new(Some(CpuModelSource {
                weights_path: weights_path.clone(),
                config_json: config_data,
            })),
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

            // TODO(metal): seq_len > ~500 produces NaN in kin-infer Metal attention
            // kernels for the batched code path (fused_attention_batched —
            // scale_mask_alibi_grouped.metal / softmax_rows.metal — likely softmax
            // max-subtract missing). See embedder agent diagnosis 2026-04-14 and
            // planning/metal-bert-nan-bug.md. Vue produced 2980/2980 zero-vectors
            // against that bug before the sanitize guard landed in kin-db 0d620a7.
            //
            // This dispatcher routes long-sequence batches through the single-input
            // `forward` path (different Metal kernel — fused_attention — which is
            // known-correct on this regime). True CPU execution is not possible
            // from here without a kin-infer constructor that accepts a GpuBackend;
            // that is a separate follow-up. The single-input forward path is
            // functionally "CPU-equivalent correctness" for BGE-small today.
            //
            // Remove this dispatcher when kin-infer's batched attention kernel is
            // fixed and `KIN_EMBED_BACKEND=metal cargo test -p kin-db --test \
            // metal_seq_len_regression` passes the batched sweep at seq_len>=512.
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
                    self.model
                        .forward_batched(&token_ids, &attention_masks)
                        .map_err(|e| KinDbError::IndexError(format!("inference failed: {e}")))?
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
                    // Route through the CPU-only BertModel twin so we are
                    // guaranteed a non-Metal attention kernel. Falls back to
                    // the primary model only if the CPU twin cannot be
                    // constructed (e.g. weight file unavailable) — better
                    // than failing the whole index build.
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
            // non-finite vectors (e.g. `metal` forced via env and the kernel
            // misbehaves), retry per-sample through the single-input `forward`
            // path. Preserves the existing sanitize_embedding contract for
            // downstream writers while keeping the dispatcher's explicit log.
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
                let vector = sanitize_embedding(vector, self.dimensions, || {
                    missing_texts
                        .get(*original_idx)
                        .map(String::as_str)
                        .unwrap_or("<missing>")
                });
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

/// Conservative seq_len threshold for auto dispatch. The Metal batched
/// attention kernel begins producing NaN in the ~500-token regime; 256 keeps
/// the chunked path well below that zone. Irrelevant when
/// `EMBED_AUTO_PREFERS_CPU` is true (current state — Metal is unreliable
/// even at short sequences in the daemon process).
#[cfg(feature = "embeddings")]
const EMBED_CPU_SEQ_THRESHOLD: usize = 256;

/// When auto dispatch resolves, should it prefer CPU unconditionally?
///
/// Empirically, kin-infer's Metal attention produces NaN through both
/// `forward_batched` and single-input `forward` in the running daemon for
/// BGE-small even at seq_len=8. Until the Metal kernel bug is root-caused
/// and fixed (see `planning/metal-bert-nan-bug.md`), auto dispatch routes
/// everything through the CPU BertModel twin. When the fix lands and the
/// `metal_seq_len_regression` tests pass with `KIN_EMBED_BACKEND=metal`,
/// flip this to `false` (or remove it) to re-enable threshold-based
/// Metal routing for short sequences.
#[cfg(feature = "embeddings")]
const EMBED_AUTO_PREFERS_CPU: bool = true;

#[cfg(feature = "embeddings")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EmbedBackendChoice {
    Metal { reason: &'static str },
    Cpu { reason: &'static str },
}

/// Pick the inference path for a chunk based on `KIN_EMBED_BACKEND` and the
/// chunk's longest sequence length.
///
/// - `metal` (forced): always route through `forward_batched`. Useful to
///   verify the Metal kernel fix once it lands.
/// - `cpu` (forced): always route through per-sample `forward`, which on
///   Metal uses the non-broken fused_attention kernel and on pure-CPU builds
///   is the SIMD path. Debug escape hatch.
/// - `auto` (default): route long sequences through the per-sample path
///   (max_seq > EMBED_CPU_SEQ_THRESHOLD), short ones through batched Metal.
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
fn auto_choice(max_seq: usize) -> EmbedBackendChoice {
    if EMBED_AUTO_PREFERS_CPU {
        EmbedBackendChoice::Cpu {
            reason: "auto_metal_unreliable",
        }
    } else if max_seq > EMBED_CPU_SEQ_THRESHOLD {
        EmbedBackendChoice::Cpu {
            reason: "seq_threshold",
        }
    } else {
        EmbedBackendChoice::Metal {
            reason: "auto_short_seq",
        }
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
    fn resolve_embed_backend_honors_env_and_threshold() {
        // Use a unique env var sequence; reset at the end to avoid bleed
        // into sibling tests that share process env.
        let prev = std::env::var("KIN_EMBED_BACKEND").ok();

        std::env::set_var("KIN_EMBED_BACKEND", "auto");
        // `EMBED_AUTO_PREFERS_CPU` is currently `true`: auto routes
        // everything through CPU regardless of seq_len. Both short and long
        // sequences must land on Cpu until Metal is patched.
        assert!(matches!(
            resolve_embed_backend(8),
            EmbedBackendChoice::Cpu { .. }
        ));
        assert!(matches!(
            resolve_embed_backend(128),
            EmbedBackendChoice::Cpu { .. }
        ));
        assert!(matches!(
            resolve_embed_backend(EMBED_CPU_SEQ_THRESHOLD + 1),
            EmbedBackendChoice::Cpu { .. }
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

        std::env::set_var("KIN_EMBED_BACKEND", "nonsense-value");
        assert!(matches!(
            resolve_embed_backend(1024),
            EmbedBackendChoice::Cpu { .. }
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
}
