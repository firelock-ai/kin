// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Universal transformer inference engine — pure Rust, GPU-accelerated.
//!
//! Supports encoder (BERT, RoBERTa, ALBERT, DeBERTa, T5, nomic-embed, GTE) and
//! decoder-only (LLaMA, Mistral, Gemma, GPT-2, Phi, Qwen2) architectures.
//!
//! GPU backends: Metal (macOS), CUDA (Linux/Windows). Custom shaders/kernels,
//! no external ML frameworks. Transparent CPU fallback with SIMD acceleration.
//!
//! Weight loading: safetensors (single or sharded), F32/F16/BF16/Q8_0/Q4_0.
//! Positional: learned, ALiBi, RoPE, relative bias (T5), disentangled (DeBERTa).
//! Attention: MHA, GQA, MQA. Norm: LayerNorm, RMSNorm. FFN: GELU, SwiGLU, GeGLU, ReGLU.

#[cfg(feature = "cuda")]
pub mod cuda_backend;
pub mod gpu;
pub mod macos_qos;
#[cfg(all(feature = "metal", target_os = "macos"))]
pub mod metal_backend;
pub mod resource;
pub mod watchdog;

use half::{bf16, f16};
use ndarray::{s, Array1, Array2};
use safetensors::{Dtype, SafeTensors};
use std::borrow::Cow;
use std::collections::HashMap;
use std::path::Path;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum InferError {
    #[error("model error: {0}")]
    ModelError(String),
    #[error("io error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("gpu out of memory: {0}")]
    OutOfMemory(String),
    #[error("model incompatible: {0}")]
    ModelIncompatible(String),
    #[error("backend error: {0}")]
    BackendError(String),
    #[error("internal invariant violated: {0}")]
    Internal(String),
    #[error("non-finite model output: {0}")]
    NonFiniteOutput(String),
}

// ---------------------------------------------------------------------------
// Model architecture detection
// ---------------------------------------------------------------------------

/// Detected model architecture family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelArchitecture {
    Bert,
    Roberta,
    Albert,
    Deberta,
    T5Encoder,
    Gpt2,
    Llama,
    Mistral,
    Phi,
    Gemma,
    Qwen2,
    NomicBert,
    Unknown,
}

impl ModelArchitecture {
    fn from_model_type(model_type: &str) -> Self {
        match model_type {
            "bert" => Self::Bert,
            "roberta" | "xlm-roberta" => Self::Roberta,
            "albert" => Self::Albert,
            "deberta" | "deberta-v2" => Self::Deberta,
            "t5" | "mt5" => Self::T5Encoder,
            "gpt2" => Self::Gpt2,
            "llama" => Self::Llama,
            "mistral" => Self::Mistral,
            "phi" | "phi3" => Self::Phi,
            "gemma" | "gemma2" => Self::Gemma,
            "qwen2" => Self::Qwen2,
            "nomic_bert" | "nomic-bert" => Self::NomicBert,
            _ => Self::Unknown,
        }
    }

    pub fn is_decoder_only(self) -> bool {
        matches!(
            self,
            Self::Gpt2 | Self::Llama | Self::Mistral | Self::Phi | Self::Gemma | Self::Qwen2
        )
    }

    fn uses_rmsnorm(self) -> bool {
        matches!(
            self,
            Self::Llama | Self::Mistral | Self::Gemma | Self::Qwen2
        )
    }

    fn uses_rope(self) -> bool {
        matches!(
            self,
            Self::Llama | Self::Mistral | Self::Phi | Self::Gemma | Self::Qwen2 | Self::NomicBert
        )
    }

    fn uses_pre_ln(self) -> bool {
        matches!(
            self,
            Self::Gpt2 | Self::Llama | Self::Mistral | Self::Phi | Self::Gemma | Self::Qwen2
        )
    }
}

// ---------------------------------------------------------------------------
// Model configuration (parsed from config.json)
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub struct BertConfig {
    #[serde(alias = "n_embd")]
    pub hidden_size: usize,
    #[serde(alias = "n_layer")]
    pub num_hidden_layers: usize,
    #[serde(alias = "n_head")]
    pub num_attention_heads: usize,
    #[serde(alias = "n_inner")]
    pub intermediate_size: usize,
    #[serde(alias = "n_positions")]
    pub max_position_embeddings: usize,
    pub vocab_size: usize,
    #[serde(default)]
    pub type_vocab_size: Option<usize>,
    #[serde(default = "default_eps", alias = "layer_norm_epsilon")]
    pub layer_norm_eps: f64,
    #[serde(default)]
    pub position_embedding_type: Option<String>,
    #[serde(default = "default_feed_forward_type")]
    pub feed_forward_type: String,
    /// GPT-style FFN activation key (nomic_bert: "swiglu"). Normalized into
    /// `feed_forward_type` after load so the gated-FFN path activates.
    #[serde(default)]
    pub activation_function: Option<String>,
    /// Sentence-Transformers pooling override ("cls" or "mean"). When None the
    /// architecture default applies (mean for BERT-family, cls for nomic_bert).
    #[serde(default)]
    pub pooling_mode: Option<String>,
    #[serde(default)]
    pub pad_token_id: Option<u32>,
    // --- Universal extensions ---
    #[serde(default)]
    pub model_type: Option<String>,
    /// GQA/MQA: when < num_attention_heads, K/V heads are repeated.
    #[serde(default)]
    pub num_key_value_heads: Option<usize>,
    /// ALBERT: shared layer groups.
    #[serde(default)]
    pub num_hidden_groups: Option<usize>,
    /// ALBERT: factorized embedding dimension (< hidden_size).
    #[serde(default)]
    pub embedding_size: Option<usize>,
    /// Pre-LN vs Post-LN (auto-detected from architecture if not set).
    #[serde(default)]
    pub pre_ln: Option<bool>,
    /// RoPE base frequency (default 10000.0).
    #[serde(default = "default_rope_theta", alias = "rotary_emb_base")]
    pub rope_theta: f64,
    /// RMSNorm epsilon (used by LLaMA family, defaults to layer_norm_eps).
    #[serde(default)]
    pub rms_norm_eps: Option<f64>,
    /// T5 relative attention: number of buckets.
    #[serde(default = "default_t5_buckets")]
    pub relative_attention_num_buckets: usize,
    /// T5 relative attention: max distance.
    #[serde(default = "default_t5_max_distance")]
    pub relative_attention_max_distance: usize,
    /// DeBERTa: max relative positions.
    #[serde(default)]
    pub max_relative_positions: Option<usize>,
    /// EOS token for generation.
    #[serde(default)]
    pub eos_token_id: Option<u32>,
    /// Whether to tie word embeddings with LM head.
    #[serde(default = "default_true")]
    pub tie_word_embeddings: bool,
    /// The sequence length the model was actually *trained* on. Long-context
    /// RoPE models (e.g. nomic_bert / arctic-embed-m-long) advertise a much
    /// larger positional ceiling via `n_positions` (`max_position_embeddings`)
    /// that is reached only by RoPE extrapolation — quality degrades and cost
    /// grows O(seq²) past this point. When present we cap tokenization here so
    /// we never feed the model beyond its trained range.
    #[serde(default)]
    pub max_trained_positions: Option<usize>,
}

impl BertConfig {
    /// The maximum sequence length tokenization should produce. Prefer the
    /// model's trained range (`max_trained_positions`) over the advertised
    /// positional ceiling (`max_position_embeddings` / `n_positions`), which on
    /// long-context RoPE models overstates the usable window. Falls back to the
    /// positional ceiling when the config does not declare a trained range.
    pub fn effective_max_seq_len(&self) -> usize {
        self.max_trained_positions
            .filter(|trained| *trained > 0)
            .map(|trained| trained.min(self.max_position_embeddings))
            .unwrap_or(self.max_position_embeddings)
    }
}

fn default_eps() -> f64 {
    1e-12
}
fn default_feed_forward_type() -> String {
    "original".to_string()
}
fn default_rope_theta() -> f64 {
    10000.0
}
fn default_t5_buckets() -> usize {
    32
}
fn default_t5_max_distance() -> usize {
    128
}
fn default_true() -> bool {
    true
}

/// Whether the batched attention path passes Q/K/V to the accelerator in the
/// native position-major `[batch*seq, hidden]` layout, letting the backend do the
/// head-major reshape on-device instead of the host scattering `qf`/`kf`/`vf`
/// every layer. Sampled once per process.
///
/// Selected by the throughput resource profile; `KIN_INFER_RESHAPE_GPU=1/0`
/// overrides the profile in either direction. Off under proof, where the host
/// scatter reproduces the original layout byte-for-byte.
fn reshape_on_gpu() -> bool {
    use std::sync::OnceLock;
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        crate::resource::env_flag_override("KIN_INFER_RESHAPE_GPU")
            .unwrap_or_else(|| crate::resource::active_gpu_kernel_plan().reshape_gpu)
    })
}

#[cfg(test)]
thread_local! {
    static POOLED_OUTPUT_TEST_OVERRIDE: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn set_pooled_output_test_override(enabled: Option<bool>) {
    POOLED_OUTPUT_TEST_OVERRIDE.with(|override_value| override_value.set(enabled));
}

/// Whether the batched embed path may return pooled embeddings directly from the
/// accelerator instead of reading the full hidden matrix back to the host.
fn pooled_output_enabled() -> bool {
    #[cfg(test)]
    if let Some(enabled) = POOLED_OUTPUT_TEST_OVERRIDE.with(|override_value| override_value.get()) {
        return enabled;
    }

    use std::sync::OnceLock;
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        crate::resource::env_flag_override("KIN_INFER_POOLED_OUTPUT")
            .unwrap_or_else(|| crate::resource::active_gpu_kernel_plan().pooled_output)
    })
}

/// Length-bucketing gate for `forward_batched`. When ON, mixed-length batches are
/// split into coarse length bins so the projection/FFN GEMMs stop running short
/// sequences padded to the batch's global `max_len`; when OFF the default
/// single-encode path is byte-for-byte unchanged. Sampled once per process.
///
/// Opt-out (`KIN_INFER_BUCKET=0`): the bucketed path is bit-identical per
/// entity (see `forward_batched_bucketed`), keeping the OFF override as the
/// safe fallback — the pattern used for the MMA flip.
fn bucket_enabled() -> bool {
    use std::sync::OnceLock;
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        !matches!(
            std::env::var("KIN_INFER_BUCKET").ok().as_deref(),
            Some("0") | Some("false") | Some("no") | Some("off")
        )
    })
}

/// Diagnostic gate (`KIN_INFER_NO_FOLD`): when ON, the batched forward skips the
/// fused residency folds (`linear_add_norm`, `ffn_swiglu_add_norm`) and routes
/// the attention-output and FFN blocks through the same per-op
/// linear+add+norm / ffn+add+norm path the single-`forward` (batch=1) path uses.
/// Pure routing — the per-op branches are the existing fallbacks, so the result
/// is numerically the unfused computation. Default OFF leaves the folded path
/// byte-for-byte unchanged. Used to A/B whether the fused folds are the source of
/// the intermittent batched nondeterminism. Sampled once per process.
fn no_fold_enabled() -> bool {
    use std::sync::OnceLock;
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        matches!(
            std::env::var("KIN_INFER_NO_FOLD").ok().as_deref(),
            Some("1") | Some("true") | Some("yes") | Some("on")
        )
    })
}

/// Per-layer divergence trace gate (`KIN_INFER_DUMP_LAYER`). OFF by default — zero
/// effect on the runtime path. When set, both `forward` (batch=1) and
/// `encode_batched` print a stable fingerprint of one chosen entity's hidden state
/// after the embedding and after each transformer layer, so a single-forward
/// trajectory and a batched trajectory for the SAME tokens can be diffed
/// layer-by-layer to localize the first divergent op. Sampled once per process.
fn dump_layer_enabled() -> bool {
    use std::sync::OnceLock;
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| std::env::var_os("KIN_INFER_DUMP_LAYER").is_some())
}

/// Escape hatch (`KIN_INFER_NO_RESIDENT_STACK`): force `encode_batched` to run the
/// per-layer accelerator path instead of the whole-stack GPU-resident pass. Read
/// fresh each call so a single process can A/B the two paths bit-for-bit.
fn resident_stack_disabled() -> bool {
    std::env::var_os("KIN_INFER_NO_RESIDENT_STACK").is_some()
}

/// Which entity to trace for the per-layer dump (`KIN_INFER_DUMP_ENTITY`, default 0).
fn dump_entity_index() -> usize {
    use std::sync::OnceLock;
    static IDX: OnceLock<usize> = OnceLock::new();
    *IDX.get_or_init(|| {
        std::env::var("KIN_INFER_DUMP_ENTITY")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    })
}

/// Print an l2/sum/first4 fingerprint of `rows` (a flattened slice of one entity's
/// hidden state). Same format on both paths so single vs batched DUMP lines diff
/// cleanly. `layer` 0 = post-embedding, `1..=num_layers` = after each transformer
/// layer; `sub` is "embed", "attn" (post-attention output), or "ffn" (layer output).
fn dump_hidden(path: &str, layer: i32, sub: &str, rows: &[f32]) {
    let sum: f64 = rows.iter().map(|&x| x as f64).sum();
    let l2: f64 = rows
        .iter()
        .map(|&x| (x as f64) * (x as f64))
        .sum::<f64>()
        .sqrt();
    let g = |i: usize| rows.get(i).copied().unwrap_or(0.0);
    eprintln!(
        "DUMP path={path} layer={layer} sub={sub} rows={n} l2={l2:.6} sum={sum:.6} first4=[{:.5},{:.5},{:.5},{:.5}]",
        g(0), g(1), g(2), g(3), n = rows.len()
    );
}

/// Coarse length bin used to group inputs for length-bucketed batching: the
/// smallest standard cap that still fits `len`, or 2048 for anything longer. This
/// is only a grouping key — `encode_batched` still pads each group to its real
/// longest member, so the bin merely keeps near-length inputs together without
/// over-fragmenting the batch.
fn length_bin(len: usize) -> usize {
    const BINS: [usize; 5] = [64, 128, 256, 512, 1024];
    for &b in BINS.iter() {
        if len <= b {
            return b;
        }
    }
    2048
}

impl BertConfig {
    pub fn architecture(&self) -> ModelArchitecture {
        self.model_type
            .as_deref()
            .map(ModelArchitecture::from_model_type)
            .unwrap_or(ModelArchitecture::Unknown)
    }

    fn effective_pre_ln(&self) -> bool {
        self.pre_ln
            .unwrap_or_else(|| self.architecture().uses_pre_ln())
    }

    fn effective_num_kv_heads(&self) -> usize {
        self.num_key_value_heads.unwrap_or(self.num_attention_heads)
    }

    fn effective_rms_eps(&self) -> f32 {
        self.rms_norm_eps.unwrap_or(self.layer_norm_eps) as f32
    }

    fn uses_rmsnorm(&self) -> bool {
        self.architecture().uses_rmsnorm()
    }

    /// CLS pooling (take the first-token hidden state) vs mean pooling.
    /// Explicit `pooling_mode` wins; otherwise nomic_bert pools on CLS and the
    /// rest of the BERT family pools on the mean.
    fn uses_cls_pooling(&self) -> bool {
        match self.pooling_mode.as_deref() {
            Some(mode) => mode.eq_ignore_ascii_case("cls"),
            None => self.architecture() == ModelArchitecture::NomicBert,
        }
    }
}

// ---------------------------------------------------------------------------
// Weight storage
// ---------------------------------------------------------------------------

/// All weights for a single transformer layer.
struct TransformerLayerWeights {
    // Self-attention
    q_weight: Array2<f32>,
    q_bias: Option<Array1<f32>>,
    q_ln_weight: Option<Array1<f32>>,
    q_ln_bias: Option<Array1<f32>>,
    k_weight: Array2<f32>,
    k_bias: Option<Array1<f32>>,
    k_ln_weight: Option<Array1<f32>>,
    k_ln_bias: Option<Array1<f32>>,
    v_weight: Array2<f32>,
    v_bias: Option<Array1<f32>>,
    qkv_weight: Option<Array2<f32>>,
    qkv_bias: Option<Array1<f32>>,
    attn_out_weight: Array2<f32>,
    attn_out_bias: Option<Array1<f32>>,
    norm1_weight: Array1<f32>,
    norm1_bias: Option<Array1<f32>>,
    // FFN
    ffn_up_weight: Option<Array2<f32>>,
    ffn_up_bias: Option<Array1<f32>>,
    ffn_gate_weight: Option<Array2<f32>>,
    ffn_up_gated_weight: Option<Array2<f32>>,
    ffn_down_weight: Array2<f32>,
    ffn_down_bias: Option<Array1<f32>>,
    norm2_weight: Array1<f32>,
    norm2_bias: Option<Array1<f32>>,
    // T5 relative attention bias (layer 0 only, shared across heads)
    relative_attention_bias: Option<Array2<f32>>,
    // DeBERTa relative position embeddings
    rel_pos_embeddings: Option<Array2<f32>>,
}

/// Complete model weights.
pub struct ModelWeights {
    word_embeddings: Array2<f32>,
    position_embeddings: Option<Array2<f32>>,
    token_type_embeddings: Option<Array2<f32>>,
    embed_ln_weight: Option<Array1<f32>>,
    embed_ln_bias: Option<Array1<f32>>,
    /// ALBERT: project embedding_size -> hidden_size.
    embed_projection: Option<Array2<f32>>,
    layers: Vec<TransformerLayerWeights>,
    /// Final norm (decoder-only models apply norm after all layers).
    final_norm_weight: Option<Array1<f32>>,
    final_norm_bias: Option<Array1<f32>>,
    /// LM head for decoder-only generation (None = tied to word_embeddings).
    lm_head_weight: Option<Array2<f32>>,
    lm_head_bias: Option<Array1<f32>>,
    /// Classification head for cross-encoder models.
    classifier: Option<ClassifierHead>,
}

/// Cross-encoder classification head.
///
/// Two shapes occur in the wild and both must score correctly:
/// - `Linear` — a single `classifier.weight` `[num_labels, hidden]` (+ optional bias),
///   e.g. `BertForSequenceClassification` rerankers.
/// - `Roberta` — the two-layer `RobertaClassificationHead`: `dense` (`[hidden, hidden]`) →
///   `tanh` → `out_proj` (`[num_labels, hidden]`), e.g. `XLMRobertaForSequenceClassification`
///   (`BAAI/bge-reranker-base`).
enum ClassifierHead {
    Linear {
        weight: Array2<f32>,
        bias: Option<Array1<f32>>,
    },
    Roberta {
        dense_weight: Array2<f32>,
        dense_bias: Option<Array1<f32>>,
        out_proj_weight: Array2<f32>,
        out_proj_bias: Option<Array1<f32>>,
    },
}

/// The loaded, ready-to-run model.
pub struct BertModel {
    pub config: BertConfig,
    weights: ModelWeights,
    head_dim: usize,
    #[allow(dead_code)]
    kv_head_dim: usize,
    /// Precomputed RoPE sin/cos tables: [max_seq_len, head_dim].
    rope_cos: Option<Array2<f32>>,
    rope_sin: Option<Array2<f32>>,
    /// GPU compute backend (Metal/CUDA/CPU). Created lazily on first forward pass.
    gpu: Option<Box<dyn gpu::GpuCompute>>,
}

// ---------------------------------------------------------------------------
// KV cache for decoder-only generation
// ---------------------------------------------------------------------------

/// Per-layer key/value cache for autoregressive decoding.
pub struct KvCache {
    /// key[layer] = [cached_seq_len, kv_dim]
    pub key: Vec<Array2<f32>>,
    /// value[layer] = [cached_seq_len, kv_dim]
    pub value: Vec<Array2<f32>>,
}

impl KvCache {
    pub fn new(num_layers: usize, kv_dim: usize) -> Self {
        Self {
            key: (0..num_layers)
                .map(|_| Array2::<f32>::zeros((0, kv_dim)))
                .collect(),
            value: (0..num_layers)
                .map(|_| Array2::<f32>::zeros((0, kv_dim)))
                .collect(),
        }
    }

    fn append_kv(
        &mut self,
        layer: usize,
        new_k: &Array2<f32>,
        new_v: &Array2<f32>,
    ) -> Result<(Array2<f32>, Array2<f32>), InferError> {
        let k = if self.key[layer].nrows() == 0 {
            new_k.clone()
        } else {
            ndarray::concatenate(ndarray::Axis(0), &[self.key[layer].view(), new_k.view()])
                .map_err(|e| {
                    InferError::Internal(format!("kv-cache key concat (kv_dim mismatch): {e}"))
                })?
        };
        let v = if self.value[layer].nrows() == 0 {
            new_v.clone()
        } else {
            ndarray::concatenate(ndarray::Axis(0), &[self.value[layer].view(), new_v.view()])
                .map_err(|e| {
                    InferError::Internal(format!("kv-cache value concat (kv_dim mismatch): {e}"))
                })?
        };
        self.key[layer] = k.clone();
        self.value[layer] = v.clone();
        Ok((k, v))
    }
}

/// Sampling parameters for text generation.
pub struct SamplingParams {
    pub temperature: f32,
    pub top_k: usize,
    pub top_p: f32,
    pub repetition_penalty: f32,
    /// Xorshift64 RNG state for stochastic sampling. Mutated on each sample.
    /// Set to 0 for deterministic (argmax) behavior regardless of temperature.
    pub rng_state: u64,
}

impl Default for SamplingParams {
    fn default() -> Self {
        Self {
            temperature: 1.0,
            top_k: 50,
            top_p: 0.9,
            repetition_penalty: 1.0,
            rng_state: 0xdeadbeef_cafebabe,
        }
    }
}

impl SamplingParams {
    /// Advance the xorshift64 RNG and return a value in [0.0, 1.0).
    fn next_rand(&mut self) -> f64 {
        let mut s = self.rng_state;
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        self.rng_state = s;
        (s as f64) / (u64::MAX as f64)
    }
}

// ---------------------------------------------------------------------------
// Weight loading from safetensors
// ---------------------------------------------------------------------------

fn load_1d(tensors: &SafeTensors, name: &str, expected: usize) -> Result<Array1<f32>, InferError> {
    let view = tensors
        .tensor(name)
        .map_err(|e| InferError::ModelError(format!("missing tensor '{name}': {e}")))?;
    let floats = decode_tensor_to_f32(name, &view, expected)?;
    Ok(Array1::from(floats))
}

fn load_2d(
    tensors: &SafeTensors,
    name: &str,
    rows: usize,
    cols: usize,
) -> Result<Array2<f32>, InferError> {
    let view = tensors
        .tensor(name)
        .map_err(|e| InferError::ModelError(format!("missing tensor '{name}': {e}")))?;
    let floats = decode_tensor_to_f32(name, &view, rows * cols)?;
    Array2::from_shape_vec((rows, cols), floats).map_err(|e| {
        InferError::ModelIncompatible(format!(
            "tensor '{name}': cannot reshape to {rows}x{cols}: {e}"
        ))
    })
}

fn decode_tensor_to_f32(
    name: &str,
    view: &safetensors::tensor::TensorView<'_>,
    expected_values: usize,
) -> Result<Vec<f32>, InferError> {
    let data = view.data();
    match view.dtype() {
        Dtype::F32 => {
            let expected_bytes = expected_values * 4;
            if data.len() != expected_bytes {
                return Err(InferError::ModelError(format!(
                    "tensor '{name}': expected {expected_bytes} bytes, got {}",
                    data.len()
                )));
            }
            Ok(data
                .chunks_exact(4)
                .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
                .collect())
        }
        Dtype::F16 => {
            let expected_bytes = expected_values * 2;
            if data.len() != expected_bytes {
                return Err(InferError::ModelError(format!(
                    "tensor '{name}': expected {expected_bytes} bytes, got {}",
                    data.len()
                )));
            }
            Ok(data
                .chunks_exact(2)
                .map(|c| f16::from_bits(u16::from_le_bytes([c[0], c[1]])).to_f32())
                .collect())
        }
        Dtype::BF16 => {
            let expected_bytes = expected_values * 2;
            if data.len() != expected_bytes {
                return Err(InferError::ModelError(format!(
                    "tensor '{name}': expected {expected_bytes} bytes, got {}",
                    data.len()
                )));
            }
            Ok(data
                .chunks_exact(2)
                .map(|c| bf16::from_bits(u16::from_le_bytes([c[0], c[1]])).to_f32())
                .collect())
        }
        Dtype::I8 => {
            if data.len() != expected_values {
                return Err(InferError::ModelError(format!(
                    "tensor '{name}': expected {expected_values} bytes for I8, got {}",
                    data.len()
                )));
            }
            Ok(data.iter().map(|&b| b as i8 as f32).collect())
        }
        other => Err(InferError::ModelError(format!(
            "tensor '{name}': unsupported dtype {other:?}"
        ))),
    }
}

/// Q8_0 dequantization: 32 values per block, 1 f16 scale + 32 i8 quants.
pub fn dequantize_q8_block(block: &[u8]) -> [f32; 32] {
    debug_assert!(block.len() >= 34);
    let scale = f16::from_bits(u16::from_le_bytes([block[0], block[1]])).to_f32();
    let mut out = [0.0f32; 32];
    for i in 0..32 {
        out[i] = block[2 + i] as i8 as f32 * scale;
    }
    out
}

/// Q4_0 dequantization: 32 values per block, 1 f16 scale + 16 bytes (2 nibbles each).
pub fn dequantize_q4_block(block: &[u8]) -> [f32; 32] {
    debug_assert!(block.len() >= 18);
    let scale = f16::from_bits(u16::from_le_bytes([block[0], block[1]])).to_f32();
    let mut out = [0.0f32; 32];
    for i in 0..16 {
        let byte = block[2 + i];
        let lo = (byte & 0x0F) as i8 - 8;
        let hi = ((byte >> 4) & 0x0F) as i8 - 8;
        out[i * 2] = lo as f32 * scale;
        out[i * 2 + 1] = hi as f32 * scale;
    }
    out
}

/// Try multiple naming conventions for a safetensors key.
fn resolve_name(tensors: &SafeTensors, candidates: &[String]) -> Result<String, InferError> {
    for name in candidates {
        if tensors.tensor(name).is_ok() {
            return Ok(name.clone());
        }
    }
    Err(InferError::ModelError(format!(
        "none of these tensor names found: {:?}",
        candidates
    )))
}

fn candidates(suffixes: &[&str]) -> Vec<String> {
    let prefixes = [
        "",
        "bert.",
        "model.",
        "roberta.",
        "transformer.",
        "deberta.",
    ];
    let mut out = Vec::new();
    for pfx in &prefixes {
        for sfx in suffixes {
            out.push(format!("{pfx}{sfx}"));
        }
    }
    out
}

fn load_1d_flexible(
    tensors: &SafeTensors,
    suffixes: &[&str],
    expected: usize,
) -> Result<Array1<f32>, InferError> {
    let name = resolve_name(tensors, &candidates(suffixes))?;
    load_1d(tensors, &name, expected)
}

fn load_2d_flexible(
    tensors: &SafeTensors,
    suffixes: &[&str],
    rows: usize,
    cols: usize,
) -> Result<Array2<f32>, InferError> {
    let name = resolve_name(tensors, &candidates(suffixes))?;
    load_2d(tensors, &name, rows, cols)
}

fn try_load_1d_flexible(
    tensors: &SafeTensors,
    suffixes: &[&str],
    expected: usize,
) -> Result<Option<Array1<f32>>, InferError> {
    match resolve_name(tensors, &candidates(suffixes)) {
        Ok(name) => load_1d(tensors, &name, expected).map(Some),
        Err(_) => Ok(None),
    }
}

fn try_load_2d_flexible(
    tensors: &SafeTensors,
    suffixes: &[&str],
    rows: usize,
    cols: usize,
) -> Result<Option<Array2<f32>>, InferError> {
    match resolve_name(tensors, &candidates(suffixes)) {
        Ok(name) => load_2d(tensors, &name, rows, cols).map(Some),
        Err(_) => Ok(None),
    }
}

/// Load the cross-encoder classification head, if present.
///
/// Prefers the two-layer `RobertaClassificationHead` (`classifier.dense` → tanh →
/// `classifier.out_proj`) when its tensors exist; otherwise falls back to a single
/// linear head (`classifier.weight`/`score.weight`). Returns `None` for models with
/// no head (plain encoders). Rerankers are single-label, so the output projection is
/// loaded as `[1, hidden]`.
fn load_classifier_head(
    tensors: &SafeTensors,
    h: usize,
) -> Result<Option<ClassifierHead>, InferError> {
    if let Some(dense_weight) = try_load_2d_flexible(tensors, &["classifier.dense.weight"], h, h)? {
        let dense_bias = try_load_1d_flexible(tensors, &["classifier.dense.bias"], h)?;
        let out_proj_weight = load_2d_flexible(tensors, &["classifier.out_proj.weight"], 1, h)?;
        let out_proj_bias = try_load_1d_flexible(tensors, &["classifier.out_proj.bias"], 1)?;
        return Ok(Some(ClassifierHead::Roberta {
            dense_weight,
            dense_bias,
            out_proj_weight,
            out_proj_bias,
        }));
    }
    if let Some(weight) =
        try_load_2d_flexible(tensors, &["classifier.weight", "score.weight"], 1, h)?
    {
        let bias = try_load_1d_flexible(tensors, &["classifier.bias", "score.bias"], 1)?;
        return Ok(Some(ClassifierHead::Linear { weight, bias }));
    }
    Ok(None)
}

/// Memory-maps a safetensors file for zero-copy deserialization.
///
/// The mapping exposes the same bytes as reading the file into a `Vec<u8>`, so
/// parsed tensors and downstream embeddings are unchanged; it only avoids the
/// up-front heap copy of the full weight file.
fn load_safetensors_mmap(weights_path: &Path) -> Result<memmap2::Mmap, InferError> {
    let file = std::fs::File::open(weights_path)
        .map_err(|e| InferError::ModelError(format!("failed to open weights: {e}")))?;
    unsafe {
        memmap2::MmapOptions::new()
            .map(&file)
            .map_err(|e| InferError::ModelError(format!("failed to mmap weights: {e}")))
    }
}

/// Load sharded safetensors: reads index.json, merges all shards into one
/// `HashMap<tensor_name, (shard_data, offset, length)>` view.
pub fn load_sharded_index(index_path: &Path) -> Result<HashMap<String, String>, InferError> {
    let data = std::fs::read_to_string(index_path)
        .map_err(|e| InferError::ModelError(format!("failed to read shard index: {e}")))?;
    let parsed: serde_json::Value = serde_json::from_str(&data)
        .map_err(|e| InferError::ModelError(format!("failed to parse shard index: {e}")))?;
    let weight_map = parsed
        .get("weight_map")
        .and_then(|v| v.as_object())
        .ok_or_else(|| InferError::ModelError("shard index missing weight_map".into()))?;
    let mut map = HashMap::new();
    for (tensor_name, file_val) in weight_map {
        if let Some(file) = file_val.as_str() {
            map.insert(tensor_name.clone(), file.to_string());
        }
    }
    Ok(map)
}

// ---------------------------------------------------------------------------
// Model loading
// ---------------------------------------------------------------------------

impl BertModel {
    /// Load a model from a safetensors file + config.
    pub fn load(weights_path: &Path, config: BertConfig) -> Result<Self, InferError> {
        let _span = tracing::info_span!(
            "kin_infer.model.load",
            weights_path = %weights_path.display(),
            hidden_size = config.hidden_size,
            layers = config.num_hidden_layers,
            heads = config.num_attention_heads,
            architecture = ?config.architecture()
        )
        .entered();
        let mmap = load_safetensors_mmap(weights_path)?;
        let tensors = SafeTensors::deserialize(&mmap)
            .map_err(|e| InferError::ModelError(format!("failed to parse safetensors: {e}")))?;
        Self::load_from_tensors(&tensors, config)
    }

    fn load_from_tensors(
        tensors: &SafeTensors,
        mut config: BertConfig,
    ) -> Result<Self, InferError> {
        let _names: Vec<_> = tensors.names().into_iter().collect();

        // GPT-style configs (nomic_bert) name the FFN activation via
        // `activation_function`; fold it into `feed_forward_type` so the gated
        // SwiGLU/GeGLU path engages. Only override the BERT default ("original").
        if config.feed_forward_type == default_feed_forward_type() {
            if let Some(act) = config.activation_function.as_deref() {
                config.feed_forward_type = act.to_string();
            }
        }
        let arch = config.architecture();

        let h = config.hidden_size;
        let inter = config.intermediate_size;
        let vocab = config.vocab_size;
        let max_pos = config.max_position_embeddings;
        let type_vocab = config.type_vocab_size.unwrap_or(2);
        let embed_dim = config.embedding_size.unwrap_or(h);
        let num_kv_heads = config.effective_num_kv_heads();
        let kv_dim = num_kv_heads * (h / config.num_attention_heads);

        // Embedding tables
        let word_embeddings = load_2d_flexible(
            tensors,
            &["embeddings.word_embeddings.weight", "embed_tokens.weight"],
            vocab,
            embed_dim,
        )?;

        let skip_pos =
            config.position_embedding_type.as_deref() == Some("alibi") || arch.uses_rope();
        let position_embeddings = if skip_pos {
            None
        } else {
            try_load_2d_flexible(
                tensors,
                &[
                    "embeddings.position_embeddings.weight",
                    "embed_positions.weight",
                ],
                max_pos,
                embed_dim,
            )?
        };

        let token_type_embeddings = try_load_2d_flexible(
            tensors,
            &["embeddings.token_type_embeddings.weight"],
            type_vocab,
            embed_dim,
        )?;

        let embed_ln_weight = try_load_1d_flexible(
            tensors,
            &["embeddings.LayerNorm.weight", "emb_ln.weight"],
            h,
        )?;
        let embed_ln_bias =
            try_load_1d_flexible(tensors, &["embeddings.LayerNorm.bias", "emb_ln.bias"], h)?;

        // ALBERT: factorized embedding projection
        let embed_projection = if embed_dim != h {
            Some(load_2d_flexible(
                tensors,
                &[
                    "encoder.embedding_hidden_mapping_in.weight",
                    "embeddings.projection.weight",
                ],
                h,
                embed_dim,
            )?)
        } else {
            None
        };

        // Determine unique layer count (ALBERT shares layers)
        let num_groups = config.num_hidden_groups.unwrap_or(config.num_hidden_layers);
        let unique_layers = num_groups.min(config.num_hidden_layers);

        let mut layers = Vec::with_capacity(unique_layers);
        for i in 0..unique_layers {
            let lp = format!("encoder.layer.{i}");
            let lp_dec = format!("layers.{i}");
            let lp_nomic = format!("encoder.layers.{i}");

            // nomic_bert packs Q|K|V into one fused `attn.Wqkv.weight` [h+2*kv_dim, h]
            // (rows: 0..h = Q, h..h+kv_dim = K, h+kv_dim.. = V), with no biases.
            // When present, slice each projection out of it; otherwise fall back to
            // the per-projection tensors below.
            let fused_wqkv = try_load_2d_flexible(
                tensors,
                &[&format!("{lp_nomic}.attn.Wqkv.weight")],
                h + 2 * kv_dim,
                h,
            )?;

            let q_weight = if let Some(ref wqkv) = fused_wqkv {
                wqkv.slice(s![0..h, ..]).to_owned()
            } else {
                load_2d_flexible(
                    tensors,
                    &[
                        &format!("{lp}.attention.self.query.weight"),
                        &format!("{lp_dec}.self_attn.q_proj.weight"),
                    ],
                    h,
                    h,
                )?
            };
            let q_bias = try_load_1d_flexible(
                tensors,
                &[
                    &format!("{lp}.attention.self.query.bias"),
                    &format!("{lp_dec}.self_attn.q_proj.bias"),
                ],
                h,
            )?;
            let q_ln_weight = try_load_1d_flexible(
                tensors,
                &[&format!("{lp}.attention.self.layer_norm_q.weight")],
                h,
            )?;
            let q_ln_bias = try_load_1d_flexible(
                tensors,
                &[&format!("{lp}.attention.self.layer_norm_q.bias")],
                h,
            )?;
            let k_weight = if let Some(ref wqkv) = fused_wqkv {
                wqkv.slice(s![h..h + kv_dim, ..]).to_owned()
            } else {
                load_2d_flexible(
                    tensors,
                    &[
                        &format!("{lp}.attention.self.key.weight"),
                        &format!("{lp_dec}.self_attn.k_proj.weight"),
                    ],
                    kv_dim,
                    h,
                )?
            };
            let k_bias = try_load_1d_flexible(
                tensors,
                &[
                    &format!("{lp}.attention.self.key.bias"),
                    &format!("{lp_dec}.self_attn.k_proj.bias"),
                ],
                kv_dim,
            )?;
            let k_ln_weight = try_load_1d_flexible(
                tensors,
                &[&format!("{lp}.attention.self.layer_norm_k.weight")],
                h,
            )?;
            let k_ln_bias = try_load_1d_flexible(
                tensors,
                &[&format!("{lp}.attention.self.layer_norm_k.bias")],
                h,
            )?;
            let v_weight = if let Some(ref wqkv) = fused_wqkv {
                wqkv.slice(s![h + kv_dim..h + 2 * kv_dim, ..]).to_owned()
            } else {
                load_2d_flexible(
                    tensors,
                    &[
                        &format!("{lp}.attention.self.value.weight"),
                        &format!("{lp_dec}.self_attn.v_proj.weight"),
                    ],
                    kv_dim,
                    h,
                )?
            };
            let v_bias = try_load_1d_flexible(
                tensors,
                &[
                    &format!("{lp}.attention.self.value.bias"),
                    &format!("{lp_dec}.self_attn.v_proj.bias"),
                ],
                kv_dim,
            )?;
            let (qkv_weight, qkv_bias) = build_fused_projection(
                [&q_weight, &k_weight, &v_weight],
                [q_bias.as_ref(), k_bias.as_ref(), v_bias.as_ref()],
            );
            let attn_out_weight = load_2d_flexible(
                tensors,
                &[
                    &format!("{lp}.attention.output.dense.weight"),
                    &format!("{lp_dec}.self_attn.o_proj.weight"),
                    &format!("{lp_nomic}.attn.out_proj.weight"),
                ],
                h,
                h,
            )?;
            let attn_out_bias = try_load_1d_flexible(
                tensors,
                &[
                    &format!("{lp}.attention.output.dense.bias"),
                    &format!("{lp_dec}.self_attn.o_proj.bias"),
                ],
                h,
            )?;
            let norm1_weight = load_1d_flexible(
                tensors,
                &[
                    &format!("{lp}.layer_norm_1.weight"),
                    &format!("{lp}.attention.output.LayerNorm.weight"),
                    &format!("{lp_dec}.input_layernorm.weight"),
                    &format!("{lp_nomic}.norm1.weight"),
                ],
                h,
            )?;
            let norm1_bias = try_load_1d_flexible(
                tensors,
                &[
                    &format!("{lp}.layer_norm_1.bias"),
                    &format!("{lp}.attention.output.LayerNorm.bias"),
                    &format!("{lp_dec}.input_layernorm.bias"),
                    &format!("{lp_nomic}.norm1.bias"),
                ],
                h,
            )?;

            // FFN weights — detect gated vs standard. nomic_bert's gated MLP is
            // `fc11(x) * silu(fc12(x))`, so fc12 is the activated gate and fc11 is
            // the linear up-projection — the opposite of Llama's gate_proj/up_proj
            // naming. Map fc12 → gate (silu) and fc11 → up below.
            let is_glu = config.feed_forward_type.ends_with("glu");
            let ffn_gate_weight = try_load_2d_flexible(
                tensors,
                &[
                    &format!("{lp_dec}.mlp.gate_proj.weight"),
                    &format!("{lp_nomic}.mlp.fc12.weight"),
                ],
                inter,
                h,
            )?;
            let ffn_up_gated_weight = if is_glu && ffn_gate_weight.is_none() {
                try_load_2d_flexible(
                    tensors,
                    &[&format!("{lp}.mlp.up_gated_layer.weight")],
                    inter * 2,
                    h,
                )?
            } else {
                None
            };
            let ffn_up_weight = if ffn_gate_weight.is_none() && ffn_up_gated_weight.is_none() {
                Some(load_2d_flexible(
                    tensors,
                    &[
                        &format!("{lp}.mlp.up_layer.weight"),
                        &format!("{lp}.intermediate.dense.weight"),
                        &format!("{lp_dec}.mlp.up_proj.weight"),
                    ],
                    inter,
                    h,
                )?)
            } else if ffn_gate_weight.is_some() {
                // SwiGLU models have a separate up_proj (nomic_bert: mlp.fc11, the
                // un-activated linear path).
                try_load_2d_flexible(
                    tensors,
                    &[
                        &format!("{lp_dec}.mlp.up_proj.weight"),
                        &format!("{lp_nomic}.mlp.fc11.weight"),
                    ],
                    inter,
                    h,
                )?
            } else {
                None
            };
            let ffn_up_bias = try_load_1d_flexible(
                tensors,
                &[
                    &format!("{lp}.mlp.up_layer.bias"),
                    &format!("{lp}.intermediate.dense.bias"),
                ],
                inter,
            )?;
            let ffn_down_weight = load_2d_flexible(
                tensors,
                &[
                    &format!("{lp}.mlp.down_layer.weight"),
                    &format!("{lp}.output.dense.weight"),
                    &format!("{lp_dec}.mlp.down_proj.weight"),
                    &format!("{lp_nomic}.mlp.fc2.weight"),
                ],
                h,
                inter,
            )?;
            let ffn_down_bias = try_load_1d_flexible(
                tensors,
                &[
                    &format!("{lp}.mlp.down_layer.bias"),
                    &format!("{lp}.output.dense.bias"),
                ],
                h,
            )?;
            let norm2_weight = load_1d_flexible(
                tensors,
                &[
                    &format!("{lp}.layer_norm_2.weight"),
                    &format!("{lp}.output.LayerNorm.weight"),
                    &format!("{lp_dec}.post_attention_layernorm.weight"),
                    &format!("{lp_nomic}.norm2.weight"),
                ],
                h,
            )?;
            let norm2_bias = try_load_1d_flexible(
                tensors,
                &[
                    &format!("{lp}.layer_norm_2.bias"),
                    &format!("{lp}.output.LayerNorm.bias"),
                    &format!("{lp_dec}.post_attention_layernorm.bias"),
                    &format!("{lp_nomic}.norm2.bias"),
                ],
                h,
            )?;

            // T5 relative attention bias (first layer only)
            let relative_attention_bias = if i == 0 && arch == ModelArchitecture::T5Encoder {
                let n_buckets = config.relative_attention_num_buckets;
                let n_heads = config.num_attention_heads;
                try_load_2d_flexible(
                    tensors,
                    &["encoder.block.0.layer.0.SelfAttention.relative_attention_bias.weight"],
                    n_buckets,
                    n_heads,
                )?
            } else {
                None
            };

            // DeBERTa relative position embeddings
            let rel_pos_embeddings = if arch == ModelArchitecture::Deberta {
                let max_rel = config.max_relative_positions.unwrap_or(512) * 2;
                try_load_2d_flexible(
                    tensors,
                    &[
                        "deberta.embeddings.rel_embeddings.weight",
                        "encoder.rel_embeddings.weight",
                    ],
                    max_rel,
                    h,
                )?
            } else {
                None
            };

            layers.push(TransformerLayerWeights {
                q_weight,
                q_bias,
                q_ln_weight,
                q_ln_bias,
                k_weight,
                k_bias,
                k_ln_weight,
                k_ln_bias,
                v_weight,
                v_bias,
                qkv_weight,
                qkv_bias,
                attn_out_weight,
                attn_out_bias,
                norm1_weight,
                norm1_bias,
                ffn_up_weight,
                ffn_up_bias,
                ffn_gate_weight,
                ffn_up_gated_weight,
                ffn_down_weight,
                ffn_down_bias,
                norm2_weight,
                norm2_bias,
                relative_attention_bias,
                rel_pos_embeddings,
            });
        }

        // Final norm (decoder-only)
        let final_norm_weight = try_load_1d_flexible(
            tensors,
            &["norm.weight", "model.norm.weight", "ln_f.weight"],
            h,
        )?;
        let final_norm_bias =
            try_load_1d_flexible(tensors, &["norm.bias", "model.norm.bias", "ln_f.bias"], h)?;

        // LM head
        let lm_head_weight = try_load_2d_flexible(tensors, &["lm_head.weight"], vocab, h)?;
        let lm_head_bias = try_load_1d_flexible(tensors, &["lm_head.bias"], vocab)?;

        // Classification head (for cross-encoders)
        let classifier = load_classifier_head(tensors, h)?;

        let head_dim = h / config.num_attention_heads;
        let kv_head_dim = h / config.num_attention_heads;

        // Precompute RoPE tables
        let (rope_cos, rope_sin) = if arch.uses_rope() {
            let (c, s) = precompute_rope(max_pos, head_dim, config.rope_theta);
            (Some(c), Some(s))
        } else {
            (None, None)
        };

        // Auto-detect best GPU backend (Metal > CUDA > CPU)
        let gpu_compute = gpu::create_compute();

        Ok(Self {
            weights: ModelWeights {
                word_embeddings,
                position_embeddings,
                token_type_embeddings,
                embed_ln_weight,
                embed_ln_bias,
                embed_projection,
                layers,
                final_norm_weight,
                final_norm_bias,
                lm_head_weight,
                lm_head_bias,
                classifier,
            },
            head_dim,
            kv_head_dim,
            rope_cos,
            rope_sin,
            config,
            gpu: Some(gpu_compute),
        })
    }

    fn has_accelerator_backend(&self) -> bool {
        self.gpu
            .as_ref()
            .is_some_and(|compute| compute.backend() != gpu::GpuBackend::Cpu)
    }

    pub fn uses_accelerator(&self) -> bool {
        self.has_accelerator_backend()
    }

    pub fn backend(&self) -> gpu::GpuBackend {
        self.gpu
            .as_ref()
            .map(|compute| compute.backend())
            .unwrap_or(gpu::GpuBackend::Cpu)
    }

    // -----------------------------------------------------------------------
    // Encoder forward pass (embedding generation)
    // -----------------------------------------------------------------------

    pub fn forward(
        &self,
        token_ids: &[Vec<u32>],
        attention_masks: &[Vec<u32>],
    ) -> Result<Vec<Vec<f32>>, InferError> {
        let batch_size = token_ids.len();
        let max_seq_len = token_ids.iter().map(|ids| ids.len()).max().unwrap_or(0);
        let _span = tracing::info_span!(
            "kin_infer.model.forward",
            batch_size = batch_size,
            max_seq_len = max_seq_len,
            hidden_size = self.config.hidden_size,
            backend = %self.backend()
        )
        .entered();
        let mut results = Vec::with_capacity(batch_size);
        #[cfg(all(feature = "metal", target_os = "macos"))]
        crate::metal_backend::record_forward_calls(batch_size);

        for b in 0..batch_size {
            let ids = &token_ids[b];
            let mask = &attention_masks[b];
            let seq_len = ids.len();
            let h = self.config.hidden_size;
            let embed_dim = self.config.embedding_size.unwrap_or(h);
            let _batch_span = tracing::info_span!(
                "kin_infer.model.forward.batch",
                batch_index = b,
                seq_len = seq_len
            )
            .entered();

            // 1. Embedding lookup
            let _embed_span =
                tracing::info_span!("kin_infer.model.forward.embedding_lookup").entered();
            let mut hidden = Array2::<f32>::zeros((seq_len, embed_dim));
            for (pos, &id) in ids.iter().enumerate() {
                let word = self.weights.word_embeddings.row(id as usize);
                for j in 0..embed_dim {
                    let mut val = word[j];
                    if let Some(ref tte) = self.weights.token_type_embeddings {
                        val += tte[[0, j]];
                    }
                    if let Some(ref pe) = self.weights.position_embeddings {
                        if pos < pe.nrows() {
                            val += pe[[pos, j]];
                        }
                    }
                    hidden[[pos, j]] = val;
                }
            }

            // ALBERT: project up from embedding_size to hidden_size
            if let Some(ref proj) = self.weights.embed_projection {
                let _project_span = tracing::info_span!(
                    "kin_infer.model.forward.embedding_projection",
                    rows = seq_len,
                    cols = embed_dim
                )
                .entered();
                hidden = self.linear(&hidden, proj, None)?;
            }

            // 2. Embedding LayerNorm
            let _embed_norm_span =
                tracing::info_span!("kin_infer.model.forward.embedding_norm").entered();
            self.optional_layer_norm(
                &mut hidden,
                self.weights.embed_ln_weight.as_ref(),
                self.weights.embed_ln_bias.as_ref(),
                self.config.layer_norm_eps as f32,
            )?;

            if dump_layer_enabled() && b == dump_entity_index() {
                dump_hidden("single", 0, "embed", hidden.as_slice().unwrap_or(&[]));
            }

            // 3. Transformer layers (ALBERT: reuse layers[i % num_groups]).
            // Each Metal op drains its own autoreleased command buffer/encoders
            // (see the per-op `autoreleasepool` wraps in metal_backend.rs), so no
            // ObjC temporaries survive a forward even on a pool-less worker thread.
            let num_groups = self.weights.layers.len();
            for i in 0..self.config.num_hidden_layers {
                let layer = &self.weights.layers[i % num_groups];
                hidden = self.encoder_layer(&hidden, mask, layer, i)?;
                if dump_layer_enabled() && b == dump_entity_index() {
                    dump_hidden(
                        "single",
                        (i + 1) as i32,
                        "ffn",
                        hidden.as_slice().unwrap_or(&[]),
                    );
                }
            }

            // 4. Pooling (CLS or mean) + L2 normalize
            let _pool_span =
                tracing::info_span!("kin_infer.model.forward.pool_and_normalize").entered();
            let pooled = if self.config.uses_cls_pooling() {
                cls_pool(&hidden)
            } else {
                mean_pool(&hidden, mask)
            };
            let normalized = l2_normalize(&pooled);
            results.push(normalized.to_vec());
        }

        ensure_finite_embeddings(&results)?;
        Ok(results)
    }

    /// Borrow one layer's weight slices as the backend `LayerTensors` view. Shared
    /// by the per-layer accelerator path and the whole-stack resident pass so both
    /// hand the backend an identical tensor set.
    fn layer_tensors<'a>(
        &self,
        layer: &'a TransformerLayerWeights,
    ) -> crate::gpu::LayerTensors<'a> {
        crate::gpu::LayerTensors {
            norm1_weight: layer
                .norm1_weight
                .as_slice()
                .expect("loaded weight is std-layout contiguous"),
            norm1_bias: layer.norm1_bias.as_ref().and_then(|x| x.as_slice()),

            qkv_weight: layer.qkv_weight.as_ref().and_then(|x| x.as_slice()),
            qkv_bias: layer.qkv_bias.as_ref().and_then(|x| x.as_slice()),
            q_weight: layer.q_weight.as_slice(),
            q_bias: layer.q_bias.as_ref().and_then(|x| x.as_slice()),
            k_weight: layer.k_weight.as_slice(),
            k_bias: layer.k_bias.as_ref().and_then(|x| x.as_slice()),
            v_weight: layer.v_weight.as_slice(),
            v_bias: layer.v_bias.as_ref().and_then(|x| x.as_slice()),
            q_ln_weight: layer.q_ln_weight.as_ref().and_then(|x| x.as_slice()),
            q_ln_bias: layer.q_ln_bias.as_ref().and_then(|x| x.as_slice()),
            k_ln_weight: layer.k_ln_weight.as_ref().and_then(|x| x.as_slice()),
            k_ln_bias: layer.k_ln_bias.as_ref().and_then(|x| x.as_slice()),

            attn_out_weight: layer
                .attn_out_weight
                .as_slice()
                .expect("loaded weight is std-layout contiguous"),
            attn_out_bias: layer.attn_out_bias.as_ref().and_then(|x| x.as_slice()),

            norm2_weight: layer
                .norm2_weight
                .as_slice()
                .expect("loaded weight is std-layout contiguous"),
            norm2_bias: layer.norm2_bias.as_ref().and_then(|x| x.as_slice()),

            ffn_gate_weight: layer.ffn_gate_weight.as_ref().and_then(|x| x.as_slice()),
            ffn_up_weight: layer.ffn_up_weight.as_ref().and_then(|x| x.as_slice()),
            ffn_up_bias: layer.ffn_up_bias.as_ref().and_then(|x| x.as_slice()),
            ffn_down_weight: layer
                .ffn_down_weight
                .as_slice()
                .expect("loaded weight is std-layout contiguous"),
            ffn_down_bias: layer.ffn_down_bias.as_ref().and_then(|x| x.as_slice()),
            ffn_up_gated_weight: layer
                .ffn_up_gated_weight
                .as_ref()
                .and_then(|x| x.as_slice()),

            relative_attention_bias: layer
                .relative_attention_bias
                .as_ref()
                .and_then(|x| x.as_slice()),
            rel_pos_embeddings: layer.rel_pos_embeddings.as_ref().and_then(|x| x.as_slice()),
        }
    }

    /// Batched forward pass: all inputs processed together for projections/FFN,
    /// split only for per-input attention. Reduces GPU dispatches by batch_size×.
    ///
    /// Length-bucketing (gated by `bucket_enabled()` / `KIN_INFER_BUCKET`): when the
    /// batch spans more than one coarse length bin, inputs are partitioned by bin and
    /// encoded per group, so each group pads only to its own max length. Outputs are
    /// reassembled in input order with a global-max-len row stride. Single-bin batches
    /// use the legacy path unchanged.
    ///
    /// **Trap**: the bucketing gate must fire before the global `max_len` allocation
    /// (`[batch_size * max_len, hidden_size]`). Allocating that buffer first — then
    /// bucketing — produces no benefit and was the defect this path guards against.
    /// Keep the `bucket_enabled()` check above the `max_len` computation.
    // Multi-output tensor op (inline tuple clearer than an alias) with flat-offset index loops over ndarray rows.
    #[allow(clippy::type_complexity, clippy::needless_range_loop)]
    pub fn encode_batched(
        &self,
        token_ids: &[Vec<u32>],
        attention_masks: &[Vec<u32>],
    ) -> Result<(Array2<f32>, Vec<Vec<u8>>, usize), InferError> {
        let batch_size = token_ids.len();
        if batch_size == 0 {
            return Ok((
                ndarray::Array2::zeros((0, self.config.hidden_size)),
                vec![],
                0,
            ));
        }

        // Length-bucketing gate — must precede the global max_len allocation below.
        // See the doc-comment trap note above.
        if bucket_enabled() {
            use std::collections::BTreeMap;
            let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
            for (idx, ids) in token_ids.iter().enumerate() {
                groups.entry(length_bin(ids.len())).or_default().push(idx);
            }
            if groups.len() > 1 {
                let h = self.config.hidden_size;
                let global_max_len = token_ids.iter().map(|t| t.len()).max().unwrap_or(0);
                let bucket_count = groups.len();
                let _span = tracing::info_span!(
                    "kin_infer.model.encode_batched",
                    batch_size,
                    max_seq_len = global_max_len,
                    hidden_size = h,
                    backend = %self.backend(),
                    bucket_count,
                )
                .entered();
                let mut out_hidden = Array2::<f32>::zeros((batch_size * global_max_len, h));
                let mut out_masks: Vec<Vec<u8>> = vec![vec![0u8; global_max_len]; batch_size];
                for indices in groups.values() {
                    let sub_ids: Vec<Vec<u32>> =
                        indices.iter().map(|&i| token_ids[i].clone()).collect();
                    let sub_mask_in: Vec<Vec<u32>> = indices
                        .iter()
                        .map(|&i| attention_masks[i].clone())
                        .collect();
                    let (sub_hidden, sub_masks_out, sub_max_len) =
                        self.encode_batched(&sub_ids, &sub_mask_in)?;
                    for (slot, &orig) in indices.iter().enumerate() {
                        let src = slot * sub_max_len;
                        let dst = orig * global_max_len;
                        out_hidden
                            .slice_mut(s![dst..dst + sub_max_len, ..])
                            .assign(&sub_hidden.slice(s![src..src + sub_max_len, ..]));
                        out_masks[orig][..sub_max_len].copy_from_slice(&sub_masks_out[slot]);
                    }
                }
                return Ok((out_hidden, out_masks, global_max_len));
            }
        }

        let h = self.config.hidden_size;
        let embed_dim = self.config.embedding_size.unwrap_or(h);
        let max_len = token_ids.iter().map(|t| t.len()).max().unwrap_or(0);
        let _span = tracing::info_span!(
            "kin_infer.model.encode_batched",
            batch_size = batch_size,
            max_seq_len = max_len,
            hidden_size = h,
            backend = %self.backend(),
            bucket_count = 1_usize,
        )
        .entered();

        // 1. Batched embedding: [batch_size * max_len, embed_dim]
        let total_rows = batch_size * max_len;
        let _embed_span = tracing::info_span!(
            "kin_infer.model.encode_batched.embedding_lookup",
            total_rows = total_rows,
            embed_dim = embed_dim
        )
        .entered();
        let mut hidden = Array2::<f32>::zeros((total_rows, embed_dim));
        // Also build per-input masks (padded to max_len)
        let mut masks: Vec<Vec<u8>> = Vec::with_capacity(batch_size);

        for b in 0..batch_size {
            let ids = &token_ids[b];
            let mask_in = &attention_masks[b];
            let base = b * max_len;

            let mut padded_mask = vec![0u8; max_len];
            for (pos, &id) in ids.iter().enumerate() {
                let word = self.weights.word_embeddings.row(id as usize);
                for j in 0..embed_dim {
                    let mut val = word[j];
                    if let Some(ref tte) = self.weights.token_type_embeddings {
                        val += tte[[0, j]];
                    }
                    if let Some(ref pe) = self.weights.position_embeddings {
                        if pos < pe.nrows() {
                            val += pe[[pos, j]];
                        }
                    }
                    hidden[[base + pos, j]] = val;
                }
                padded_mask[pos] = mask_in[pos] as u8;
            }
            masks.push(padded_mask);
        }

        // ALBERT: project up [total_rows, embed_dim] → [total_rows, h]
        if let Some(ref proj) = self.weights.embed_projection {
            let _project_span = tracing::info_span!(
                "kin_infer.model.encode_batched.embedding_projection",
                rows = total_rows,
                cols = embed_dim
            )
            .entered();
            hidden = self.linear(&hidden, proj, None)?;
        }

        // 2. Batched embedding LayerNorm
        let _embed_norm_span =
            tracing::info_span!("kin_infer.model.encode_batched.embedding_norm").entered();
        self.optional_layer_norm(
            &mut hidden,
            self.weights.embed_ln_weight.as_ref(),
            self.weights.embed_ln_bias.as_ref(),
            self.config.layer_norm_eps as f32,
        )?;

        if dump_layer_enabled() {
            let e = dump_entity_index();
            if e < batch_size {
                let real = token_ids[e].len();
                let block: Vec<f32> = hidden
                    .slice(ndarray::s![e * max_len..e * max_len + real, ..])
                    .iter()
                    .copied()
                    .collect();
                dump_hidden("batched", 0, "embed", &block);
            }
        }

        // 3. Transformer layers
        let num_groups = self.weights.layers.len();
        let eps = self.config.layer_norm_eps as f32;
        let rms_eps = eps;
        let pre_ln = self.config.effective_pre_ln();
        let use_rms = self.config.uses_rmsnorm();
        let num_heads = self.config.num_attention_heads;
        let head_dim = h / num_heads;
        let scale = 1.0 / (head_dim as f32).sqrt();
        let alibi_slopes = if self.config.position_embedding_type.as_deref() == Some("alibi") {
            Some(alibi_head_slopes(num_heads))
        } else {
            None
        };
        let flat_masks: Vec<u32> = masks
            .iter()
            .flat_map(|mask| mask.iter().map(|&value| value as u32))
            .collect();
        let total_dim = num_heads * head_dim;
        let all_heads = batch_size * num_heads;
        let zero_bias = Array1::zeros(h);

        // Whole-stack GPU-resident pass: hold the residual activations on-device
        // across every transformer layer and read them back once, instead of the
        // per-layer host round-trip. Falls back to the per-layer loop below when
        // the backend declines (CPU/CUDA) or a per-layer divergence dump is asked.
        let mut layers_resident = false;
        if self.should_try_resident_stack() {
            if let Some(gpu) = self.gpu.as_ref() {
                let rope_cos_slice = if self.weights.position_embeddings.is_none() {
                    self.rope_cos
                        .as_ref()
                        .and_then(|x| x.as_slice())
                        .unwrap_or(&[])
                } else {
                    &[]
                };
                let rope_sin_slice = if self.weights.position_embeddings.is_none() {
                    self.rope_sin
                        .as_ref()
                        .and_then(|x| x.as_slice())
                        .unwrap_or(&[])
                } else {
                    &[]
                };
                let layer_config = crate::gpu::LayerConfig {
                    batch_size,
                    max_len,
                    hidden_size: h,
                    num_heads,
                    head_dim,
                    inter_size: self.config.intermediate_size,
                    eps,
                    rms_eps,
                    use_rms,
                    pre_ln,
                    scale,
                    alibi_slopes: alibi_slopes.as_deref(),
                };
                let layer_tensors: Vec<crate::gpu::LayerTensors> =
                    (0..self.config.num_hidden_layers)
                        .map(|i| self.layer_tensors(&self.weights.layers[i % num_groups]))
                        .collect();
                if let Some(out) = gpu.forward_layers_batched(
                    hidden
                        .as_slice()
                        .expect("activation buffer is row-major contiguous"),
                    &flat_masks,
                    &layer_tensors,
                    &layer_config,
                    rope_cos_slice,
                    rope_sin_slice,
                )? {
                    hidden = Array2::from_shape_vec((total_rows, h), out).map_err(|e| {
                        InferError::Internal(format!(
                            "fused stack output not {total_rows}x{h}: {e}"
                        ))
                    })?;
                    layers_resident = true;
                }
            }
        }

        let layer_range = if layers_resident {
            0..0
        } else {
            0..self.config.num_hidden_layers
        };
        for i in layer_range {
            let layer = &self.weights.layers[i % num_groups];

            if let Some(gpu) = self.gpu.as_ref() {
                let layer_tensors = self.layer_tensors(layer);

                let layer_config = crate::gpu::LayerConfig {
                    batch_size,
                    max_len,
                    hidden_size: h,
                    num_heads,
                    head_dim,
                    inter_size: self.config.intermediate_size,
                    eps,
                    rms_eps,
                    use_rms,
                    pre_ln,
                    scale,
                    alibi_slopes: alibi_slopes.as_deref(),
                };

                let rope_cos_slice = if self.weights.position_embeddings.is_none() {
                    self.rope_cos
                        .as_ref()
                        .and_then(|x| x.as_slice())
                        .unwrap_or(&[])
                } else {
                    &[]
                };
                let rope_sin_slice = if self.weights.position_embeddings.is_none() {
                    self.rope_sin
                        .as_ref()
                        .and_then(|x| x.as_slice())
                        .unwrap_or(&[])
                } else {
                    &[]
                };

                if let Some(fused_out) = gpu.forward_layer_batched(
                    hidden
                        .as_slice()
                        .expect("activation buffer is row-major contiguous"),
                    &flat_masks,
                    &layer_tensors,
                    &layer_config,
                    rope_cos_slice,
                    rope_sin_slice,
                )? {
                    hidden = Array2::from_shape_vec((total_rows, h), fused_out).map_err(|e| {
                        InferError::Internal(format!(
                            "fused layer output not {total_rows}x{h}: {e}"
                        ))
                    })?;

                    if dump_layer_enabled() {
                        let e = dump_entity_index();
                        if e < batch_size {
                            let real = token_ids[e].len();
                            let block: Vec<f32> = hidden
                                .slice(ndarray::s![e * max_len..e * max_len + real, ..])
                                .iter()
                                .copied()
                                .collect();
                            dump_hidden("batched", (i + 1) as i32, "ffn", &block);
                        }
                    }
                    continue;
                }
            }

            // --- Batched pre-LN norm [total_rows, h] ---
            let normed_for_attn = if pre_ln {
                let mut n = hidden.clone();
                self.norm(
                    &mut n,
                    &layer.norm1_weight,
                    layer.norm1_bias.as_ref().or(Some(&zero_bias)),
                    if use_rms { rms_eps } else { eps },
                    use_rms,
                )?;
                n
            } else {
                hidden.clone()
            };

            let attn_input = if pre_ln { &normed_for_attn } else { &hidden };

            let (mut q, mut k, v) = self.project_qkv(attn_input, layer, eps)?;

            // Apply RoPE per input (positions restart at 0 for each) before
            // attention; Q+K for each input share one GPU submission.
            self.rope_qk_batched(&mut q, &mut k, batch_size, max_len, head_dim)?;

            // --- Fully batched attention: treat batch_size × num_heads as independent heads ---
            let needs_per_head =
                layer.rel_pos_embeddings.is_some() || layer.relative_attention_bias.is_some();

            let attn_output = if !needs_per_head && self.has_accelerator_backend() {
                let gpu = self.gpu.as_ref().ok_or_else(|| {
                    InferError::BackendError("accelerator backend expected but absent".into())
                })?;
                let base_alibi = alibi_slopes.as_deref().unwrap_or(&[]);

                let q_data: Cow<'_, [f32]> = q
                    .as_slice()
                    .map(Cow::Borrowed)
                    .unwrap_or_else(|| Cow::Owned(q.iter().copied().collect()));
                let k_data: Cow<'_, [f32]> = k
                    .as_slice()
                    .map(Cow::Borrowed)
                    .unwrap_or_else(|| Cow::Owned(k.iter().copied().collect()));
                let v_data: Cow<'_, [f32]> = v
                    .as_slice()
                    .map(Cow::Borrowed)
                    .unwrap_or_else(|| Cow::Owned(v.iter().copied().collect()));

                if reshape_on_gpu() {
                    // Lever A: hand Q/K/V to the backend in the native
                    // position-major [batch*seq, hidden] layout. The accelerator
                    // does the head-major reshape + un-reshape on-device, so the
                    // per-layer host scatter never runs. The output already comes
                    // back position-major, ready to wrap as [total_rows, h].
                    let out_flat = gpu.fused_attention_batched_posmajor(
                        q_data.as_ref(),
                        k_data.as_ref(),
                        v_data.as_ref(),
                        batch_size,
                        num_heads,
                        max_len,
                        head_dim,
                        scale,
                        base_alibi,
                        &flat_masks,
                    )?;
                    Array2::from_shape_vec((total_rows, h), out_flat).map_err(|e| {
                        InferError::Internal(format!(
                            "posmajor attention output not {total_rows}x{h}: {e}"
                        ))
                    })?
                } else {
                    // Reshape Q,K,V from [batch_size * max_len, num_heads * head_dim]
                    // to [(batch_size * num_heads), max_len, head_dim] head-major flat
                    let mut qf = vec![0.0f32; all_heads * max_len * head_dim];
                    let mut kf = vec![0.0f32; all_heads * max_len * head_dim];
                    let mut vf = vec![0.0f32; all_heads * max_len * head_dim];

                    // Position-major [batch*seq, heads*head_dim] -> head-major
                    // [(batch*heads), seq, head_dim]. Each (b, head) owns a disjoint
                    // [max_len*head_dim] output block, so the scatter parallelizes
                    // cleanly over the head-major chunks (measured ~10% of batched
                    // wall single-threaded; this spreads it over the rayon pool).
                    use rayon::prelude::*;
                    let block = max_len * head_dim;
                    let (qs, ks, vs) = (q_data.as_ref(), k_data.as_ref(), v_data.as_ref());
                    qf.par_chunks_mut(block)
                        .zip(kf.par_chunks_mut(block))
                        .zip(vf.par_chunks_mut(block))
                        .enumerate()
                        .for_each(|(blk, ((qchunk, kchunk), vchunk))| {
                            let b = blk / num_heads;
                            let hd = blk % num_heads;
                            for s in 0..max_len {
                                let src = (b * max_len + s) * total_dim + hd * head_dim;
                                let dst = s * head_dim;
                                qchunk[dst..dst + head_dim]
                                    .copy_from_slice(&qs[src..src + head_dim]);
                                kchunk[dst..dst + head_dim]
                                    .copy_from_slice(&ks[src..src + head_dim]);
                                vchunk[dst..dst + head_dim]
                                    .copy_from_slice(&vs[src..src + head_dim]);
                            }
                        });

                    let out_flat = gpu.fused_attention_batched(
                        &qf,
                        &kf,
                        &vf,
                        batch_size,
                        num_heads,
                        max_len,
                        head_dim,
                        scale,
                        base_alibi,
                        &flat_masks,
                    )?;

                    // Reshape back to [batch_size * max_len, num_heads * head_dim]
                    let mut out = Array2::<f32>::zeros((total_rows, h));
                    let out_s = out
                        .as_slice_mut()
                        .expect("freshly allocated Array2 is contiguous");
                    for b in 0..batch_size {
                        for s in 0..max_len {
                            for hd in 0..num_heads {
                                let src = (b * num_heads + hd) * max_len * head_dim + s * head_dim;
                                let dst = (b * max_len + s) * total_dim + hd * head_dim;
                                out_s[dst..dst + head_dim]
                                    .copy_from_slice(&out_flat[src..src + head_dim]);
                            }
                        }
                    }
                    out
                }
            } else {
                // CPU fallback per-input per-head
                let mut out = Array2::<f32>::zeros((total_rows, h));
                for b in 0..batch_size {
                    let base = b * max_len;
                    let mask_b = &masks[b];
                    for head in 0..num_heads {
                        let off = head * head_dim;
                        let qh = q.slice(s![base..base + max_len, off..off + head_dim]);
                        let kh = k.slice(s![base..base + max_len, off..off + head_dim]);
                        let vh = v.slice(s![base..base + max_len, off..off + head_dim]);
                        let mut scores = qh.dot(&kh.t());
                        scores *= scale;
                        for ii in 0..max_len {
                            for jj in 0..max_len {
                                if mask_b[jj] == 0 {
                                    scores[[ii, jj]] = f32::NEG_INFINITY;
                                }
                            }
                        }
                        softmax_rows(&mut scores);
                        let ho = scores.dot(&vh);
                        for ii in 0..max_len {
                            for jj in 0..head_dim {
                                out[[base + ii, off + jj]] = ho[[ii, jj]];
                            }
                        }
                    }
                }
                out
            };

            // --- Batched output projection + residual (+ post-LN norm1) ---
            // Post-LN LayerNorm folds the projection, residual, and norm into one
            // resident GPU submission; the pre-LN / RMSNorm cases keep the per-op
            // path (their norm1 already ran before attention, or is RMS-shaped).
            let post_attn = if !pre_ln && !use_rms && !no_fold_enabled() {
                self.linear_add_norm(
                    &attn_output,
                    &layer.attn_out_weight,
                    layer.attn_out_bias.as_ref(),
                    &hidden,
                    &layer.norm1_weight,
                    layer.norm1_bias.as_ref().unwrap_or(&zero_bias),
                    eps,
                )?
            } else {
                let attn_proj = self.linear(
                    &attn_output,
                    &layer.attn_out_weight,
                    layer.attn_out_bias.as_ref(),
                )?;
                let mut post_attn = &hidden + &attn_proj;
                if !pre_ln {
                    self.norm(
                        &mut post_attn,
                        &layer.norm1_weight,
                        layer.norm1_bias.as_ref().or(Some(&zero_bias)),
                        rms_eps,
                        use_rms,
                    )?;
                }
                post_attn
            };

            if dump_layer_enabled() {
                let e = dump_entity_index();
                if e < batch_size {
                    let real = token_ids[e].len();
                    let block: Vec<f32> = post_attn
                        .slice(ndarray::s![e * max_len..e * max_len + real, ..])
                        .iter()
                        .copied()
                        .collect();
                    dump_hidden("batched", (i + 1) as i32, "attn", &block);
                }
            }

            // --- Batched FFN (+ post-LN residual + norm2) ---
            // Post-LN + gated SwiGLU with no down-projection bias folds the FFN,
            // the residual, and norm2 into one resident GPU submission. The
            // pre-LN / non-gated / RMSNorm cases keep the per-op path.
            let post_ln_swiglu_fold = !pre_ln
                && !use_rms
                && !no_fold_enabled()
                && layer.ffn_gate_weight.is_some()
                && layer.ffn_down_bias.is_none();

            if post_ln_swiglu_fold {
                hidden = self.ffn_swiglu_add_norm(
                    &post_attn,
                    layer.ffn_gate_weight.as_ref().ok_or_else(|| {
                        InferError::ModelIncompatible("SwiGLU FFN requires ffn_gate_weight".into())
                    })?,
                    layer.ffn_up_weight.as_ref().ok_or_else(|| {
                        InferError::ModelIncompatible("FFN requires ffn_up_weight".into())
                    })?,
                    &layer.ffn_down_weight,
                    layer.ffn_down_bias.as_ref(),
                    &post_attn,
                    &layer.norm2_weight,
                    layer.norm2_bias.as_ref().unwrap_or(&zero_bias),
                    eps,
                )?;
            } else {
                let ffn_input = if pre_ln {
                    let mut n = post_attn.clone();
                    self.norm(
                        &mut n,
                        &layer.norm2_weight,
                        layer.norm2_bias.as_ref().or(Some(&zero_bias)),
                        if use_rms { rms_eps } else { eps },
                        use_rms,
                    )?;
                    n
                } else {
                    post_attn.clone()
                };

                let ffn_down = if let Some(ref gate_weight) = layer.ffn_gate_weight {
                    self.ffn_swiglu(
                        &ffn_input,
                        gate_weight,
                        layer.ffn_up_weight.as_ref().ok_or_else(|| {
                            InferError::ModelIncompatible("FFN requires ffn_up_weight".into())
                        })?,
                        &layer.ffn_down_weight,
                        layer.ffn_down_bias.as_ref(),
                    )?
                } else if let Some(ref up_gated_weight) = layer.ffn_up_gated_weight {
                    let up_gated = self.linear(&ffn_input, up_gated_weight, None)?;
                    let gated = if self.config.feed_forward_type == "reglu" {
                        reglu_2d(&up_gated, self.config.intermediate_size)
                    } else {
                        geglu_2d(&up_gated, self.config.intermediate_size)
                    };
                    self.linear(&gated, &layer.ffn_down_weight, layer.ffn_down_bias.as_ref())?
                } else {
                    let ffn_up = self.linear(
                        &ffn_input,
                        layer.ffn_up_weight.as_ref().ok_or_else(|| {
                            InferError::ModelIncompatible("FFN requires ffn_up_weight".into())
                        })?,
                        layer.ffn_up_bias.as_ref(),
                    )?;
                    let ffn_activated = self.gelu(&ffn_up)?;
                    self.linear(
                        &ffn_activated,
                        &layer.ffn_down_weight,
                        layer.ffn_down_bias.as_ref(),
                    )?
                };

                hidden = &post_attn + &ffn_down;
                if !pre_ln {
                    self.norm(
                        &mut hidden,
                        &layer.norm2_weight,
                        layer.norm2_bias.as_ref().or(Some(&zero_bias)),
                        if use_rms { rms_eps } else { eps },
                        use_rms,
                    )?;
                }
            }

            if dump_layer_enabled() {
                let e = dump_entity_index();
                if e < batch_size {
                    let real = token_ids[e].len();
                    let block: Vec<f32> = hidden
                        .slice(ndarray::s![e * max_len..e * max_len + real, ..])
                        .iter()
                        .copied()
                        .collect();
                    dump_hidden("batched", (i + 1) as i32, "ffn", &block);
                }
            }
        }

        Ok((hidden, masks, max_len))
    }

    /// Batched forward pass: all inputs processed together for projections/FFN,
    /// split only for per-input attention. Reduces GPU dispatches by batch_size×.
    pub fn forward_batched(
        &self,
        token_ids: &[Vec<u32>],
        attention_masks: &[Vec<u32>],
    ) -> Result<Vec<Vec<f32>>, InferError> {
        let batch_size = token_ids.len();
        if batch_size == 0 {
            return Ok(vec![]);
        }
        if batch_size == 1 {
            if let Some(results) = self.try_forward_batched_pooled(token_ids, attention_masks)? {
                #[cfg(all(feature = "metal", target_os = "macos"))]
                crate::metal_backend::record_forward_calls(1);
                ensure_finite_embeddings(&results)?;
                return Ok(results);
            }
            return self.forward(token_ids, attention_masks);
        }

        // Length-bucketing (opt-out via KIN_INFER_BUCKET=0): split mixed-length
        // inputs into coarse length bins so the projection/FFN GEMMs stop running
        // short sequences padded to the batch's global max_len. Bit-identical per
        // entity to the default path below; see `forward_batched_bucketed`.
        if bucket_enabled() {
            return self.forward_batched_bucketed(token_ids, attention_masks);
        }
        #[cfg(all(feature = "metal", target_os = "macos"))]
        crate::metal_backend::record_forward_calls(1);

        if let Some(results) = self.try_forward_batched_pooled(token_ids, attention_masks)? {
            ensure_finite_embeddings(&results)?;
            return Ok(results);
        }

        let (hidden, masks, max_len) = self.encode_batched(token_ids, attention_masks)?;

        // 4. Per-input mean/CLS pooling + L2 normalize
        let _pool_span =
            tracing::info_span!("kin_infer.model.forward_batched.pool_and_normalize").entered();
        let results = self.pool_and_normalize(&hidden, &masks, max_len);
        ensure_finite_embeddings(&results)?;
        Ok(results)
    }

    #[allow(clippy::needless_range_loop)]
    fn try_forward_batched_pooled(
        &self,
        token_ids: &[Vec<u32>],
        attention_masks: &[Vec<u32>],
    ) -> Result<Option<Vec<Vec<f32>>>, InferError> {
        if !pooled_output_enabled() || resident_stack_disabled() || dump_layer_enabled() {
            return Ok(None);
        }
        let Some(gpu) = self.gpu.as_ref() else {
            return Ok(None);
        };
        if self.has_relative_attention_layers() {
            return Ok(None);
        }

        let batch_size = token_ids.len();
        let h = self.config.hidden_size;
        let embed_dim = self.config.embedding_size.unwrap_or(h);
        let max_len = token_ids.iter().map(|t| t.len()).max().unwrap_or(0);
        let total_rows = batch_size * max_len;

        let mut hidden = Array2::<f32>::zeros((total_rows, embed_dim));
        let mut masks: Vec<Vec<u8>> = Vec::with_capacity(batch_size);
        for b in 0..batch_size {
            let ids = &token_ids[b];
            let mask_in = &attention_masks[b];
            let base = b * max_len;
            let mut padded_mask = vec![0u8; max_len];
            for (pos, &id) in ids.iter().enumerate() {
                let word = self.weights.word_embeddings.row(id as usize);
                for j in 0..embed_dim {
                    let mut val = word[j];
                    if let Some(ref tte) = self.weights.token_type_embeddings {
                        val += tte[[0, j]];
                    }
                    if let Some(ref pe) = self.weights.position_embeddings {
                        if pos < pe.nrows() {
                            val += pe[[pos, j]];
                        }
                    }
                    hidden[[base + pos, j]] = val;
                }
                padded_mask[pos] = mask_in[pos] as u8;
            }
            masks.push(padded_mask);
        }

        let num_heads = self.config.num_attention_heads;
        let head_dim = h / num_heads;
        let eps = self.config.layer_norm_eps as f32;
        let rms_eps = eps;
        let pre_ln = self.config.effective_pre_ln();
        let use_rms = self.config.uses_rmsnorm();
        let scale = 1.0 / (head_dim as f32).sqrt();
        let alibi_slopes = if self.config.position_embedding_type.as_deref() == Some("alibi") {
            Some(alibi_head_slopes(num_heads))
        } else {
            None
        };
        let flat_masks: Vec<u32> = masks
            .iter()
            .flat_map(|mask| mask.iter().map(|&value| value as u32))
            .collect();
        let num_groups = self.weights.layers.len();
        let layer_config = crate::gpu::LayerConfig {
            batch_size,
            max_len,
            hidden_size: h,
            num_heads,
            head_dim,
            inter_size: self.config.intermediate_size,
            eps,
            rms_eps,
            use_rms,
            pre_ln,
            scale,
            alibi_slopes: alibi_slopes.as_deref(),
        };
        let layer_tensors: Vec<crate::gpu::LayerTensors> = (0..self.config.num_hidden_layers)
            .map(|i| self.layer_tensors(&self.weights.layers[i % num_groups]))
            .collect();
        let rope_cos_slice = if self.weights.position_embeddings.is_none() {
            self.rope_cos
                .as_ref()
                .and_then(|x| x.as_slice())
                .unwrap_or(&[])
        } else {
            &[]
        };
        let rope_sin_slice = if self.weights.position_embeddings.is_none() {
            self.rope_sin
                .as_ref()
                .and_then(|x| x.as_slice())
                .unwrap_or(&[])
        } else {
            &[]
        };
        let pooling = if self.config.uses_cls_pooling() {
            crate::gpu::PoolingMode::Cls
        } else {
            crate::gpu::PoolingMode::Mean
        };
        let projection = self
            .weights
            .embed_projection
            .as_ref()
            .map(|proj| proj.as_slice().expect("embed projection is contiguous"));
        let norm_weight = self
            .weights
            .embed_ln_weight
            .as_ref()
            .map(|weight| weight.as_slice().expect("embed norm weight is contiguous"));
        let norm_bias = self
            .weights
            .embed_ln_bias
            .as_ref()
            .map(|bias| bias.as_slice().expect("embed norm bias is contiguous"));
        let embedding = crate::gpu::EmbeddingPrelude {
            input_dim: embed_dim,
            projection,
            norm_weight,
            norm_bias,
            eps,
        };

        let Some(flat) = gpu.forward_layers_batched_pooled(
            hidden
                .as_slice()
                .expect("activation buffer is row-major contiguous"),
            &flat_masks,
            &layer_tensors,
            &layer_config,
            &embedding,
            rope_cos_slice,
            rope_sin_slice,
            pooling,
        )?
        else {
            return Ok(None);
        };

        if flat.len() != batch_size * h {
            return Err(InferError::Internal(format!(
                "pooled GPU output not {batch_size}x{h}: len={}",
                flat.len()
            )));
        }
        Ok(Some(
            flat.chunks_exact(h)
                .map(|row| l2_normalize(&Array1::from_vec(row.to_vec())).to_vec())
                .collect(),
        ))
    }

    /// Per-input mean/CLS pooling + L2 normalize over an encoded batch.
    ///
    /// `hidden` is the `[batch * max_len, hidden]` block from `encode_batched`,
    /// `masks[b]` is input `b`'s padded attention mask, and `max_len` is the row
    /// stride. Returns one L2-normalized embedding per input, in input order.
    /// Pooling is mask-aware, so padding rows contribute nothing.
    // Index drives flat-offset slicing (base = b * max_len) into the hidden ndarray; range loop is the clearer form.
    #[allow(clippy::needless_range_loop)]
    fn pool_and_normalize(
        &self,
        hidden: &Array2<f32>,
        masks: &[Vec<u8>],
        max_len: usize,
    ) -> Vec<Vec<f32>> {
        let batch_size = masks.len();
        let mut results = Vec::with_capacity(batch_size);
        let cls_pooling = self.config.uses_cls_pooling();
        for b in 0..batch_size {
            let base = b * max_len;
            let h_b = hidden
                .slice(ndarray::s![base..base + max_len, ..])
                .to_owned();
            let pooled = if cls_pooling {
                cls_pool(&h_b)
            } else {
                mean_pool(
                    &h_b,
                    &masks[b].iter().map(|&m| m as u32).collect::<Vec<_>>(),
                )
            };
            results.push(l2_normalize(&pooled).to_vec());
        }
        results
    }

    /// Length-bucketed `forward_batched` (gated by `KIN_INFER_BUCKET`).
    ///
    /// Groups inputs by coarse length bin (`length_bin`) and encodes each group
    /// independently, so every `encode_batched` call pads only to its group's
    /// longest member instead of the whole batch's global `max_len`. This removes
    /// the padding rows the projection/FFN GEMMs would otherwise process for short
    /// sequences that share a batch with a long one.
    ///
    /// Output is bit-identical, per entity, to the unbucketed path: a GEMM output
    /// row depends only on the matching input row (rows are independent and the
    /// kernel's K-accumulation order is fixed regardless of batch composition),
    /// attention masks padded columns to -inf, and pooling is mask-aware. Only the
    /// batch each entity rides in — and thus the amount of wasted padding —
    /// changes; the math for a real token row does not. Results are reassembled
    /// into the original input order before returning.
    ///
    /// Side-effect note: bucketing changes the order in which entities ride each
    /// sub-batch call, which changes HNSW insert order downstream. This is
    /// irrelevant to embedding values, but downstream callers that depend on stable
    /// insertion order must account for it.
    fn forward_batched_bucketed(
        &self,
        token_ids: &[Vec<u32>],
        attention_masks: &[Vec<u32>],
    ) -> Result<Vec<Vec<f32>>, InferError> {
        use std::collections::BTreeMap;
        let batch_size = token_ids.len();

        // Group original input indices by coarse length bin (deterministic order).
        let mut groups: BTreeMap<usize, Vec<usize>> = BTreeMap::new();
        for (idx, ids) in token_ids.iter().enumerate() {
            groups.entry(length_bin(ids.len())).or_default().push(idx);
        }

        let _span = tracing::info_span!(
            "kin_infer.model.forward_batched.bucketed",
            batch_size = batch_size,
            groups = groups.len()
        )
        .entered();
        #[cfg(all(feature = "metal", target_os = "macos"))]
        crate::metal_backend::record_forward_calls(groups.len());

        // One empty slot per input; every index lands in exactly one group and
        // every group writes its results back, so all slots are filled.
        let mut results: Vec<Vec<f32>> = vec![Vec::new(); batch_size];
        for indices in groups.values() {
            let group_ids: Vec<Vec<u32>> = indices.iter().map(|&i| token_ids[i].clone()).collect();
            let group_masks: Vec<Vec<u32>> = indices
                .iter()
                .map(|&i| attention_masks[i].clone())
                .collect();
            let pooled =
                if let Some(pooled) = self.try_forward_batched_pooled(&group_ids, &group_masks)? {
                    pooled
                } else {
                    let (hidden, masks, max_len) = self.encode_batched(&group_ids, &group_masks)?;
                    self.pool_and_normalize(&hidden, &masks, max_len)
                };
            for (slot, &orig) in indices.iter().enumerate() {
                results[orig] = pooled[slot].clone();
            }
        }
        ensure_finite_embeddings(&results)?;
        Ok(results)
    }

    fn should_try_resident_stack(&self) -> bool {
        !resident_stack_disabled() && !dump_layer_enabled() && !self.has_relative_attention_layers()
    }

    fn has_relative_attention_layers(&self) -> bool {
        self.weights.layers.iter().any(|layer| {
            layer.rel_pos_embeddings.is_some() || layer.relative_attention_bias.is_some()
        })
    }

    /// Batched cross-encoder forward pass. Extracts the `[CLS]` token (index 0) from each
    /// sequence and applies the linear classification head.
    pub fn forward_cross_encoder_batched(
        &self,
        token_ids: &[Vec<u32>],
        attention_masks: &[Vec<u32>],
    ) -> Result<Vec<f32>, InferError> {
        let batch_size = token_ids.len();
        if batch_size == 0 {
            return Ok(vec![]);
        }
        let (hidden, _masks, max_len) = self.encode_batched(token_ids, attention_masks)?;

        let mut cls_tokens = ndarray::Array2::<f32>::zeros((batch_size, self.config.hidden_size));
        for b in 0..batch_size {
            let base = b * max_len;
            let cls = hidden.row(base);
            cls_tokens.row_mut(b).assign(&cls);
        }

        let logits = self.classify_pooled(&cls_tokens)?;
        let mut results = Vec::with_capacity(batch_size);
        for b in 0..batch_size {
            results.push(logits[[b, 0]]);
        }
        Ok(results)
    }

    /// Apply the cross-encoder classification head to pooled `[CLS]` representations,
    /// returning `[batch, num_labels]` logits. The two-layer RoBERTa head computes
    /// `out_proj(tanh(dense(x)))`; the single-linear head computes `x·Wᵀ + b`.
    fn classify_pooled(&self, pooled: &Array2<f32>) -> Result<Array2<f32>, InferError> {
        match self.weights.classifier.as_ref() {
            Some(ClassifierHead::Linear { weight, bias }) => {
                self.linear(pooled, weight, bias.as_ref())
            }
            Some(ClassifierHead::Roberta {
                dense_weight,
                dense_bias,
                out_proj_weight,
                out_proj_bias,
            }) => {
                let mut hidden = self.linear(pooled, dense_weight, dense_bias.as_ref())?;
                hidden.mapv_inplace(|v| v.tanh());
                self.linear(&hidden, out_proj_weight, out_proj_bias.as_ref())
            }
            None => Err(InferError::ModelError(
                "cross-encoder requires a classification head".into(),
            )),
        }
    }

    /// GPU-accelerated linear projection helper.
    fn linear(
        &self,
        x: &Array2<f32>,
        weight: &Array2<f32>,
        bias: Option<&Array1<f32>>,
    ) -> Result<Array2<f32>, InferError> {
        let _span = tracing::info_span!(
            "kin_infer.model.linear",
            rows = x.nrows(),
            input_dim = x.ncols(),
            output_dim = weight.nrows(),
            bias = bias.is_some(),
            backend = %self.backend()
        )
        .entered();
        if let Some(ref gpu) = self.gpu {
            gpu_linear_bias(x, weight, bias, gpu.as_ref())
        } else {
            Ok(linear_with_optional_bias(x, weight, bias))
        }
    }

    /// GPU-accelerated norm helper.
    fn norm(
        &self,
        x: &mut Array2<f32>,
        weight: &Array1<f32>,
        bias: Option<&Array1<f32>>,
        eps: f32,
        use_rms: bool,
    ) -> Result<(), InferError> {
        let _span = tracing::info_span!(
            "kin_infer.model.norm",
            rows = x.nrows(),
            cols = x.ncols(),
            use_rms = use_rms,
            bias = bias.is_some(),
            backend = %self.backend(),
            eps = eps
        )
        .entered();
        if use_rms {
            if let Some(ref gpu) = self.gpu {
                gpu_rms_norm_2d(x, weight, eps, gpu.as_ref())?;
            } else {
                rms_norm_2d(x, weight, eps);
            }
        } else if let Some(bias) = bias {
            if let Some(ref gpu) = self.gpu {
                gpu_layer_norm_2d(x, weight, bias, eps, gpu.as_ref())?;
            } else {
                layer_norm_2d(x, weight, bias, eps);
            }
        }
        Ok(())
    }

    // Multi-output tensor op: a 3-tuple of Q/K/V arrays is clearer inline than behind a type alias.
    #[allow(clippy::type_complexity)]
    fn project_qkv(
        &self,
        x: &Array2<f32>,
        layer: &TransformerLayerWeights,
        eps: f32,
    ) -> Result<(Array2<f32>, Array2<f32>, Array2<f32>), InferError> {
        let _span = tracing::info_span!(
            "kin_infer.model.project_qkv",
            rows = x.nrows(),
            input_dim = x.ncols(),
            fused_qkv = layer.qkv_weight.is_some(),
            backend = %self.backend(),
            eps = eps
        )
        .entered();
        if let Some(ref qkv_weight) = layer.qkv_weight {
            let q_rows = layer.q_weight.nrows();
            let k_rows = layer.k_weight.nrows();
            let qkv = self.linear(x, qkv_weight, layer.qkv_bias.as_ref())?;

            let mut q = qkv.slice(s![.., 0..q_rows]).to_owned();
            self.optional_layer_norm(
                &mut q,
                layer.q_ln_weight.as_ref(),
                layer.q_ln_bias.as_ref(),
                eps,
            )?;

            let mut k = qkv.slice(s![.., q_rows..q_rows + k_rows]).to_owned();
            self.optional_layer_norm(
                &mut k,
                layer.k_ln_weight.as_ref(),
                layer.k_ln_bias.as_ref(),
                eps,
            )?;

            let v = qkv.slice(s![.., q_rows + k_rows..]).to_owned();
            Ok((q, k, v))
        } else if let Some(ref gpu) = self.gpu {
            let mut projected = gpu_linear_many_bias(
                x,
                &[
                    (&layer.q_weight, layer.q_bias.as_ref()),
                    (&layer.k_weight, layer.k_bias.as_ref()),
                    (&layer.v_weight, layer.v_bias.as_ref()),
                ],
                gpu.as_ref(),
            )?;
            let v = projected
                .pop()
                .ok_or_else(|| InferError::Internal("qkv projection missing V output".into()))?;
            let mut k = projected
                .pop()
                .ok_or_else(|| InferError::Internal("qkv projection missing K output".into()))?;
            let mut q = projected
                .pop()
                .ok_or_else(|| InferError::Internal("qkv projection missing Q output".into()))?;
            self.optional_layer_norm(
                &mut q,
                layer.q_ln_weight.as_ref(),
                layer.q_ln_bias.as_ref(),
                eps,
            )?;
            self.optional_layer_norm(
                &mut k,
                layer.k_ln_weight.as_ref(),
                layer.k_ln_bias.as_ref(),
                eps,
            )?;
            Ok((q, k, v))
        } else {
            let mut q = self.linear(x, &layer.q_weight, layer.q_bias.as_ref())?;
            self.optional_layer_norm(
                &mut q,
                layer.q_ln_weight.as_ref(),
                layer.q_ln_bias.as_ref(),
                eps,
            )?;
            let mut k = self.linear(x, &layer.k_weight, layer.k_bias.as_ref())?;
            self.optional_layer_norm(
                &mut k,
                layer.k_ln_weight.as_ref(),
                layer.k_ln_bias.as_ref(),
                eps,
            )?;
            let v = self.linear(x, &layer.v_weight, layer.v_bias.as_ref())?;
            Ok((q, k, v))
        }
    }

    /// GPU-accelerated optional LayerNorm helper.
    fn optional_layer_norm(
        &self,
        x: &mut Array2<f32>,
        gamma: Option<&Array1<f32>>,
        bias: Option<&Array1<f32>>,
        eps: f32,
    ) -> Result<(), InferError> {
        let _span = tracing::info_span!(
            "kin_infer.model.optional_layer_norm",
            rows = x.nrows(),
            cols = x.ncols(),
            enabled = gamma.is_some() && bias.is_some(),
            backend = %self.backend(),
            eps = eps
        )
        .entered();
        if let (Some(gamma), Some(bias)) = (gamma, bias) {
            if let Some(ref gpu) = self.gpu {
                gpu_layer_norm_2d(x, gamma, bias, eps, gpu.as_ref())?;
            } else {
                layer_norm_2d(x, gamma, bias, eps);
            }
        }
        Ok(())
    }

    /// GPU-accelerated row-wise softmax helper.
    fn softmax(&self, x: &mut Array2<f32>) -> Result<(), InferError> {
        let _span = tracing::info_span!(
            "kin_infer.model.softmax",
            rows = x.nrows(),
            cols = x.ncols(),
            backend = %self.backend()
        )
        .entered();
        if let Some(ref gpu) = self.gpu {
            gpu_softmax_rows(x, gpu.as_ref())?;
        } else {
            softmax_rows(x);
        }
        Ok(())
    }

    /// GPU-accelerated GELU helper.
    fn gelu(&self, x: &Array2<f32>) -> Result<Array2<f32>, InferError> {
        if let Some(ref gpu) = self.gpu {
            gpu_gelu_2d(x, gpu.as_ref())
        } else {
            Ok(gelu_2d(x))
        }
    }

    /// GPU-accelerated SwiGLU helper.
    fn swiglu(&self, gate: &Array2<f32>, up: &Array2<f32>) -> Result<Array2<f32>, InferError> {
        let _span = tracing::info_span!(
            "kin_infer.model.swiglu",
            rows = gate.nrows(),
            cols = gate.ncols(),
            backend = %self.backend()
        )
        .entered();
        if let Some(ref gpu) = self.gpu {
            gpu_swiglu_2d(gate, up, gpu.as_ref())
        } else {
            Ok(swiglu_2d(gate, up))
        }
    }

    /// Full SwiGLU feed-forward block: `down( silu(x@gate^T) * (x@up^T) )`.
    ///
    /// On an accelerator backend with no down-projection bias and contiguous
    /// inputs, the whole chain is fused into one GPU submission (3 matmuls + the
    /// SwiGLU activation), collapsing the per-op commit+wait round-trips that
    /// dominate embedding latency. Otherwise it falls back to the per-op path,
    /// which is the numerical reference.
    fn ffn_swiglu(
        &self,
        x: &Array2<f32>,
        gate_w: &Array2<f32>,
        up_w: &Array2<f32>,
        down_w: &Array2<f32>,
        down_bias: Option<&Array1<f32>>,
    ) -> Result<Array2<f32>, InferError> {
        let _span = tracing::info_span!(
            "kin_infer.model.ffn_swiglu",
            rows = x.nrows(),
            hidden = x.ncols(),
            inter = gate_w.nrows(),
            backend = %self.backend()
        )
        .entered();
        if let Some(ref gpu) = self.gpu {
            if down_bias.is_none() {
                if let (Some(xs), Some(gw), Some(uw), Some(dw)) = (
                    x.as_slice(),
                    gate_w.as_slice(),
                    up_w.as_slice(),
                    down_w.as_slice(),
                ) {
                    let rows = x.nrows();
                    let hidden = x.ncols();
                    let inter = gate_w.nrows();
                    let out = gpu.fused_ffn_swiglu(xs, gw, uw, dw, rows, hidden, inter)?;
                    return Array2::from_shape_vec((rows, hidden), out).map_err(|e| {
                        InferError::Internal(format!(
                            "fused_ffn_swiglu output not {rows}x{hidden}: {e}"
                        ))
                    });
                }
            }
        }
        let gate = self.linear(x, gate_w, None)?;
        let up = self.linear(x, up_w, None)?;
        let activated = self.swiglu(&gate, &up)?;
        self.linear(&activated, down_w, down_bias)
    }

    /// Post-LN projection + residual + LayerNorm: `layer_norm(residual + x @ w^T)`.
    ///
    /// On an accelerator backend with no projection bias and contiguous inputs the
    /// whole chain is fused into one GPU submission (matmul + residual add + norm),
    /// keeping the projection result resident so the intermediate never round-trips
    /// through host memory. Otherwise it falls back to the per-op `linear` + add +
    /// `norm` path, which is the numerical reference.
    #[allow(clippy::too_many_arguments)]
    fn linear_add_norm(
        &self,
        x: &Array2<f32>,
        weight: &Array2<f32>,
        bias: Option<&Array1<f32>>,
        residual: &Array2<f32>,
        norm_gamma: &Array1<f32>,
        norm_beta: &Array1<f32>,
        eps: f32,
    ) -> Result<Array2<f32>, InferError> {
        let _span = tracing::info_span!(
            "kin_infer.model.linear_add_norm",
            rows = x.nrows(),
            cols = x.ncols(),
            hidden = weight.nrows(),
            backend = %self.backend()
        )
        .entered();
        if let Some(ref gpu) = self.gpu {
            if bias.is_none() {
                if let (Some(xs), Some(ws), Some(rs), Some(gs), Some(bs)) = (
                    x.as_slice(),
                    weight.as_slice(),
                    residual.as_slice(),
                    norm_gamma.as_slice(),
                    norm_beta.as_slice(),
                ) {
                    let rows = x.nrows();
                    let cols = x.ncols();
                    let hidden = weight.nrows();
                    let out =
                        gpu.fused_linear_add_norm(xs, ws, rs, gs, bs, rows, cols, hidden, eps)?;
                    return Array2::from_shape_vec((rows, hidden), out).map_err(|e| {
                        InferError::Internal(format!(
                            "fused_linear_add_norm output not {rows}x{hidden}: {e}"
                        ))
                    });
                }
            }
        }
        let proj = self.linear(x, weight, bias)?;
        let mut sum = residual + &proj;
        self.norm(&mut sum, norm_gamma, Some(norm_beta), eps, false)?;
        Ok(sum)
    }

    /// Post-LN SwiGLU FFN block: `layer_norm(residual + ffn_swiglu(x))`.
    ///
    /// On an accelerator backend with no down-projection bias and contiguous
    /// inputs the residual add and norm2 fold into the FFN's single GPU
    /// submission, so the down-projection never round-trips to host memory
    /// un-normed. Otherwise it falls back to the per-op `ffn_swiglu` + add +
    /// `norm` path, the numerical reference.
    #[allow(clippy::too_many_arguments)]
    fn ffn_swiglu_add_norm(
        &self,
        x: &Array2<f32>,
        gate_w: &Array2<f32>,
        up_w: &Array2<f32>,
        down_w: &Array2<f32>,
        down_bias: Option<&Array1<f32>>,
        residual: &Array2<f32>,
        norm_gamma: &Array1<f32>,
        norm_beta: &Array1<f32>,
        eps: f32,
    ) -> Result<Array2<f32>, InferError> {
        let _span = tracing::info_span!(
            "kin_infer.model.ffn_swiglu_add_norm",
            rows = x.nrows(),
            hidden = x.ncols(),
            inter = gate_w.nrows(),
            backend = %self.backend()
        )
        .entered();
        if let Some(ref gpu) = self.gpu {
            if down_bias.is_none() {
                if let (Some(xs), Some(gw), Some(uw), Some(dw), Some(rs), Some(gs), Some(bs)) = (
                    x.as_slice(),
                    gate_w.as_slice(),
                    up_w.as_slice(),
                    down_w.as_slice(),
                    residual.as_slice(),
                    norm_gamma.as_slice(),
                    norm_beta.as_slice(),
                ) {
                    let rows = x.nrows();
                    let hidden = x.ncols();
                    let inter = gate_w.nrows();
                    let out = gpu.fused_ffn_swiglu_add_norm(
                        xs, gw, uw, dw, rs, gs, bs, rows, hidden, inter, eps,
                    )?;
                    return Array2::from_shape_vec((rows, hidden), out).map_err(|e| {
                        InferError::Internal(format!(
                            "fused_ffn_swiglu_add_norm output not {rows}x{hidden}: {e}"
                        ))
                    });
                }
            }
        }
        let down = self.ffn_swiglu(x, gate_w, up_w, down_w, down_bias)?;
        let mut sum = residual + &down;
        self.norm(&mut sum, norm_gamma, Some(norm_beta), eps, false)?;
        Ok(sum)
    }

    /// GPU-accelerated RoPE helper.
    fn rope(
        &self,
        x: &mut Array2<f32>,
        seq_offset: usize,
        seq_len: usize,
        head_dim: usize,
    ) -> Result<(), InferError> {
        let _span = tracing::info_span!(
            "kin_infer.model.rope",
            rows = x.nrows(),
            cols = x.ncols(),
            seq_offset = seq_offset,
            seq_len = seq_len,
            head_dim = head_dim,
            backend = %self.backend()
        )
        .entered();
        if let (Some(ref cos), Some(ref sin)) = (&self.rope_cos, &self.rope_sin) {
            if let Some(ref gpu) = self.gpu {
                gpu_apply_rope(x, cos, sin, seq_offset, seq_len, head_dim, gpu.as_ref())?;
            } else {
                apply_rope(x, cos, sin, seq_offset, seq_len, head_dim);
            }
        }
        Ok(())
    }

    /// Apply RoPE to Q and K together. On an accelerator backend both rotations
    /// are submitted in one command buffer (they share the cos/sin tables and
    /// are mutually independent), halving the RoPE round-trips per layer. Falls
    /// back to two independent `rope` calls otherwise. No-op without RoPE tables.
    fn rope_qk(
        &self,
        q: &mut Array2<f32>,
        k: &mut Array2<f32>,
        seq_len: usize,
        head_dim: usize,
    ) -> Result<(), InferError> {
        let (Some(cos), Some(sin)) = (&self.rope_cos, &self.rope_sin) else {
            return Ok(());
        };
        let gpu = match &self.gpu {
            Some(gpu) => gpu.as_ref(),
            None => {
                self.rope(q, 0, seq_len, head_dim)?;
                self.rope(k, 0, seq_len, head_dim)?;
                return Ok(());
            }
        };
        let total_dim = q.ncols();
        let half = head_dim / 2;
        let max_rows = cos.nrows().min(sin.nrows());
        let actual = max_rows.min(seq_len);
        if actual == 0 {
            return Ok(());
        }

        // Both Q and K must be contiguous and same-width to share one submission.
        let q_contig = q.as_slice().is_some();
        let k_owned = if k.ncols() == total_dim {
            k.as_slice().map(|s| s.to_vec())
        } else {
            None
        };
        let (true, Some(mut k_vec)) = (q_contig, k_owned) else {
            self.rope(q, 0, seq_len, head_dim)?;
            self.rope(k, 0, seq_len, head_dim)?;
            return Ok(());
        };

        let mut cos_compact = Vec::with_capacity(actual * half);
        let mut sin_compact = Vec::with_capacity(actual * half);
        for pos in 0..actual {
            for d in 0..half {
                cos_compact.push(cos[[pos, d]]);
                sin_compact.push(sin[[pos, d]]);
            }
        }

        let q_slice = q.as_slice_mut().expect("q contiguous");
        gpu.rope_pair(
            q_slice,
            &mut k_vec,
            &cos_compact,
            &sin_compact,
            0,
            actual,
            head_dim,
            total_dim,
        )?;
        k.as_slice_mut()
            .expect("k contiguous")
            .copy_from_slice(&k_vec);
        Ok(())
    }

    /// Single encoder transformer layer with support for all attention/norm variants.
    /// Apply RoPE independently to each input in a batched [batch_size * max_len,
    /// total_dim] tensor, restarting positions at 0 for every input. No-op when the
    /// model has no RoPE tables.
    fn rope_batched(
        &self,
        x: &mut Array2<f32>,
        batch_size: usize,
        max_len: usize,
        head_dim: usize,
    ) -> Result<(), InferError> {
        if self.rope_cos.is_none() || max_len == 0 {
            return Ok(());
        }
        for b in 0..batch_size {
            let base = b * max_len;
            let mut block = x.slice(s![base..base + max_len, ..]).to_owned();
            self.rope(&mut block, 0, max_len, head_dim)?;
            x.slice_mut(s![base..base + max_len, ..]).assign(&block);
        }
        Ok(())
    }

    /// Apply RoPE to Q and K together in the batched path: positions restart at 0
    /// for every input, and Q+K for each input share one GPU submission via
    /// `rope_pair` (halving the RoPE round-trips per layer vs two `rope_batched`
    /// calls). Falls back to the two-call path when there is no accelerator or the
    /// shared compact tables can't be built. No-op without RoPE tables.
    fn rope_qk_batched(
        &self,
        q: &mut Array2<f32>,
        k: &mut Array2<f32>,
        batch_size: usize,
        max_len: usize,
        head_dim: usize,
    ) -> Result<(), InferError> {
        let (Some(cos), Some(sin)) = (&self.rope_cos, &self.rope_sin) else {
            return Ok(());
        };
        let Some(gpu) = self.gpu.as_ref() else {
            self.rope_batched(q, batch_size, max_len, head_dim)?;
            self.rope_batched(k, batch_size, max_len, head_dim)?;
            return Ok(());
        };
        if max_len == 0 || batch_size == 0 {
            return Ok(());
        }
        let total_dim = q.ncols();
        let half = head_dim / 2;
        let actual = cos.nrows().min(sin.nrows()).min(max_len);
        if actual == 0 || k.ncols() != total_dim {
            self.rope_batched(q, batch_size, max_len, head_dim)?;
            self.rope_batched(k, batch_size, max_len, head_dim)?;
            return Ok(());
        }

        // Positions restart at 0 per input, so the compact cos/sin tables are the
        // same for every batch element — build them once.
        let mut cos_compact = Vec::with_capacity(actual * half);
        let mut sin_compact = Vec::with_capacity(actual * half);
        for pos in 0..actual {
            for d in 0..half {
                cos_compact.push(cos[[pos, d]]);
                sin_compact.push(sin[[pos, d]]);
            }
        }

        // Escape hatch / parity reference: `KIN_ROPE_PERELEM` forces the
        // per-input RoPE path (one submission per input) instead of the single
        // whole-batch dispatch. Used by the batched-RoPE parity test to A/B the
        // two strategies through the identical forward_batched path.
        if std::env::var_os("KIN_ROPE_PERELEM").is_some() {
            for b in 0..batch_size {
                let base = b * max_len;
                self.rope_batched_one(
                    q,
                    k,
                    base,
                    actual,
                    head_dim,
                    &cos_compact,
                    &sin_compact,
                    total_dim,
                )?;
            }
            return Ok(());
        }

        // One GPU submission for the whole batch (Q and K), positions reset per
        // input inside the kernel. Requires contiguous [batch*max_len, total_dim]
        // q/k; otherwise fall back to the per-input path.
        let k_vec = k.as_slice().map(|s| s.to_vec());
        let (Some(q_slice), Some(mut k_vec)) = (q.as_slice_mut(), k_vec) else {
            for b in 0..batch_size {
                let base = b * max_len;
                self.rope_batched_one(
                    q,
                    k,
                    base,
                    actual,
                    head_dim,
                    &cos_compact,
                    &sin_compact,
                    total_dim,
                )?;
            }
            return Ok(());
        };
        gpu.rope_pair_batched(
            q_slice,
            &mut k_vec,
            &cos_compact,
            &sin_compact,
            batch_size,
            max_len,
            actual,
            head_dim,
            total_dim,
        )?;
        k.as_slice_mut()
            .expect("k contiguous")
            .copy_from_slice(&k_vec);
        Ok(())
    }

    /// Per-input RoPE fallback for the batched path when q/k aren't contiguous.
    #[allow(clippy::too_many_arguments)]
    fn rope_batched_one(
        &self,
        q: &mut Array2<f32>,
        k: &mut Array2<f32>,
        base: usize,
        actual: usize,
        head_dim: usize,
        cos_compact: &[f32],
        sin_compact: &[f32],
        total_dim: usize,
    ) -> Result<(), InferError> {
        let Some(gpu) = self.gpu.as_ref() else {
            return Ok(());
        };
        let mut q_block: Vec<f32> = q
            .slice(s![base..base + actual, ..])
            .iter()
            .copied()
            .collect();
        let mut k_block: Vec<f32> = k
            .slice(s![base..base + actual, ..])
            .iter()
            .copied()
            .collect();
        gpu.rope_pair(
            &mut q_block,
            &mut k_block,
            cos_compact,
            sin_compact,
            0,
            actual,
            head_dim,
            total_dim,
        )?;
        q.slice_mut(s![base..base + actual, ..])
            .iter_mut()
            .zip(q_block)
            .for_each(|(dst, src)| *dst = src);
        k.slice_mut(s![base..base + actual, ..])
            .iter_mut()
            .zip(k_block)
            .for_each(|(dst, src)| *dst = src);
        Ok(())
    }

    fn encoder_layer(
        &self,
        hidden: &Array2<f32>,
        mask: &[u32],
        layer: &TransformerLayerWeights,
        layer_idx: usize,
    ) -> Result<Array2<f32>, InferError> {
        let _span = tracing::info_span!(
            "kin_infer.model.encoder_layer",
            layer_idx = layer_idx,
            seq_len = hidden.nrows(),
            hidden_size = hidden.ncols(),
            backend = %self.backend()
        )
        .entered();
        let h = self.config.hidden_size;
        let num_heads = self.config.num_attention_heads;
        let num_kv_heads = self.config.effective_num_kv_heads();
        let eps = self.config.layer_norm_eps as f32;
        let pre_ln = self.config.effective_pre_ln();
        let use_rms = self.config.uses_rmsnorm();
        let rms_eps = self.config.effective_rms_eps();

        // Pre-LN: normalize before attention
        let normed_for_attn = if pre_ln {
            let mut n = hidden.clone();
            self.norm(
                &mut n,
                &layer.norm1_weight,
                layer.norm1_bias.as_ref().or(Some(&Array1::zeros(h))),
                if use_rms { rms_eps } else { eps },
                use_rms,
            )?;
            n
        } else {
            hidden.clone()
        };

        let attn_input = if pre_ln { &normed_for_attn } else { hidden };

        let (mut q, mut k, v) = self.project_qkv(attn_input, layer, eps)?;

        // Apply RoPE if configured (Q and K in one GPU submission).
        let seq_len = q.nrows();
        self.rope_qk(&mut q, &mut k, seq_len, self.head_dim)?;

        // GQA: repeat K/V heads if needed
        let (k_full, v_full) = if num_kv_heads < num_heads {
            (
                repeat_kv(&k, num_kv_heads, num_heads),
                repeat_kv(&v, num_kv_heads, num_heads),
            )
        } else {
            (k, v)
        };

        // Multi-head attention
        let seq_len = hidden.nrows();
        let head_dim = self.head_dim;
        let scale = 1.0 / (head_dim as f32).sqrt();
        let alibi_slopes = if self.config.position_embedding_type.as_deref() == Some("alibi") {
            Some(alibi_head_slopes(num_heads))
        } else {
            None
        };

        // Only DeBERTa or T5 bias requires per-head processing.
        let needs_per_head =
            layer.rel_pos_embeddings.is_some() || layer.relative_attention_bias.is_some();

        let attn_output = if !needs_per_head && self.has_accelerator_backend() {
            // === Fused GPU attention: 4 ops in 1 command buffer ===
            // Q×K^T → scale+ALiBi+mask → softmax → scores×V
            let gpu = self.gpu.as_ref().ok_or_else(|| {
                InferError::BackendError("accelerator backend expected but absent".into())
            })?;
            let total_dim = num_heads * head_dim;

            // Reshape Q, K, V to head-major [num_heads, seq_len, head_dim]
            let q_data: Vec<f32> = q
                .as_slice()
                .map(|s| s.to_vec())
                .unwrap_or_else(|| q.iter().copied().collect());
            let k_data: Vec<f32> = k_full
                .as_slice()
                .map(|s| s.to_vec())
                .unwrap_or_else(|| k_full.iter().copied().collect());
            let v_data: Vec<f32> = v_full
                .as_slice()
                .map(|s| s.to_vec())
                .unwrap_or_else(|| v_full.iter().copied().collect());

            let mut q_flat = vec![0.0f32; num_heads * seq_len * head_dim];
            let mut k_flat = vec![0.0f32; num_heads * seq_len * head_dim];
            let mut v_flat = vec![0.0f32; num_heads * seq_len * head_dim];
            for s in 0..seq_len {
                for hd in 0..num_heads {
                    let src = s * total_dim + hd * head_dim;
                    let dst = hd * seq_len * head_dim + s * head_dim;
                    q_flat[dst..dst + head_dim].copy_from_slice(&q_data[src..src + head_dim]);
                    k_flat[dst..dst + head_dim].copy_from_slice(&k_data[src..src + head_dim]);
                    v_flat[dst..dst + head_dim].copy_from_slice(&v_data[src..src + head_dim]);
                }
            }

            // Build mask as u32 array
            let mask_u32: Vec<u32> = mask.to_vec();
            let alibi = alibi_slopes.as_deref().unwrap_or(&[]);

            // Single fused call: 4 GPU ops in 1 command buffer
            let out_flat = gpu.fused_attention(
                &q_flat, &k_flat, &v_flat, num_heads, seq_len, head_dim, scale, alibi, &mask_u32,
            )?;

            // Reshape back to [seq_len, num_heads * head_dim]
            let mut output = Array2::<f32>::zeros((seq_len, h));
            {
                let out_slice = output
                    .as_slice_mut()
                    .expect("freshly allocated Array2 is contiguous");
                for hd in 0..num_heads {
                    for s in 0..seq_len {
                        let src = hd * seq_len * head_dim + s * head_dim;
                        let dst = s * total_dim + hd * head_dim;
                        out_slice[dst..dst + head_dim]
                            .copy_from_slice(&out_flat[src..src + head_dim]);
                    }
                }
            }
            output
        } else {
            // === Per-head path for DeBERTa or non-GPU fallback ===
            let mut attn_out = Array2::<f32>::zeros((seq_len, h));
            for head in 0..num_heads {
                let offset = head * head_dim;
                let q_h = q.slice(s![.., offset..offset + head_dim]);
                let k_h = k_full.slice(s![.., offset..offset + head_dim]);
                let v_h = v_full.slice(s![.., offset..offset + head_dim]);

                let mut scores = q_h.dot(&k_h.t());
                scores *= scale;

                // DeBERTa disentangled attention
                if let Some(ref rel_emb) = layer.rel_pos_embeddings {
                    let max_rel = rel_emb.nrows() / 2;
                    for i in 0..seq_len {
                        for j in 0..seq_len {
                            let rel_pos =
                                (j as i32 - i as i32).clamp(-(max_rel as i32), max_rel as i32 - 1);
                            let idx = (rel_pos + max_rel as i32) as usize;
                            if idx < rel_emb.nrows() {
                                let mut c2p = 0.0f32;
                                let mut p2c = 0.0f32;
                                for d in 0..head_dim {
                                    let rel_d = rel_emb[[idx, offset + d]];
                                    c2p += q_h[[i, d]] * rel_d;
                                    p2c += rel_d * k_h[[j, d]];
                                }
                                scores[[i, j]] += (c2p + p2c) * scale;
                            }
                        }
                    }
                }

                // ALiBi
                if let Some(ref slopes) = alibi_slopes {
                    let slope = slopes[head];
                    for i in 0..seq_len {
                        for j in 0..seq_len {
                            scores[[i, j]] += slope * i.abs_diff(j) as f32;
                        }
                    }
                }

                // T5 relative position bias
                if let Some(ref bias_table) = layer.relative_attention_bias {
                    let n_heads = self.config.num_attention_heads;
                    let n_buckets = self.config.relative_attention_num_buckets;
                    let max_dist = self.config.relative_attention_max_distance;
                    for i in 0..seq_len {
                        for j in 0..seq_len {
                            let bucket = t5_relative_position_bucket(
                                j as i32 - i as i32,
                                n_buckets,
                                max_dist,
                                false,
                            );
                            if bucket < bias_table.nrows() && head < n_heads {
                                scores[[i, j]] += bias_table[[bucket, head]];
                            }
                        }
                    }
                }

                // Padding mask
                for i in 0..seq_len {
                    for j in 0..seq_len {
                        if mask[j] == 0 {
                            scores[[i, j]] = f32::NEG_INFINITY;
                        }
                    }
                }

                self.softmax(&mut scores)?;
                let head_out = scores.dot(&v_h);
                for i in 0..seq_len {
                    for j in 0..head_dim {
                        attn_out[[i, offset + j]] = head_out[[i, j]];
                    }
                }
            }
            attn_out
        };

        // Output projection + residual (GPU-accelerated matmul)
        let attn_projected = self.linear(
            &attn_output,
            &layer.attn_out_weight,
            layer.attn_out_bias.as_ref(),
        )?;
        let mut post_attn = hidden + &attn_projected;
        if !pre_ln {
            self.norm(
                &mut post_attn,
                &layer.norm1_weight,
                layer.norm1_bias.as_ref().or(Some(&Array1::zeros(h))),
                if use_rms { rms_eps } else { eps },
                use_rms,
            )?;
        }
        if dump_layer_enabled() {
            dump_hidden(
                "single",
                (layer_idx + 1) as i32,
                "attn",
                post_attn.as_slice().unwrap_or(&[]),
            );
        }

        // FFN
        let ffn_input = if pre_ln {
            let mut n = post_attn.clone();
            self.norm(
                &mut n,
                &layer.norm2_weight,
                layer.norm2_bias.as_ref().or(Some(&Array1::zeros(h))),
                if use_rms { rms_eps } else { eps },
                use_rms,
            )?;
            n
        } else {
            post_attn.clone()
        };

        let ffn_down = if let Some(ref gate_weight) = layer.ffn_gate_weight {
            // SwiGLU: silu(gate) * up (fused GPU FFN when no down-bias)
            self.ffn_swiglu(
                &ffn_input,
                gate_weight,
                layer.ffn_up_weight.as_ref().ok_or_else(|| {
                    InferError::ModelIncompatible("SwiGLU FFN requires ffn_up_weight".into())
                })?,
                &layer.ffn_down_weight,
                layer.ffn_down_bias.as_ref(),
            )?
        } else if let Some(ref up_gated_weight) = layer.ffn_up_gated_weight {
            let up_gated = self.linear(&ffn_input, up_gated_weight, None)?;
            let gated = if self.config.feed_forward_type == "reglu" {
                reglu_2d(&up_gated, self.config.intermediate_size)
            } else {
                geglu_2d(&up_gated, self.config.intermediate_size)
            };
            self.linear(&gated, &layer.ffn_down_weight, layer.ffn_down_bias.as_ref())?
        } else {
            let ffn_up = self.linear(
                &ffn_input,
                layer.ffn_up_weight.as_ref().ok_or_else(|| {
                    InferError::ModelIncompatible("FFN requires ffn_up_weight".into())
                })?,
                layer.ffn_up_bias.as_ref(),
            )?;
            let ffn_activated = self.gelu(&ffn_up)?;
            self.linear(
                &ffn_activated,
                &layer.ffn_down_weight,
                layer.ffn_down_bias.as_ref(),
            )?
        };

        let mut output = &post_attn + &ffn_down;
        if !pre_ln {
            self.norm(
                &mut output,
                &layer.norm2_weight,
                layer.norm2_bias.as_ref().or(Some(&Array1::zeros(h))),
                if use_rms { rms_eps } else { eps },
                use_rms,
            )?;
        }

        Ok(output)
    }

    // -----------------------------------------------------------------------
    // Decoder-only forward pass (single step for generation)
    // -----------------------------------------------------------------------

    /// Decoder forward: process `token_ids` through all layers with optional KV cache.
    /// Returns the hidden state [seq_len, hidden_size] after the final norm.
    fn decoder_forward(
        &self,
        token_ids: &[u32],
        cache: &mut KvCache,
        start_pos: usize,
    ) -> Result<Array2<f32>, InferError> {
        let h = self.config.hidden_size;
        let seq_len = token_ids.len();
        let _span = tracing::info_span!(
            "kin_infer.model.decoder_forward",
            seq_len = seq_len,
            start_pos = start_pos,
            hidden_size = h,
            backend = %self.backend()
        )
        .entered();

        // Embedding lookup (no position embeddings for RoPE models)
        let mut hidden = Array2::<f32>::zeros((seq_len, h));
        for (i, &id) in token_ids.iter().enumerate() {
            let word = self.weights.word_embeddings.row(id as usize);
            for j in 0..h {
                hidden[[i, j]] = word[j];
            }
            if let Some(ref pe) = self.weights.position_embeddings {
                let pos = start_pos + i;
                if pos < pe.nrows() {
                    for j in 0..h {
                        hidden[[i, j]] += pe[[pos, j]];
                    }
                }
            }
        }

        let num_heads = self.config.num_attention_heads;
        let num_kv_heads = self.config.effective_num_kv_heads();
        let head_dim = self.head_dim;
        let _kv_dim = num_kv_heads * head_dim;
        let eps = self.config.layer_norm_eps as f32;
        let rms_eps = self.config.effective_rms_eps();
        let use_rms = self.config.uses_rmsnorm();

        for (li, layer) in self.weights.layers.iter().enumerate() {
            let _layer_span = tracing::info_span!(
                "kin_infer.model.decoder_layer",
                layer_idx = li,
                seq_len = seq_len,
                cache_seq_len = cache.key[li].nrows() + seq_len
            )
            .entered();
            // Pre-LN (decoder-only models always use pre-LN)
            let mut normed = hidden.clone();
            self.norm(
                &mut normed,
                &layer.norm1_weight,
                layer.norm1_bias.as_ref().or(Some(&Array1::zeros(h))),
                if use_rms { rms_eps } else { eps },
                use_rms,
            )?;

            let (mut q, mut k, v) = self.project_qkv(&normed, layer, eps)?;

            // RoPE
            self.rope(&mut q, start_pos, seq_len, head_dim)?;
            self.rope(&mut k, start_pos, seq_len, head_dim)?;

            // KV cache
            let (k_full, v_full) = cache.append_kv(li, &k, &v)?;
            let kv_seq_len = k_full.nrows();

            // GQA: repeat K/V
            let (k_rep, v_rep) = if num_kv_heads < num_heads {
                (
                    repeat_kv(&k_full, num_kv_heads, num_heads),
                    repeat_kv(&v_full, num_kv_heads, num_heads),
                )
            } else {
                (k_full, v_full)
            };

            // Multi-head causal attention
            let scale = 1.0 / (head_dim as f32).sqrt();
            let mut attn_output = Array2::<f32>::zeros((seq_len, h));

            for head in 0..num_heads {
                let offset = head * head_dim;
                let q_h = q.slice(s![.., offset..offset + head_dim]);
                let k_h = k_rep.slice(s![.., offset..offset + head_dim]);
                let v_h = v_rep.slice(s![.., offset..offset + head_dim]);

                // Q × K^T (GPU-accelerated: matmul_transb)
                let mut scores = if let Some(ref gpu) = self.gpu {
                    let q_data: Vec<f32> = q_h.iter().copied().collect();
                    let k_data: Vec<f32> = k_h.iter().copied().collect();
                    let c = gpu.matmul(&q_data, &k_data, seq_len, kv_seq_len, head_dim)?;
                    Array2::from_shape_vec((seq_len, kv_seq_len), c)
                        .unwrap_or_else(|_| q_h.dot(&k_h.t()))
                } else {
                    q_h.dot(&k_h.t())
                };
                scores *= scale;

                // Causal mask
                for i in 0..seq_len {
                    for j in 0..kv_seq_len {
                        if j > start_pos + i {
                            scores[[i, j]] = f32::NEG_INFINITY;
                        }
                    }
                }

                self.softmax(&mut scores)?;
                // scores × V using GPU matmul with a transposed V buffer when available.
                let head_out = if let Some(ref gpu) = self.gpu {
                    let s_data: Vec<f32> = scores
                        .as_slice()
                        .map(|s| s.to_vec())
                        .unwrap_or_else(|| scores.iter().copied().collect());
                    let mut v_t = vec![0.0f32; head_dim * kv_seq_len];
                    for row in 0..kv_seq_len {
                        for col in 0..head_dim {
                            v_t[col * kv_seq_len + row] = v_h[[row, col]];
                        }
                    }
                    let c = gpu.matmul(&s_data, &v_t, seq_len, head_dim, kv_seq_len)?;
                    Array2::from_shape_vec((seq_len, head_dim), c)
                        .unwrap_or_else(|_| scores.dot(&v_h))
                } else {
                    scores.dot(&v_h)
                };
                for i in 0..seq_len {
                    for j in 0..head_dim {
                        attn_output[[i, offset + j]] = head_out[[i, j]];
                    }
                }
            }

            // Output projection + residual (GPU-accelerated)
            let attn_proj = self.linear(
                &attn_output,
                &layer.attn_out_weight,
                layer.attn_out_bias.as_ref(),
            )?;
            hidden = &hidden + &attn_proj;

            // Post-attention norm + FFN (GPU-accelerated)
            let mut normed2 = hidden.clone();
            self.norm(
                &mut normed2,
                &layer.norm2_weight,
                layer.norm2_bias.as_ref().or(Some(&Array1::zeros(h))),
                if use_rms { rms_eps } else { eps },
                use_rms,
            )?;

            let ffn_out = if let Some(ref gate_w) = layer.ffn_gate_weight {
                self.ffn_swiglu(
                    &normed2,
                    gate_w,
                    layer.ffn_up_weight.as_ref().ok_or_else(|| {
                        InferError::ModelIncompatible("FFN requires ffn_up_weight".into())
                    })?,
                    &layer.ffn_down_weight,
                    layer.ffn_down_bias.as_ref(),
                )?
            } else {
                let up = self.linear(
                    &normed2,
                    layer.ffn_up_weight.as_ref().ok_or_else(|| {
                        InferError::ModelIncompatible("FFN requires ffn_up_weight".into())
                    })?,
                    layer.ffn_up_bias.as_ref(),
                )?;
                let act = self.gelu(&up)?;
                self.linear(&act, &layer.ffn_down_weight, layer.ffn_down_bias.as_ref())?
            };

            hidden = &hidden + &ffn_out;
        }

        // Final norm (GPU-accelerated)
        if let Some(ref w) = self.weights.final_norm_weight {
            self.norm(
                &mut hidden,
                w,
                self.weights
                    .final_norm_bias
                    .as_ref()
                    .or(Some(&Array1::zeros(h))),
                if use_rms { rms_eps } else { eps },
                use_rms,
            )?;
        }

        Ok(hidden)
    }

    /// Project hidden states to vocabulary logits.
    fn lm_logits(&self, hidden: &Array2<f32>) -> Array2<f32> {
        if let Some(ref w) = self.weights.lm_head_weight {
            let mut out = hidden.dot(&w.t());
            if let Some(ref b) = self.weights.lm_head_bias {
                for mut row in out.rows_mut() {
                    row += b;
                }
            }
            out
        } else if self.config.tie_word_embeddings {
            // Tied embeddings: use word_embeddings as LM head
            hidden.dot(&self.weights.word_embeddings.t())
        } else {
            Array2::zeros((hidden.nrows(), self.config.vocab_size))
        }
    }

    /// Autoregressive text generation.
    pub fn generate(
        &self,
        prompt_ids: &[u32],
        max_tokens: usize,
        params: &mut SamplingParams,
    ) -> Result<Vec<u32>, InferError> {
        let _span = tracing::info_span!(
            "kin_infer.model.generate",
            prompt_len = prompt_ids.len(),
            max_tokens = max_tokens,
            backend = %self.backend()
        )
        .entered();
        let kv_dim = self.config.effective_num_kv_heads() * self.head_dim;
        let mut cache = KvCache::new(self.config.num_hidden_layers, kv_dim);
        let mut generated = Vec::with_capacity(max_tokens);
        let eos = self.config.eos_token_id.unwrap_or(u32::MAX);

        // Prefill: process entire prompt at once
        let hidden = self.decoder_forward(prompt_ids, &mut cache, 0)?;
        let logits = self.lm_logits(&hidden);
        let last_logits = logits.row(logits.nrows() - 1).to_owned();
        let token = sample_token(&last_logits, prompt_ids, &generated, params);
        generated.push(token);

        if token == eos {
            return Ok(generated);
        }

        // Decode: one token at a time
        for _ in 1..max_tokens {
            let pos = prompt_ids.len() + generated.len() - 1;
            let last = *generated
                .last()
                .ok_or_else(|| InferError::Internal("generation buffer empty".into()))?;
            let hidden = self.decoder_forward(&[last], &mut cache, pos)?;
            let logits = self.lm_logits(&hidden);
            let last_logits = logits.row(0).to_owned();
            let token = sample_token(&last_logits, prompt_ids, &generated, params);
            generated.push(token);
            if token == eos {
                break;
            }
        }

        Ok(generated)
    }
}

// ---------------------------------------------------------------------------
// RoPE (Rotary Position Embeddings)
// ---------------------------------------------------------------------------

fn precompute_rope(max_seq_len: usize, head_dim: usize, theta: f64) -> (Array2<f32>, Array2<f32>) {
    let half = head_dim / 2;
    let mut cos = Array2::<f32>::zeros((max_seq_len, head_dim));
    let mut sin = Array2::<f32>::zeros((max_seq_len, head_dim));
    for pos in 0..max_seq_len {
        for i in 0..half {
            let freq = (pos as f64) / theta.powf(2.0 * i as f64 / head_dim as f64);
            let c = freq.cos() as f32;
            let s = freq.sin() as f32;
            cos[[pos, i]] = c;
            cos[[pos, i + half]] = c;
            sin[[pos, i]] = s;
            sin[[pos, i + half]] = s;
        }
    }
    (cos, sin)
}

/// Apply RoPE rotation in-place to a [seq_len, total_dim] tensor.
fn apply_rope(
    x: &mut Array2<f32>,
    cos_table: &Array2<f32>,
    sin_table: &Array2<f32>,
    start_pos: usize,
    seq_len: usize,
    head_dim: usize,
) {
    let half = head_dim / 2;
    let total_dim = x.ncols();
    let num_heads = total_dim / head_dim;

    for pos in 0..seq_len {
        let abs_pos = start_pos + pos;
        if abs_pos >= cos_table.nrows() {
            continue;
        }
        for head in 0..num_heads {
            let offset = head * head_dim;
            for i in 0..half {
                let c = cos_table[[abs_pos, i]];
                let s = sin_table[[abs_pos, i]];
                let x0 = x[[pos, offset + i]];
                let x1 = x[[pos, offset + i + half]];
                x[[pos, offset + i]] = x0 * c - x1 * s;
                x[[pos, offset + i + half]] = x0 * s + x1 * c;
            }
        }
    }
}

fn gpu_apply_rope(
    x: &mut Array2<f32>,
    cos_table: &Array2<f32>,
    sin_table: &Array2<f32>,
    start_pos: usize,
    seq_len: usize,
    head_dim: usize,
    gpu: &dyn gpu::GpuCompute,
) -> Result<(), InferError> {
    let _span = tracing::info_span!(
        "kin_infer.gpu.apply_rope",
        rows = x.nrows(),
        cols = x.ncols(),
        start_pos = start_pos,
        seq_len = seq_len,
        head_dim = head_dim,
        backend = %gpu.backend()
    )
    .entered();
    let total_dim = x.ncols();
    let half = head_dim / 2;
    let max_rows = cos_table.nrows().min(sin_table.nrows());
    let actual_seq_len = max_rows.saturating_sub(start_pos).min(seq_len);
    if actual_seq_len == 0 {
        return Ok(());
    }

    if let Some(data) = x.as_slice_mut() {
        // Backends expect compact [seq_len, half_head_dim] tables.
        let mut cos_compact = Vec::with_capacity(actual_seq_len * half);
        let mut sin_compact = Vec::with_capacity(actual_seq_len * half);
        for pos in start_pos..start_pos + actual_seq_len {
            for d in 0..half {
                cos_compact.push(cos_table[[pos, d]]);
                sin_compact.push(sin_table[[pos, d]]);
            }
        }

        gpu.rope(
            data,
            &cos_compact,
            &sin_compact,
            0,
            actual_seq_len,
            head_dim,
            total_dim,
        )?;
    } else {
        apply_rope(x, cos_table, sin_table, start_pos, seq_len, head_dim);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// GQA / MQA (Grouped-Query / Multi-Query Attention)
// ---------------------------------------------------------------------------

/// Repeat K/V heads to match the number of Q heads for GQA.
fn repeat_kv(x: &Array2<f32>, num_kv_heads: usize, num_heads: usize) -> Array2<f32> {
    if num_kv_heads == num_heads {
        return x.clone();
    }
    let repeat = num_heads / num_kv_heads;
    let seq_len = x.nrows();
    let kv_head_dim = x.ncols() / num_kv_heads;
    let out_dim = num_heads * kv_head_dim;
    let mut out = Array2::<f32>::zeros((seq_len, out_dim));
    for kv_h in 0..num_kv_heads {
        let src_offset = kv_h * kv_head_dim;
        for r in 0..repeat {
            let dst_offset = (kv_h * repeat + r) * kv_head_dim;
            for i in 0..seq_len {
                for j in 0..kv_head_dim {
                    out[[i, dst_offset + j]] = x[[i, src_offset + j]];
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// T5 relative position bias
// ---------------------------------------------------------------------------

fn t5_relative_position_bucket(
    relative_position: i32,
    num_buckets: usize,
    max_distance: usize,
    bidirectional: bool,
) -> usize {
    let mut n_buckets = num_buckets;
    let mut offset = 0i32;
    let mut rel = relative_position;

    if bidirectional {
        n_buckets /= 2;
        if rel > 0 {
            offset = n_buckets as i32;
        } else {
            rel = -rel;
        }
    } else {
        rel = (-rel).max(0);
    }

    let max_exact = n_buckets / 2;
    let is_small = (rel as usize) < max_exact;

    let bucket = if is_small {
        rel as usize
    } else {
        let val = ((rel as f64 / max_exact as f64).ln()
            / (max_distance as f64 / max_exact as f64).ln()
            * (n_buckets - max_exact) as f64) as usize;
        max_exact + val.min(n_buckets - max_exact - 1)
    };

    (bucket as i32 + offset) as usize
}

// ---------------------------------------------------------------------------
// Token sampling
// ---------------------------------------------------------------------------

fn sample_token(
    logits: &Array1<f32>,
    prompt: &[u32],
    generated: &[u32],
    params: &mut SamplingParams,
) -> u32 {
    let mut scores: Vec<f32> = logits.to_vec();

    // Repetition penalty
    if params.repetition_penalty != 1.0 {
        let mut seen = std::collections::HashSet::new();
        for &t in prompt.iter().chain(generated.iter()) {
            seen.insert(t);
        }
        for &t in &seen {
            let idx = t as usize;
            if idx < scores.len() {
                if scores[idx] > 0.0 {
                    scores[idx] /= params.repetition_penalty;
                } else {
                    scores[idx] *= params.repetition_penalty;
                }
            }
        }
    }

    // Temperature
    if params.temperature != 1.0 && params.temperature > 0.0 {
        for s in &mut scores {
            *s /= params.temperature;
        }
    }

    // Greedy: temperature ~0 or RNG disabled
    if params.temperature < 1e-6 || params.rng_state == 0 {
        return scores
            .iter()
            .enumerate()
            .max_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(i, _)| i as u32)
            .unwrap_or(0);
    }

    // Top-k filtering
    let mut indexed: Vec<(usize, f32)> = scores.iter().copied().enumerate().collect();
    indexed.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    let k = params.top_k.min(indexed.len());
    indexed.truncate(k);

    // Top-p (nucleus) filtering: softmax over filtered set, then cumulative cutoff
    let max_score = indexed[0].1;
    let mut probs: Vec<(usize, f32)> = indexed
        .iter()
        .map(|&(i, s)| (i, (s - max_score).exp()))
        .collect();
    let sum: f32 = probs.iter().map(|(_, p)| p).sum();
    for (_, p) in &mut probs {
        *p /= sum;
    }
    let mut cumsum = 0.0;
    let mut cutoff = probs.len();
    for (i, &(_, p)) in probs.iter().enumerate() {
        cumsum += p;
        if cumsum >= params.top_p {
            cutoff = i + 1;
            break;
        }
    }
    probs.truncate(cutoff);

    // Renormalize
    let norm: f32 = probs.iter().map(|(_, p)| p).sum();
    if norm > 0.0 {
        for (_, p) in &mut probs {
            *p /= norm;
        }
    }

    // Stochastic sampling: weighted random selection via xorshift64
    let r = params.next_rand() as f32;
    let mut accum = 0.0f32;
    for &(idx, p) in &probs {
        accum += p;
        if r < accum {
            return idx as u32;
        }
    }
    // Fallback to last token in filtered set
    probs.last().map(|&(i, _)| i as u32).unwrap_or(0)
}

// ---------------------------------------------------------------------------
// ALiBi
// ---------------------------------------------------------------------------

fn alibi_head_slopes(n_heads: usize) -> Vec<f32> {
    fn slopes_power_of_two(n: usize) -> Vec<f32> {
        let start = 2f32.powf(-(2f32.powf(-(n as f32).log2() + 3.0)));
        let ratio = start;
        (0..n).map(|i| start * ratio.powi(i as i32)).collect()
    }
    let mut slopes = if (n_heads as f32).log2().fract() == 0.0 {
        slopes_power_of_two(n_heads)
    } else {
        let closest_power = 2usize.pow((n_heads as f32).log2().floor() as u32);
        let mut base = slopes_power_of_two(closest_power);
        let extended = alibi_head_slopes(closest_power * 2);
        base.extend(
            extended
                .into_iter()
                .step_by(2)
                .take(n_heads - closest_power),
        );
        base
    };
    for slope in &mut slopes {
        *slope *= -1.0;
    }
    slopes
}

// ---------------------------------------------------------------------------
// Math primitives
// ---------------------------------------------------------------------------

pub fn linear(x: &Array2<f32>, weight: &Array2<f32>, bias: &Array1<f32>) -> Array2<f32> {
    let mut out = x.dot(&weight.t());
    for mut row in out.rows_mut() {
        row += bias;
    }
    out
}

fn linear_without_bias(x: &Array2<f32>, weight: &Array2<f32>) -> Array2<f32> {
    x.dot(&weight.t())
}

fn build_fused_projection<const N: usize>(
    weights: [&Array2<f32>; N],
    biases: [Option<&Array1<f32>>; N],
) -> (Option<Array2<f32>>, Option<Array1<f32>>) {
    let Some(first) = weights.first() else {
        return (None, None);
    };
    let input_dim = first.ncols();
    if weights.iter().any(|weight| weight.ncols() != input_dim) {
        return (None, None);
    }

    let total_rows = weights.iter().map(|weight| weight.nrows()).sum();
    let mut fused_weight = Array2::<f32>::zeros((total_rows, input_dim));
    let mut fused_bias = if biases.iter().any(Option::is_some) {
        Some(Array1::<f32>::zeros(total_rows))
    } else {
        None
    };

    let mut row_start = 0usize;
    for (weight, bias) in weights.iter().zip(biases.iter()) {
        let row_end = row_start + weight.nrows();
        fused_weight
            .slice_mut(s![row_start..row_end, ..])
            .assign(weight);
        if let (Some(dst), Some(src)) = (fused_bias.as_mut(), bias.as_ref()) {
            dst.slice_mut(s![row_start..row_end]).assign(src);
        }
        row_start = row_end;
    }

    (Some(fused_weight), fused_bias)
}

/// GPU-accelerated linear: C = X × W^T using GpuCompute::matmul.
fn gpu_linear(
    x: &Array2<f32>,
    weight: &Array2<f32>,
    gpu: &dyn gpu::GpuCompute,
) -> Result<Array2<f32>, InferError> {
    let m = x.nrows();
    let k = x.ncols();
    let n = weight.nrows(); // weight is [N, K], we want X[M,K] × W^T[K,N] = [M,N]
                            // Borrow contiguous storage so persistent GPU weight caches can hit.
    let a_data: Cow<'_, [f32]> = x
        .as_slice()
        .map(Cow::Borrowed)
        .unwrap_or_else(|| Cow::Owned(x.iter().copied().collect()));
    let w_data: Cow<'_, [f32]> = weight
        .as_slice()
        .map(Cow::Borrowed)
        .unwrap_or_else(|| Cow::Owned(weight.iter().copied().collect()));
    let c = gpu.matmul(a_data.as_ref(), w_data.as_ref(), m, n, k)?;
    Ok(Array2::from_shape_vec((m, n), c).unwrap_or_else(|_| linear_without_bias(x, weight)))
}

fn linear_with_optional_bias(
    x: &Array2<f32>,
    weight: &Array2<f32>,
    bias: Option<&Array1<f32>>,
) -> Array2<f32> {
    let mut out = x.dot(&weight.t());
    if let Some(bias) = bias {
        for mut row in out.rows_mut() {
            row += bias;
        }
    }
    out
}

/// GPU-accelerated linear with optional bias.
fn gpu_linear_bias(
    x: &Array2<f32>,
    weight: &Array2<f32>,
    bias: Option<&Array1<f32>>,
    gpu: &dyn gpu::GpuCompute,
) -> Result<Array2<f32>, InferError> {
    let _span = tracing::info_span!(
        "kin_infer.gpu.linear_bias",
        rows = x.nrows(),
        input_dim = x.ncols(),
        output_dim = weight.nrows(),
        bias = bias.is_some(),
        backend = %gpu.backend()
    )
    .entered();
    let mut out = gpu_linear(x, weight, gpu)?;
    if let Some(bias) = bias {
        for mut row in out.rows_mut() {
            row += bias;
        }
    }
    Ok(out)
}

fn gpu_linear_many_bias(
    x: &Array2<f32>,
    projections: &[(&Array2<f32>, Option<&Array1<f32>>)],
    gpu: &dyn gpu::GpuCompute,
) -> Result<Vec<Array2<f32>>, InferError> {
    let _span = tracing::info_span!(
        "kin_infer.gpu.linear_many_bias",
        rows = x.nrows(),
        input_dim = x.ncols(),
        projection_count = projections.len(),
        backend = %gpu.backend()
    )
    .entered();
    if projections.is_empty() {
        return Ok(Vec::new());
    }

    let m = x.nrows();
    let k = x.ncols();

    let x_data: Cow<'_, [f32]> = x
        .as_slice()
        .map(Cow::Borrowed)
        .unwrap_or_else(|| Cow::Owned(x.iter().copied().collect()));
    let weight_data: Vec<Cow<'_, [f32]>> = projections
        .iter()
        .map(|(weight, _)| {
            weight
                .as_slice()
                .map(Cow::Borrowed)
                .unwrap_or_else(|| Cow::Owned(weight.iter().copied().collect()))
        })
        .collect();
    let weight_refs: Vec<&[f32]> = weight_data.iter().map(|data| data.as_ref()).collect();
    let ns: Vec<usize> = projections
        .iter()
        .map(|(weight, _)| weight.nrows())
        .collect();
    let outputs = gpu.matmul_many(x_data.as_ref(), &weight_refs, m, &ns, k)?;

    outputs
        .into_iter()
        .zip(projections.iter().zip(ns.iter().copied()))
        .map(|(out, (projection, n))| {
            let (_, bias) = *projection;
            let mut matrix = Array2::from_shape_vec((m, n), out).map_err(|e| {
                InferError::Internal(format!("gpu matmul_many output not {m}x{n}: {e}"))
            })?;
            if let Some(bias) = bias {
                for mut row in matrix.rows_mut() {
                    row += bias;
                }
            }
            Ok(matrix)
        })
        .collect()
}

/// LayerNorm: (x - mean) / sqrt(var + eps) * gamma + beta.
fn layer_norm_2d(x: &mut Array2<f32>, gamma: &Array1<f32>, beta: &Array1<f32>, eps: f32) {
    for mut row in x.rows_mut() {
        let len = row.len() as f32;
        let mean = row.sum() / len;
        let var = row.iter().map(|&v| (v - mean) * (v - mean)).sum::<f32>() / len;
        let inv_std = 1.0 / (var + eps).sqrt();
        for (i, v) in row.iter_mut().enumerate() {
            *v = (*v - mean) * inv_std * gamma[i] + beta[i];
        }
    }
}

/// GPU-accelerated LayerNorm.
fn gpu_layer_norm_2d(
    x: &mut Array2<f32>,
    gamma: &Array1<f32>,
    beta: &Array1<f32>,
    eps: f32,
    gpu: &dyn gpu::GpuCompute,
) -> Result<(), InferError> {
    let _span = tracing::info_span!(
        "kin_infer.gpu.layer_norm_2d",
        rows = x.nrows(),
        cols = x.ncols(),
        backend = %gpu.backend(),
        eps = eps
    )
    .entered();
    let rows = x.nrows();
    let cols = x.ncols();
    if let Some(data) = x.as_slice_mut() {
        let g = gamma
            .as_slice()
            .expect("norm weight is std-layout contiguous");
        let b = beta.as_slice().expect("norm bias is std-layout contiguous");
        gpu.layer_norm(data, g, b, rows, cols, eps)?;
    } else {
        layer_norm_2d(x, gamma, beta, eps);
    }
    Ok(())
}

/// RMSNorm: x * rsqrt(mean(x^2) + eps) * weight. No bias, no mean subtraction.
fn rms_norm_2d(x: &mut Array2<f32>, weight: &Array1<f32>, eps: f32) {
    for mut row in x.rows_mut() {
        let len = row.len() as f32;
        let rms = (row.iter().map(|&v| v * v).sum::<f32>() / len + eps).sqrt();
        let inv_rms = 1.0 / rms;
        for (i, v) in row.iter_mut().enumerate() {
            *v = *v * inv_rms * weight[i];
        }
    }
}

/// GPU-accelerated RMSNorm.
fn gpu_rms_norm_2d(
    x: &mut Array2<f32>,
    weight: &Array1<f32>,
    eps: f32,
    gpu: &dyn gpu::GpuCompute,
) -> Result<(), InferError> {
    let _span = tracing::info_span!(
        "kin_infer.gpu.rms_norm_2d",
        rows = x.nrows(),
        cols = x.ncols(),
        backend = %gpu.backend(),
        eps = eps
    )
    .entered();
    let rows = x.nrows();
    let cols = x.ncols();
    if let Some(data) = x.as_slice_mut() {
        let w = weight
            .as_slice()
            .expect("norm weight is std-layout contiguous");
        gpu.rms_norm(data, w, rows, cols, eps)?;
    } else {
        rms_norm_2d(x, weight, eps);
    }
    Ok(())
}

/// GPU-accelerated row-wise softmax.
fn gpu_softmax_rows(x: &mut Array2<f32>, gpu: &dyn gpu::GpuCompute) -> Result<(), InferError> {
    let _span = tracing::info_span!(
        "kin_infer.gpu.softmax_rows",
        rows = x.nrows(),
        cols = x.ncols(),
        backend = %gpu.backend()
    )
    .entered();
    let rows = x.nrows();
    let cols = x.ncols();
    if let Some(data) = x.as_slice_mut() {
        gpu.softmax(data, rows, cols)?;
    } else {
        softmax_rows(x);
    }
    Ok(())
}

// GELU constant kept at full precision (0.7978845608 = sqrt(2/π)) to document intent; f32 truncation is expected.
#[allow(clippy::excessive_precision)]
fn gelu(x: f32) -> f32 {
    x * 0.5 * (1.0 + (x * 0.7978845608 * (1.0 + 0.044715 * x * x)).tanh())
}

fn gelu_2d(x: &Array2<f32>) -> Array2<f32> {
    x.mapv(gelu)
}

fn gpu_gelu_2d(x: &Array2<f32>, gpu: &dyn gpu::GpuCompute) -> Result<Array2<f32>, InferError> {
    let mut out = x.to_owned();
    if let Some(data) = out.as_slice_mut() {
        gpu.gelu(data)?;
        Ok(out)
    } else {
        Ok(gelu_2d(x))
    }
}

/// SiLU (Sigmoid Linear Unit): x * sigmoid(x).
fn silu(x: f32) -> f32 {
    x / (1.0 + (-x).exp())
}

/// SwiGLU: silu(gate) * up. Both inputs are [seq_len, intermediate_size].
fn swiglu_2d(gate: &Array2<f32>, up: &Array2<f32>) -> Array2<f32> {
    let mut out = gate.mapv(silu);
    out *= up;
    out
}

fn gpu_swiglu_2d(
    gate: &Array2<f32>,
    up: &Array2<f32>,
    gpu: &dyn gpu::GpuCompute,
) -> Result<Array2<f32>, InferError> {
    let _span = tracing::info_span!(
        "kin_infer.gpu.swiglu_2d",
        rows = gate.nrows(),
        cols = gate.ncols(),
        backend = %gpu.backend()
    )
    .entered();
    let mut out = gate.to_owned();
    if let Some(data) = out.as_slice_mut() {
        gpu.silu(data)?;
    } else {
        return Ok(swiglu_2d(gate, up));
    }

    if let Some(up_data) = up.as_slice() {
        if let Some(out_data) = out.as_slice_mut() {
            gpu.elementwise_mul(out_data, up_data)?;
            return Ok(out);
        }
    }

    out *= up;
    Ok(out)
}

fn relu_2d(x: &Array2<f32>) -> Array2<f32> {
    x.mapv(|v| v.max(0.0))
}

fn gated_mlp_2d(
    x: &Array2<f32>,
    intermediate_size: usize,
    activation: fn(&Array2<f32>) -> Array2<f32>,
) -> Array2<f32> {
    let seq_len = x.nrows();
    let up = x.slice(s![.., 0..intermediate_size]).to_owned();
    let gate = x
        .slice(s![.., intermediate_size..intermediate_size * 2])
        .to_owned();
    let activated = activation(&gate);
    let mut out = Array2::<f32>::zeros((seq_len, intermediate_size));
    for i in 0..seq_len {
        for j in 0..intermediate_size {
            out[[i, j]] = up[[i, j]] * activated[[i, j]];
        }
    }
    out
}

fn geglu_2d(x: &Array2<f32>, intermediate_size: usize) -> Array2<f32> {
    gated_mlp_2d(x, intermediate_size, gelu_2d)
}

fn reglu_2d(x: &Array2<f32>, intermediate_size: usize) -> Array2<f32> {
    gated_mlp_2d(x, intermediate_size, relu_2d)
}

fn softmax_rows(x: &mut Array2<f32>) {
    for mut row in x.rows_mut() {
        let max = row.iter().cloned().fold(f32::NEG_INFINITY, f32::max);
        row.mapv_inplace(|v| (v - max).exp());
        let sum = row.sum();
        if sum > 0.0 {
            row /= sum;
        }
    }
}

fn mean_pool(hidden: &Array2<f32>, mask: &[u32]) -> Array1<f32> {
    let h = hidden.ncols();
    let mut sum = Array1::<f32>::zeros(h);
    let mut count = 0.0f32;
    for (i, &m) in mask.iter().enumerate() {
        if m != 0 {
            sum += &hidden.row(i);
            count += 1.0;
        }
    }
    if count > 0.0 {
        sum /= count;
    }
    sum
}

/// CLS pooling: the first-token ([CLS]) hidden state. Used by nomic_bert /
/// SweRank-style sentence encoders whose pooling layer selects the CLS token.
fn cls_pool(hidden: &Array2<f32>) -> Array1<f32> {
    if hidden.nrows() == 0 {
        return Array1::<f32>::zeros(hidden.ncols());
    }
    hidden.row(0).to_owned()
}

fn l2_normalize(v: &Array1<f32>) -> Array1<f32> {
    let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 1e-12 {
        v / norm
    } else {
        v.clone()
    }
}

/// Fail loud with a typed error if any output embedding contains a non-finite
/// value (NaN or ±Inf), so a corrupt vector can never silently reach the vector
/// index. Backend-agnostic and O(batch × dim) — negligible against the forward
/// pass — it catches a non-finite produced anywhere upstream at the kin-infer
/// output boundary instead of letting `l2_normalize` pass it through unchanged.
fn ensure_finite_embeddings(rows: &[Vec<f32>]) -> Result<(), InferError> {
    for (i, row) in rows.iter().enumerate() {
        if let Some(j) = row.iter().position(|x| !x.is_finite()) {
            return Err(InferError::NonFiniteOutput(format!(
                "embedding {i} dim {j} is {}; refusing to emit a corrupt vector",
                row[j]
            )));
        }
    }
    Ok(())
}

/// SIMD-accelerated dot product with platform-specific implementations.
pub fn dot_product(a: &[f32], b: &[f32]) -> f32 {
    #[cfg(target_arch = "aarch64")]
    {
        dot_product_neon(a, b)
    }
    #[cfg(all(
        target_arch = "x86_64",
        target_feature = "avx2",
        target_feature = "fma"
    ))]
    {
        // Safety: AVX2+FMA checked via target_feature cfg
        unsafe { dot_product_avx2(a, b) }
    }
    #[cfg(not(any(
        target_arch = "aarch64",
        all(
            target_arch = "x86_64",
            target_feature = "avx2",
            target_feature = "fma"
        )
    )))]
    {
        dot_product_scalar(a, b)
    }
}

/// ARM NEON dot product using intrinsics.
#[cfg(target_arch = "aarch64")]
fn dot_product_neon(a: &[f32], b: &[f32]) -> f32 {
    use std::arch::aarch64::*;
    let len = a.len();
    let chunks = len / 4;
    let mut sum;
    // Safety: NEON is always available on aarch64.
    unsafe {
        let mut acc = vdupq_n_f32(0.0);
        for i in 0..chunks {
            let off = i * 4;
            let va = vld1q_f32(a.as_ptr().add(off));
            let vb = vld1q_f32(b.as_ptr().add(off));
            acc = vfmaq_f32(acc, va, vb);
        }
        sum = vaddvq_f32(acc);
    }
    for i in (chunks * 4)..len {
        sum += a[i] * b[i];
    }
    sum
}

/// x86 AVX2+FMA dot product using intrinsics.
#[cfg(all(
    target_arch = "x86_64",
    target_feature = "avx2",
    target_feature = "fma"
))]
unsafe fn dot_product_avx2(a: &[f32], b: &[f32]) -> f32 {
    use std::arch::x86_64::*;
    let len = a.len();
    let chunks = len / 8;
    let mut acc = _mm256_setzero_ps();
    for i in 0..chunks {
        let off = i * 8;
        let va = _mm256_loadu_ps(a.as_ptr().add(off));
        let vb = _mm256_loadu_ps(b.as_ptr().add(off));
        acc = _mm256_fmadd_ps(va, vb, acc);
    }
    // Horizontal sum: 8 lanes -> 1 scalar
    let hi = _mm256_extractf128_ps(acc, 1);
    let lo = _mm256_castps256_ps128(acc);
    let sum128 = _mm_add_ps(lo, hi);
    let shuf = _mm_movehdup_ps(sum128);
    let sums = _mm_add_ps(sum128, shuf);
    let shuf2 = _mm_movehl_ps(sums, sums);
    let result = _mm_add_ss(sums, shuf2);
    let mut sum = _mm_cvtss_f32(result);
    for i in (chunks * 8)..len {
        sum += a[i] * b[i];
    }
    sum
}

/// Scalar fallback dot product.
#[allow(dead_code)]
fn dot_product_scalar(a: &[f32], b: &[f32]) -> f32 {
    a.iter().zip(b.iter()).map(|(x, y)| x * y).sum()
}

/// Configures the global Rayon pool so its workers run at an elevated QoS class
/// (performance cores) on macOS.
///
/// Safe to call repeatedly and from a host process whose global Rayon pool is
/// already initialized: `build_global` returns an error on a duplicate
/// initialization, which is intentionally ignored, so the call never panics or
/// errors and a pre-existing global pool is left untouched.
pub fn init_performance_threads() {
    let _ = rayon::ThreadPoolBuilder::new()
        .start_handler(|_| macos_qos::set_thread_qos_user_initiated())
        .build_global();
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    struct PooledOnlyGpu {
        calls: Arc<AtomicUsize>,
    }

    struct PooledOutputOverrideGuard;

    impl PooledOutputOverrideGuard {
        fn enabled() -> Self {
            set_pooled_output_test_override(Some(true));
            Self
        }
    }

    impl Drop for PooledOutputOverrideGuard {
        fn drop(&mut self) {
            set_pooled_output_test_override(None);
        }
    }

    impl PooledOnlyGpu {
        fn unexpected<T>(op: &str) -> Result<T, InferError> {
            Err(InferError::Internal(format!(
                "unexpected mock GPU call: {op}"
            )))
        }
    }

    impl gpu::GpuCompute for PooledOnlyGpu {
        fn matmul(
            &self,
            _a: &[f32],
            _b: &[f32],
            _m: usize,
            _n: usize,
            _k: usize,
        ) -> Result<Vec<f32>, InferError> {
            Self::unexpected("matmul")
        }

        fn batched_matmul(
            &self,
            _q: &[f32],
            _k: &[f32],
            _num_heads: usize,
            _seq_len: usize,
            _head_dim: usize,
        ) -> Result<Vec<f32>, InferError> {
            Self::unexpected("batched_matmul")
        }

        fn batched_attn_values(
            &self,
            _scores: &[f32],
            _v: &[f32],
            _num_heads: usize,
            _seq_len: usize,
            _head_dim: usize,
        ) -> Result<Vec<f32>, InferError> {
            Self::unexpected("batched_attn_values")
        }

        fn softmax(&self, _data: &mut [f32], _rows: usize, _cols: usize) -> Result<(), InferError> {
            Self::unexpected("softmax")
        }

        fn layer_norm(
            &self,
            _data: &mut [f32],
            _gamma: &[f32],
            _beta: &[f32],
            _rows: usize,
            _cols: usize,
            _eps: f32,
        ) -> Result<(), InferError> {
            Self::unexpected("layer_norm")
        }

        fn rms_norm(
            &self,
            _data: &mut [f32],
            _weight: &[f32],
            _rows: usize,
            _cols: usize,
            _eps: f32,
        ) -> Result<(), InferError> {
            Self::unexpected("rms_norm")
        }

        fn gelu(&self, _data: &mut [f32]) -> Result<(), InferError> {
            Self::unexpected("gelu")
        }

        fn silu(&self, _data: &mut [f32]) -> Result<(), InferError> {
            Self::unexpected("silu")
        }

        fn elementwise_mul(&self, _a: &mut [f32], _b: &[f32]) -> Result<(), InferError> {
            Self::unexpected("elementwise_mul")
        }

        fn rope(
            &self,
            _data: &mut [f32],
            _cos_table: &[f32],
            _sin_table: &[f32],
            _seq_offset: usize,
            _seq_len: usize,
            _head_dim: usize,
            _total_dim: usize,
        ) -> Result<(), InferError> {
            Self::unexpected("rope")
        }

        fn forward_layers_batched_pooled(
            &self,
            hidden: &[f32],
            masks: &[u32],
            layers: &[gpu::LayerTensors],
            config: &gpu::LayerConfig,
            embedding: &gpu::EmbeddingPrelude<'_>,
            _rope_cos: &[f32],
            _rope_sin: &[f32],
            pooling: gpu::PoolingMode,
        ) -> Result<Option<Vec<f32>>, InferError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            assert_eq!(config.batch_size, 1);
            assert_eq!(config.max_len, 2);
            assert_eq!(config.hidden_size, 2);
            assert_eq!(hidden.len(), 4);
            assert_eq!(masks, &[1, 1]);
            assert!(layers.is_empty());
            assert_eq!(embedding.input_dim, 2);
            assert!(embedding.projection.is_none());
            assert!(embedding.norm_weight.is_none());
            assert!(embedding.norm_bias.is_none());
            assert_eq!(pooling, gpu::PoolingMode::Mean);
            Ok(Some(vec![3.0, 4.0]))
        }

        fn backend(&self) -> gpu::GpuBackend {
            gpu::GpuBackend::Metal
        }

        fn device_name(&self) -> &str {
            "pooled-only-test"
        }
    }

    #[test]
    fn effective_max_seq_len_prefers_trained_range() {
        // Long-context RoPE model: the positional ceiling (n_positions) far
        // exceeds the trained range, so we must cap at the trained range.
        let json = r#"{
            "n_embd": 768, "n_layer": 12, "n_head": 12, "n_inner": 3072,
            "n_positions": 8192, "vocab_size": 30528, "max_trained_positions": 2048
        }"#;
        let config: BertConfig = serde_json::from_str(json).expect("parse config");
        assert_eq!(config.max_position_embeddings, 8192);
        assert_eq!(config.effective_max_seq_len(), 2048);
    }

    #[test]
    fn effective_max_seq_len_falls_back_to_positional_ceiling() {
        // No declared trained range → fall back to the positional ceiling.
        let json = r#"{
            "n_embd": 768, "n_layer": 12, "n_head": 12, "n_inner": 3072,
            "n_positions": 512, "vocab_size": 30528
        }"#;
        let config: BertConfig = serde_json::from_str(json).expect("parse config");
        assert_eq!(config.effective_max_seq_len(), 512);
    }

    #[test]
    fn effective_max_seq_len_never_exceeds_positional_ceiling() {
        // A trained range larger than the positional ceiling is clamped down so
        // we never index past addressable positions.
        let json = r#"{
            "n_embd": 768, "n_layer": 12, "n_head": 12, "n_inner": 3072,
            "n_positions": 1024, "vocab_size": 30528, "max_trained_positions": 4096
        }"#;
        let config: BertConfig = serde_json::from_str(json).expect("parse config");
        assert_eq!(config.effective_max_seq_len(), 1024);
    }

    /// Validate that the single-dispatch batched RoPE (`rope_qk_batched` →
    /// `rope_pair_batched`, used by `forward_batched`) is numerically identical to
    /// the proven per-element RoPE path (`rope_qk`, used by `forward`). Embeds the
    /// SAME inputs through both paths and asserts the embeddings match. Uses a real
    /// nomic_bert model (the RoPE arm) at /tmp/nomic; auto-skips if absent or if its
    /// config.json is not a parseable `BertConfig` (e.g. a modeling-code-only config).
    #[test]
    fn batched_rope_matches_per_element_forward() {
        let dir = std::path::Path::new("/tmp/nomic");
        if !dir.join("model.safetensors").exists() {
            eprintln!("SKIP: nomic model absent at /tmp/nomic; batched-RoPE parity test skipped.");
            return;
        }
        let cfg_json = std::fs::read_to_string(dir.join("config.json")).expect("read config.json");
        let config: BertConfig = match serde_json::from_str(&cfg_json) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("SKIP: /tmp/nomic config.json is not a parseable BertConfig ({e}).");
                return;
            }
        };
        let vocab = config.vocab_size.max(2);
        let model = BertModel::load(&dir.join("model.safetensors"), config).expect("load model");

        // Synthetic mixed-length batch (RoPE positions differ per length).
        let lens = [5usize, 17, 32, 48];
        let mut token_ids: Vec<Vec<u32>> = Vec::new();
        let mut masks: Vec<Vec<u32>> = Vec::new();
        for (i, &len) in lens.iter().enumerate() {
            let ids: Vec<u32> = (0..len)
                .map(|j| ((i * 131 + j * 7 + 3) % vocab) as u32)
                .collect();
            masks.push(vec![1u32; len]);
            token_ids.push(ids);
        }

        // Compare the SAME forward_batched path with single-dispatch RoPE vs the
        // per-element RoPE fallback (KIN_ROPE_PERELEM). This isolates MY batched
        // RoPE kernel from the legitimate forward-vs-forward_batched path/padding
        // differences and from the pre-existing shared-GPU nondeterminism — only
        // the RoPE dispatch strategy differs between the two runs here.
        std::env::set_var("KIN_ROPE_PERELEM", "1");
        let per_elem = model
            .forward_batched(&token_ids, &masks)
            .expect("forward_batched perelem");
        std::env::remove_var("KIN_ROPE_PERELEM");
        let batched = model
            .forward_batched(&token_ids, &masks)
            .expect("forward_batched single");

        assert_eq!(per_elem.len(), batched.len(), "embedding count mismatch");
        let mut max_abs = 0.0f32;
        let mut min_cos = 1.0f32;
        for (a, b) in per_elem.iter().zip(batched.iter()) {
            assert_eq!(a.len(), b.len(), "embedding dim mismatch");
            let mut dot = 0.0f32;
            let (mut na, mut nb) = (0.0f32, 0.0f32);
            for (&x, &y) in a.iter().zip(b.iter()) {
                max_abs = max_abs.max((x - y).abs());
                dot += x * y;
                na += x * x;
                nb += y * y;
            }
            let cos = dot / (na.sqrt() * nb.sqrt()).max(1e-12);
            min_cos = min_cos.min(cos);
        }
        eprintln!(
            "[batched-rope parity] max_abs_err={max_abs:.3e}  min_cosine={min_cos:.12}  ({} embeddings)",
            per_elem.len()
        );
        assert!(
            min_cos >= 1.0 - 1e-5,
            "batched RoPE diverges from per-element: min_cosine={min_cos} (max_abs={max_abs})"
        );
    }

    /// Regression for the cold-start batched-embedding corruption.
    ///
    /// `forward_layer_batched` built the fused `[gate|up]` FFN weight under the
    /// SAME `concat_cache` key as the per-op `fused_ffn_swiglu`, but with a
    /// DIFFERENT (block-interleaved) byte layout. Whichever path populated the key
    /// first won; the other read a wrong-layout weight and produced an embedding
    /// orthogonal to ground truth (cosine ~0). It stayed hidden because the daemon
    /// usually ran a single `forward` first, seeding the correct layout — but a
    /// cold batched embed (no prior single forward) was garbage, and which path
    /// ran first varied per process, so the same text drifted across restarts.
    ///
    /// Two SEPARATE model instances give independent concat caches: `model_cold`
    /// runs the batched path with a genuinely cold cache (no prior single forward),
    /// while `model_ref` provides the always-correct single-`forward` reference.
    /// The target also rides a much longer filler so the batch pads it wide,
    /// folding the batch-invariance check into the same assertion. The two must be
    /// BYTE-IDENTICAL.
    #[test]
    fn batched_cold_matches_single_forward() {
        let dir = std::path::Path::new("/tmp/nomic");
        if !dir.join("model.safetensors").exists() {
            eprintln!("SKIP: nomic model absent at /tmp/nomic; cold-batched regression skipped.");
            return;
        }
        let cfg_json = std::fs::read_to_string(dir.join("config.json")).expect("read config.json");
        let load = || {
            let config: BertConfig = serde_json::from_str(&cfg_json).expect("parse config.json");
            BertModel::load(&dir.join("model.safetensors"), config).expect("load model")
        };
        let model_cold = load();
        let model_ref = load();
        let vocab = serde_json::from_str::<BertConfig>(&cfg_json)
            .unwrap()
            .vocab_size
            .max(2);

        let target: Vec<u32> = (0..50).map(|j| ((37 + j * 7) % vocab) as u32).collect();
        let tmask = vec![1u32; target.len()];
        // Long filler (len 96) forces the target to pad wide in the batched call.
        let filler: Vec<u32> = (0..96).map(|j| ((11 + j * 13) % vocab) as u32).collect();
        let fmask = vec![1u32; filler.len()];

        // Cold batched FIRST on a fresh instance: no prior single forward seeded the
        // shared concat cache, so the batched path must build the correct layout
        // itself. result[0] is the target's embedding (input order is preserved).
        let batched = model_cold
            .forward_batched(&[target.clone(), filler], &[tmask.clone(), fmask])
            .expect("cold forward_batched")
            .remove(0);
        // Always-correct single-sequence reference on a separate instance.
        let reference = model_ref
            .forward(std::slice::from_ref(&target), std::slice::from_ref(&tmask))
            .expect("forward reference")
            .remove(0);

        let (mut dot, mut na, mut nb, mut max_abs) = (0.0f64, 0.0f64, 0.0f64, 0.0f32);
        for (&x, &y) in reference.iter().zip(batched.iter()) {
            dot += x as f64 * y as f64;
            na += (x as f64).powi(2);
            nb += (y as f64).powi(2);
            max_abs = max_abs.max((x - y).abs());
        }
        let cos = dot / (na.sqrt() * nb.sqrt()).max(1e-12);
        let identical: bool = reference
            .iter()
            .zip(batched.iter())
            .all(|(a, b)| a.to_bits() == b.to_bits());
        let is_metal = format!("{:?}", model_cold.backend()) == "Metal";
        eprintln!(
            "[cold-batched regression] backend_metal={is_metal} byte_identical={identical} \
             cosine={cos:.12} max_abs={max_abs:.3e}"
        );
        // Correctness floor (any backend): the layout-collision bug makes the cold
        // batched embedding orthogonal to ground truth (cosine ~0). A tolerance well
        // above the CPU's legitimate ~1e-7 single-vs-batched reduction-order drift
        // still fails hard on the ~0 bug.
        assert!(
            cos >= 1.0 - 1e-5,
            "cold batched embedding diverged from single forward: cosine={cos:.12} \
             max_abs={max_abs:.3e} (a ~0 cosine is the concat-cache layout-collision bug)"
        );
        // Determinism guarantee (Metal): a cold batched embed must be BYTE-IDENTICAL
        // to the single forward — that bit-equality across the batched/single split is
        // what keeps a text's embedding stable across daemon restarts.
        if is_metal {
            assert!(
                identical,
                "Metal cold batched embedding is not byte-identical to single forward: \
                 cosine={cos:.12} max_abs={max_abs:.3e}"
            );
        }
    }

    /// Guard for batch-SIZE / batch-COMPOSITION invariance of a single entity's
    /// embedding — the sibling of `batched_cold_matches_single_forward` (which
    /// guards padding-LAYOUT invariance via the concat-cache fix).
    ///
    /// Motivation: the GEMM kernel is *selected* by a batch-derived dimension. In
    /// the batched path the projection/FFN GEMMs gate on `use_mma(m = total_rows)`
    /// where `total_rows = batch_size * max_len`, and attention gates on
    /// `use_mma(m = max_len)`; `use_mma` flips the scalar tile → simdgroup MMA at
    /// `m >= 32`. So a short text crosses the scalar↔MMA boundary as its batch
    /// grows or as a longer neighbor widens `max_len`. The two kernels reduce over
    /// K differently, so if they ever disagree, the SAME text would get a
    /// last-bit-different vector depending only on the batch it rode in — exactly
    /// the kind of run-to-run drift the freeze must not have.
    ///
    /// A 12-token target is embedded alone (per-op single `forward`) and then under
    /// a battery of batched compositions that straddle the threshold on the
    /// projection axis (n copies → total_rows 12→96) and the attention axis (long
    /// fillers → max_len 12→60). Every config's target vector must be BYTE-IDENTICAL
    /// to the lone-forward baseline on Metal (a strict determinism guarantee), and
    /// cosine-identical on any backend. This locks today's good behavior so a future
    /// flip of `KIN_INFER_MMA_WIDE` / `KIN_INFER_GEMM_FP16` / steel, or any edit to
    /// the `use_mma` shape floor, cannot silently reintroduce batch-dependence.
    // Test-local config table: inline tuple type is clearer than an alias for a one-off fixture.
    #[allow(clippy::type_complexity)]
    #[test]
    fn embedding_is_invariant_to_batch_size_and_composition() {
        let dir = std::path::Path::new("/tmp/nomic");
        if !dir.join("model.safetensors").exists() {
            eprintln!(
                "SKIP: nomic model absent at /tmp/nomic; batch-size invariance guard skipped."
            );
            return;
        }
        let cfg_json = std::fs::read_to_string(dir.join("config.json")).expect("read config.json");
        let config: BertConfig = serde_json::from_str(&cfg_json).expect("parse config.json");
        let model = BertModel::load(&dir.join("model.safetensors"), config).expect("load model");
        let vocab = model.config.vocab_size.max(2);

        // 12-token target: BELOW the m>=32 MMA floor when alone, crosses it as the
        // batch grows. A filler of length `len` (deterministic, content-distinct).
        let synth = |len: usize, salt: u32| -> (Vec<u32>, Vec<u32>) {
            let ids: Vec<u32> = (0..len)
                .map(|i| {
                    1 + ((i as u32)
                        .wrapping_mul(2654435761)
                        .wrapping_add(salt.wrapping_mul(40503))
                        % (vocab as u32 - 1))
                })
                .collect();
            (ids, vec![1u32; len])
        };
        let (target, tmask) = synth(12, 7);

        // Baseline: lone single `forward` (per-op path, m = seq_len = 12 → scalar).
        let baseline = model
            .forward(std::slice::from_ref(&target), std::slice::from_ref(&tmask))
            .expect("forward baseline")
            .remove(0);

        let is_metal = format!("{:?}", model.backend()) == "Metal";

        // (label, batch). Target is always index 0; the rest only shape total_rows /
        // max_len so the target straddles the scalar↔MMA threshold on each axis.
        let configs: Vec<(&str, Vec<(Vec<u32>, Vec<u32>)>)> = vec![
            ("n2_same", vec![(target.clone(), tmask.clone()); 2]), // total_rows 24, scalar
            ("n3_same", vec![(target.clone(), tmask.clone()); 3]), // total_rows 36, proj→MMA
            ("n8_same", vec![(target.clone(), tmask.clone()); 8]), // total_rows 96, proj MMA
            (
                "filler20",
                vec![(target.clone(), tmask.clone()), synth(20, 101)],
            ), // max_len 20 (attn scalar), proj MMA
            (
                "filler40",
                vec![(target.clone(), tmask.clone()), synth(40, 102)],
            ), // max_len 40 → attn MMA too
            (
                "filler60",
                vec![(target.clone(), tmask.clone()), synth(60, 103)],
            ), // max_len 60, both MMA
        ];

        for (label, batch) in &configs {
            let ids: Vec<Vec<u32>> = batch.iter().map(|(i, _)| i.clone()).collect();
            let masks: Vec<Vec<u32>> = batch.iter().map(|(_, m)| m.clone()).collect();
            let out = model
                .forward_batched(&ids, &masks)
                .unwrap_or_else(|e| panic!("forward_batched {label}: {e:?}"));
            let got = &out[0]; // target is index 0
            assert_eq!(got.len(), baseline.len(), "{label}: embedding dim mismatch");

            let (mut dot, mut na, mut nb, mut max_abs) = (0.0f64, 0.0f64, 0.0f64, 0.0f32);
            let mut byte_identical = true;
            for (&a, &b) in baseline.iter().zip(got.iter()) {
                if a.to_bits() != b.to_bits() {
                    byte_identical = false;
                }
                dot += a as f64 * b as f64;
                na += (a as f64).powi(2);
                nb += (b as f64).powi(2);
                max_abs = max_abs.max((a - b).abs());
            }
            let cos = dot / (na.sqrt() * nb.sqrt()).max(1e-12);
            eprintln!(
                "[batch-size invariance] {label:<9} byte_identical={byte_identical} \
                 cosine={cos:.12} max_abs={max_abs:.3e}"
            );

            // Any backend: the target must not change with the batch it rides in.
            assert!(
                cos >= 1.0 - 1e-5,
                "{label}: embedding drifted with batch composition (cosine={cos:.12}, \
                 max_abs={max_abs:.3e}) — a batch-dependent kernel divergence"
            );
            // Metal: the freeze's determinism guarantee is BYTE equality across the
            // scalar↔MMA threshold and the single↔batched code-path split.
            if is_metal {
                assert!(
                    byte_identical,
                    "{label}: Metal embedding is not byte-identical to the lone forward \
                     (cosine={cos:.12}, max_abs={max_abs:.3e}) — batch-size-dependent kernel \
                     selection reintroduced last-bit drift"
                );
            }
        }
    }

    /// Batch-composition parity gate for length-bucketed batching.
    ///
    /// Asserts that per-entity embeddings are bit-identical (Metal) or
    /// cosine ≥ 1 − 1e-5 (all backends) regardless of how inputs are batched:
    ///
    ///   (a) `encode_batched` called directly on the full mixed set (post-fix:
    ///       auto-bucketed internally; KIN_INFER_BUCKET=0 exercises the legacy
    ///       global-max-len path in a separate run)
    ///   (b) `encode_batched` per coarse length bin + `pool_and_normalize`
    ///       (cross-check: mirrors the per-group sub-calls encode_batched now
    ///       performs internally for multi-bin batches)
    ///   (c) `forward` one entity at a time (canonical per-op reference)
    ///
    /// Corpus mixes short entities (len 20, bin 64) with a long one (len 200,
    /// bin 256): in the legacy path all four pad to max_len = 200; after the
    /// fix shorts pad only to 20. This is the docstring-heavy pattern that
    /// collapsed sympy throughput to 8 ents/s and motivated this regression
    /// coverage.
    ///
    /// Requires `/tmp/nomic` (model.safetensors + config.json); skips if absent.
    #[test]
    fn bucket_composition_parity() {
        let dir = std::path::Path::new("/tmp/nomic");
        if !dir.join("model.safetensors").exists() {
            eprintln!(
                "SKIP: nomic model absent at /tmp/nomic; bucket-composition parity test skipped."
            );
            return;
        }
        let cfg_json = std::fs::read_to_string(dir.join("config.json")).expect("read config.json");
        let config: BertConfig = match serde_json::from_str(&cfg_json) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("SKIP: /tmp/nomic config.json is not a parseable BertConfig ({e}).");
                return;
            }
        };
        let model = BertModel::load(&dir.join("model.safetensors"), config).expect("load model");
        let vocab = model.config.vocab_size.max(2);
        let is_metal = format!("{:?}", model.backend()) == "Metal";

        let synth = |len: usize, salt: u32| -> (Vec<u32>, Vec<u32>) {
            let ids: Vec<u32> = (0..len)
                .map(|i| {
                    1 + ((i as u32)
                        .wrapping_mul(2654435761)
                        .wrapping_add(salt.wrapping_mul(40503))
                        % (vocab as u32 - 1))
                })
                .collect();
            (ids, vec![1u32; len])
        };

        // 3 short (len 20, bin 64) + 1 long (len 200, bin 256).
        let corpus: Vec<(Vec<u32>, Vec<u32>)> =
            vec![synth(20, 1), synth(20, 2), synth(20, 3), synth(200, 4)];
        let n = corpus.len();
        let all_ids: Vec<Vec<u32>> = corpus.iter().map(|(ids, _)| ids.clone()).collect();
        let all_masks: Vec<Vec<u32>> = corpus.iter().map(|(_, m)| m.clone()).collect();

        // (c) Canonical reference: one entity at a time.
        let single: Vec<Vec<f32>> = corpus
            .iter()
            .map(|(ids, mask)| {
                model
                    .forward(std::slice::from_ref(ids), std::slice::from_ref(mask))
                    .expect("single forward")
                    .remove(0)
            })
            .collect();

        // (a) encode_batched called directly on the full mixed batch: post-fix this
        // auto-bucketed internally (shorts pad only to 20, not 200).
        let (hidden_mixed, masks_mixed, max_len_mixed) = model
            .encode_batched(&all_ids, &all_masks)
            .expect("encode_batched mixed");
        let encode_batched_direct =
            model.pool_and_normalize(&hidden_mixed, &masks_mixed, max_len_mixed);

        // (b) Per-bucket: group by length_bin, encode each bucket, reassemble.
        let bin_of = |l: usize| -> usize {
            const BINS: [usize; 5] = [64, 128, 256, 512, 1024];
            for &b in &BINS {
                if l <= b {
                    return b;
                }
            }
            2048
        };
        let mut groups: std::collections::BTreeMap<usize, Vec<usize>> =
            std::collections::BTreeMap::new();
        for (i, (ids, _)) in corpus.iter().enumerate() {
            groups.entry(bin_of(ids.len())).or_default().push(i);
        }
        let mut per_bucket: Vec<Vec<f32>> = vec![Vec::new(); n];
        for indices in groups.values() {
            let g_ids: Vec<Vec<u32>> = indices.iter().map(|&i| corpus[i].0.clone()).collect();
            let g_masks: Vec<Vec<u32>> = indices.iter().map(|&i| corpus[i].1.clone()).collect();
            let (h, m, ml) = model
                .encode_batched(&g_ids, &g_masks)
                .expect("encode_batched per-bucket");
            let pooled = model.pool_and_normalize(&h, &m, ml);
            for (slot, &orig) in indices.iter().enumerate() {
                per_bucket[orig] = pooled[slot].clone();
            }
        }

        // Assert bit-identical (Metal) / cosine-identical (all) vs single-forward.
        for i in 0..n {
            let baseline = &single[i];
            for (label, got) in [
                ("encode-batched-direct", &encode_batched_direct[i]),
                ("per-bucket", &per_bucket[i]),
            ] {
                assert_eq!(
                    baseline.len(),
                    got.len(),
                    "entity {i} ({label}): embedding dim mismatch"
                );
                let mut byte_identical = true;
                let (mut dot, mut na, mut nb) = (0.0f64, 0.0f64, 0.0f64);
                let mut max_abs = 0.0f32;
                for (&x, &y) in baseline.iter().zip(got.iter()) {
                    if x.to_bits() != y.to_bits() {
                        byte_identical = false;
                    }
                    dot += x as f64 * y as f64;
                    na += (x as f64).powi(2);
                    nb += (y as f64).powi(2);
                    max_abs = max_abs.max((x - y).abs());
                }
                let cos = dot / (na.sqrt() * nb.sqrt()).max(1e-12);
                eprintln!(
                    "[bucket-parity] entity {i} ({label}): byte_identical={byte_identical} \
                     cosine={cos:.12} max_abs={max_abs:.3e}"
                );
                assert!(
                    cos >= 1.0 - 1e-5,
                    "entity {i} ({label}): drifted from single-forward reference \
                     (cosine={cos:.12}, max_abs={max_abs:.3e})"
                );
                if is_metal {
                    assert!(
                        byte_identical,
                        "entity {i} ({label}): Metal result not byte-identical to single-forward \
                         (cosine={cos:.12}, max_abs={max_abs:.3e})"
                    );
                }
            }
        }
    }

    #[test]
    fn test_gelu_zero() {
        assert!((gelu(0.0) - 0.0).abs() < 1e-6);
    }

    #[test]
    fn test_gelu_positive() {
        assert!((gelu(1.0) - 0.8413).abs() < 0.01);
    }

    #[test]
    fn test_silu() {
        assert!((silu(0.0) - 0.0).abs() < 1e-6);
        // silu(1.0) = 1.0 / (1 + e^-1) ~ 0.7311
        assert!((silu(1.0) - 0.7311).abs() < 0.01);
        // silu(-1.0) = -1.0 / (1 + e^1) ~ -0.2689
        assert!((silu(-1.0) - (-0.2689)).abs() < 0.01);
    }

    #[test]
    fn test_layer_norm() {
        let mut x = Array2::from_shape_vec((1, 4), vec![1.0, 2.0, 3.0, 4.0]).unwrap();
        let gamma = Array1::ones(4);
        let beta = Array1::zeros(4);
        layer_norm_2d(&mut x, &gamma, &beta, 1e-5);
        let row = x.row(0);
        let mean: f32 = row.sum() / 4.0;
        assert!(mean.abs() < 1e-5);
    }

    #[test]
    fn test_rms_norm() {
        let mut x = Array2::from_shape_vec((1, 4), vec![1.0, 2.0, 3.0, 4.0]).unwrap();
        let weight = Array1::ones(4);
        rms_norm_2d(&mut x, &weight, 1e-6);
        // RMS of [1,2,3,4] = sqrt((1+4+9+16)/4) = sqrt(7.5) ~ 2.7386
        // After norm: each val / rms
        let rms = (30.0f32 / 4.0).sqrt();
        assert!((x[[0, 0]] - 1.0 / rms).abs() < 1e-4);
        assert!((x[[0, 3]] - 4.0 / rms).abs() < 1e-4);
    }

    #[test]
    fn test_softmax() {
        let mut x = Array2::from_shape_vec((1, 3), vec![1.0, 2.0, 3.0]).unwrap();
        softmax_rows(&mut x);
        let row = x.row(0);
        let sum: f32 = row.sum();
        assert!((sum - 1.0).abs() < 1e-5);
        assert!(row[0] < row[1]);
        assert!(row[1] < row[2]);
    }

    #[test]
    fn test_l2_normalize() {
        let v = Array1::from(vec![3.0, 4.0]);
        let n = l2_normalize(&v);
        let norm: f32 = n.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-5);
        assert!((n[0] - 0.6).abs() < 1e-5);
        assert!((n[1] - 0.8).abs() < 1e-5);
    }

    #[test]
    fn ensure_finite_embeddings_passes_clean_output() {
        let rows = vec![vec![0.1, -0.2, 0.3], vec![1.0, 2.0, 3.0]];
        assert!(ensure_finite_embeddings(&rows).is_ok());
        // Zero vector (degenerate but finite) is allowed through.
        assert!(ensure_finite_embeddings(&[vec![0.0; 4]]).is_ok());
        assert!(ensure_finite_embeddings(&[]).is_ok());
    }

    #[test]
    fn ensure_finite_embeddings_rejects_nonfinite() {
        for bad in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            let rows = vec![vec![0.1, 0.2, 0.3], vec![0.4, bad, 0.6]];
            let err = ensure_finite_embeddings(&rows).unwrap_err();
            match err {
                InferError::NonFiniteOutput(msg) => {
                    assert!(msg.contains("embedding 1 dim 1"), "msg: {msg}");
                }
                other => panic!("expected NonFiniteOutput, got {other:?}"),
            }
        }
    }

    #[test]
    fn test_mean_pool_with_mask() {
        let hidden = Array2::from_shape_vec((3, 2), vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0]).unwrap();
        let mask = vec![1, 1, 0];
        let pooled = mean_pool(&hidden, &mask);
        assert!((pooled[0] - 2.0).abs() < 1e-5);
        assert!((pooled[1] - 3.0).abs() < 1e-5);
    }

    #[test]
    fn test_linear() {
        let x = Array2::from_shape_vec((1, 2), vec![3.0, 4.0]).unwrap();
        let w = Array2::eye(2);
        let b = Array1::zeros(2);
        let out = linear(&x, &w, &b);
        assert!((out[[0, 0]] - 3.0).abs() < 1e-5);
        assert!((out[[0, 1]] - 4.0).abs() < 1e-5);
    }

    #[test]
    fn test_build_fused_projection_matches_individual_linears() {
        let x = Array2::from_shape_vec((2, 3), vec![1.0, -2.0, 0.5, 0.25, 1.5, -1.0]).unwrap();
        let q_weight =
            Array2::from_shape_vec((2, 3), vec![1.0, 0.0, -1.0, 0.5, 0.25, 0.75]).unwrap();
        let k_weight = Array2::from_shape_vec((1, 3), vec![0.2, -0.4, 0.6]).unwrap();
        let v_weight = Array2::from_shape_vec((2, 3), vec![0.3, 0.1, 0.9, -0.5, 0.8, 0.4]).unwrap();
        let q_bias = Array1::from(vec![0.1, -0.2]);
        let v_bias = Array1::from(vec![0.05, 0.15]);

        let (fused_weight, fused_bias) = build_fused_projection(
            [&q_weight, &k_weight, &v_weight],
            [Some(&q_bias), None, Some(&v_bias)],
        );
        let fused = linear_with_optional_bias(&x, &fused_weight.unwrap(), fused_bias.as_ref());

        let q_end = q_weight.nrows();
        let k_end = q_end + k_weight.nrows();
        let fused_q = fused.slice(s![.., 0..q_end]).to_owned();
        let fused_k = fused.slice(s![.., q_end..k_end]).to_owned();
        let fused_v = fused.slice(s![.., k_end..]).to_owned();

        let q = linear_with_optional_bias(&x, &q_weight, Some(&q_bias));
        let k = linear_with_optional_bias(&x, &k_weight, None);
        let v = linear_with_optional_bias(&x, &v_weight, Some(&v_bias));

        assert_eq!(fused_q, q);
        assert_eq!(fused_k, k);
        assert_eq!(fused_v, v);
    }

    #[test]
    fn test_rope_rotation() {
        let head_dim = 4;
        let (cos, sin) = precompute_rope(8, head_dim, 10000.0);
        // Position 0 should have cos=1, sin=0 for all frequencies
        assert!((cos[[0, 0]] - 1.0).abs() < 1e-5);
        assert!(sin[[0, 0]].abs() < 1e-5);
        // Position > 0 should rotate
        assert!(cos[[1, 0]] < 1.0);
        assert!(sin[[1, 0]] > 0.0);
    }

    #[test]
    fn test_rope_preserves_norm() {
        let head_dim = 4;
        let (cos, sin) = precompute_rope(8, head_dim, 10000.0);
        let mut x = Array2::from_shape_vec((1, 4), vec![1.0, 0.0, 0.0, 1.0]).unwrap();
        let norm_before: f32 = x.iter().map(|v| v * v).sum::<f32>().sqrt();
        apply_rope(&mut x, &cos, &sin, 3, 1, head_dim);
        let norm_after: f32 = x.iter().map(|v| v * v).sum::<f32>().sqrt();
        assert!((norm_before - norm_after).abs() < 1e-5);
    }

    #[test]
    fn test_gqa_repeat_kv() {
        // 2 KV heads -> 4 Q heads (repeat=2)
        let x = Array2::from_shape_vec(
            (1, 4), // 2 heads * head_dim=2
            vec![1.0, 2.0, 3.0, 4.0],
        )
        .unwrap();
        let repeated = repeat_kv(&x, 2, 4);
        assert_eq!(repeated.ncols(), 8); // 4 heads * head_dim=2
                                         // Head 0 and 1 should be copies of KV head 0
        assert!((repeated[[0, 0]] - 1.0).abs() < 1e-6);
        assert!((repeated[[0, 2]] - 1.0).abs() < 1e-6);
        // Head 2 and 3 should be copies of KV head 1
        assert!((repeated[[0, 4]] - 3.0).abs() < 1e-6);
        assert!((repeated[[0, 6]] - 3.0).abs() < 1e-6);
    }

    #[test]
    fn test_swiglu() {
        let gate = Array2::from_shape_vec((1, 2), vec![0.0, 1.0]).unwrap();
        let up = Array2::from_shape_vec((1, 2), vec![2.0, 3.0]).unwrap();
        let out = swiglu_2d(&gate, &up);
        // silu(0) * 2 = 0, silu(1) * 3 ~ 0.7311 * 3 ~ 2.1932
        assert!(out[[0, 0]].abs() < 1e-5);
        assert!((out[[0, 1]] - 2.1932).abs() < 0.01);
    }

    #[test]
    fn test_t5_relative_position_bucket() {
        // Bucket 0 = relative distance 0
        assert_eq!(t5_relative_position_bucket(0, 32, 128, false), 0);
        // Small positive distances map linearly
        assert_eq!(t5_relative_position_bucket(-1, 32, 128, false), 1);
        assert_eq!(t5_relative_position_bucket(-2, 32, 128, false), 2);
        // Large distances get bucketed logarithmically
        let b100 = t5_relative_position_bucket(-100, 32, 128, false);
        assert!(b100 > 10 && b100 < 32);
    }

    #[test]
    fn test_q8_dequant() {
        let mut block = [0u8; 34];
        // Scale = 1.0 in f16
        let scale_bits = f16::from_f32(1.0).to_bits().to_le_bytes();
        block[0] = scale_bits[0];
        block[1] = scale_bits[1];
        // First quant = 2 (as i8)
        block[2] = 2u8;
        let out = dequantize_q8_block(&block);
        assert!((out[0] - 2.0).abs() < 0.01);
    }

    #[test]
    fn test_q4_dequant() {
        let mut block = [0u8; 18];
        // Scale = 1.0 in f16
        let scale_bits = f16::from_f32(1.0).to_bits().to_le_bytes();
        block[0] = scale_bits[0];
        block[1] = scale_bits[1];
        // First byte: lo=8 (0 centered), hi=12 (4 centered)
        // After -8 offset: lo=0, hi=4
        block[2] = 0x80 | 0x0C; // 0xC8 = hi=12, lo=8... wait let me think
                                // nibbles: lo = block & 0x0F, hi = (block >> 4) & 0x0F
                                // We want lo=10 (maps to 10-8=2), hi=12 (maps to 12-8=4)
        block[2] = (12 << 4) | 10; // 0xCA
        let out = dequantize_q4_block(&block);
        assert!((out[0] - 2.0).abs() < 0.01); // (10-8)*1.0
        assert!((out[1] - 4.0).abs() < 0.01); // (12-8)*1.0
    }

    #[test]
    fn test_dot_product() {
        assert!((dot_product(&[1.0, 2.0, 3.0], &[4.0, 5.0, 6.0]) - 32.0).abs() < 1e-5);
        assert!((dot_product(&[], &[]) - 0.0).abs() < 1e-5);
    }

    #[test]
    fn test_kv_cache_append() {
        let mut cache = KvCache::new(1, 4);
        let k1 = Array2::from_shape_vec((2, 4), vec![1.0; 8]).unwrap();
        let v1 = Array2::from_shape_vec((2, 4), vec![2.0; 8]).unwrap();
        let (k, v) = cache.append_kv(0, &k1, &v1).unwrap();
        assert_eq!(k.nrows(), 2);
        assert_eq!(v.nrows(), 2);

        let k2 = Array2::from_shape_vec((1, 4), vec![3.0; 4]).unwrap();
        let v2 = Array2::from_shape_vec((1, 4), vec![4.0; 4]).unwrap();
        let (k, v) = cache.append_kv(0, &k2, &v2).unwrap();
        assert_eq!(k.nrows(), 3);
        assert_eq!(v.nrows(), 3);
        assert!((k[[2, 0]] - 3.0).abs() < 1e-6);
    }

    // -- Typed-error shape mocks -------------------------------------------
    // Hand-built CPU models (gpu = None, std-layout weights) exercise the
    // forward-pass ModelIncompatible paths without loading a real model.

    /// One transformer layer with all attention/norm weights present at the
    /// given dims; the three FFN weights are caller-controlled so a test can
    /// omit one and hit a typed-error path.
    fn mock_layer(
        h: usize,
        inter: usize,
        ffn_gate_weight: Option<Array2<f32>>,
        ffn_up_weight: Option<Array2<f32>>,
    ) -> TransformerLayerWeights {
        TransformerLayerWeights {
            q_weight: Array2::zeros((h, h)),
            q_bias: None,
            q_ln_weight: None,
            q_ln_bias: None,
            k_weight: Array2::zeros((h, h)),
            k_bias: None,
            k_ln_weight: None,
            k_ln_bias: None,
            v_weight: Array2::zeros((h, h)),
            v_bias: None,
            qkv_weight: None,
            qkv_bias: None,
            attn_out_weight: Array2::zeros((h, h)),
            attn_out_bias: None,
            norm1_weight: Array1::ones(h),
            norm1_bias: None,
            ffn_up_weight,
            ffn_up_bias: None,
            ffn_gate_weight,
            ffn_up_gated_weight: None,
            ffn_down_weight: Array2::zeros((h, inter)),
            ffn_down_bias: None,
            norm2_weight: Array1::ones(h),
            norm2_bias: None,
            relative_attention_bias: None,
            rel_pos_embeddings: None,
        }
    }

    /// Minimal single-layer CPU encoder (gpu = None) around `layer`.
    fn mock_encoder(layer: TransformerLayerWeights) -> BertModel {
        let json = r#"{
            "n_embd": 4, "n_layer": 1, "n_head": 1, "n_inner": 4,
            "n_positions": 16, "vocab_size": 4
        }"#;
        let config: BertConfig = serde_json::from_str(json).expect("parse config");
        let h = config.hidden_size;
        let weights = ModelWeights {
            word_embeddings: Array2::zeros((config.vocab_size, h)),
            position_embeddings: None,
            token_type_embeddings: None,
            embed_ln_weight: None,
            embed_ln_bias: None,
            embed_projection: None,
            layers: vec![layer],
            final_norm_weight: None,
            final_norm_bias: None,
            lm_head_weight: None,
            lm_head_bias: None,
            classifier: None,
        };
        BertModel {
            config,
            weights,
            head_dim: h,
            kv_head_dim: h,
            rope_cos: None,
            rope_sin: None,
            gpu: None,
        }
    }

    /// Minimal CPU model (gpu = None, no layers) carrying only a classification head,
    /// for exercising the cross-encoder scoring path in isolation.
    fn mock_classifier_model(h: usize, head: ClassifierHead) -> BertModel {
        let json = format!(
            r#"{{ "n_embd": {h}, "n_layer": 0, "n_head": 1, "n_inner": {h},
                  "n_positions": 16, "vocab_size": 4 }}"#
        );
        let config: BertConfig = serde_json::from_str(&json).expect("parse config");
        let weights = ModelWeights {
            word_embeddings: Array2::zeros((config.vocab_size, h)),
            position_embeddings: None,
            token_type_embeddings: None,
            embed_ln_weight: None,
            embed_ln_bias: None,
            embed_projection: None,
            layers: vec![],
            final_norm_weight: None,
            final_norm_bias: None,
            lm_head_weight: None,
            lm_head_bias: None,
            classifier: Some(head),
        };
        BertModel {
            config,
            weights,
            head_dim: h,
            kv_head_dim: h,
            rope_cos: None,
            rope_sin: None,
            gpu: None,
        }
    }

    fn mock_embedding_model_with_gpu(
        layers: Vec<TransformerLayerWeights>,
        gpu: Box<dyn gpu::GpuCompute>,
    ) -> BertModel {
        let layer_count = layers.len();
        let json = format!(
            r#"{{ "n_embd": 2, "n_layer": {layer_count}, "n_head": 1, "n_inner": 2,
                  "n_positions": 16, "vocab_size": 4 }}"#
        );
        let config: BertConfig = serde_json::from_str(&json).expect("parse config");
        let weights = ModelWeights {
            word_embeddings: Array2::zeros((config.vocab_size, config.hidden_size)),
            position_embeddings: None,
            token_type_embeddings: None,
            embed_ln_weight: None,
            embed_ln_bias: None,
            embed_projection: None,
            layers,
            final_norm_weight: None,
            final_norm_bias: None,
            lm_head_weight: None,
            lm_head_bias: None,
            classifier: None,
        };
        BertModel {
            config,
            weights,
            head_dim: 2,
            kv_head_dim: 2,
            rope_cos: None,
            rope_sin: None,
            gpu: Some(gpu),
        }
    }

    #[test]
    fn forward_batched_single_entity_uses_pooled_output_when_enabled() {
        let calls = Arc::new(AtomicUsize::new(0));
        let model = mock_embedding_model_with_gpu(
            vec![],
            Box::new(PooledOnlyGpu {
                calls: Arc::clone(&calls),
            }),
        );

        let _override = PooledOutputOverrideGuard::enabled();
        let result = model
            .forward_batched(&[vec![1, 2]], &[vec![1, 1]])
            .expect("forward_batched");

        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], vec![0.6, 0.8]);
    }

    #[test]
    fn pooled_output_declines_relative_attention_layers() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut layer = mock_layer(
            2,
            2,
            Some(Array2::zeros((2, 2))),
            Some(Array2::zeros((2, 2))),
        );
        layer.relative_attention_bias = Some(Array2::zeros((1, 1)));
        let model = mock_embedding_model_with_gpu(
            vec![layer],
            Box::new(PooledOnlyGpu {
                calls: Arc::clone(&calls),
            }),
        );

        let _override = PooledOutputOverrideGuard::enabled();
        let result = model
            .try_forward_batched_pooled(&[vec![1, 2]], &[vec![1, 1]])
            .expect("try pooled");

        assert!(result.is_none());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn relative_attention_layers_decline_resident_stack() {
        let mut layer = mock_layer(4, 4, Some(Array2::zeros((4, 4))), None);
        layer.relative_attention_bias = Some(Array2::zeros((1, 1)));
        let model = mock_encoder(layer);

        assert!(model.has_relative_attention_layers());
        assert!(!model.should_try_resident_stack());
    }

    #[test]
    fn cross_encoder_two_layer_roberta_head_matches_hand_computed() {
        use ndarray::{arr1, arr2};
        // RobertaClassificationHead: out_proj(tanh(dense(x) + dense_bias)) + out_proj_bias.
        let dense_weight = arr2(&[[0.1f32, 0.2, -0.3], [-0.4, 0.5, 0.6], [0.7, -0.8, 0.9]]);
        let dense_bias = arr1(&[0.05f32, -0.1, 0.2]);
        let out_proj_weight = arr2(&[[0.3f32, -0.6, 0.9]]);
        let out_proj_bias = arr1(&[0.25f32]);
        let model = mock_classifier_model(
            3,
            ClassifierHead::Roberta {
                dense_weight: dense_weight.clone(),
                dense_bias: Some(dense_bias.clone()),
                out_proj_weight: out_proj_weight.clone(),
                out_proj_bias: Some(out_proj_bias.clone()),
            },
        );

        let x = arr2(&[[1.0f32, -2.0, 0.5]]);
        let logit = model.classify_pooled(&x).expect("classify")[[0, 0]];

        let tanhd = (dense_weight.dot(&x.row(0)) + &dense_bias).mapv(|v| v.tanh());
        let expected = out_proj_weight.row(0).dot(&tanhd) + out_proj_bias[0];
        assert!(
            (logit - expected).abs() < 1e-5,
            "two-layer head logit {logit} != hand-computed {expected}"
        );
    }

    #[test]
    fn cross_encoder_single_linear_head_matches_hand_computed() {
        use ndarray::{arr1, arr2};
        // Single-linear head must not regress: logits = x·Wᵀ + b.
        let weight = arr2(&[[0.5f32, -1.0, 2.0]]);
        let bias = arr1(&[0.1f32]);
        let model = mock_classifier_model(
            3,
            ClassifierHead::Linear {
                weight: weight.clone(),
                bias: Some(bias.clone()),
            },
        );

        let x = arr2(&[[1.0f32, 2.0, -0.5]]);
        let logit = model.classify_pooled(&x).expect("classify")[[0, 0]];

        let expected = weight.row(0).dot(&x.row(0)) + bias[0];
        assert!(
            (logit - expected).abs() < 1e-5,
            "single-linear head logit {logit} != hand-computed {expected}"
        );
    }

    #[test]
    fn cross_encoder_missing_head_is_typed_error() {
        // No classification head -> typed error, not a panic.
        let model = mock_encoder(mock_layer(4, 4, None, None));
        let err = model
            .classify_pooled(&Array2::zeros((1, 4)))
            .expect_err("a model with no classification head must surface a typed error");
        assert!(
            matches!(err, InferError::ModelError(_)),
            "expected ModelError for missing head, got {err:?}"
        );
    }

    #[test]
    fn absent_ffn_up_weight_is_model_incompatible_not_panic() {
        // GELU FFN path: no gate, no up -> the required up projection is absent.
        let model = mock_encoder(mock_layer(4, 4, None, None));
        let err = model
            .forward(&[vec![0u32, 1]], &[vec![1u32, 1]])
            .expect_err("missing ffn_up_weight must surface a typed error, not panic");
        assert!(
            matches!(err, InferError::ModelIncompatible(_)),
            "expected ModelIncompatible, got {err:?}"
        );
    }

    #[test]
    fn swiglu_missing_up_weight_is_model_incompatible() {
        // SwiGLU path: gate present but up absent -> still a model-shape problem.
        let gate = Array2::zeros((4, 4));
        let model = mock_encoder(mock_layer(4, 4, Some(gate), None));
        let err = model
            .forward(&[vec![0u32, 1]], &[vec![1u32, 1]])
            .expect_err("SwiGLU FFN without ffn_up_weight must error");
        assert!(
            matches!(err, InferError::ModelIncompatible(_)),
            "expected ModelIncompatible, got {err:?}"
        );
    }

    #[test]
    fn typed_error_variants_render_distinctly() {
        assert_eq!(
            InferError::ModelIncompatible("x".into()).to_string(),
            "model incompatible: x"
        );
        assert_eq!(
            InferError::BackendError("x".into()).to_string(),
            "backend error: x"
        );
        assert_eq!(
            InferError::Internal("x".into()).to_string(),
            "internal invariant violated: x"
        );
    }

    #[test]
    fn test_model_architecture_detection() {
        assert_eq!(
            ModelArchitecture::from_model_type("bert"),
            ModelArchitecture::Bert
        );
        assert_eq!(
            ModelArchitecture::from_model_type("llama"),
            ModelArchitecture::Llama
        );
        assert_eq!(
            ModelArchitecture::from_model_type("mistral"),
            ModelArchitecture::Mistral
        );
        assert!(ModelArchitecture::Llama.is_decoder_only());
        assert!(!ModelArchitecture::Bert.is_decoder_only());
        assert!(ModelArchitecture::Llama.uses_rope());
        assert!(!ModelArchitecture::Bert.uses_rope());
        assert!(ModelArchitecture::Llama.uses_rmsnorm());
    }

    #[test]
    fn test_sampling_greedy() {
        let logits = Array1::from(vec![1.0, 5.0, 2.0, 0.5]);
        let mut params = SamplingParams {
            temperature: 0.0,
            top_k: 50,
            top_p: 1.0,
            repetition_penalty: 1.0,
            rng_state: 0,
        };
        assert_eq!(sample_token(&logits, &[], &[], &mut params), 1);
    }

    #[test]
    fn test_sampling_with_repetition_penalty() {
        let logits = Array1::from(vec![5.0, 4.9, 0.1]);
        let mut params = SamplingParams {
            temperature: 0.0,
            top_k: 50,
            top_p: 1.0,
            repetition_penalty: 10.0,
            rng_state: 0,
        };
        // Token 0 already generated -> heavily penalized -> token 1 wins
        assert_eq!(sample_token(&logits, &[], &[0], &mut params), 1);
    }

    #[test]
    fn test_sampling_stochastic() {
        // With stochastic sampling enabled, repeated calls should produce the
        // highest-probability token most often but not always.
        let logits = Array1::from(vec![10.0, 0.1, 0.1]);
        let mut params = SamplingParams {
            temperature: 1.0,
            top_k: 3,
            top_p: 1.0,
            repetition_penalty: 1.0,
            rng_state: 42,
        };
        let mut counts = [0u32; 3];
        for _ in 0..100 {
            let tok = sample_token(&logits, &[], &[], &mut params);
            counts[tok as usize] += 1;
        }
        // Token 0 should dominate (logit 10.0 >> 0.1)
        assert!(
            counts[0] > 80,
            "token 0 should appear most often, got {}",
            counts[0]
        );
    }

    #[test]
    fn test_xorshift_rng_produces_different_values() {
        let mut params = SamplingParams::default();
        let r1 = params.next_rand();
        let r2 = params.next_rand();
        let r3 = params.next_rand();
        assert!(r1 != r2 && r2 != r3);
        assert!((0.0..1.0).contains(&r1));
        assert!((0.0..1.0).contains(&r2));
    }

    #[test]
    fn test_init_performance_threads_is_idempotent() {
        init_performance_threads();
        init_performance_threads();
        init_performance_threads();
    }

    #[test]
    fn test_mmap_load_matches_fs_read() {
        use std::io::Write;

        let mut bytes = Vec::with_capacity(8192 + 123);
        for i in 0..(8192u32 + 123) {
            bytes.push((i % 256) as u8);
        }

        let path =
            std::env::temp_dir().join(format!("kin_infer_mmap_parity_{}.bin", std::process::id()));
        {
            let mut f = std::fs::File::create(&path).expect("create temp weights");
            f.write_all(&bytes).expect("write temp weights");
            f.flush().expect("flush temp weights");
        }

        let via_fs = std::fs::read(&path).expect("fs read");
        let mmap = load_safetensors_mmap(&path).expect("mmap load");

        assert_eq!(
            &via_fs[..],
            &mmap[..],
            "mmap bytes must match fs::read bytes"
        );
        assert_eq!(&bytes[..], &mmap[..], "mmap bytes must match written bytes");

        drop(mmap);
        let _ = std::fs::remove_file(&path);
    }
}
