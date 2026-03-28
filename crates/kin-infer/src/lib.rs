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

pub mod gpu;
#[cfg(feature = "metal")]
pub mod metal_backend;
#[cfg(feature = "cuda")]
pub mod cuda_backend;

use half::{bf16, f16};
use ndarray::{s, Array1, Array2};
use safetensors::{Dtype, SafeTensors};
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
            Self::Llama | Self::Mistral | Self::Phi | Self::Gemma | Self::Qwen2
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
    pub hidden_size: usize,
    pub num_hidden_layers: usize,
    pub num_attention_heads: usize,
    pub intermediate_size: usize,
    pub max_position_embeddings: usize,
    pub vocab_size: usize,
    #[serde(default)]
    pub type_vocab_size: Option<usize>,
    #[serde(default = "default_eps")]
    pub layer_norm_eps: f64,
    #[serde(default)]
    pub position_embedding_type: Option<String>,
    #[serde(default = "default_feed_forward_type")]
    pub feed_forward_type: String,
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
    #[serde(default = "default_rope_theta")]
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
}

fn default_eps() -> f64 { 1e-12 }
fn default_feed_forward_type() -> String { "original".to_string() }
fn default_rope_theta() -> f64 { 10000.0 }
fn default_t5_buckets() -> usize { 32 }
fn default_t5_max_distance() -> usize { 128 }
fn default_true() -> bool { true }

impl BertConfig {
    pub fn architecture(&self) -> ModelArchitecture {
        self.model_type
            .as_deref()
            .map(ModelArchitecture::from_model_type)
            .unwrap_or(ModelArchitecture::Unknown)
    }

    fn effective_pre_ln(&self) -> bool {
        self.pre_ln.unwrap_or_else(|| self.architecture().uses_pre_ln())
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
    ) -> (Array2<f32>, Array2<f32>) {
        let k = if self.key[layer].nrows() == 0 {
            new_k.clone()
        } else {
            ndarray::concatenate(ndarray::Axis(0), &[self.key[layer].view(), new_k.view()]).unwrap()
        };
        let v = if self.value[layer].nrows() == 0 {
            new_v.clone()
        } else {
            ndarray::concatenate(ndarray::Axis(0), &[self.value[layer].view(), new_v.view()])
                .unwrap()
        };
        self.key[layer] = k.clone();
        self.value[layer] = v.clone();
        (k, v)
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
    Ok(Array2::from_shape_vec((rows, cols), floats).unwrap())
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
    let prefixes = ["", "bert.", "model.", "roberta.", "transformer.", "deberta."];
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

/// Load tensors from potentially sharded safetensors files.
/// If `weights_path` ends in `.safetensors`, load it directly.
/// If a `model.safetensors.index.json` exists alongside, load the shard map.
fn load_safetensors_bytes(weights_path: &Path) -> Result<Vec<u8>, InferError> {
    std::fs::read(weights_path)
        .map_err(|e| InferError::ModelError(format!("failed to read weights: {e}")))
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
        let data = load_safetensors_bytes(weights_path)?;
        let tensors = SafeTensors::deserialize(&data)
            .map_err(|e| InferError::ModelError(format!("failed to parse safetensors: {e}")))?;
        Self::load_from_tensors(&tensors, config)
    }

    fn load_from_tensors(tensors: &SafeTensors, config: BertConfig) -> Result<Self, InferError> {
        let _names: Vec<_> = tensors.names().into_iter().collect();
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

        let skip_pos = config.position_embedding_type.as_deref() == Some("alibi")
            || arch.uses_rope();
        let position_embeddings = if skip_pos {
            None
        } else {
            try_load_2d_flexible(
                tensors,
                &["embeddings.position_embeddings.weight", "embed_positions.weight"],
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
            &["embeddings.LayerNorm.weight"],
            h,
        )?;
        let embed_ln_bias = try_load_1d_flexible(
            tensors,
            &["embeddings.LayerNorm.bias"],
            h,
        )?;

        // ALBERT: factorized embedding projection
        let embed_projection = if embed_dim != h {
            Some(load_2d_flexible(
                tensors,
                &["encoder.embedding_hidden_mapping_in.weight",
                  "embeddings.projection.weight"],
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

            let q_weight = load_2d_flexible(
                tensors,
                &[&format!("{lp}.attention.self.query.weight"),
                  &format!("{lp_dec}.self_attn.q_proj.weight")],
                h, h,
            )?;
            let q_bias = try_load_1d_flexible(
                tensors,
                &[&format!("{lp}.attention.self.query.bias"),
                  &format!("{lp_dec}.self_attn.q_proj.bias")],
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
            let k_weight = load_2d_flexible(
                tensors,
                &[&format!("{lp}.attention.self.key.weight"),
                  &format!("{lp_dec}.self_attn.k_proj.weight")],
                kv_dim, h,
            )?;
            let k_bias = try_load_1d_flexible(
                tensors,
                &[&format!("{lp}.attention.self.key.bias"),
                  &format!("{lp_dec}.self_attn.k_proj.bias")],
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
            let v_weight = load_2d_flexible(
                tensors,
                &[&format!("{lp}.attention.self.value.weight"),
                  &format!("{lp_dec}.self_attn.v_proj.weight")],
                kv_dim, h,
            )?;
            let v_bias = try_load_1d_flexible(
                tensors,
                &[&format!("{lp}.attention.self.value.bias"),
                  &format!("{lp_dec}.self_attn.v_proj.bias")],
                kv_dim,
            )?;
            let attn_out_weight = load_2d_flexible(
                tensors,
                &[&format!("{lp}.attention.output.dense.weight"),
                  &format!("{lp_dec}.self_attn.o_proj.weight")],
                h, h,
            )?;
            let attn_out_bias = try_load_1d_flexible(
                tensors,
                &[&format!("{lp}.attention.output.dense.bias"),
                  &format!("{lp_dec}.self_attn.o_proj.bias")],
                h,
            )?;
            let norm1_weight = load_1d_flexible(
                tensors,
                &[&format!("{lp}.layer_norm_1.weight"),
                  &format!("{lp}.attention.output.LayerNorm.weight"),
                  &format!("{lp_dec}.input_layernorm.weight")],
                h,
            )?;
            let norm1_bias = try_load_1d_flexible(
                tensors,
                &[&format!("{lp}.layer_norm_1.bias"),
                  &format!("{lp}.attention.output.LayerNorm.bias"),
                  &format!("{lp_dec}.input_layernorm.bias")],
                h,
            )?;

            // FFN weights — detect gated vs standard
            let is_glu = config.feed_forward_type.ends_with("glu");
            let ffn_gate_weight = try_load_2d_flexible(
                tensors,
                &[&format!("{lp_dec}.mlp.gate_proj.weight")],
                inter, h,
            )?;
            let ffn_up_gated_weight = if is_glu && ffn_gate_weight.is_none() {
                try_load_2d_flexible(
                    tensors,
                    &[&format!("{lp}.mlp.up_gated_layer.weight")],
                    inter * 2, h,
                )?
            } else {
                None
            };
            let ffn_up_weight = if ffn_gate_weight.is_none() && ffn_up_gated_weight.is_none() {
                Some(load_2d_flexible(
                    tensors,
                    &[&format!("{lp}.mlp.up_layer.weight"),
                      &format!("{lp}.intermediate.dense.weight"),
                      &format!("{lp_dec}.mlp.up_proj.weight")],
                    inter, h,
                )?)
            } else if ffn_gate_weight.is_some() {
                // SwiGLU models have separate up_proj
                try_load_2d_flexible(
                    tensors,
                    &[&format!("{lp_dec}.mlp.up_proj.weight")],
                    inter, h,
                )?
            } else {
                None
            };
            let ffn_up_bias = try_load_1d_flexible(
                tensors,
                &[&format!("{lp}.mlp.up_layer.bias"),
                  &format!("{lp}.intermediate.dense.bias")],
                inter,
            )?;
            let ffn_down_weight = load_2d_flexible(
                tensors,
                &[&format!("{lp}.mlp.down_layer.weight"),
                  &format!("{lp}.output.dense.weight"),
                  &format!("{lp_dec}.mlp.down_proj.weight")],
                h, inter,
            )?;
            let ffn_down_bias = try_load_1d_flexible(
                tensors,
                &[&format!("{lp}.mlp.down_layer.bias"),
                  &format!("{lp}.output.dense.bias")],
                h,
            )?;
            let norm2_weight = load_1d_flexible(
                tensors,
                &[&format!("{lp}.layer_norm_2.weight"),
                  &format!("{lp}.output.LayerNorm.weight"),
                  &format!("{lp_dec}.post_attention_layernorm.weight")],
                h,
            )?;
            let norm2_bias = try_load_1d_flexible(
                tensors,
                &[&format!("{lp}.layer_norm_2.bias"),
                  &format!("{lp}.output.LayerNorm.bias"),
                  &format!("{lp_dec}.post_attention_layernorm.bias")],
                h,
            )?;

            // T5 relative attention bias (first layer only)
            let relative_attention_bias = if i == 0 && arch == ModelArchitecture::T5Encoder {
                let n_buckets = config.relative_attention_num_buckets;
                let n_heads = config.num_attention_heads;
                try_load_2d_flexible(
                    tensors,
                    &["encoder.block.0.layer.0.SelfAttention.relative_attention_bias.weight"],
                    n_buckets, n_heads,
                )?
            } else {
                None
            };

            // DeBERTa relative position embeddings
            let rel_pos_embeddings = if arch == ModelArchitecture::Deberta {
                let max_rel = config.max_relative_positions.unwrap_or(512) * 2;
                try_load_2d_flexible(
                    tensors,
                    &["deberta.embeddings.rel_embeddings.weight",
                      "encoder.rel_embeddings.weight"],
                    max_rel, h,
                )?
            } else {
                None
            };

            layers.push(TransformerLayerWeights {
                q_weight, q_bias, q_ln_weight, q_ln_bias,
                k_weight, k_bias, k_ln_weight, k_ln_bias,
                v_weight, v_bias,
                attn_out_weight, attn_out_bias,
                norm1_weight, norm1_bias,
                ffn_up_weight, ffn_up_bias, ffn_gate_weight, ffn_up_gated_weight,
                ffn_down_weight, ffn_down_bias,
                norm2_weight, norm2_bias,
                relative_attention_bias, rel_pos_embeddings,
            });
        }

        // Final norm (decoder-only)
        let final_norm_weight = try_load_1d_flexible(
            tensors, &["norm.weight", "model.norm.weight", "ln_f.weight"], h,
        )?;
        let final_norm_bias = try_load_1d_flexible(
            tensors, &["norm.bias", "model.norm.bias", "ln_f.bias"], h,
        )?;

        // LM head
        let lm_head_weight = try_load_2d_flexible(
            tensors, &["lm_head.weight"], vocab, h,
        )?;
        let lm_head_bias = try_load_1d_flexible(
            tensors, &["lm_head.bias"], vocab,
        )?;

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
            },
            head_dim,
            kv_head_dim,
            rope_cos,
            rope_sin,
            config,
            gpu: Some(gpu_compute),
        })
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
        let mut results = Vec::with_capacity(batch_size);

        for b in 0..batch_size {
            let ids = &token_ids[b];
            let mask = &attention_masks[b];
            let seq_len = ids.len();
            let h = self.config.hidden_size;
            let embed_dim = self.config.embedding_size.unwrap_or(h);

            // 1. Embedding lookup
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
                hidden = self.linear(&hidden, proj, None);
            }

            // 2. Embedding LayerNorm
            self.optional_layer_norm(
                &mut hidden,
                self.weights.embed_ln_weight.as_ref(),
                self.weights.embed_ln_bias.as_ref(),
                self.config.layer_norm_eps as f32,
            );

            // 3. Transformer layers (ALBERT: reuse layers[i % num_groups])
            let num_groups = self.weights.layers.len();
            for i in 0..self.config.num_hidden_layers {
                let layer = &self.weights.layers[i % num_groups];
                hidden = self.encoder_layer(&hidden, mask, layer, i)?;
            }

            // 4. Mean pooling + L2 normalize
            let pooled = mean_pool(&hidden, mask);
            let normalized = l2_normalize(&pooled);
            results.push(normalized.to_vec());
        }

        Ok(results)
    }

    /// GPU-accelerated linear projection helper.
    fn linear(&self, x: &Array2<f32>, weight: &Array2<f32>, bias: Option<&Array1<f32>>) -> Array2<f32> {
        if let Some(ref gpu) = self.gpu {
            gpu_linear_bias(x, weight, bias, gpu.as_ref())
        } else {
            linear_with_optional_bias(x, weight, bias)
        }
    }

    /// GPU-accelerated norm helper.
    fn norm(&self, x: &mut Array2<f32>, weight: &Array1<f32>, bias: Option<&Array1<f32>>, eps: f32, use_rms: bool) {
        if use_rms {
            if let Some(ref gpu) = self.gpu {
                gpu_rms_norm_2d(x, weight, eps, gpu.as_ref());
            } else {
                rms_norm_2d(x, weight, eps);
            }
        } else if let Some(bias) = bias {
            if let Some(ref gpu) = self.gpu {
                gpu_layer_norm_2d(x, weight, bias, eps, gpu.as_ref());
            } else {
                layer_norm_2d(x, weight, bias, eps);
            }
        }
    }

    /// GPU-accelerated optional LayerNorm helper.
    fn optional_layer_norm(
        &self,
        x: &mut Array2<f32>,
        gamma: Option<&Array1<f32>>,
        bias: Option<&Array1<f32>>,
        eps: f32,
    ) {
        if let (Some(gamma), Some(bias)) = (gamma, bias) {
            if let Some(ref gpu) = self.gpu {
                gpu_layer_norm_2d(x, gamma, bias, eps, gpu.as_ref());
            } else {
                layer_norm_2d(x, gamma, bias, eps);
            }
        }
    }

    /// GPU-accelerated row-wise softmax helper.
    fn softmax(&self, x: &mut Array2<f32>) {
        if let Some(ref gpu) = self.gpu {
            gpu_softmax_rows(x, gpu.as_ref());
        } else {
            softmax_rows(x);
        }
    }

    /// GPU-accelerated GELU helper.
    fn gelu(&self, x: &Array2<f32>) -> Array2<f32> {
        if let Some(ref gpu) = self.gpu {
            gpu_gelu_2d(x, gpu.as_ref())
        } else {
            gelu_2d(x)
        }
    }

    /// GPU-accelerated SwiGLU helper.
    fn swiglu(&self, gate: &Array2<f32>, up: &Array2<f32>) -> Array2<f32> {
        if let Some(ref gpu) = self.gpu {
            gpu_swiglu_2d(gate, up, gpu.as_ref())
        } else {
            swiglu_2d(gate, up)
        }
    }

    /// Single encoder transformer layer with support for all attention/norm variants.
    fn encoder_layer(
        &self,
        hidden: &Array2<f32>,
        mask: &[u32],
        layer: &TransformerLayerWeights,
        _layer_idx: usize,
    ) -> Result<Array2<f32>, InferError> {
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
            self.norm(&mut n, &layer.norm1_weight,
                layer.norm1_bias.as_ref().or(Some(&Array1::zeros(h))), if use_rms { rms_eps } else { eps }, use_rms);
            n
        } else {
            hidden.clone()
        };

        let attn_input = if pre_ln { &normed_for_attn } else { hidden };

        // Q, K, V projections (GPU-accelerated matmul)
        let mut q = self.linear(attn_input, &layer.q_weight, layer.q_bias.as_ref());
        self.optional_layer_norm(&mut q, layer.q_ln_weight.as_ref(), layer.q_ln_bias.as_ref(), eps);
        let mut k = self.linear(attn_input, &layer.k_weight, layer.k_bias.as_ref());
        self.optional_layer_norm(&mut k, layer.k_ln_weight.as_ref(), layer.k_ln_bias.as_ref(), eps);
        let v = self.linear(attn_input, &layer.v_weight, layer.v_bias.as_ref());

        // Apply RoPE if configured
        if let (Some(ref cos), Some(ref sin)) = (&self.rope_cos, &self.rope_sin) {
            let seq_len = q.nrows();
            apply_rope(&mut q, cos, sin, 0, seq_len, self.head_dim);
            apply_rope(&mut k, cos, sin, 0, seq_len, self.head_dim);
        }

        // GQA: repeat K/V heads if needed
        let (k_full, v_full) = if num_kv_heads < num_heads {
            (repeat_kv(&k, num_kv_heads, num_heads), repeat_kv(&v, num_kv_heads, num_heads))
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

        // Check for special attention patterns requiring per-head processing
        // Only DeBERTa disentangled attention requires per-head processing
        // (it accesses individual Q/K elements per position pair).
        // ALiBi and T5 bias can be applied on the flat batched scores.
        let needs_per_head = layer.rel_pos_embeddings.is_some();

        let attn_output = if !needs_per_head && self.gpu.is_some() {
            // === Batched GPU path: all heads in 2 dispatches ===
            // Handles standard BERT, ALiBi (Jina), T5 relative bias.
            let gpu = self.gpu.as_ref().unwrap();
            let total_dim = num_heads * head_dim;

            // Reshape Q, K, V from [seq_len, num_heads * head_dim] to
            // head-major [num_heads, seq_len, head_dim] flat
            let q_data: Vec<f32> = q.as_slice().map(|s| s.to_vec())
                .unwrap_or_else(|| q.iter().copied().collect());
            let k_data: Vec<f32> = k_full.as_slice().map(|s| s.to_vec())
                .unwrap_or_else(|| k_full.iter().copied().collect());
            let v_data: Vec<f32> = v_full.as_slice().map(|s| s.to_vec())
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

            // Dispatch 1: Q × K^T for all heads → [num_heads, seq_len, seq_len]
            let mut scores = gpu.batched_matmul(&q_flat, &k_flat, num_heads, seq_len, head_dim);

            // Scale + ALiBi + T5 bias + padding mask (CPU — trivial cost vs matmul)
            for hd in 0..num_heads {
                let base = hd * seq_len * seq_len;
                let alibi_slope = alibi_slopes.as_ref().map(|s| s[hd]);
                for i in 0..seq_len {
                    for j in 0..seq_len {
                        let idx = base + i * seq_len + j;
                        scores[idx] *= scale;

                        // ALiBi: linear distance bias per head
                        if let Some(slope) = alibi_slope {
                            scores[idx] += slope * i.abs_diff(j) as f32;
                        }

                        // T5 relative position bias
                        if let Some(ref bias_table) = layer.relative_attention_bias {
                            let n_buckets = self.config.relative_attention_num_buckets;
                            let max_dist = self.config.relative_attention_max_distance;
                            let bucket = t5_relative_position_bucket(
                                j as i32 - i as i32, n_buckets, max_dist, false,
                            );
                            if bucket < bias_table.nrows() && hd < num_heads {
                                scores[idx] += bias_table[[bucket, hd]];
                            }
                        }

                        if mask[j] == 0 {
                            scores[idx] = f32::NEG_INFINITY;
                        }
                    }
                }
            }

            // GPU softmax over all heads at once
            gpu.softmax(&mut scores, num_heads * seq_len, seq_len);

            // Dispatch 2: scores × V for all heads → [num_heads, seq_len, head_dim]
            let out_flat = gpu.batched_attn_values(&scores, &v_flat, num_heads, seq_len, head_dim);

            // Reshape back to [seq_len, num_heads * head_dim]
            let mut output = Array2::<f32>::zeros((seq_len, h));
            {
                let out_slice = output.as_slice_mut().unwrap();
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
            // === Per-head CPU path (DeBERTa/ALiBi/T5 or no GPU) ===
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
                            let rel_pos = (j as i32 - i as i32)
                                .clamp(-(max_rel as i32), max_rel as i32 - 1);
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
                                j as i32 - i as i32, n_buckets, max_dist, false,
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

                self.softmax(&mut scores);
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
            &attn_output, &layer.attn_out_weight, layer.attn_out_bias.as_ref(),
        );
        let mut post_attn = hidden + &attn_projected;
        if !pre_ln {
            self.norm(&mut post_attn, &layer.norm1_weight,
                layer.norm1_bias.as_ref().or(Some(&Array1::zeros(h))), if use_rms { rms_eps } else { eps }, use_rms);
        }

        // FFN
        let ffn_input = if pre_ln {
            let mut n = post_attn.clone();
            self.norm(&mut n, &layer.norm2_weight,
                layer.norm2_bias.as_ref().or(Some(&Array1::zeros(h))), if use_rms { rms_eps } else { eps }, use_rms);
            n
        } else {
            post_attn.clone()
        };

        let ffn_down = if let Some(ref gate_weight) = layer.ffn_gate_weight {
            // SwiGLU: silu(gate) * up (GPU-accelerated matmuls)
            let gate = self.linear(&ffn_input, gate_weight, None);
            let up = self.linear(
                &ffn_input,
                layer.ffn_up_weight.as_ref().expect("ffn_up_weight missing for SwiGLU"),
                None,
            );
            let activated = self.swiglu(&gate, &up);
            self.linear(&activated, &layer.ffn_down_weight, layer.ffn_down_bias.as_ref())
        } else if let Some(ref up_gated_weight) = layer.ffn_up_gated_weight {
            let up_gated = self.linear(&ffn_input, up_gated_weight, None);
            let gated = if self.config.feed_forward_type == "reglu" {
                reglu_2d(&up_gated, self.config.intermediate_size)
            } else {
                geglu_2d(&up_gated, self.config.intermediate_size)
            };
            self.linear(&gated, &layer.ffn_down_weight, layer.ffn_down_bias.as_ref())
        } else {
            let ffn_up = self.linear(
                &ffn_input,
                layer.ffn_up_weight.as_ref().expect("ffn_up_weight missing"),
                layer.ffn_up_bias.as_ref(),
            );
            let ffn_activated = self.gelu(&ffn_up);
            self.linear(&ffn_activated, &layer.ffn_down_weight, layer.ffn_down_bias.as_ref())
        };

        let mut output = &post_attn + &ffn_down;
        if !pre_ln {
            self.norm(&mut output, &layer.norm2_weight,
                layer.norm2_bias.as_ref().or(Some(&Array1::zeros(h))), if use_rms { rms_eps } else { eps }, use_rms);
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
            // Pre-LN (decoder-only models always use pre-LN)
            let mut normed = hidden.clone();
            self.norm(&mut normed, &layer.norm1_weight,
                layer.norm1_bias.as_ref().or(Some(&Array1::zeros(h))),
                if use_rms { rms_eps } else { eps }, use_rms);

            // Q, K, V projections (GPU-accelerated)
            let mut q = self.linear(&normed, &layer.q_weight, layer.q_bias.as_ref());
            let mut k = self.linear(&normed, &layer.k_weight, layer.k_bias.as_ref());
            let v = self.linear(&normed, &layer.v_weight, layer.v_bias.as_ref());

            // RoPE
            if let (Some(ref cos), Some(ref sin)) = (&self.rope_cos, &self.rope_sin) {
                apply_rope(&mut q, cos, sin, start_pos, seq_len, head_dim);
                apply_rope(&mut k, cos, sin, start_pos, seq_len, head_dim);
            }

            // KV cache
            let (k_full, v_full) = cache.append_kv(li, &k, &v);
            let kv_seq_len = k_full.nrows();

            // GQA: repeat K/V
            let (k_rep, v_rep) = if num_kv_heads < num_heads {
                (repeat_kv(&k_full, num_kv_heads, num_heads),
                 repeat_kv(&v_full, num_kv_heads, num_heads))
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
                    let c = gpu.matmul(&q_data, &k_data, seq_len, kv_seq_len, head_dim);
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

                self.softmax(&mut scores);
                // scores × V (standard matmul, not transposed — CPU for now)
                let head_out = scores.dot(&v_h);
                for i in 0..seq_len {
                    for j in 0..head_dim {
                        attn_output[[i, offset + j]] = head_out[[i, j]];
                    }
                }
            }

            // Output projection + residual (GPU-accelerated)
            let attn_proj = self.linear(
                &attn_output, &layer.attn_out_weight, layer.attn_out_bias.as_ref(),
            );
            hidden = &hidden + &attn_proj;

            // Post-attention norm + FFN (GPU-accelerated)
            let mut normed2 = hidden.clone();
            self.norm(&mut normed2, &layer.norm2_weight,
                layer.norm2_bias.as_ref().or(Some(&Array1::zeros(h))),
                if use_rms { rms_eps } else { eps }, use_rms);

            let ffn_out = if let Some(ref gate_w) = layer.ffn_gate_weight {
                let gate = self.linear(&normed2, gate_w, None);
                let up = self.linear(
                    &normed2,
                    layer.ffn_up_weight.as_ref().expect("ffn_up_weight missing"),
                    None,
                );
                let act = self.swiglu(&gate, &up);
                self.linear(&act, &layer.ffn_down_weight, layer.ffn_down_bias.as_ref())
            } else {
                let up = self.linear(
                    &normed2,
                    layer.ffn_up_weight.as_ref().expect("ffn_up_weight"),
                    layer.ffn_up_bias.as_ref(),
                );
                let act = self.gelu(&up);
                self.linear(&act, &layer.ffn_down_weight, layer.ffn_down_bias.as_ref())
            };

            hidden = &hidden + &ffn_out;
        }

        // Final norm (GPU-accelerated)
        if let Some(ref w) = self.weights.final_norm_weight {
            self.norm(&mut hidden, w,
                self.weights.final_norm_bias.as_ref().or(Some(&Array1::zeros(h))),
                if use_rms { rms_eps } else { eps }, use_rms);
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
            let hidden = self.decoder_forward(&[*generated.last().unwrap()], &mut cache, pos)?;
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
        let val = ((rel as f64 / max_exact as f64).ln() / (max_distance as f64 / max_exact as f64).ln()
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
        base.extend(extended.into_iter().step_by(2).take(n_heads - closest_power));
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

/// GPU-accelerated linear: C = X × W^T using GpuCompute::matmul.
fn gpu_linear(x: &Array2<f32>, weight: &Array2<f32>, gpu: &dyn gpu::GpuCompute) -> Array2<f32> {
    let m = x.nrows();
    let k = x.ncols();
    let n = weight.nrows(); // weight is [N, K], we want X[M,K] × W^T[K,N] = [M,N]
    // Force contiguous layout for GPU transfer
    let a_data: Vec<f32> = x.as_slice()
        .map(|s| s.to_vec())
        .unwrap_or_else(|| x.iter().copied().collect());
    let w_data: Vec<f32> = weight.as_slice()
        .map(|s| s.to_vec())
        .unwrap_or_else(|| weight.iter().copied().collect());
    let c = gpu.matmul(&a_data, &w_data, m, n, k);
    Array2::from_shape_vec((m, n), c).unwrap_or_else(|_| linear_without_bias(x, weight))
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
) -> Array2<f32> {
    let mut out = gpu_linear(x, weight, gpu);
    if let Some(bias) = bias {
        for mut row in out.rows_mut() {
            row += bias;
        }
    }
    out
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
) {
    let rows = x.nrows();
    let cols = x.ncols();
    if let Some(data) = x.as_slice_mut() {
        let g = gamma.as_slice().unwrap();
        let b = beta.as_slice().unwrap();
        gpu.layer_norm(data, g, b, rows, cols, eps);
    } else {
        layer_norm_2d(x, gamma, beta, eps);
    }
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
) {
    let rows = x.nrows();
    let cols = x.ncols();
    if let Some(data) = x.as_slice_mut() {
        let w = weight.as_slice().unwrap();
        gpu.rms_norm(data, w, rows, cols, eps);
    } else {
        rms_norm_2d(x, weight, eps);
    }
}

/// GPU-accelerated row-wise softmax.
fn gpu_softmax_rows(x: &mut Array2<f32>, gpu: &dyn gpu::GpuCompute) {
    let rows = x.nrows();
    let cols = x.ncols();
    if let Some(data) = x.as_slice_mut() {
        gpu.softmax(data, rows, cols);
    } else {
        softmax_rows(x);
    }
}

fn gelu(x: f32) -> f32 {
    x * 0.5 * (1.0 + (x * 0.7978845608 * (1.0 + 0.044715 * x * x)).tanh())
}

fn gelu_2d(x: &Array2<f32>) -> Array2<f32> {
    x.mapv(gelu)
}

fn gpu_gelu_2d(x: &Array2<f32>, gpu: &dyn gpu::GpuCompute) -> Array2<f32> {
    let mut out = x.to_owned();
    if let Some(data) = out.as_slice_mut() {
        gpu.gelu(data);
        out
    } else {
        gelu_2d(x)
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
) -> Array2<f32> {
    let mut out = gate.to_owned();
    if let Some(data) = out.as_slice_mut() {
        gpu.silu(data);
    } else {
        return swiglu_2d(gate, up);
    }

    if let Some(up_data) = up.as_slice() {
        if let Some(out_data) = out.as_slice_mut() {
            gpu.elementwise_mul(out_data, up_data);
            return out;
        }
    }

    out *= up;
    out
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
    let gate = x.slice(s![.., intermediate_size..intermediate_size * 2]).to_owned();
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

fn l2_normalize(v: &Array1<f32>) -> Array1<f32> {
    let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 1e-12 { v / norm } else { v.clone() }
}

/// SIMD-accelerated dot product with platform-specific implementations.
pub fn dot_product(a: &[f32], b: &[f32]) -> f32 {
    #[cfg(target_arch = "aarch64")]
    {
        dot_product_neon(a, b)
    }
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2", target_feature = "fma"))]
    {
        // Safety: AVX2+FMA checked via target_feature cfg
        unsafe { dot_product_avx2(a, b) }
    }
    #[cfg(not(any(
        target_arch = "aarch64",
        all(target_arch = "x86_64", target_feature = "avx2", target_feature = "fma")
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
#[cfg(all(target_arch = "x86_64", target_feature = "avx2", target_feature = "fma"))]
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
        ).unwrap();
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
        let (k, v) = cache.append_kv(0, &k1, &v1);
        assert_eq!(k.nrows(), 2);
        assert_eq!(v.nrows(), 2);

        let k2 = Array2::from_shape_vec((1, 4), vec![3.0; 4]).unwrap();
        let v2 = Array2::from_shape_vec((1, 4), vec![4.0; 4]).unwrap();
        let (k, v) = cache.append_kv(0, &k2, &v2);
        assert_eq!(k.nrows(), 3);
        assert_eq!(v.nrows(), 3);
        assert!((k[[2, 0]] - 3.0).abs() < 1e-6);
    }

    #[test]
    fn test_model_architecture_detection() {
        assert_eq!(ModelArchitecture::from_model_type("bert"), ModelArchitecture::Bert);
        assert_eq!(ModelArchitecture::from_model_type("llama"), ModelArchitecture::Llama);
        assert_eq!(ModelArchitecture::from_model_type("mistral"), ModelArchitecture::Mistral);
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
        assert!(counts[0] > 80, "token 0 should appear most often, got {}", counts[0]);
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
}
