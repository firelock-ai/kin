// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Minimal BERT inference engine using ndarray. Zero framework dependencies.
//!
//! Loads weights from safetensors, runs the standard BERT forward pass:
//! token_ids → embeddings → N transformer layers → mean pooling → L2 normalize.

use half::{bf16, f16};
use ndarray::{s, Array1, Array2};
use safetensors::{Dtype, SafeTensors};
use std::path::Path;

use crate::error::KinDbError;

// ---------------------------------------------------------------------------
// Model configuration (parsed from config.json)
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
pub(crate) struct BertConfig {
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
}

fn default_eps() -> f64 {
    1e-12
}

fn default_feed_forward_type() -> String {
    "original".to_string()
}

// ---------------------------------------------------------------------------
// Weight storage
// ---------------------------------------------------------------------------

/// All weights for a single transformer layer.
struct TransformerLayerWeights {
    // Self-attention
    q_weight: Array2<f32>,
    q_bias: Array1<f32>,
    q_ln_weight: Option<Array1<f32>>,
    q_ln_bias: Option<Array1<f32>>,
    k_weight: Array2<f32>,
    k_bias: Array1<f32>,
    k_ln_weight: Option<Array1<f32>>,
    k_ln_bias: Option<Array1<f32>>,
    v_weight: Array2<f32>,
    v_bias: Array1<f32>,
    attn_out_weight: Array2<f32>,
    attn_out_bias: Array1<f32>,
    norm1_weight: Array1<f32>,
    norm1_bias: Array1<f32>,
    // FFN
    ffn_up_weight: Option<Array2<f32>>,
    ffn_up_bias: Option<Array1<f32>>,
    ffn_up_gated_weight: Option<Array2<f32>>,
    ffn_down_weight: Array2<f32>,
    ffn_down_bias: Array1<f32>,
    norm2_weight: Array1<f32>,
    norm2_bias: Array1<f32>,
}

/// Complete BERT model weights.
pub(crate) struct BertWeights {
    // Embedding tables
    word_embeddings: Array2<f32>,
    position_embeddings: Option<Array2<f32>>,
    token_type_embeddings: Array2<f32>,
    embed_ln_weight: Array1<f32>,
    embed_ln_bias: Array1<f32>,
    // Transformer layers
    layers: Vec<TransformerLayerWeights>,
}

/// The loaded, ready-to-run BERT model.
pub(crate) struct BertModel {
    pub config: BertConfig,
    weights: BertWeights,
    head_dim: usize,
}

// ---------------------------------------------------------------------------
// Weight loading from safetensors
// ---------------------------------------------------------------------------

/// Read a 1-D f32 tensor from the safetensors data.
fn load_1d(
    tensors: &SafeTensors,
    name: &str,
    expected: usize,
) -> Result<Array1<f32>, KinDbError> {
    let view = tensors
        .tensor(name)
        .map_err(|e| KinDbError::IndexError(format!("missing tensor '{name}': {e}")))?;
    let floats = decode_tensor_to_f32(name, &view, expected)?;
    Ok(Array1::from(floats))
}

/// Read a 2-D f32 tensor from the safetensors data (row-major).
fn load_2d(
    tensors: &SafeTensors,
    name: &str,
    rows: usize,
    cols: usize,
) -> Result<Array2<f32>, KinDbError> {
    let view = tensors
        .tensor(name)
        .map_err(|e| KinDbError::IndexError(format!("missing tensor '{name}': {e}")))?;
    let floats = decode_tensor_to_f32(name, &view, rows * cols)?;
    Ok(Array2::from_shape_vec((rows, cols), floats).unwrap())
}

fn decode_tensor_to_f32(
    name: &str,
    view: &safetensors::tensor::TensorView<'_>,
    expected_values: usize,
) -> Result<Vec<f32>, KinDbError> {
    let data = view.data();
    match view.dtype() {
        Dtype::F32 => {
            let expected_bytes = expected_values * 4;
            if data.len() != expected_bytes {
                return Err(KinDbError::IndexError(format!(
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
                return Err(KinDbError::IndexError(format!(
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
                return Err(KinDbError::IndexError(format!(
                    "tensor '{name}': expected {expected_bytes} bytes, got {}",
                    data.len()
                )));
            }
            Ok(data
                .chunks_exact(2)
                .map(|c| bf16::from_bits(u16::from_le_bytes([c[0], c[1]])).to_f32())
                .collect())
        }
        other => Err(KinDbError::IndexError(format!(
            "tensor '{name}': unsupported dtype {other:?}"
        ))),
    }
}

/// Try multiple naming conventions for a safetensors key.
/// HuggingFace models use different prefixes: "bert.encoder.layer.N." vs "encoder.layer.N."
fn resolve_name(tensors: &SafeTensors, candidates: &[String]) -> Result<String, KinDbError> {
    for name in candidates {
        if tensors.tensor(name).is_ok() {
            return Ok(name.clone());
        }
    }
    Err(KinDbError::IndexError(format!(
        "none of these tensor names found: {:?}",
        candidates
    )))
}

/// Build candidate names for a tensor with common HuggingFace BERT prefixes.
fn candidates(suffixes: &[&str]) -> Vec<String> {
    let prefixes = ["", "bert.", "model.", "roberta."];
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
) -> Result<Array1<f32>, KinDbError> {
    let name = resolve_name(tensors, &candidates(suffixes))?;
    load_1d(tensors, &name, expected)
}

fn load_2d_flexible(
    tensors: &SafeTensors,
    suffixes: &[&str],
    rows: usize,
    cols: usize,
) -> Result<Array2<f32>, KinDbError> {
    let name = resolve_name(tensors, &candidates(suffixes))?;
    load_2d(tensors, &name, rows, cols)
}

fn try_load_1d_flexible(
    tensors: &SafeTensors,
    suffixes: &[&str],
    expected: usize,
) -> Result<Option<Array1<f32>>, KinDbError> {
    match resolve_name(tensors, &candidates(suffixes)) {
        Ok(name) => load_1d(tensors, &name, expected).map(Some),
        Err(_) => Ok(None),
    }
}

impl BertModel {
    /// Load a BERT model from a safetensors file + config.
    pub fn load(weights_path: &Path, config: BertConfig) -> Result<Self, KinDbError> {
        let data = std::fs::read(weights_path)
            .map_err(|e| KinDbError::IndexError(format!("failed to read weights: {e}")))?;
        let tensors = SafeTensors::deserialize(&data)
            .map_err(|e| KinDbError::IndexError(format!("failed to parse safetensors: {e}")))?;

        // Log available tensor names for debugging if needed.
        let _names: Vec<_> = tensors.names().into_iter().collect();

        let h = config.hidden_size;
        let inter = config.intermediate_size;
        let vocab = config.vocab_size;
        let max_pos = config.max_position_embeddings;
        let type_vocab = config.type_vocab_size.unwrap_or(2);

        // Embedding tables
        let word_embeddings = load_2d_flexible(
            &tensors,
            &["embeddings.word_embeddings.weight"],
            vocab,
            h,
        )?;
        let position_embeddings = if config.position_embedding_type.as_deref() == Some("alibi") {
            None
        } else {
            Some(load_2d_flexible(
                &tensors,
                &["embeddings.position_embeddings.weight"],
                max_pos,
                h,
            )?)
        };
        let token_type_embeddings = load_2d_flexible(
            &tensors,
            &["embeddings.token_type_embeddings.weight"],
            type_vocab,
            h,
        )?;
        let embed_ln_weight = load_1d_flexible(
            &tensors,
            &["embeddings.LayerNorm.weight"],
            h,
        )?;
        let embed_ln_bias = load_1d_flexible(
            &tensors,
            &["embeddings.LayerNorm.bias"],
            h,
        )?;

        // Transformer layers
        let mut layers = Vec::with_capacity(config.num_hidden_layers);
        for i in 0..config.num_hidden_layers {
            let lp = format!("encoder.layer.{i}");

            let q_weight = load_2d_flexible(
                &tensors,
                &[&format!("{lp}.attention.self.query.weight")],
                h,
                h,
            )?;
            let q_bias = load_1d_flexible(
                &tensors,
                &[&format!("{lp}.attention.self.query.bias")],
                h,
            )?;
            let q_ln_weight = try_load_1d_flexible(
                &tensors,
                &[&format!("{lp}.attention.self.layer_norm_q.weight")],
                h,
            )?;
            let q_ln_bias = try_load_1d_flexible(
                &tensors,
                &[&format!("{lp}.attention.self.layer_norm_q.bias")],
                h,
            )?;
            let k_weight = load_2d_flexible(
                &tensors,
                &[&format!("{lp}.attention.self.key.weight")],
                h,
                h,
            )?;
            let k_bias = load_1d_flexible(
                &tensors,
                &[&format!("{lp}.attention.self.key.bias")],
                h,
            )?;
            let k_ln_weight = try_load_1d_flexible(
                &tensors,
                &[&format!("{lp}.attention.self.layer_norm_k.weight")],
                h,
            )?;
            let k_ln_bias = try_load_1d_flexible(
                &tensors,
                &[&format!("{lp}.attention.self.layer_norm_k.bias")],
                h,
            )?;
            let v_weight = load_2d_flexible(
                &tensors,
                &[&format!("{lp}.attention.self.value.weight")],
                h,
                h,
            )?;
            let v_bias = load_1d_flexible(
                &tensors,
                &[&format!("{lp}.attention.self.value.bias")],
                h,
            )?;
            let attn_out_weight = load_2d_flexible(
                &tensors,
                &[&format!("{lp}.attention.output.dense.weight")],
                h,
                h,
            )?;
            let attn_out_bias = load_1d_flexible(
                &tensors,
                &[&format!("{lp}.attention.output.dense.bias")],
                h,
            )?;
            let norm1_weight = load_1d_flexible(
                &tensors,
                &[
                    &format!("{lp}.layer_norm_1.weight"),
                    &format!("{lp}.attention.output.LayerNorm.weight"),
                ],
                h,
            )?;
            let norm1_bias = load_1d_flexible(
                &tensors,
                &[
                    &format!("{lp}.layer_norm_1.bias"),
                    &format!("{lp}.attention.output.LayerNorm.bias"),
                ],
                h,
            )?;
            let (ffn_up_weight, ffn_up_bias, ffn_up_gated_weight) =
                if config.feed_forward_type.ends_with("glu") {
                    (
                        None,
                        None,
                        Some(load_2d_flexible(
                            &tensors,
                            &[&format!("{lp}.mlp.up_gated_layer.weight")],
                            inter * 2,
                            h,
                        )?),
                    )
                } else {
                    (
                        Some(load_2d_flexible(
                            &tensors,
                            &[
                                &format!("{lp}.mlp.up_layer.weight"),
                                &format!("{lp}.intermediate.dense.weight"),
                            ],
                            inter,
                            h,
                        )?),
                        try_load_1d_flexible(
                            &tensors,
                            &[
                                &format!("{lp}.mlp.up_layer.bias"),
                                &format!("{lp}.intermediate.dense.bias"),
                            ],
                            inter,
                        )?,
                        None,
                    )
                };
            let ffn_down_weight = load_2d_flexible(
                &tensors,
                &[
                    &format!("{lp}.mlp.down_layer.weight"),
                    &format!("{lp}.output.dense.weight"),
                ],
                h,
                inter,
            )?;
            let ffn_down_bias = load_1d_flexible(
                &tensors,
                &[
                    &format!("{lp}.mlp.down_layer.bias"),
                    &format!("{lp}.output.dense.bias"),
                ],
                h,
            )?;
            let norm2_weight = load_1d_flexible(
                &tensors,
                &[
                    &format!("{lp}.layer_norm_2.weight"),
                    &format!("{lp}.output.LayerNorm.weight"),
                ],
                h,
            )?;
            let norm2_bias = load_1d_flexible(
                &tensors,
                &[
                    &format!("{lp}.layer_norm_2.bias"),
                    &format!("{lp}.output.LayerNorm.bias"),
                ],
                h,
            )?;

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
                attn_out_weight,
                attn_out_bias,
                norm1_weight,
                norm1_bias,
                ffn_up_weight,
                ffn_up_bias,
                ffn_up_gated_weight,
                ffn_down_weight,
                ffn_down_bias,
                norm2_weight,
                norm2_bias,
            });
        }

        let head_dim = h / config.num_attention_heads;

        Ok(Self {
            weights: BertWeights {
                word_embeddings,
                position_embeddings,
                token_type_embeddings,
                embed_ln_weight,
                embed_ln_bias,
                layers,
            },
            head_dim,
            config,
        })
    }

    /// Run the BERT forward pass on a batch of token sequences.
    ///
    /// `token_ids`: `[batch_size][seq_len]` (pre-padded to same length)
    /// `attention_masks`: `[batch_size][seq_len]` (1 for real tokens, 0 for padding)
    ///
    /// Returns: `[batch_size][hidden_size]` mean-pooled, L2-normalized embeddings.
    pub fn forward(
        &self,
        token_ids: &[Vec<u32>],
        attention_masks: &[Vec<u32>],
    ) -> Result<Vec<Vec<f32>>, KinDbError> {
        let batch_size = token_ids.len();
        let mut results = Vec::with_capacity(batch_size);

        // Process each sequence independently (simpler, avoids 3D tensor gymnastics).
        // For code embedding workloads the batch sizes are small, so this is fine.
        for b in 0..batch_size {
            let ids = &token_ids[b];
            let mask = &attention_masks[b];
            let seq_len = ids.len();
            let h = self.config.hidden_size;

            // 1. Embedding lookup: word + position + token_type
            let mut hidden = Array2::<f32>::zeros((seq_len, h));
            for (pos, &id) in ids.iter().enumerate() {
                let word = self.weights.word_embeddings.row(id as usize);
                let ttype = self.weights.token_type_embeddings.row(0); // single segment
                for j in 0..h {
                    let mut value = word[j] + ttype[j];
                    if let Some(position_embeddings) = &self.weights.position_embeddings {
                        value += position_embeddings[[pos, j]];
                    }
                    hidden[[pos, j]] = value;
                }
            }

            // 2. Embedding LayerNorm
            layer_norm_2d(
                &mut hidden,
                &self.weights.embed_ln_weight,
                &self.weights.embed_ln_bias,
                self.config.layer_norm_eps as f32,
            );

            // 3. Transformer layers
            for layer in &self.weights.layers {
                hidden = self.transformer_layer(&hidden, mask, layer)?;
            }

            // 4. Mean pooling over non-padding tokens
            let pooled = mean_pool(&hidden, mask);

            // 5. L2 normalize
            let normalized = l2_normalize(&pooled);

            results.push(normalized.to_vec());
        }

        Ok(results)
    }

    /// Single transformer layer: self-attention → residual + LN → FFN → residual + LN.
    fn transformer_layer(
        &self,
        hidden: &Array2<f32>,
        mask: &[u32],
        layer: &TransformerLayerWeights,
    ) -> Result<Array2<f32>, KinDbError> {
        let h = self.config.hidden_size;
        let num_heads = self.config.num_attention_heads;

        // --- Multi-head self-attention ---
        // Q, K, V projections: [seq_len, hidden] x [hidden, hidden]^T → [seq_len, hidden]
        let mut q = linear(hidden, &layer.q_weight, &layer.q_bias);
        apply_optional_layer_norm(
            &mut q,
            layer.q_ln_weight.as_ref(),
            layer.q_ln_bias.as_ref(),
            self.config.layer_norm_eps as f32,
        );
        let mut k = linear(hidden, &layer.k_weight, &layer.k_bias);
        apply_optional_layer_norm(
            &mut k,
            layer.k_ln_weight.as_ref(),
            layer.k_ln_bias.as_ref(),
            self.config.layer_norm_eps as f32,
        );
        let v = linear(hidden, &layer.v_weight, &layer.v_bias);

        let seq_len = hidden.nrows();
        let head_dim = self.head_dim;
        let scale = 1.0 / (head_dim as f32).sqrt();
        let alibi_slopes = if self.config.position_embedding_type.as_deref() == Some("alibi") {
            Some(alibi_head_slopes(num_heads))
        } else {
            None
        };

        // Compute attention per head, then concatenate
        let mut attn_output = Array2::<f32>::zeros((seq_len, h));

        for head in 0..num_heads {
            let offset = head * head_dim;

            // Extract head slices: [seq_len, head_dim]
            let q_h = q.slice(s![.., offset..offset + head_dim]);
            let k_h = k.slice(s![.., offset..offset + head_dim]);
            let v_h = v.slice(s![.., offset..offset + head_dim]);

            // Attention scores: Q * K^T / sqrt(d_k) → [seq_len, seq_len]
            let mut scores = q_h.dot(&k_h.t());
            scores *= scale;

            if let Some(slopes) = &alibi_slopes {
                let slope = slopes[head];
                for i in 0..seq_len {
                    for j in 0..seq_len {
                        scores[[i, j]] += slope * i.abs_diff(j) as f32;
                    }
                }
            }

            // Apply attention mask (set padding positions to -inf)
            for i in 0..seq_len {
                for j in 0..seq_len {
                    if mask[j] == 0 {
                        scores[[i, j]] = f32::NEG_INFINITY;
                    }
                }
            }

            // Softmax over last axis
            softmax_rows(&mut scores);

            // Attention output: scores * V → [seq_len, head_dim]
            let head_out = scores.dot(&v_h);

            // Write into concatenated output
            for i in 0..seq_len {
                for j in 0..head_dim {
                    attn_output[[i, offset + j]] = head_out[[i, j]];
                }
            }
        }

        // Output projection
        let attn_projected = linear(&attn_output, &layer.attn_out_weight, &layer.attn_out_bias);

        // Residual + LayerNorm
        let mut post_attn = hidden + &attn_projected;
        layer_norm_2d(
            &mut post_attn,
            &layer.norm1_weight,
            &layer.norm1_bias,
            self.config.layer_norm_eps as f32,
        );

        // --- Feed-forward network ---
        let ffn_down = if let Some(up_gated_weight) = &layer.ffn_up_gated_weight {
            let up_gated = linear_without_bias(&post_attn, up_gated_weight);
            let gated = if self.config.feed_forward_type == "reglu" {
                reglu_2d(&up_gated, self.config.intermediate_size)
            } else {
                geglu_2d(&up_gated, self.config.intermediate_size)
            };
            linear(&gated, &layer.ffn_down_weight, &layer.ffn_down_bias)
        } else {
            let ffn_up = linear_with_optional_bias(
                &post_attn,
                layer.ffn_up_weight.as_ref().expect("ffn_up_weight missing"),
                layer.ffn_up_bias.as_ref(),
            );
            let ffn_activated = gelu_2d(&ffn_up);
            linear(&ffn_activated, &layer.ffn_down_weight, &layer.ffn_down_bias)
        };

        // Residual + LayerNorm
        let mut output = &post_attn + &ffn_down;
        layer_norm_2d(
            &mut output,
            &layer.norm2_weight,
            &layer.norm2_bias,
            self.config.layer_norm_eps as f32,
        );

        Ok(output)
    }
}

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

/// Linear layer: x @ W^T + b. W is [out_features, in_features] (row-major as stored).
fn linear(x: &Array2<f32>, weight: &Array2<f32>, bias: &Array1<f32>) -> Array2<f32> {
    // x: [seq, in_features], weight: [out_features, in_features]
    // result: [seq, out_features]
    let mut out = x.dot(&weight.t());
    // Add bias to each row
    for mut row in out.rows_mut() {
        row += bias;
    }
    out
}

fn linear_without_bias(x: &Array2<f32>, weight: &Array2<f32>) -> Array2<f32> {
    x.dot(&weight.t())
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

/// Layer normalization over the last axis of a 2D array (in-place).
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

fn apply_optional_layer_norm(
    x: &mut Array2<f32>,
    gamma: Option<&Array1<f32>>,
    beta: Option<&Array1<f32>>,
    eps: f32,
) {
    if let (Some(gamma), Some(beta)) = (gamma, beta) {
        layer_norm_2d(x, gamma, beta, eps);
    }
}

/// GELU activation (exact form used by BERT).
fn gelu(x: f32) -> f32 {
    x * 0.5 * (1.0 + (x * 0.7978845608 * (1.0 + 0.044715 * x * x)).tanh())
}

/// GELU applied element-wise to a 2D array (returns new array).
fn gelu_2d(x: &Array2<f32>) -> Array2<f32> {
    x.mapv(gelu)
}

fn relu_2d(x: &Array2<f32>) -> Array2<f32> {
    x.mapv(|value| value.max(0.0))
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

/// Row-wise softmax (in-place).
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

/// Mean pooling: average hidden states of non-padding tokens.
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

/// L2 normalize a vector.
fn l2_normalize(v: &Array1<f32>) -> Array1<f32> {
    let norm = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 1e-12 {
        v / norm
    } else {
        v.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gelu_zero() {
        assert!((gelu(0.0) - 0.0).abs() < 1e-6);
    }

    #[test]
    fn test_gelu_positive() {
        // GELU(1.0) ≈ 0.8413
        assert!((gelu(1.0) - 0.8413).abs() < 0.01);
    }

    #[test]
    fn test_layer_norm() {
        let mut x = Array2::from_shape_vec((1, 4), vec![1.0, 2.0, 3.0, 4.0]).unwrap();
        let gamma = Array1::ones(4);
        let beta = Array1::zeros(4);
        layer_norm_2d(&mut x, &gamma, &beta, 1e-5);
        // After LN, mean should be ~0, std ~1
        let row = x.row(0);
        let mean: f32 = row.sum() / 4.0;
        assert!(mean.abs() < 1e-5);
    }

    #[test]
    fn test_softmax() {
        let mut x = Array2::from_shape_vec((1, 3), vec![1.0, 2.0, 3.0]).unwrap();
        softmax_rows(&mut x);
        let row = x.row(0);
        let sum: f32 = row.sum();
        assert!((sum - 1.0).abs() < 1e-5);
        // Values should be monotonically increasing
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
        let hidden = Array2::from_shape_vec(
            (3, 2),
            vec![1.0, 2.0, 3.0, 4.0, 5.0, 6.0],
        )
        .unwrap();
        let mask = vec![1, 1, 0]; // Only first two tokens
        let pooled = mean_pool(&hidden, &mask);
        assert!((pooled[0] - 2.0).abs() < 1e-5); // (1+3)/2
        assert!((pooled[1] - 3.0).abs() < 1e-5); // (2+4)/2
    }

    #[test]
    fn test_linear() {
        // Identity-like: W = I, b = 0
        let x = Array2::from_shape_vec((1, 2), vec![3.0, 4.0]).unwrap();
        let w = Array2::eye(2);
        let b = Array1::zeros(2);
        let out = linear(&x, &w, &b);
        assert!((out[[0, 0]] - 3.0).abs() < 1e-5);
        assert!((out[[0, 1]] - 4.0).abs() < 1e-5);
    }
}
