// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Minimal BERT inference engine using ndarray. Zero framework dependencies.
//!
//! Loads weights from safetensors, runs the standard BERT forward pass:
//! token_ids → embeddings → N transformer layers → mean pooling → L2 normalize.

use ndarray::{s, Array1, Array2};
use safetensors::SafeTensors;
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
}

fn default_eps() -> f64 {
    1e-12
}

// ---------------------------------------------------------------------------
// Weight storage
// ---------------------------------------------------------------------------

/// All weights for a single transformer layer.
struct TransformerLayerWeights {
    // Self-attention
    q_weight: Array2<f32>,
    q_bias: Array1<f32>,
    k_weight: Array2<f32>,
    k_bias: Array1<f32>,
    v_weight: Array2<f32>,
    v_bias: Array1<f32>,
    attn_out_weight: Array2<f32>,
    attn_out_bias: Array1<f32>,
    attn_ln_weight: Array1<f32>,
    attn_ln_bias: Array1<f32>,
    // FFN
    ffn_up_weight: Array2<f32>,
    ffn_up_bias: Array1<f32>,
    ffn_down_weight: Array2<f32>,
    ffn_down_bias: Array1<f32>,
    ffn_ln_weight: Array1<f32>,
    ffn_ln_bias: Array1<f32>,
}

/// Complete BERT model weights.
pub(crate) struct BertWeights {
    // Embedding tables
    word_embeddings: Array2<f32>,
    position_embeddings: Array2<f32>,
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
    let data = view.data();
    if data.len() != expected * 4 {
        return Err(KinDbError::IndexError(format!(
            "tensor '{name}': expected {} bytes, got {}",
            expected * 4,
            data.len()
        )));
    }
    let floats: Vec<f32> = data
        .chunks_exact(4)
        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect();
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
    let data = view.data();
    let expected = rows * cols * 4;
    if data.len() != expected {
        return Err(KinDbError::IndexError(format!(
            "tensor '{name}': expected {expected} bytes ({rows}x{cols}), got {}",
            data.len()
        )));
    }
    let floats: Vec<f32> = data
        .chunks_exact(4)
        .map(|c| f32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect();
    Ok(Array2::from_shape_vec((rows, cols), floats).unwrap())
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
    let prefixes = ["", "bert.", "model."];
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
        let position_embeddings = load_2d_flexible(
            &tensors,
            &["embeddings.position_embeddings.weight"],
            max_pos,
            h,
        )?;
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
            let attn_ln_weight = load_1d_flexible(
                &tensors,
                &[&format!("{lp}.attention.output.LayerNorm.weight")],
                h,
            )?;
            let attn_ln_bias = load_1d_flexible(
                &tensors,
                &[&format!("{lp}.attention.output.LayerNorm.bias")],
                h,
            )?;

            let ffn_up_weight = load_2d_flexible(
                &tensors,
                &[&format!("{lp}.intermediate.dense.weight")],
                inter,
                h,
            )?;
            let ffn_up_bias = load_1d_flexible(
                &tensors,
                &[&format!("{lp}.intermediate.dense.bias")],
                inter,
            )?;
            let ffn_down_weight = load_2d_flexible(
                &tensors,
                &[&format!("{lp}.output.dense.weight")],
                h,
                inter,
            )?;
            let ffn_down_bias = load_1d_flexible(
                &tensors,
                &[&format!("{lp}.output.dense.bias")],
                h,
            )?;
            let ffn_ln_weight = load_1d_flexible(
                &tensors,
                &[&format!("{lp}.output.LayerNorm.weight")],
                h,
            )?;
            let ffn_ln_bias = load_1d_flexible(
                &tensors,
                &[&format!("{lp}.output.LayerNorm.bias")],
                h,
            )?;

            layers.push(TransformerLayerWeights {
                q_weight,
                q_bias,
                k_weight,
                k_bias,
                v_weight,
                v_bias,
                attn_out_weight,
                attn_out_bias,
                attn_ln_weight,
                attn_ln_bias,
                ffn_up_weight,
                ffn_up_bias,
                ffn_down_weight,
                ffn_down_bias,
                ffn_ln_weight,
                ffn_ln_bias,
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
                let posn = self.weights.position_embeddings.row(pos);
                let ttype = self.weights.token_type_embeddings.row(0); // single segment
                for j in 0..h {
                    hidden[[pos, j]] = word[j] + posn[j] + ttype[j];
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
        let q = linear(hidden, &layer.q_weight, &layer.q_bias);
        let k = linear(hidden, &layer.k_weight, &layer.k_bias);
        let v = linear(hidden, &layer.v_weight, &layer.v_bias);

        let seq_len = hidden.nrows();
        let head_dim = self.head_dim;
        let scale = 1.0 / (head_dim as f32).sqrt();

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
            &layer.attn_ln_weight,
            &layer.attn_ln_bias,
            self.config.layer_norm_eps as f32,
        );

        // --- Feed-forward network ---
        let ffn_up = linear(&post_attn, &layer.ffn_up_weight, &layer.ffn_up_bias);
        let ffn_activated = gelu_2d(&ffn_up);
        let ffn_down = linear(&ffn_activated, &layer.ffn_down_weight, &layer.ffn_down_bias);

        // Residual + LayerNorm
        let mut output = &post_attn + &ffn_down;
        layer_norm_2d(
            &mut output,
            &layer.ffn_ln_weight,
            &layer.ffn_ln_bias,
            self.config.layer_norm_eps as f32,
        );

        Ok(output)
    }
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

/// GELU activation (exact form used by BERT).
fn gelu(x: f32) -> f32 {
    x * 0.5 * (1.0 + (x * 0.7978845608 * (1.0 + 0.044715 * x * x)).tanh())
}

/// GELU applied element-wise to a 2D array (returns new array).
fn gelu_2d(x: &Array2<f32>) -> Array2<f32> {
    x.mapv(gelu)
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
