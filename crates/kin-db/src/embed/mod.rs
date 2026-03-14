use candle_core::{DType, Device, Tensor};
use candle_nn::VarBuilder;
use candle_transformers::models::bert::{BertModel, Config as BertConfig};
use hf_hub::{api::sync::Api, Repo, RepoType};
use tokenizers::Tokenizer;

use crate::error::KinDbError;

/// Default HuggingFace model ID.
const DEFAULT_MODEL_ID: &str = "BAAI/bge-small-en-v1.5";

/// Default model revision.
const DEFAULT_REVISION: &str = "main";

/// The floating-point dtype used for inference.
const DTYPE: DType = DType::F32;

/// Generates code embeddings using a local BERT model via Candle.
///
/// Uses BGE-small-en-v1.5 by default (384 dimensions, ~130 MB).
/// Supports Metal (Apple Silicon), CUDA (NVIDIA), and CPU fallback.
/// The model is downloaded from HuggingFace Hub on first use and cached locally.
pub struct CodeEmbedder {
    model: BertModel,
    tokenizer: Tokenizer,
    device: Device,
    dimensions: usize,
}

impl CodeEmbedder {
    /// Create a new embedder with the default code model (BGE-small-en-v1.5).
    ///
    /// Auto-detects the best available device: Metal -> CUDA -> CPU.
    pub fn new() -> Result<Self, KinDbError> {
        Self::with_model(DEFAULT_MODEL_ID, DEFAULT_REVISION)
    }

    /// Create with a specific HuggingFace model.
    pub fn with_model(model_id: &str, revision: &str) -> Result<Self, KinDbError> {
        let device = best_device();

        let repo = Repo::with_revision(model_id.to_string(), RepoType::Model, revision.to_string());
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

        let config_data = std::fs::read_to_string(&config_path).map_err(|e| {
            KinDbError::IndexError(format!("failed to read config: {e}"))
        })?;
        let config: BertConfig = serde_json::from_str(&config_data).map_err(|e| {
            KinDbError::IndexError(format!("failed to parse model config: {e}"))
        })?;

        let dimensions = config.hidden_size;

        let tokenizer = Tokenizer::from_file(&tokenizer_path).map_err(|e| {
            KinDbError::IndexError(format!("failed to load tokenizer: {e}"))
        })?;

        let vb = unsafe {
            VarBuilder::from_mmaped_safetensors(&[weights_path], DTYPE, &device).map_err(|e| {
                KinDbError::IndexError(format!("failed to load model weights: {e}"))
            })?
        };

        let model = BertModel::load(vb, &config).map_err(|e| {
            KinDbError::IndexError(format!("failed to initialise BERT model: {e}"))
        })?;

        Ok(Self {
            model,
            tokenizer,
            device,
            dimensions,
        })
    }

    /// Generate an embedding for a single entity.
    ///
    /// The input text is composed as `"{name} {signature} {body_preview}"`.
    pub fn embed_entity(
        &self,
        name: &str,
        signature: &str,
        body: &str,
    ) -> Result<Vec<f32>, KinDbError> {
        let text = format_entity_text(name, signature, body);
        let mut vecs = self.embed_batch(&[text])?;
        vecs.pop()
            .ok_or_else(|| KinDbError::IndexError("embedding returned empty result".into()))
    }

    /// Batch-embed multiple pre-formatted text strings. More efficient than
    /// calling [`embed_entity`] in a loop because the GPU can parallelise
    /// across the batch.
    pub fn embed_batch(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, KinDbError> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }

        let encodings = self
            .tokenizer
            .encode_batch(texts.to_vec(), true)
            .map_err(|e| KinDbError::IndexError(format!("tokenization failed: {e}")))?;

        let token_ids: Vec<Vec<u32>> = encodings.iter().map(|e| e.get_ids().to_vec()).collect();
        let attention_masks: Vec<Vec<u32>> =
            encodings.iter().map(|e| e.get_attention_mask().to_vec()).collect();
        let type_ids: Vec<Vec<u32>> =
            encodings.iter().map(|e| e.get_type_ids().to_vec()).collect();

        let token_ids_t = to_tensor_2d(&token_ids, &self.device)?;
        let attention_mask_t = to_tensor_2d(&attention_masks, &self.device)?;
        let type_ids_t = to_tensor_2d(&type_ids, &self.device)?;

        let embeddings = self
            .model
            .forward(&token_ids_t, &type_ids_t, Some(&attention_mask_t))
            .map_err(|e| KinDbError::IndexError(format!("model forward pass failed: {e}")))?;

        // Mean pooling: mask padding tokens, then average over sequence length.
        let mask = attention_mask_t
            .to_dtype(DTYPE)
            .map_err(|e| KinDbError::IndexError(format!("dtype conversion failed: {e}")))?
            .unsqueeze(2)
            .map_err(|e| KinDbError::IndexError(format!("unsqueeze failed: {e}")))?;

        let masked = embeddings
            .broadcast_mul(&mask)
            .map_err(|e| KinDbError::IndexError(format!("broadcast_mul failed: {e}")))?;

        let summed = masked
            .sum(1)
            .map_err(|e| KinDbError::IndexError(format!("sum failed: {e}")))?;

        let mask_sum = mask
            .sum(1)
            .map_err(|e| KinDbError::IndexError(format!("mask sum failed: {e}")))?
            .clamp(1e-9, f64::MAX)
            .map_err(|e| KinDbError::IndexError(format!("clamp failed: {e}")))?;

        let pooled = summed
            .broadcast_div(&mask_sum)
            .map_err(|e| KinDbError::IndexError(format!("broadcast_div failed: {e}")))?;

        // L2 normalize.
        let normalized = normalize_l2(&pooled)?;

        // Convert to Vec<Vec<f32>>.
        let n = texts.len();
        let flat: Vec<f32> = normalized
            .to_vec2()
            .map_err(|e| KinDbError::IndexError(format!("tensor to vec failed: {e}")))?
            .into_iter()
            .flatten()
            .collect();

        Ok(flat
            .chunks(self.dimensions)
            .take(n)
            .map(|c| c.to_vec())
            .collect())
    }

    /// The number of dimensions produced by this model.
    pub fn dimensions(&self) -> usize {
        self.dimensions
    }

    /// The device this embedder is running on (Metal, CUDA, or CPU).
    pub fn device(&self) -> &Device {
        &self.device
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

/// Select the best available compute device.
///
/// Priority: Metal (macOS) -> CUDA -> CPU.
fn best_device() -> Device {
    #[cfg(feature = "metal")]
    {
        if let Ok(device) = Device::new_metal(0) {
            return device;
        }
    }
    #[cfg(feature = "cuda")]
    {
        if let Ok(device) = Device::new_cuda(0) {
            return device;
        }
    }
    Device::Cpu
}

/// Convert a batch of u32 sequences to a 2D tensor, padding to max length.
fn to_tensor_2d(batch: &[Vec<u32>], device: &Device) -> Result<Tensor, KinDbError> {
    let max_len = batch.iter().map(|s| s.len()).max().unwrap_or(0);
    let padded: Vec<Vec<u32>> = batch
        .iter()
        .map(|s| {
            let mut v = s.clone();
            v.resize(max_len, 0);
            v
        })
        .collect();
    let flat: Vec<u32> = padded.into_iter().flatten().collect();
    Tensor::from_vec(flat, (batch.len(), max_len), device)
        .map_err(|e| KinDbError::IndexError(format!("tensor creation failed: {e}")))
}

/// L2-normalize each row of a 2D tensor.
fn normalize_l2(tensor: &Tensor) -> Result<Tensor, KinDbError> {
    let l2 = tensor
        .sqr()
        .map_err(|e| KinDbError::IndexError(format!("sqr failed: {e}")))?
        .sum_keepdim(1)
        .map_err(|e| KinDbError::IndexError(format!("sum_keepdim failed: {e}")))?
        .sqrt()
        .map_err(|e| KinDbError::IndexError(format!("sqrt failed: {e}")))?
        .clamp(1e-12, f64::MAX)
        .map_err(|e| KinDbError::IndexError(format!("clamp failed: {e}")))?;
    tensor
        .broadcast_div(&l2)
        .map_err(|e| KinDbError::IndexError(format!("normalize div failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Default embedding dimensions for BGE-small-en-v1.5.
    const BGE_SMALL_DIMS: usize = 384;

    #[test]
    fn embedder_initialises() {
        let embedder = CodeEmbedder::new().expect("model should initialise");
        assert_eq!(embedder.dimensions(), BGE_SMALL_DIMS);
    }

    #[test]
    fn device_is_detected() {
        let embedder = CodeEmbedder::new().unwrap();
        let device = embedder.device();
        // On macOS with metal feature, should be Metal; otherwise CPU is fine.
        println!("Embedding device: {:?}", device);
    }

    #[test]
    fn single_entity_embedding_has_correct_dims() {
        let embedder = CodeEmbedder::new().unwrap();
        let vec = embedder
            .embed_entity("parse_config", "fn parse_config(path: &str) -> Config", "")
            .unwrap();
        assert_eq!(vec.len(), BGE_SMALL_DIMS);
    }

    #[test]
    fn batch_embedding_returns_correct_count() {
        let embedder = CodeEmbedder::new().unwrap();
        let texts = vec![
            "fn foo() -> i32".to_string(),
            "fn bar(x: i32) -> bool".to_string(),
            "struct Config { port: u16 }".to_string(),
        ];
        let results = embedder.embed_batch(&texts).unwrap();
        assert_eq!(results.len(), 3);
        for v in &results {
            assert_eq!(v.len(), BGE_SMALL_DIMS);
        }
    }

    #[test]
    fn similar_names_produce_closer_embeddings() {
        let embedder = CodeEmbedder::new().unwrap();
        let v_parse_a = embedder
            .embed_entity("parse_json", "fn parse_json(s: &str) -> Value", "")
            .unwrap();
        let v_parse_b = embedder
            .embed_entity("parse_yaml", "fn parse_yaml(s: &str) -> Value", "")
            .unwrap();
        let v_unrelated = embedder
            .embed_entity("render_template", "fn render_template(ctx: &Context) -> Html", "")
            .unwrap();

        let sim_parsers = cosine_similarity(&v_parse_a, &v_parse_b);
        let sim_different = cosine_similarity(&v_parse_a, &v_unrelated);

        assert!(
            sim_parsers > sim_different,
            "similar functions ({sim_parsers:.4}) should be more similar than \
             unrelated ones ({sim_different:.4})"
        );
    }

    #[test]
    fn empty_batch_returns_empty() {
        let embedder = CodeEmbedder::new().unwrap();
        let results = embedder.embed_batch(&[]).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn format_entity_text_joins_parts() {
        assert_eq!(format_entity_text("foo", "fn foo()", "{ 1 }"), "foo fn foo() { 1 }");
        assert_eq!(format_entity_text("foo", "", ""), "foo");
        assert_eq!(format_entity_text("", "", ""), "");
    }

    /// Cosine similarity helper for tests.
    fn cosine_similarity(a: &[f32], b: &[f32]) -> f32 {
        let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
        let norm_a: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
        let norm_b: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm_a == 0.0 || norm_b == 0.0 {
            return 0.0;
        }
        dot / (norm_a * norm_b)
    }
}
