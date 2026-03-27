// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

#[cfg(feature = "embeddings")]
mod inference;

#[cfg(feature = "embeddings")]
use hf_hub::{api::sync::Api, Repo, RepoType};
#[cfg(feature = "embeddings")]
use tokenizers::Tokenizer;

#[cfg(feature = "embeddings")]
use self::inference::{BertConfig, BertModel};

use crate::error::KinDbError;

/// Default HuggingFace model ID.
///
/// Jina Code Embeddings v2 — a BERT-architecture model trained specifically
/// on code. 768 dimensions, ~270 MB.
const DEFAULT_MODEL_ID: &str = "jinaai/jina-embeddings-v2-base-code";

/// Default model revision.
const DEFAULT_REVISION: &str = "main";

/// Generates code embeddings using a local BERT model via a custom inference
/// runtime. Pure Rust, zero framework dependencies (ndarray + safetensors).
///
/// Uses Jina Code Embeddings v2 by default (768 dimensions, ~270 MB).
/// The model is downloaded from HuggingFace Hub on first use and cached locally.
pub struct CodeEmbedder {
    #[cfg(feature = "embeddings")]
    model: BertModel,
    #[cfg(feature = "embeddings")]
    tokenizer: Tokenizer,
    #[cfg(feature = "embeddings")]
    dimensions: usize,
}

impl std::fmt::Debug for CodeEmbedder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodeEmbedder")
            .field("dimensions", {
                #[cfg(feature = "embeddings")]
                { &self.dimensions }
                #[cfg(not(feature = "embeddings"))]
                { &0usize }
            })
            .finish()
    }
}

impl CodeEmbedder {
    /// Create a new embedder with the default code model (Jina Code v2).
    pub fn new() -> Result<Self, KinDbError> {
        Self::with_model(DEFAULT_MODEL_ID, DEFAULT_REVISION)
    }

    /// Create with a specific HuggingFace model.
    #[cfg(feature = "embeddings")]
    pub fn with_model(model_id: &str, revision: &str) -> Result<Self, KinDbError> {
        let repo = Repo::with_revision(
            model_id.to_string(),
            RepoType::Model,
            revision.to_string(),
        );
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

        let tokenizer = Tokenizer::from_file(&tokenizer_path)
            .map_err(|e| KinDbError::IndexError(format!("failed to load tokenizer: {e}")))?;

        let model = BertModel::load(&weights_path, config)
            .map_err(|e| KinDbError::IndexError(format!("failed to load BERT model: {e}")))?;

        Ok(Self {
            model,
            tokenizer,
            dimensions,
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
        if texts.is_empty() {
            return Ok(Vec::new());
        }

        let encodings = self
            .tokenizer
            .encode_batch(texts.to_vec(), true)
            .map_err(|e| KinDbError::IndexError(format!("tokenization failed: {e}")))?;

        let token_ids: Vec<Vec<u32>> = encodings.iter().map(|e| e.get_ids().to_vec()).collect();
        let attention_masks: Vec<Vec<u32>> = encodings
            .iter()
            .map(|e| e.get_attention_mask().to_vec())
            .collect();

        // Pad all sequences to the same length
        let max_len = token_ids.iter().map(|s| s.len()).max().unwrap_or(0);
        let padded_ids: Vec<Vec<u32>> = token_ids
            .into_iter()
            .map(|mut s| {
                s.resize(max_len, 0);
                s
            })
            .collect();
        let padded_masks: Vec<Vec<u32>> = attention_masks
            .into_iter()
            .map(|mut s| {
                s.resize(max_len, 0);
                s
            })
            .collect();

        self.model.forward(&padded_ids, &padded_masks)
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

#[cfg(not(feature = "embeddings"))]
fn disabled_error() -> KinDbError {
    KinDbError::IndexError(
        "embeddings support is disabled in this build. Rebuild with `--features embeddings`."
            .into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Default embedding dimensions for Jina Code Embeddings v2.
    const JINA_CODE_DIMS: usize = 768;

    #[test]
    fn format_entity_text_joins_parts() {
        assert_eq!(
            format_entity_text("foo", "fn foo()", "{ 1 }"),
            "foo fn foo() { 1 }"
        );
        assert_eq!(format_entity_text("foo", "", ""), "foo");
        assert_eq!(format_entity_text("", "", ""), "");
    }

    #[cfg(feature = "embeddings")]
    #[test]
    #[ignore]
    fn embedder_initialises() {
        let embedder = CodeEmbedder::new().expect("model should initialise");
        assert_eq!(embedder.dimensions(), JINA_CODE_DIMS);
    }

    #[cfg(feature = "embeddings")]
    #[test]
    #[ignore]
    fn single_entity_embedding_has_correct_dims() {
        let embedder = CodeEmbedder::new().unwrap();
        let vec = embedder
            .embed_entity("parse_config", "fn parse_config(path: &str) -> Config", "")
            .unwrap();
        assert_eq!(vec.len(), JINA_CODE_DIMS);
    }

    #[cfg(feature = "embeddings")]
    #[test]
    #[ignore]
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
            assert_eq!(v.len(), JINA_CODE_DIMS);
        }
    }

    #[cfg(feature = "embeddings")]
    #[test]
    #[ignore]
    fn similar_names_produce_closer_embeddings() {
        let embedder = CodeEmbedder::new().unwrap();
        let v_parse_a = embedder
            .embed_entity("parse_json", "fn parse_json(s: &str) -> Value", "")
            .unwrap();
        let v_parse_b = embedder
            .embed_entity("parse_yaml", "fn parse_yaml(s: &str) -> Value", "")
            .unwrap();
        let v_unrelated = embedder
            .embed_entity(
                "render_template",
                "fn render_template(ctx: &Context) -> Html",
                "",
            )
            .unwrap();

        let sim_parsers = cosine_similarity(&v_parse_a, &v_parse_b);
        let sim_different = cosine_similarity(&v_parse_a, &v_unrelated);

        assert!(
            sim_parsers > sim_different,
            "similar functions ({sim_parsers:.4}) should be more similar than \
             unrelated ones ({sim_different:.4})"
        );
    }

    #[cfg(feature = "embeddings")]
    #[test]
    #[ignore]
    fn empty_batch_returns_empty() {
        let embedder = CodeEmbedder::new().unwrap();
        let results = embedder.embed_batch(&[]).unwrap();
        assert!(results.is_empty());
    }

    #[cfg(not(feature = "embeddings"))]
    #[test]
    fn disabled_embedder_returns_clear_error() {
        let err = CodeEmbedder::new().expect_err("embedder should be disabled");
        assert!(matches!(err, KinDbError::IndexError(msg) if msg.contains("embeddings support is disabled")));
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
