use fastembed::{EmbeddingModel, InitOptions, TextEmbedding};

use crate::error::KinDbError;

/// Default embedding dimensions for BGE-small-en-v1.5.
const BGE_SMALL_DIMS: usize = 384;

/// Generates code embeddings using a local ONNX model via fastembed.
///
/// Uses BGE-small-en-v1.5 by default (384 dimensions, ~33 MB, fast on CPU).
/// The model is downloaded on first use and cached locally.
pub struct CodeEmbedder {
    model: TextEmbedding,
    dimensions: usize,
}

impl CodeEmbedder {
    /// Create a new embedder with the default code model (BGE-small-en-v1.5).
    pub fn new() -> Result<Self, KinDbError> {
        Self::with_model(EmbeddingModel::BGESmallENV15)
    }

    /// Create with a specific fastembed model.
    pub fn with_model(model: EmbeddingModel) -> Result<Self, KinDbError> {
        let dimensions = model_dimensions(&model);
        let options = InitOptions::new(model).with_show_download_progress(true);
        let embedding = TextEmbedding::try_new(options).map_err(|e| {
            KinDbError::IndexError(format!("failed to initialise embedding model: {e}"))
        })?;
        Ok(Self {
            model: embedding,
            dimensions,
        })
    }

    /// Generate an embedding for a single entity.
    ///
    /// The input text is composed as `"{name} {signature} {body_preview}"`.
    pub fn embed_entity(
        &mut self,
        name: &str,
        signature: &str,
        body: &str,
    ) -> Result<Vec<f32>, KinDbError> {
        let text = format_entity_text(name, signature, body);
        let mut vecs = self.model.embed(vec![text], None).map_err(|e| {
            KinDbError::IndexError(format!("embedding generation failed: {e}"))
        })?;
        vecs.pop()
            .ok_or_else(|| KinDbError::IndexError("embedding returned empty result".into()))
    }

    /// Batch-embed multiple pre-formatted text strings. More efficient than
    /// calling [`embed_entity`] in a loop because the ONNX runtime can
    /// parallelise across the batch.
    pub fn embed_batch(&mut self, texts: &[String]) -> Result<Vec<Vec<f32>>, KinDbError> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }
        self.model.embed(texts.to_vec(), None).map_err(|e| {
            KinDbError::IndexError(format!("batch embedding failed: {e}"))
        })
    }

    /// The number of dimensions produced by this model.
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

/// Map well-known models to their output dimensions.
fn model_dimensions(model: &EmbeddingModel) -> usize {
    match model {
        EmbeddingModel::BGESmallENV15 | EmbeddingModel::BGESmallENV15Q => BGE_SMALL_DIMS,
        EmbeddingModel::BGEBaseENV15 | EmbeddingModel::BGEBaseENV15Q => 768,
        EmbeddingModel::BGELargeENV15 | EmbeddingModel::BGELargeENV15Q => 1024,
        EmbeddingModel::AllMiniLML6V2 | EmbeddingModel::AllMiniLML6V2Q => 384,
        EmbeddingModel::AllMiniLML12V2 | EmbeddingModel::AllMiniLML12V2Q => 384,
        EmbeddingModel::AllMpnetBaseV2 => 768,
        EmbeddingModel::NomicEmbedTextV1 => 768,
        EmbeddingModel::NomicEmbedTextV15 | EmbeddingModel::NomicEmbedTextV15Q => 768,
        EmbeddingModel::JinaEmbeddingsV2BaseCode => 768,
        EmbeddingModel::JinaEmbeddingsV2BaseEN => 768,
        // Fall back to a safe default; callers can override via with_model.
        _ => BGE_SMALL_DIMS,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedder_initialises() {
        let embedder = CodeEmbedder::new().expect("model should initialise");
        assert_eq!(embedder.dimensions(), BGE_SMALL_DIMS);
    }

    #[test]
    fn single_entity_embedding_has_correct_dims() {
        let mut embedder = CodeEmbedder::new().unwrap();
        let vec = embedder
            .embed_entity("parse_config", "fn parse_config(path: &str) -> Config", "")
            .unwrap();
        assert_eq!(vec.len(), BGE_SMALL_DIMS);
    }

    #[test]
    fn batch_embedding_returns_correct_count() {
        let mut embedder = CodeEmbedder::new().unwrap();
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
        let mut embedder = CodeEmbedder::new().unwrap();
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
        let mut embedder = CodeEmbedder::new().unwrap();
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
