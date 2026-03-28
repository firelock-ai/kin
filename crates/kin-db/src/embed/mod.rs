// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

#[cfg(feature = "embeddings")]
mod inference;

#[cfg(feature = "embeddings")]
use hf_hub::{api::sync::Api, Repo, RepoType};
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
/// Jina Code Embeddings v2 — strong local code embeddings on a BERT-family
/// encoder once the runtime supports ALiBi + half-precision weights.
const DEFAULT_MODEL_ID: &str = "jinaai/jina-embeddings-v2-base-code";

/// Default model revision.
const DEFAULT_REVISION: &str = "main";
pub const EMBEDDING_BODY_PREVIEW_KEY: &str = "embedding_body_preview";

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
    /// Create a new embedder with the default code model (Jina Code v2).
    pub fn new() -> Result<Self, KinDbError> {
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

        self.model
            .forward(&token_ids, &attention_masks)
            .map_err(|e| KinDbError::IndexError(format!("inference failed: {e}")))
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

/// Build the text representation for a persisted graph entity.
pub fn format_graph_entity_text(entity: &Entity) -> String {
    let mut parts = Vec::with_capacity(6);

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

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{
        EntityId, EntityMetadata, FilePathId, FingerprintAlgorithm, Hash256, LanguageId,
        SemanticFingerprint, Visibility,
    };

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

        let formatted = format_graph_entity_text(&entity);
        assert!(formatted.contains("function"));
        assert!(formatted.contains("src/config.rs"));
        assert!(formatted.contains("parse_config"));
        assert!(formatted.contains("fn parse_config(path: &str) -> Config"));
        assert!(formatted.contains("Parse a config file"));
        assert!(formatted.contains("fn parse_config(path: &str) -> Config { ... }"));
    }

    #[test]
    fn default_dimensions_match_jina_model() {
        #[cfg(feature = "embeddings")]
        {
            let embedder = CodeEmbedder::new().unwrap();
            assert_eq!(embedder.dimensions(), JINA_CODE_DIMS);
        }
    }
}
