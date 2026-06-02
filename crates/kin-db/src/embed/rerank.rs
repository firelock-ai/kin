use kin_infer::{BertConfig, BertModel};
use tokenizers::tokenizer::{PaddingParams, PaddingStrategy, TruncationParams, TruncationStrategy};
use tokenizers::Tokenizer;
use crate::error::KinDbError;
use hf_hub::{api::sync::Api, Repo, RepoType};

pub struct CrossEncoder {
    model: BertModel,
    tokenizer: Tokenizer,
}

impl CrossEncoder {
    pub fn new(model_id: &str, revision: &str) -> Result<Self, KinDbError> {
        let _span = tracing::info_span!("kindb.cross_encoder.new", model_id = %model_id, revision = %revision).entered();
        let repo = Repo::with_revision(model_id.to_string(), RepoType::Model, revision.to_string());
        let api = Api::new().map_err(|e| KinDbError::IndexError(format!("failed to initialise HuggingFace API: {e}")))?;
        let api = api.repo(repo);

        let config_path = api.get("config.json").map_err(|e| KinDbError::IndexError(format!("failed to download model config: {e}")))?;
        let tokenizer_path = api.get("tokenizer.json").map_err(|e| KinDbError::IndexError(format!("failed to download tokenizer: {e}")))?;
        let weights_path = api.get("model.safetensors").map_err(|e| KinDbError::IndexError(format!("failed to download model weights: {e}")))?;

        let config_data = std::fs::read_to_string(&config_path).map_err(|e| KinDbError::IndexError(format!("failed to read config: {e}")))?;
        let config: BertConfig = serde_json::from_str(&config_data).map_err(|e| KinDbError::IndexError(format!("failed to parse model config: {e}")))?;

        let mut tokenizer = Tokenizer::from_file(&tokenizer_path).map_err(|e| KinDbError::IndexError(format!("failed to load tokenizer: {e}")))?;
        
        let pad_id = tokenizer
            .token_to_id("<pad>")
            .or_else(|| tokenizer.get_padding().map(|padding| padding.pad_id))
            .or(config.pad_token_id)
            .unwrap_or(0);
        let pad_token = tokenizer.id_to_token(pad_id).unwrap_or_else(|| "<pad>".to_string());

        let max_length = config.max_position_embeddings.min(512);

        tokenizer.with_truncation(Some(TruncationParams {
            direction: tokenizers::tokenizer::TruncationDirection::Right,
            max_length,
            strategy: TruncationStrategy::LongestFirst,
            stride: 0,
        })).map_err(|e| KinDbError::IndexError(format!("failed to configure truncation: {e}")))?;

        tokenizer.with_padding(Some(PaddingParams {
            strategy: PaddingStrategy::BatchLongest,
            direction: tokenizers::tokenizer::PaddingDirection::Right,
            pad_to_multiple_of: None,
            pad_id,
            pad_type_id: 0,
            pad_token,
        }));

        let model = BertModel::load(&weights_path, config).map_err(|e| KinDbError::IndexError(format!("failed to load cross-encoder model: {e}")))?;

        Ok(Self {
            model,
            tokenizer,
        })
    }

    pub fn rerank(&self, query: &str, documents: &[&str]) -> Result<Vec<f32>, KinDbError> {
        let _span = tracing::info_span!("kindb.cross_encoder.rerank", query_len = query.len(), docs = documents.len()).entered();
        if documents.is_empty() {
            return Ok(Vec::new());
        }

        // Cross-encoder inputs are query/document pairs tokenized as
        // `[CLS] Query [SEP] Document [SEP]` via the tokenizer's dual-input path.
        let pairs: Vec<(String, String)> = documents.iter().map(|doc| (query.to_string(), doc.to_string())).collect();

        let encodings = self.tokenizer.encode_batch(
            pairs.into_iter()
                 .map(|(q, d)| tokenizers::EncodeInput::Dual(q.into(), d.into()))
                 .collect::<Vec<_>>(), 
            true
        ).map_err(|e| KinDbError::IndexError(format!("tokenization failed: {e}")))?;

        let token_ids: Vec<Vec<u32>> = encodings.iter().map(|e| e.get_ids().to_vec()).collect();
        let attention_masks: Vec<Vec<u32>> = encodings.iter().map(|e| e.get_attention_mask().to_vec()).collect();

        self.model.forward_cross_encoder_batched(&token_ids, &attention_masks).map_err(|e| KinDbError::IndexError(format!("inference failed: {e}")))
    }
}
