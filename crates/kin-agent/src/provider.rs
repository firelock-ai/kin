// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! An OpenAI-compatible chat-completions client.
//!
//! One adapter reaches LM Studio, Ollama, llama.cpp, vLLM, OpenRouter and OpenAI, because
//! they all speak the same wire format for `tools` and `tool_calls`. The API key is read
//! from a named environment variable and never accepted on argv, so it cannot land in a
//! process listing or a transcript.

use serde_json::{json, Value};
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("the chat endpoint at {url} could not be reached: {source}")]
    Transport { url: String, source: reqwest::Error },
    #[error("the chat endpoint at {url} answered {status}: {body}")]
    Status {
        url: String,
        status: u16,
        body: String,
    },
    #[error("the chat endpoint at {url} answered with a body that is not JSON: {source}")]
    Body { url: String, source: reqwest::Error },
    #[error("the chat endpoint answered with no choices")]
    NoChoices,
    #[error("the environment variable {name} names an API key but is not set")]
    MissingKey { name: String },
}

/// How to reach a model.
#[derive(Debug, Clone)]
pub struct ProviderConfig {
    pub base_url: String,
    pub model: String,
    pub api_key: Option<String>,
    pub temperature: Option<f32>,
    pub request_timeout: Duration,
}

impl ProviderConfig {
    /// Normalize a base URL: trailing slashes go, and a bare host gains `/v1`, so
    /// `http://127.0.0.1:1234` and `http://127.0.0.1:1234/v1/` mean the same endpoint.
    pub fn normalize_base_url(raw: &str) -> String {
        let trimmed = raw.trim().trim_end_matches('/');
        if trimmed.ends_with("/v1") || trimmed.ends_with("/openai") || trimmed.contains("/v1/") {
            trimmed.to_string()
        } else {
            format!("{trimmed}/v1")
        }
    }

    /// Read the key from the named variable, failing loudly when it is named and absent.
    pub fn api_key_from_env(name: Option<&str>) -> Result<Option<String>, ProviderError> {
        let Some(name) = name else { return Ok(None) };
        match std::env::var(name) {
            Ok(value) if !value.trim().is_empty() => Ok(Some(value)),
            _ => Err(ProviderError::MissingKey {
                name: name.to_string(),
            }),
        }
    }

    pub fn chat_url(&self) -> String {
        format!("{}/chat/completions", self.base_url)
    }

    pub fn models_url(&self) -> String {
        format!("{}/models", self.base_url)
    }
}

/// What one completion cost, when the endpoint said.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Usage {
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
}

impl Usage {
    pub fn is_empty(&self) -> bool {
        self.input_tokens.is_none() && self.output_tokens.is_none()
    }

    pub fn to_json(&self) -> Option<Value> {
        if self.is_empty() {
            return None;
        }
        let mut map = serde_json::Map::new();
        if let Some(value) = self.input_tokens {
            map.insert("input_tokens".into(), Value::from(value));
        }
        if let Some(value) = self.output_tokens {
            map.insert("output_tokens".into(), Value::from(value));
        }
        Some(Value::Object(map))
    }
}

/// One completion.
#[derive(Debug, Clone)]
pub struct Completion {
    pub choice: Value,
    pub usage: Usage,
    pub api_ms: u128,
}

pub struct Provider {
    client: reqwest::blocking::Client,
    config: ProviderConfig,
}

impl Provider {
    pub fn new(config: ProviderConfig) -> Result<Self, ProviderError> {
        let client = reqwest::blocking::Client::builder()
            .timeout(config.request_timeout)
            .build()
            .map_err(|source| ProviderError::Transport {
                url: config.base_url.clone(),
                source,
            })?;
        Ok(Provider { client, config })
    }

    pub fn config(&self) -> &ProviderConfig {
        &self.config
    }

    /// The model ids the endpoint serves, used by `kin agent doctor`.
    pub fn list_models(&self) -> Result<Vec<String>, ProviderError> {
        let url = self.config.models_url();
        let response = self
            .request(self.client.get(&url))
            .send()
            .map_err(|source| ProviderError::Transport {
                url: url.clone(),
                source,
            })?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().unwrap_or_default();
            return Err(ProviderError::Status {
                url,
                status: status.as_u16(),
                body: truncate(&body, 400),
            });
        }
        let body: Value = response
            .json()
            .map_err(|source| ProviderError::Body { url, source })?;
        Ok(body
            .get("data")
            .and_then(Value::as_array)
            .map(|models| {
                models
                    .iter()
                    .filter_map(|model| model.get("id").and_then(Value::as_str))
                    .map(ToString::to_string)
                    .collect()
            })
            .unwrap_or_default())
    }

    /// One turn. `tools` empty means a tool-free turn, which is how the forced final
    /// answer is asked for: the model is given nothing to call.
    pub fn complete(
        &self,
        messages: &[Value],
        tools: &[Value],
    ) -> Result<Completion, ProviderError> {
        let url = self.config.chat_url();
        let mut body = json!({
            "model": self.config.model,
            "messages": messages,
            "stream": false,
        });
        if let Some(temperature) = self.config.temperature {
            body["temperature"] = json!(temperature);
        }
        if !tools.is_empty() {
            body["tools"] = Value::Array(tools.to_vec());
            body["tool_choice"] = json!("auto");
        }

        let started = std::time::Instant::now();
        let response = self
            .request(self.client.post(&url))
            .json(&body)
            .send()
            .map_err(|source| ProviderError::Transport {
                url: url.clone(),
                source,
            })?;
        let api_ms = started.elapsed().as_millis();
        let status = response.status();
        if !status.is_success() {
            let text = response.text().unwrap_or_default();
            return Err(ProviderError::Status {
                url,
                status: status.as_u16(),
                body: truncate(&text, 400),
            });
        }
        let payload: Value = response
            .json()
            .map_err(|source| ProviderError::Body { url, source })?;
        let choice = payload
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|choices| choices.first())
            .cloned()
            .ok_or(ProviderError::NoChoices)?;
        let usage = payload
            .get("usage")
            .map(|usage| Usage {
                input_tokens: usage.get("prompt_tokens").and_then(Value::as_u64),
                output_tokens: usage.get("completion_tokens").and_then(Value::as_u64),
            })
            .unwrap_or_default();
        Ok(Completion {
            choice,
            usage,
            api_ms,
        })
    }

    fn request(
        &self,
        builder: reqwest::blocking::RequestBuilder,
    ) -> reqwest::blocking::RequestBuilder {
        match self.config.api_key.as_deref() {
            Some(key) => builder.bearer_auth(key),
            None => builder,
        }
    }
}

fn truncate(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_string();
    }
    text.chars().take(limit).collect::<String>() + "..."
}
