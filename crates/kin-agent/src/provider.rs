// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! An OpenAI-compatible chat-completions client.
//!
//! One adapter reaches LM Studio, Ollama, llama.cpp, vLLM, OpenRouter and OpenAI, because
//! they all speak the same wire format for `tools` and `tool_calls`. The API key is read
//! from a named environment variable and never accepted on argv, so it cannot land in a
//! process listing or a transcript.

use serde_json::{json, Value};
use std::time::{Duration, Instant};

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
    #[error("request context accounting failed: {0}")]
    Accounting(String),
    #[error("request context accounting failed: {reason}")]
    RejectedCompletion { reason: String, usage: Usage },
    #[error("the environment variable {name} names an API key but is not set")]
    MissingKey { name: String },
    #[error("KIN_AGENT_OUTPUT_TOKEN_PARAMETER must be max_tokens or max_completion_tokens")]
    InvalidOutputTokenParameter,
}

impl ProviderError {
    pub(crate) fn is_accounting_failure(&self) -> bool {
        matches!(self, Self::Accounting(_) | Self::RejectedCompletion { .. })
    }
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

    /// The server root the OpenAI-compatible base hangs off, where a server keeps its own
    /// API beside the compatible one.
    pub fn origin(&self) -> &str {
        self.base_url
            .strip_suffix("/v1")
            .unwrap_or(self.base_url.as_str())
    }
}

/// How long one context-window probe may take before the run starts without its answer.
const DISCOVERY_TIMEOUT: Duration = Duration::from_secs(5);

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

/// Opt-in counting uses the selected server's rendered text and tokenizer contract.
/// Generic endpoints retain explicitly heuristic accounting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestAccounting {
    Heuristic,
    LlamaCpp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputTokenParameter {
    MaxTokens,
    MaxCompletionTokens,
}

impl OutputTokenParameter {
    fn select(base_url: &str, override_value: Option<&str>) -> Result<Self, ProviderError> {
        match override_value {
            Some("max_tokens") => Ok(Self::MaxTokens),
            Some("max_completion_tokens") => Ok(Self::MaxCompletionTokens),
            Some(_) => Err(ProviderError::InvalidOutputTokenParameter),
            None => {
                let openai = reqwest::Url::parse(base_url).is_ok_and(|url| {
                    url.host_str()
                        .is_some_and(|host| host.eq_ignore_ascii_case("api.openai.com"))
                });
                Ok(if openai {
                    Self::MaxCompletionTokens
                } else {
                    Self::MaxTokens
                })
            }
        }
    }

    fn key(self) -> &'static str {
        match self {
            Self::MaxTokens => "max_tokens",
            Self::MaxCompletionTokens => "max_completion_tokens",
        }
    }
}

/// The exact generation body retained across admission and dispatch.
pub(crate) struct ChatRequest {
    body: Value,
    counted_prompt_tokens: Option<u64>,
    output_token_parameter: OutputTokenParameter,
}
impl ChatRequest {
    pub(crate) fn expect_prompt_tokens(&mut self, tokens: u64) {
        self.counted_prompt_tokens = Some(tokens);
    }
    pub(crate) fn max_tokens(&self) -> u64 {
        self.output_bound().expect("bounded request")
    }
    fn output_bound(&self) -> Option<u64> {
        self.body
            .get(self.output_token_parameter())
            .and_then(Value::as_u64)
    }
    pub(crate) fn output_token_parameter(&self) -> &'static str {
        self.output_token_parameter.key()
    }
    pub(crate) fn set_max_tokens(&mut self, tokens: u64) {
        let parameter = self.output_token_parameter();
        self.body[parameter] = json!(tokens);
        self.counted_prompt_tokens = None;
    }
    pub(crate) fn heuristic_tokens(&self) -> u64 {
        let bytes = self.body.to_string().len() as u64;
        let messages = self.body["messages"].as_array().map_or(0, Vec::len) as u64;
        crate::context::estimate_tokens(bytes).saturating_add(messages.saturating_mul(8))
    }
}

pub(crate) enum PromptCount {
    Counted(u64),
    Unsupported(String),
}

pub struct Provider {
    client: reqwest::blocking::Client,
    config: ProviderConfig,
    output_token_parameter: OutputTokenParameter,
}

impl Provider {
    pub fn new(config: ProviderConfig) -> Result<Self, ProviderError> {
        let override_value = match std::env::var("KIN_AGENT_OUTPUT_TOKEN_PARAMETER") {
            Ok(value) => Some(value),
            Err(std::env::VarError::NotPresent) => None,
            Err(_) => return Err(ProviderError::InvalidOutputTokenParameter),
        };
        Self::new_with_output_token_override(config, override_value.as_deref())
    }

    fn new_with_output_token_override(
        config: ProviderConfig,
        override_value: Option<&str>,
    ) -> Result<Self, ProviderError> {
        let output_token_parameter =
            OutputTokenParameter::select(&config.base_url, override_value)?;
        let client = reqwest::blocking::Client::builder()
            .timeout(config.request_timeout)
            .build()
            .map_err(|source| ProviderError::Transport {
                url: config.base_url.clone(),
                source,
            })?;
        Ok(Provider {
            client,
            config,
            output_token_parameter,
        })
    }

    pub(crate) fn output_token_parameter(&self) -> &'static str {
        self.output_token_parameter.key()
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

    /// One turn, waiting as long as the configured request timeout allows.
    pub fn complete(
        &self,
        messages: &[Value],
        tools: &[Value],
    ) -> Result<Completion, ProviderError> {
        self.complete_within(messages, tools, self.config.request_timeout)
    }

    /// One turn that waits at most `limit` for the whole answer, from connecting to the last
    /// byte of the body. The loop passes what is left of the run's deadline, so a slow
    /// endpoint ends the wait rather than stretching the run. `tools` empty means a
    /// tool-free turn, which is how the forced final answer is asked for: the model is
    /// given nothing to call.
    pub fn complete_within(
        &self,
        messages: &[Value],
        tools: &[Value],
        limit: Duration,
    ) -> Result<Completion, ProviderError> {
        let request = self.request_body(messages, tools, None);
        self.complete_request_within(&request, limit)
    }

    fn request_body(
        &self,
        messages: &[Value],
        tools: &[Value],
        max_tokens: Option<u64>,
    ) -> ChatRequest {
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

        if let Some(max_tokens) = max_tokens {
            body[self.output_token_parameter()] = json!(max_tokens);
        }
        ChatRequest {
            body,
            counted_prompt_tokens: None,
            output_token_parameter: self.output_token_parameter,
        }
    }

    pub(crate) fn prepare_request(
        &self,
        messages: &[Value],
        tools: &[Value],
        max_tokens: u64,
    ) -> ChatRequest {
        self.request_body(messages, tools, Some(max_tokens))
    }

    /// Apply the same complete body generation will receive. Special tokens are already
    /// represented in the selected template contract: do not add another BOS here.
    /// Only an explicit unsupported route permits heuristic fallback. Other failures stop
    /// admission, including malformed success responses and tokenizer errors.
    pub(crate) fn count_prompt_within(
        &self,
        request: &ChatRequest,
        limit: Duration,
    ) -> Result<PromptCount, ProviderError> {
        let deadline = Instant::now() + limit;
        let template_url = format!("{}/apply-template", self.config.origin());
        let template = match self.accounting_json(&template_url, &request.body, deadline)? {
            Ok(value) => value,
            Err(reason) => return Ok(PromptCount::Unsupported(reason)),
        };
        let prompt = template
            .get("prompt")
            .and_then(Value::as_str)
            .ok_or_else(|| {
                ProviderError::Accounting("apply-template returned no text prompt".into())
            })?;
        let tokenize_url = format!("{}/tokenize", self.config.origin());
        let tokenized = match self.accounting_json(&tokenize_url, &json!({
            "content": prompt, "add_special": false, "parse_special": true, "with_pieces": false,
        }), deadline)? {
            Ok(value) => value,
            Err(reason) => return Ok(PromptCount::Unsupported(reason)),
        };
        let tokens = tokenized
            .get("tokens")
            .and_then(Value::as_array)
            .filter(|tokens| tokens.iter().all(|token| token.as_u64().is_some()))
            .ok_or_else(|| {
                ProviderError::Accounting("tokenize returned no valid token ID array".into())
            })?;
        if !prompt.is_empty() && tokens.is_empty() {
            return Err(ProviderError::Accounting(
                "tokenize returned zero tokens for a nonempty prompt".into(),
            ));
        }
        Ok(PromptCount::Counted(tokens.len() as u64))
    }

    fn accounting_json(
        &self,
        url: &str,
        body: &Value,
        deadline: Instant,
    ) -> Result<Result<Value, String>, ProviderError> {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ProviderError::Accounting(
                "counting deadline exhausted".into(),
            ));
        }
        let response = self
            .request(self.client.post(url))
            .timeout(remaining)
            .json(body)
            .send()
            .map_err(|source| ProviderError::Transport {
                url: url.into(),
                source,
            })?;
        let status = response.status();
        if [404, 405, 501].contains(&status.as_u16()) {
            return Ok(Err(format!(
                "{url} does not support counting (HTTP {})",
                status.as_u16()
            )));
        }
        if !status.is_success() {
            return Err(ProviderError::Status {
                url: url.into(),
                status: status.as_u16(),
                body: truncate(&response.text().unwrap_or_default(), 400),
            });
        }
        response
            .json()
            .map(Ok)
            .map_err(|source| ProviderError::Body {
                url: url.into(),
                source,
            })
    }

    pub(crate) fn complete_request_within(
        &self,
        request: &ChatRequest,
        limit: Duration,
    ) -> Result<Completion, ProviderError> {
        let url = self.config.chat_url();
        let started = std::time::Instant::now();
        let response = self
            .request(self.client.post(&url))
            .timeout(limit)
            .json(&request.body)
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
        if let (Some(expected), Some(actual)) = (request.counted_prompt_tokens, usage.input_tokens)
        {
            if actual != expected {
                return Err(ProviderError::RejectedCompletion {
                    reason: format!("generation prompt usage {actual} differs from admitted template count {expected}"),
                    usage,
                });
            }
        }
        if let (Some(bound), Some(actual)) = (request.output_bound(), usage.output_tokens) {
            if actual > bound {
                return Err(ProviderError::RejectedCompletion {
                    reason: format!(
                        "generation output usage {actual} exceeds admitted bound {bound}"
                    ),
                    usage,
                });
            }
        }
        Ok(Completion {
            choice,
            usage,
            api_ms,
        })
    }

    /// The context window the endpoint reports for this model, in tokens, when it reports one.
    ///
    /// Read first off the OpenAI-compatible model list, where vLLM names `max_model_len` and
    /// OpenRouter names `context_length`, then off LM Studio's own API, which is the one of
    /// these that knows the context a model was LOADED with. A model's maximum is never taken
    /// as its window: a model loaded below its maximum overflows at the loaded size, and a
    /// budget built on the maximum would let the endpoint cut the conversation silently.
    pub fn discover_context_window(&self) -> Option<u64> {
        let model = self.config.model.as_str();
        if model.is_empty() {
            return None;
        }
        if let Some(tokens) = self
            .get_json(&self.config.models_url())
            .and_then(|payload| context_from_model_list(&payload, model))
        {
            return Some(tokens);
        }
        let origin = self.config.origin();
        if let Some(tokens) = self
            .get_json(&format!("{origin}/api/v1/models"))
            .and_then(|payload| context_from_lmstudio_models(&payload, model))
        {
            return Some(tokens);
        }
        self.get_json(&format!("{origin}/api/v0/models/{model}"))
            .and_then(|payload| context_from_lmstudio_model(&payload))
    }

    /// A short GET whose failure is an absent answer rather than an error, for probes.
    fn get_json(&self, url: &str) -> Option<Value> {
        let response = self
            .request(self.client.get(url))
            .timeout(DISCOVERY_TIMEOUT)
            .send()
            .ok()?;
        if !response.status().is_success() {
            return None;
        }
        response.json().ok()
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

/// The window an OpenAI-compatible `/models` entry names for `model`, when it names one.
pub(crate) fn context_from_model_list(payload: &Value, model: &str) -> Option<u64> {
    let entry = payload
        .get("data")?
        .as_array()?
        .iter()
        .find(|entry| entry.get("id").and_then(Value::as_str) == Some(model))?;
    [
        "loaded_context_length",
        "max_model_len",
        "context_length",
        "context_window",
    ]
    .into_iter()
    .find_map(|key| positive_tokens(entry.get(key)))
}

/// The smallest context any loaded LM Studio instance of `model` carries, from
/// `/api/v1/models`. An instance is the model's when the model's key is the id asked for, or
/// when the instance's own id is, which is how a second loaded copy is addressed.
pub(crate) fn context_from_lmstudio_models(payload: &Value, model: &str) -> Option<u64> {
    payload
        .get("models")?
        .as_array()?
        .iter()
        .flat_map(|entry| {
            let keyed = entry.get("key").and_then(Value::as_str) == Some(model);
            entry
                .get("loaded_instances")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter(move |instance| {
                    keyed || instance.get("id").and_then(Value::as_str) == Some(model)
                })
        })
        .filter_map(|instance| positive_tokens(instance.pointer("/config/context_length")))
        .min()
}

/// The loaded context an LM Studio `/api/v0/models/<id>` answer carries. Its
/// `max_context_length` is the model's maximum, not the loaded size, and is never read.
pub(crate) fn context_from_lmstudio_model(payload: &Value) -> Option<u64> {
    positive_tokens(payload.get("loaded_context_length"))
}

fn positive_tokens(value: Option<&Value>) -> Option<u64> {
    let value = value?;
    value
        .as_u64()
        .or_else(|| {
            value
                .as_f64()
                .filter(|tokens| tokens.is_finite() && *tokens >= 1.0)
                .map(|tokens| tokens as u64)
        })
        .filter(|tokens| *tokens > 0)
}

fn truncate(text: &str, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text.to_string();
    }
    text.chars().take(limit).collect::<String>() + "..."
}

#[cfg(test)]
mod accounting_tests {
    use super::*;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;

    #[test]
    fn output_parameter_uses_the_exact_parsed_host_and_explicit_override() {
        for (base_url, override_value, expected) in [
            ("https://api.openai.com/v1", None, "max_completion_tokens"),
            (
                "https://API.OPENAI.COM:443/v1",
                None,
                "max_completion_tokens",
            ),
            ("https://api.openai.com.example/v1", None, "max_tokens"),
            ("https://other-api.openai.com/v1", None, "max_tokens"),
            ("https://api.openai.com@localhost/v1", None, "max_tokens"),
            (
                "http://localhost/v1?host=api.openai.com",
                None,
                "max_tokens",
            ),
            ("http://localhost/v1", None, "max_tokens"),
            (
                "https://api.openai.com/v1",
                Some("max_tokens"),
                "max_tokens",
            ),
            (
                "http://localhost/v1",
                Some("max_completion_tokens"),
                "max_completion_tokens",
            ),
        ] {
            let provider = Provider::new_with_output_token_override(
                ProviderConfig {
                    base_url: base_url.into(),
                    // A local model alias must not decide the protocol dialect.
                    model: "o3".into(),
                    api_key: None,
                    temperature: None,
                    request_timeout: Duration::from_secs(2),
                },
                override_value,
            )
            .unwrap();
            let mut request =
                provider.prepare_request(&[json!({"role":"user","content":"hello"})], &[], 1024);
            assert_eq!(request.output_token_parameter(), expected, "{base_url}");
            assert_eq!(request.body[expected], 1024);
            request.expect_prompt_tokens(100);
            request.set_max_tokens(192);
            assert_eq!(request.max_tokens(), 192);
            assert_eq!(request.counted_prompt_tokens, None);
            let other = if expected == "max_tokens" {
                "max_completion_tokens"
            } else {
                "max_tokens"
            };
            assert!(request.body.get(other).is_none());
            let unbounded = provider.request_body(&[], &[], None);
            assert_eq!(unbounded.output_bound(), None);
            assert!(unbounded.body.get(expected).is_none());
            assert!(unbounded.body.get(other).is_none());
        }
        for invalid in ["", "max_output_tokens", "max_tokens ", "MAX_TOKENS"] {
            assert!(matches!(
                OutputTokenParameter::select("https://api.openai.com/v1", Some(invalid)),
                Err(ProviderError::InvalidOutputTokenParameter)
            ));
        }
    }

    #[test]
    fn retained_template_count_uses_the_generation_body_and_no_extra_bos() {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/fixtures/llama_template_count.json"))
                .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let base_url = format!("http://{}/v1", listener.local_addr().unwrap());
        let server_fixture = fixture.clone();
        let server = std::thread::spawn(move || {
            let mut seen = Vec::new();
            for (route, key) in [
                ("/apply-template", "template_response"),
                ("/tokenize", "tokenize_response"),
                ("/v1/chat/completions", "completion_response"),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                assert_eq!(line.split_whitespace().nth(1), Some(route));
                let mut size = 0;
                loop {
                    line.clear();
                    reader.read_line(&mut line).unwrap();
                    if line.trim().is_empty() {
                        break;
                    }
                    if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                        size = value.trim().parse::<usize>().unwrap();
                    }
                }
                let mut bytes = vec![0; size];
                reader.read_exact(&mut bytes).unwrap();
                seen.push(serde_json::from_slice::<Value>(&bytes).unwrap());
                let body = server_fixture[key].to_string();
                write!(stream,"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",body.len(),body).unwrap();
            }
            seen
        });
        let provider = Provider::new(ProviderConfig {
            base_url,
            model: "fixture".into(),
            api_key: None,
            temperature: None,
            request_timeout: Duration::from_secs(2),
        })
        .unwrap();
        let mut request = ChatRequest {
            body: fixture["request"].clone(),
            counted_prompt_tokens: None,
            output_token_parameter: OutputTokenParameter::MaxTokens,
        };
        let PromptCount::Counted(tokens) = provider
            .count_prompt_within(&request, Duration::from_secs(2))
            .unwrap()
        else {
            panic!("expected retained template count")
        };
        assert_eq!(tokens, 481);
        request.expect_prompt_tokens(tokens);
        let completed = provider
            .complete_request_within(&request, Duration::from_secs(2))
            .unwrap();
        assert_eq!(completed.usage.input_tokens, Some(tokens));
        let seen = server.join().unwrap();
        assert_eq!(seen[0], fixture["request"]);
        assert_eq!(seen[0], seen[2]);
        assert_eq!(seen[1]["content"], fixture["template_response"]["prompt"]);
        assert_eq!(seen[1]["add_special"], false);
        assert_eq!(seen[1]["parse_special"], true);
        assert_eq!(seen[1]["with_pieces"], false);
    }
}
