// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;
use std::time::Duration;

use serde_json::Value;

use crate::error::{McpError, Result};
use crate::types::ToolCallResult;

use super::common::{
    get_optional_string_array, get_optional_string_param, get_optional_u64, get_string_param,
};

pub const YOUCOM_SEARCH_DESC: &str = "\
Search the public web with You.com and return the raw LLM-ready results payload. \
Use this when you want fresh external context that Kin's graph-native search cannot \
provide: news, current web pages, and optional domain filtering. This tool is opt-in \
and requires YDC_API_KEY; YOUCOM_BASE_URL defaults to https://api.you.com. If no key \
is configured, the tool returns a clear error instead of changing Kin's default \
behavior.";

fn resolve_youcom_base_url_with<F>(mut get_var: F) -> String
where
    F: FnMut(&str) -> Option<String>,
{
    get_var("YOUCOM_BASE_URL")
        .and_then(|value| {
            let trimmed = value.trim().trim_end_matches('/').to_string();
            (!trimmed.is_empty()).then_some(trimmed)
        })
        .unwrap_or_else(|| "https://api.you.com".to_string())
}

fn resolve_youcom_api_key_with<F>(mut get_var: F) -> Option<String>
where
    F: FnMut(&str) -> Option<String>,
{
    get_var("YDC_API_KEY").and_then(|value| {
        let trimmed = value.trim();
        (!trimmed.is_empty()).then_some(trimmed.to_string())
    })
}

fn validate_domain_filters(
    include_domains: &Option<Vec<String>>,
    exclude_domains: &Option<Vec<String>>,
    boost_domains: &Option<Vec<String>>,
) -> Result<()> {
    if include_domains.is_some() && exclude_domains.is_some() {
        return Err(McpError::InvalidParams(
            "include_domains and exclude_domains cannot be used together".into(),
        ));
    }
    if include_domains.is_some() && boost_domains.is_some() {
        return Err(McpError::InvalidParams(
            "include_domains and boost_domains cannot be used together".into(),
        ));
    }
    Ok(())
}

fn build_search_request(args: &HashMap<String, Value>) -> Result<(String, serde_json::Value)> {
    let query = get_string_param(args, "query")?;
    let count = get_optional_u64(args, "count", 10).clamp(1, 100) as u64;
    let freshness = get_optional_string_param(args, "freshness");
    let offset = get_optional_u64(args, "offset", 0).min(9);
    let country = get_optional_string_param(args, "country");
    let language = get_optional_string_param(args, "language");
    let safesearch = get_optional_string_param(args, "safesearch");
    let include_domains = get_optional_string_array(args, "include_domains");
    let exclude_domains = get_optional_string_array(args, "exclude_domains");
    let boost_domains = get_optional_string_array(args, "boost_domains");

    validate_domain_filters(&include_domains, &exclude_domains, &boost_domains)?;

    let mut request = serde_json::json!({
        "query": query,
        "count": count,
        "offset": offset,
    });

    if let Some(value) = freshness {
        request["freshness"] = serde_json::json!(value);
    }
    if let Some(value) = country {
        request["country"] = serde_json::json!(value);
    }
    if let Some(value) = language {
        request["language"] = serde_json::json!(value);
    }
    if let Some(value) = safesearch {
        request["safesearch"] = serde_json::json!(value);
    }
    if let Some(value) = include_domains {
        request["include_domains"] = serde_json::json!(value);
    }
    if let Some(value) = exclude_domains {
        request["exclude_domains"] = serde_json::json!(value);
    }
    if let Some(value) = boost_domains {
        request["boost_domains"] = serde_json::json!(value);
    }

    Ok((query, request))
}

async fn perform_youcom_search(
    base_url: &str,
    api_key: &str,
    request: &serde_json::Value,
) -> Result<serde_json::Value> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|error| McpError::Other(format!("failed to build reqwest client: {error}")))?;

    let response = client
        .post(format!("{}/v1/search", base_url.trim_end_matches('/')))
        .header("X-API-Key", api_key)
        .header(
            reqwest::header::USER_AGENT,
            format!("kin-mcp/{} (youcom_search)", env!("CARGO_PKG_VERSION")),
        )
        .json(request)
        .send()
        .await
        .map_err(|error| McpError::Other(format!("You.com search request failed: {error}")))?;

    let status = response.status();
    let body = response.text().await.map_err(|error| {
        McpError::Other(format!("failed to read You.com response body: {error}"))
    })?;

    if !status.is_success() {
        return Err(McpError::Other(format!(
            "You.com search API returned {status}: {body}"
        )));
    }

    serde_json::from_str(&body).map_err(|error| {
        McpError::Other(format!(
            "failed to parse You.com search response: {error}; body: {body}"
        ))
    })
}

pub async fn handle_youcom_search(args: &HashMap<String, Value>) -> Result<ToolCallResult> {
    let (query, request) = build_search_request(args)?;
    let api_key = resolve_youcom_api_key_with(|key| std::env::var(key).ok()).ok_or_else(|| {
        McpError::Other(
            "YDC_API_KEY is required for youcom_search; set it to a You.com API key or use a different MCP tool profile"
                .to_string(),
        )
    })?;
    let base_url = resolve_youcom_base_url_with(|key| std::env::var(key).ok());

    let response = perform_youcom_search(&base_url, &api_key, &request).await?;
    let envelope = serde_json::json!({
        "provider": "you.com",
        "query": query,
        "base_url": base_url,
        "request": request,
        "response": response,
    });

    let json = serde_json::to_string_pretty(&envelope).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_url_defaults_to_youcom() {
        assert_eq!(
            resolve_youcom_base_url_with(|_| None),
            "https://api.you.com"
        );
    }

    #[test]
    fn base_url_trims_trailing_slashes_and_whitespace() {
        let base = resolve_youcom_base_url_with(|key| {
            (key == "YOUCOM_BASE_URL").then_some(" https://example.com/api/// ".to_string())
        });
        assert_eq!(base, "https://example.com/api");
    }

    #[test]
    fn api_key_trims_and_skips_blank_values() {
        assert_eq!(
            resolve_youcom_api_key_with(|key| {
                (key == "YDC_API_KEY").then_some("  secret-key  ".to_string())
            }),
            Some("secret-key".to_string())
        );
        assert_eq!(
            resolve_youcom_api_key_with(|_| Some("   ".to_string())),
            None
        );
    }

    #[test]
    fn request_body_includes_supported_filters() {
        let mut args = HashMap::new();
        args.insert("query".into(), serde_json::json!("kin release"));
        args.insert("count".into(), serde_json::json!(25));
        args.insert("offset".into(), serde_json::json!(2));
        args.insert("freshness".into(), serde_json::json!("week"));
        args.insert("country".into(), serde_json::json!("US"));
        args.insert("language".into(), serde_json::json!("en"));
        args.insert("safesearch".into(), serde_json::json!("moderate"));
        args.insert(
            "boost_domains".into(),
            serde_json::json!(["github.com", "docs.rs"]),
        );

        let (query, request) = build_search_request(&args).unwrap();
        assert_eq!(query, "kin release");
        assert_eq!(request["query"], serde_json::json!("kin release"));
        assert_eq!(request["count"], serde_json::json!(25));
        assert_eq!(request["offset"], serde_json::json!(2));
        assert_eq!(request["freshness"], serde_json::json!("week"));
        assert_eq!(request["country"], serde_json::json!("US"));
        assert_eq!(request["language"], serde_json::json!("en"));
        assert_eq!(request["safesearch"], serde_json::json!("moderate"));
        assert_eq!(
            request["boost_domains"],
            serde_json::json!(["github.com", "docs.rs"])
        );
    }

    #[test]
    fn request_body_rejects_conflicting_domain_filters() {
        let mut args = HashMap::new();
        args.insert("query".into(), serde_json::json!("kin"));
        args.insert("include_domains".into(), serde_json::json!(["you.com"]));
        args.insert("exclude_domains".into(), serde_json::json!(["example.com"]));

        let err = build_search_request(&args).unwrap_err();
        assert!(err.to_string().contains("cannot be used together"));
    }
}
