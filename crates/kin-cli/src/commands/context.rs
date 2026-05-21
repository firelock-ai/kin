// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_model::EntityStore;
use kin_model::{EntityFilter, TokenBudget};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextRequest {
    pub entity: String,
    pub budget: String,
    #[serde(default)]
    pub assistant: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextResponse {
    pub lines: Vec<String>,
}

pub async fn run(entity: String, budget: String, assistant: Option<String>) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let response = run_daemon_context(
        &layout,
        &ContextRequest {
            entity,
            budget,
            assistant,
        },
    )
    .await?;
    for line in response.lines {
        println!("{line}");
    }
    Ok(())
}

async fn run_daemon_context(
    layout: &kin_core::KinLayout,
    request: &ContextRequest,
) -> Result<ContextResponse> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url = daemon_url.ok_or_else(|| {
        anyhow::anyhow!("Kin daemon is required for context but no daemon endpoint is available")
    })?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client
        .context(request)
        .await
        .context("daemon context failed")
}

pub fn build_context_response(
    graph: &kin_db::InMemoryGraph,
    request: &ContextRequest,
) -> Result<ContextResponse> {
    let token_budget = parse_budget(&request.budget)?;

    let assistant_hint =
        request
            .assistant
            .as_deref()
            .and_then(|a| match a.to_lowercase().as_str() {
                "claude" | "claude-code" => Some(kin_context::AssistantHint::ClaudeCode),
                "codex" => Some(kin_context::AssistantHint::Codex),
                "gemini" | "gemini-cli" => Some(kin_context::AssistantHint::GeminiCli),
                _ => None,
            });

    // Find the entity
    let filter = EntityFilter {
        name_pattern: Some(request.entity.clone()),
        ..Default::default()
    };
    let matches = graph.query_entities(&filter)?;

    if matches.is_empty() {
        return Ok(ContextResponse {
            lines: vec![format!("Entity '{}' not found", request.entity)],
        });
    }

    let target = &matches[0];
    let opts = kin_context::ContextOptions {
        budget: token_budget,
        max_depth: 2,
        include_tests: true,
        include_contracts: true,
        include_traffic: false,
        assistant_hint,
    };

    let pack = kin_context::build_context_pack(graph, &target.id, &opts)?;

    let mut lines = vec![
        format!("Context pack for '{}' ({:?}):", target.name, target.kind),
        format!(
            "  Budget: {}/{} tokens",
            pack.actual_tokens,
            token_budget.max_tokens()
        ),
        format!("  Focal: {} entries", pack.focal_entities.len()),
        format!(
            "  Dependencies: {} entries",
            pack.dependency_signatures.len()
        ),
        format!("  Transitive: {} entries", pack.transitive_deps.len()),
        format!("  Contracts: {} entries", pack.contracts.len()),
        format!("  Tests: {} entries", pack.tests.len()),
        String::new(),
        "--- Context Pack ---".to_string(),
    ];

    for entry in &pack.focal_entities {
        lines.push(entry.content.clone());
    }
    for entry in &pack.dependency_signatures {
        lines.push(entry.content.clone());
    }
    for entry in &pack.transitive_deps {
        lines.push(entry.content.clone());
    }

    Ok(ContextResponse { lines })
}

fn parse_budget(s: &str) -> Result<TokenBudget> {
    match s {
        "8k" => Ok(TokenBudget::Small8k),
        "16k" => Ok(TokenBudget::Medium16k),
        "32k" => Ok(TokenBudget::Large32k),
        _ => {
            let n: usize = s.parse().map_err(|_| {
                anyhow::anyhow!("invalid budget: use '8k', '16k', '32k', or a number")
            })?;
            Ok(TokenBudget::Custom(n))
        }
    }
}
