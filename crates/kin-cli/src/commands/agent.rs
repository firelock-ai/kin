// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin agent`: run a task through Kin's own agent loop.

use anyhow::{Context, Result};
use kin_agent::{
    AgentConfig, ExitStatus, ProviderConfig, DEFAULT_DEADLINE_S, DEFAULT_MAX_TOOL_CALLS,
    DEFAULT_MCP_TIMEOUT_S, DEFAULT_REQUEST_TIMEOUT_S,
};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Everything the `run` subcommand accepts.
#[allow(clippy::too_many_arguments)]
pub struct RunArgs {
    pub task: String,
    pub model: String,
    pub base_url: String,
    pub api_key_env: Option<String>,
    pub repo: Option<PathBuf>,
    pub mcp_command: Option<String>,
    pub out: Option<PathBuf>,
    pub max_tool_calls: Option<u32>,
    pub deadline: Option<u64>,
    pub system: Option<PathBuf>,
    pub temperature: Option<f32>,
    pub tool_profile: Option<String>,
}

/// Run one task. Returns the process exit code; the caller exits with it.
pub fn run(args: RunArgs) -> Result<i32> {
    let repo = match args.repo {
        Some(path) => path,
        None => std::env::current_dir().context("could not resolve the current directory")?,
    };
    let repo = repo
        .canonicalize()
        .with_context(|| format!("no such directory: {}", repo.display()))?;

    // `--task` takes a file when the value names one, and the literal text otherwise, so a
    // short task needs no file and a long mission is not pasted onto a command line.
    let task = read_task(&args.task)?;
    let system_prompt =
        match args.system.as_deref() {
            Some(path) => Some(std::fs::read_to_string(path).with_context(|| {
                format!("could not read the system prompt at {}", path.display())
            })?),
            None => None,
        };

    let session_stamp = kin_agent::run::timestamp().replace(':', "-");
    let out = args
        .out
        .unwrap_or_else(|| repo.join(".kin").join("agent").join(session_stamp));
    std::fs::create_dir_all(&out)
        .with_context(|| format!("could not create the output directory {}", out.display()))?;

    let provider = ProviderConfig {
        base_url: ProviderConfig::normalize_base_url(&args.base_url),
        model: args.model,
        api_key: ProviderConfig::api_key_from_env(args.api_key_env.as_deref())?,
        temperature: args.temperature,
        request_timeout: Duration::from_secs(DEFAULT_REQUEST_TIMEOUT_S),
    };

    let mcp_command = resolve_mcp_command(
        args.mcp_command.as_deref(),
        &repo,
        args.tool_profile.as_deref(),
    );

    let config = AgentConfig {
        task,
        system_prompt,
        repo: repo.clone(),
        out_dir: out.clone(),
        provider,
        mcp_command,
        mcp_timeout: Duration::from_secs(DEFAULT_MCP_TIMEOUT_S),
        max_tool_calls: args.max_tool_calls.unwrap_or(DEFAULT_MAX_TOOL_CALLS),
        deadline: Duration::from_secs(args.deadline.unwrap_or(DEFAULT_DEADLINE_S)),
        tool_profile: args.tool_profile,
    };

    eprintln!(
        "kin agent: model={} endpoint={} repo={} out={}",
        config.provider.model,
        config.provider.base_url,
        config.repo.display(),
        out.display()
    );

    let outcome = kin_agent::run(config)?;
    println!("{}", outcome.final_text);
    eprintln!(
        "kin agent: {} ({} tool calls, {} to Kin) transcript={}",
        outcome.status.subtype(),
        outcome
            .result
            .pointer("/kin_agent/tool_calls")
            .and_then(|value| value.as_u64())
            .unwrap_or(0),
        outcome
            .result
            .pointer("/kin_agent/kin_calls")
            .and_then(|value| value.as_u64())
            .unwrap_or(0),
        outcome.transcript_path.display()
    );
    Ok(outcome.status.code())
}

/// Check both halves of the run are reachable before anyone spends a GPU on a task.
pub fn doctor(
    base_url: String,
    model: Option<String>,
    repo: Option<PathBuf>,
    mcp_command: Option<String>,
    api_key_env: Option<String>,
    tool_profile: Option<String>,
) -> Result<i32> {
    let repo = match repo {
        Some(path) => path,
        None => std::env::current_dir().context("could not resolve the current directory")?,
    };
    let repo = repo
        .canonicalize()
        .with_context(|| format!("no such directory: {}", repo.display()))?;

    let provider = ProviderConfig {
        base_url: ProviderConfig::normalize_base_url(&base_url),
        model: model.clone().unwrap_or_default(),
        api_key: ProviderConfig::api_key_from_env(api_key_env.as_deref())?,
        temperature: None,
        request_timeout: Duration::from_secs(60),
    };
    println!("endpoint: {}", provider.models_url());
    let provider_ok =
        match kin_agent::Provider::new(provider.clone()).and_then(|client| client.list_models()) {
            Ok(models) => {
                println!("  answered with {} model(s)", models.len());
                if let Some(model) = model.as_deref() {
                    if models.iter().any(|id| id == model) {
                        println!("  `{model}` is served");
                    } else {
                        // Not fatal: a gateway may serve a model it does not list.
                        println!(
                            "  `{model}` is NOT in the list; served ids are: {}",
                            models.join(", ")
                        );
                    }
                }
                true
            }
            Err(err) => {
                println!("  FAILED: {err}");
                false
            }
        };

    let command = resolve_mcp_command(mcp_command.as_deref(), &repo, tool_profile.as_deref());
    println!("mcp: {}", command.join(" "));
    let mcp_ok = match kin_agent::run::probe_mcp(
        &command,
        &repo,
        Duration::from_secs(DEFAULT_MCP_TIMEOUT_S),
    ) {
        Ok(tools) => {
            let exposed = tools
                .iter()
                .filter(|name| !kin_agent::belt::is_harness_owned(name))
                .count();
            println!(
                "  initialize and tools/list answered: {} tool(s), {} exposed to the model",
                tools.len(),
                exposed
            );
            true
        }
        Err(err) => {
            println!("  FAILED: {err}");
            false
        }
    };

    if !provider_ok {
        return Ok(ExitStatus::EndpointError.code());
    }
    if !mcp_ok {
        return Ok(ExitStatus::McpError.code());
    }
    println!("both halves answered; `kin agent run` can start");
    Ok(0)
}

fn read_task(value: &str) -> Result<String> {
    let path = Path::new(value);
    if path.is_file() {
        return std::fs::read_to_string(path)
            .with_context(|| format!("could not read the task file at {value}"));
    }
    if value.trim().is_empty() {
        anyhow::bail!("--task was empty");
    }
    Ok(value.to_string())
}

/// The MCP command: an override split on whitespace, or this binary serving the repo.
fn resolve_mcp_command(
    override_command: Option<&str>,
    repo: &Path,
    tool_profile: Option<&str>,
) -> Vec<String> {
    if let Some(raw) = override_command {
        let parts: Vec<String> = raw.split_whitespace().map(ToString::to_string).collect();
        if !parts.is_empty() {
            return parts;
        }
    }
    // Prefer this exact binary over whatever `kin` resolves to on PATH, so a run cannot
    // silently drive a different build than the one the operator launched.
    let program = std::env::current_exe()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|_| "kin".to_string());
    let mut command = vec![
        program,
        "mcp".to_string(),
        "start".to_string(),
        "--repo".to_string(),
        repo.display().to_string(),
    ];
    if let Some(profile) = tool_profile {
        command.push("--tool-profile".to_string());
        command.push(profile.to_string());
    }
    command
}
