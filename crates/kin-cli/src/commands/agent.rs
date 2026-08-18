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
    pub mcp_command: Vec<String>,
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

    let mcp_commands = resolve_mcp_commands(&args.mcp_command, &repo, args.tool_profile.as_deref());

    let config = AgentConfig {
        task,
        system_prompt,
        repo: repo.clone(),
        out_dir: out.clone(),
        provider,
        mcp_commands,
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
    mcp_command: Vec<String>,
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

    let commands = resolve_mcp_commands(&mcp_command, &repo, tool_profile.as_deref());
    let mut mcp_ok = true;
    for command in &commands {
        println!("mcp: {}", command.join(" "));
        match kin_agent::run::probe_mcp(command, &repo, Duration::from_secs(DEFAULT_MCP_TIMEOUT_S))
        {
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
            }
            Err(err) => {
                println!("  FAILED: {err}");
                // Every named server must answer. A partial belt is worse than none,
                // because the model cannot tell it apart from a complete one.
                mcp_ok = false;
            }
        }
    }

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

/// The MCP commands: one per `--mcp-command`, each split on whitespace, or a single
/// default of this binary serving `--repo`.
///
/// `--mcp-command` is repeatable so one run can hold several repositories' servers, which
/// a task spanning a repository set needs. Each entry becomes its own named server and its
/// tools stay distinguishable in the transcript.
fn resolve_mcp_commands(
    overrides: &[String],
    repo: &Path,
    tool_profile: Option<&str>,
) -> Vec<Vec<String>> {
    let explicit: Vec<Vec<String>> = overrides
        .iter()
        .map(|raw| {
            raw.split_whitespace()
                .map(ToString::to_string)
                .collect::<Vec<String>>()
        })
        .filter(|parts| !parts.is_empty())
        .collect();
    if !explicit.is_empty() {
        return explicit;
    }
    vec![default_mcp_command(repo, tool_profile)]
}

fn default_mcp_command(repo: &Path, tool_profile: Option<&str>) -> Vec<String> {
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
