// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin agent`: run a task through Kin's own agent loop.

use anyhow::{Context, Result};
use kin_agent::{
    AgentConfig, ContextSource, ContextWindow, ExitStatus, ProviderConfig, ServerSpec,
    DEFAULT_CONTEXT_TOKENS, DEFAULT_DEADLINE_S, DEFAULT_MAX_TOOL_CALLS, DEFAULT_MCP_TIMEOUT_S,
    DEFAULT_REQUEST_TIMEOUT_S,
};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The smallest context window a run accepts. Below it the system prompt and the tool specs
/// alone leave no room for a conversation.
const MIN_CONTEXT_TOKENS: u64 = 2_048;
/// The smallest per-result ceiling a run accepts, so a cut result still says something.
const MIN_RESULT_BYTES: usize = 1_024;

/// Everything the `run` subcommand accepts.
#[allow(clippy::too_many_arguments)]
pub struct RunArgs {
    pub task: String,
    pub model: String,
    pub base_url: String,
    pub api_key_env: Option<String>,
    pub repo: Vec<PathBuf>,
    pub mcp_command: Vec<String>,
    pub out: Option<PathBuf>,
    pub max_tool_calls: Option<u32>,
    pub deadline: Option<u64>,
    pub context_tokens: Option<u64>,
    pub max_result_bytes: Option<usize>,
    pub system: Option<PathBuf>,
    pub temperature: Option<f32>,
    pub tool_profile: Option<String>,
}

/// Run one task. Returns the process exit code; the caller exits with it.
pub fn run(args: RunArgs) -> Result<i32> {
    if let Some(tokens) = args.context_tokens {
        if tokens < MIN_CONTEXT_TOKENS {
            anyhow::bail!(
                "--context-tokens {tokens} is below the {MIN_CONTEXT_TOKENS} a run needs for its \
                 system prompt, its tool specs and a conversation"
            );
        }
    }
    if let Some(bytes) = args.max_result_bytes {
        if bytes < MIN_RESULT_BYTES {
            anyhow::bail!(
                "--max-result-bytes {bytes} is below the smallest ceiling, {MIN_RESULT_BYTES}"
            );
        }
    }
    let servers = resolve_servers(&args.repo, &args.mcp_command, args.tool_profile.as_deref())?;
    // The first repository is the primary: the process working directory, the default for
    // a relative path, and the tree the transcript names.
    let repo = servers[0].repo.clone();

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
    let context = resolve_context_window(args.context_tokens, &provider)?;

    let mut servers = servers;
    let primary = servers.remove(0);

    let config = AgentConfig {
        task,
        system_prompt,
        repo: repo.clone(),
        out_dir: out.clone(),
        provider,
        mcp_command: primary.mcp_command,
        extra_servers: servers,
        mcp_timeout: Duration::from_secs(DEFAULT_MCP_TIMEOUT_S),
        max_tool_calls: args.max_tool_calls.unwrap_or(DEFAULT_MAX_TOOL_CALLS),
        deadline: Duration::from_secs(args.deadline.unwrap_or(DEFAULT_DEADLINE_S)),
        context,
        max_result_bytes: args.max_result_bytes,
        tool_profile: args.tool_profile,
    };

    let attached = config
        .servers()
        .iter()
        .map(|server| server.repo.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    eprintln!(
        "kin agent: model={} endpoint={} repo={} out={}",
        config.provider.model,
        config.provider.base_url,
        attached,
        out.display()
    );
    eprintln!("kin agent: {}", describe_budget(&config));

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
    if let Some(detail) = outcome
        .result
        .pointer("/kin_agent/stop_detail")
        .and_then(|value| value.as_str())
    {
        eprintln!("kin agent: stopped because {detail}");
    }
    Ok(outcome.status.code())
}

/// The model's context window: the flag, else what the endpoint reports for the loaded
/// model, else the default, with the source kept so the run can say which it used.
fn resolve_context_window(flag: Option<u64>, provider: &ProviderConfig) -> Result<ContextWindow> {
    if let Some(tokens) = flag {
        return Ok(ContextWindow {
            tokens,
            source: ContextSource::Flag,
        });
    }
    let reported = kin_agent::Provider::new(provider.clone())?.discover_context_window();
    Ok(match reported {
        Some(tokens) => ContextWindow {
            tokens,
            source: ContextSource::Endpoint,
        },
        None => ContextWindow {
            tokens: DEFAULT_CONTEXT_TOKENS,
            source: ContextSource::Default,
        },
    })
}

/// One line naming the run's budgets and where the window came from, printed before the
/// run starts so a budget stop is never a surprise.
fn describe_budget(config: &AgentConfig) -> String {
    let window = match config.context.source {
        ContextSource::Flag => format!(
            "context window {} tokens (from --context-tokens)",
            config.context.tokens
        ),
        ContextSource::Endpoint => format!(
            "context window {} tokens (reported by the endpoint for the loaded model)",
            config.context.tokens
        ),
        ContextSource::Default => format!(
            "context window {} tokens (the endpoint reported none, so this is the default; pass \
             --context-tokens to budget for the model's real window)",
            config.context.tokens
        ),
    };
    format!(
        "{window}; one tool result is sent up to {} bytes; deadline {} s",
        config.result_ceiling(),
        config.deadline.as_secs()
    )
}

/// Check both halves of the run are reachable before anyone spends a GPU on a task.
pub fn doctor(
    base_url: String,
    model: Option<String>,
    repo: Vec<PathBuf>,
    mcp_command: Vec<String>,
    api_key_env: Option<String>,
    tool_profile: Option<String>,
) -> Result<i32> {
    let servers = resolve_servers(&repo, &mcp_command, tool_profile.as_deref())?;

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
    // The window a run would budget for, so a context stop can be predicted before a run.
    if provider_ok && model.is_some() {
        let reported = kin_agent::Provider::new(provider.clone())
            .ok()
            .and_then(|client| client.discover_context_window());
        match reported {
            Some(tokens) => println!(
                "  context window: {tokens} tokens, as the endpoint reports the loaded model"
            ),
            None => println!(
                "  context window: not reported; a run budgets for {DEFAULT_CONTEXT_TOKENS} \
                 tokens unless --context-tokens names the model's real window"
            ),
        }
    }

    // Every attached repository is probed, because a run that cannot reach the second
    // server fails just as completely as one that cannot reach the first.
    let mut mcp_ok = true;
    for server in &servers {
        println!(
            "mcp: {} (serving {})",
            server.mcp_command.join(" "),
            server.repo.display()
        );
        match kin_agent::run::probe_mcp(
            &server.mcp_command,
            &server.repo,
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
            }
            Err(err) => {
                println!("  FAILED: {err}");
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

/// Every repository this invocation attaches, each paired with the server that serves it.
///
/// `--repo` and `--mcp-command` are both repeatable and pair by position, so the second
/// `--mcp-command` overrides the server for the second `--repo`. Fewer commands than
/// repositories is ordinary and the rest take the default. More commands than repositories
/// is refused rather than ignored, because a command with no repository would silently
/// never be started and the run would look like it had attached something it had not.
fn resolve_servers(
    repos: &[PathBuf],
    commands: &[String],
    tool_profile: Option<&str>,
) -> Result<Vec<ServerSpec>> {
    let mut roots: Vec<PathBuf> = repos.to_vec();
    if roots.is_empty() {
        roots.push(std::env::current_dir().context("could not resolve the current directory")?);
    }
    if commands.len() > roots.len() {
        anyhow::bail!(
            "{} --mcp-command value(s) were given for {} --repo value(s); each command needs a \
             repository to serve",
            commands.len(),
            roots.len()
        );
    }
    let mut servers = Vec::new();
    for (index, root) in roots.iter().enumerate() {
        let repo = root
            .canonicalize()
            .with_context(|| format!("no such directory: {}", root.display()))?;
        let command =
            resolve_mcp_command(commands.get(index).map(String::as_str), &repo, tool_profile);
        servers.push(ServerSpec {
            repo,
            mcp_command: command,
        });
    }
    Ok(servers)
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
