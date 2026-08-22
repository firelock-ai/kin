// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin-agent` is a Kin-native, provider-neutral agent loop.
//!
//! It speaks the OpenAI chat-completions wire format, so one adapter reaches LM Studio,
//! Ollama, llama.cpp, vLLM, OpenRouter and OpenAI, and it drives Kin over MCP rather than
//! over a translated CLI bridge, so it inherits the real tool registry, the `_kin`
//! envelope and the `negative` verdict instead of reimplementing them.
//!
//! The policy the loop enforces is the product's own thesis: repository questions are
//! answered from the graph. There is no shell tool, no file-search tool and no file-read
//! tool in the belt, so there is nothing to fall back to, and the router refuses by name
//! anything the model invents. Enforcement lives in this process rather than in a vendor's
//! permission layer, which is what makes it hold on every model rather than on one CLI.

pub mod belt;
pub mod mcp;
pub mod parse;
pub mod provider;
pub mod run;
pub mod transcript;

#[cfg(test)]
mod tests;

pub use provider::{Provider, ProviderConfig, ProviderError};
pub use run::{run, DEFAULT_SYSTEM_PROMPT};

use std::path::PathBuf;
use std::time::Duration;

/// How a run ended. The codes are the process exit codes, and they distinguish the
/// failures that must never be pooled: a task the agent could not do, a budget it spent,
/// an endpoint that was not there, and a graph server that was not there.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitStatus {
    Success,
    HarnessError,
    CapReached,
    Deadline,
    EndpointError,
    McpError,
    /// The run produced changes that repository authority never published. The task text
    /// may read like a success, but nothing landed, so this must never pool with Success.
    ChangesUnpublished,
}

impl ExitStatus {
    pub fn code(self) -> i32 {
        match self {
            ExitStatus::Success => 0,
            ExitStatus::HarnessError => 1,
            ExitStatus::CapReached => 2,
            ExitStatus::Deadline => 3,
            ExitStatus::EndpointError => 4,
            ExitStatus::McpError => 5,
            ExitStatus::ChangesUnpublished => 6,
        }
    }

    pub fn subtype(self) -> &'static str {
        match self {
            ExitStatus::Success => "success",
            ExitStatus::HarnessError => "harness_error",
            ExitStatus::CapReached => "cap_reached",
            ExitStatus::Deadline => "deadline",
            ExitStatus::EndpointError => "endpoint_error",
            ExitStatus::McpError => "mcp_error",
            ExitStatus::ChangesUnpublished => "changes_unpublished",
        }
    }
}

/// One graph server and the repository it serves.
///
/// A run attaches one of these per repository. The agent's own tools are named per server,
/// and every write is routed to the server that owns the path, so a two-repository run
/// cannot commit one repository's change into the other's graph.
#[derive(Debug, Clone)]
pub struct ServerSpec {
    pub repo: PathBuf,
    pub mcp_command: Vec<String>,
}

/// Everything one run needs.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub task: String,
    pub system_prompt: Option<String>,
    /// The primary repository: the process working directory, the default for a relative
    /// path, and the repository the transcript names.
    pub repo: PathBuf,
    pub out_dir: PathBuf,
    pub provider: ProviderConfig,
    /// The primary repository's server argv.
    pub mcp_command: Vec<String>,
    /// Further repositories attached to the same run, each with its own server. Empty for
    /// the ordinary single-repository run, whose behaviour is unchanged by this field.
    pub extra_servers: Vec<ServerSpec>,
    pub mcp_timeout: Duration,
    pub max_tool_calls: u32,
    pub deadline: Duration,
    pub tool_profile: Option<String>,
}

impl AgentConfig {
    /// Every server this run attaches, primary first.
    pub fn servers(&self) -> Vec<ServerSpec> {
        let mut servers = vec![ServerSpec {
            repo: self.repo.clone(),
            mcp_command: self.mcp_command.clone(),
        }];
        servers.extend(self.extra_servers.iter().cloned());
        servers
    }
}

/// What a finished run produced.
#[derive(Debug, Clone)]
pub struct RunOutcome {
    pub status: ExitStatus,
    pub final_text: String,
    pub transcript_path: PathBuf,
    pub trace_path: PathBuf,
    pub result: serde_json::Value,
}

/// Default tool-call budget.
pub const DEFAULT_MAX_TOOL_CALLS: u32 = 40;
/// Default wall deadline, in seconds.
pub const DEFAULT_DEADLINE_S: u64 = 900;
/// Default per-request timeout for one MCP call, in seconds. Generous, because a cold
/// graph build behind the first call is normal and killing it would report a Kin failure
/// that was really a harness impatience.
pub const DEFAULT_MCP_TIMEOUT_S: u64 = 300;
/// Default per-request timeout for one chat completion, in seconds. Local models on a
/// laptop are slow, and a short timeout here reads as an endpoint failure.
pub const DEFAULT_REQUEST_TIMEOUT_S: u64 = 600;
