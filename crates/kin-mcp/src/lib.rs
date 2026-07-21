// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

pub mod daemon_delegate;
pub mod envelope;
pub mod error;
pub mod handlers;
pub mod negative;
pub mod server;
pub mod session;
pub mod tools;
pub mod types;

pub use envelope::{
    annotate as annotate_with_envelope, finalize as finalize_with_envelope, Envelope, ENVELOPE_KEY,
    ENVELOPE_VERSION,
};
pub use error::{McpError, Result};
pub use negative::NEGATIVE_KEY;
pub use server::{
    process_daemon_message, process_message, run_stdio, run_stdio_daemon, BoundRepo,
    McpServerConfig, RepoBinder, SessionAuthorityMode,
};
pub use session::{
    AssistantSession, CoordinationEnforcementMode, CoordinationSurfaceCoverage,
    CoordinationWritePreflight, IntentRegistrationAttempt, McpMutationOperation,
    McpMutationPayload, McpTransaction, SessionRegistry,
};
pub use tools::{
    agent_default_tool_names, benchmark_tool_names, context_bench_tool_names, tool_definitions,
};
pub use types::{
    ContentBlock, JsonRpcRequest, JsonRpcResponse, ToolCallParams, ToolCallResult, ToolDefinition,
};
