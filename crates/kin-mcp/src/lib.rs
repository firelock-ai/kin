// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

pub mod daemon_delegate;
pub mod error;
pub mod graph_loader;
pub mod handlers;
pub mod server;
pub mod session;
pub mod tools;
pub mod types;

pub use error::{McpError, Result};
pub use graph_loader::{load_stdio_graph, load_stdio_graph_from_daemon, StdioGraphLoad};
pub use server::{process_message, run_stdio, McpServerConfig, SessionAuthorityMode};
pub use session::{AssistantSession, SessionRegistry};
pub use tools::{benchmark_tool_names, tool_definitions};
pub use types::{
    ContentBlock, JsonRpcRequest, JsonRpcResponse, ToolCallParams, ToolCallResult, ToolDefinition,
};
