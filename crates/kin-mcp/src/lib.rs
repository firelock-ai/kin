pub mod error;
pub mod handlers;
pub mod server;
pub mod session;
pub mod tools;
pub mod types;

pub use error::{McpError, Result};
pub use server::{McpServerConfig, process_message, run_stdio};
pub use session::{AssistantSession, SessionRegistry};
pub use tools::tool_definitions;
pub use types::{
    ContentBlock, JsonRpcRequest, JsonRpcResponse, ToolCallParams, ToolCallResult,
    ToolDefinition,
};
