// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

pub mod agent_belt;
pub mod budget;
pub mod caller_arrival;
pub mod daemon_delegate;
pub mod edge_coverage;
pub mod envelope;
pub mod error;
pub mod handlers;
pub mod negative;
pub mod server;
pub mod session;
pub mod startup_binding;
pub mod tools;
pub mod types;
pub mod verdict;

pub use agent_belt::{
    apply_belt_defaults, canonicalize_tool_name, compact_for_agent_default,
    AGENT_DEFAULT_DESCRIPTION_BUDGET, AGENT_DEFAULT_PROFILE_DESCRIPTION_BUDGET,
    DECLARATION_FILTER_ALIAS, DECLARATION_FILTER_CANONICAL,
};
pub use budget::{
    is_budgeted as is_budgeted_tool, BudgetAccounting, ResponseBudget, RESPONSE_DEFAULT_MAX_CHARS,
};
pub use daemon_delegate::note_startup_repository;
pub use edge_coverage::EDGE_COVERAGE_KEY;
pub use envelope::{
    annotate as annotate_with_envelope, finalize as finalize_with_envelope,
    finalize_bounded as finalize_with_envelope_bounded, Envelope, ENVELOPE_KEY, ENVELOPE_VERSION,
};
pub use error::{McpError, Result};
pub use handlers::LocalRepositoryAuthorityBinding;
pub use negative::NEGATIVE_KEY;
pub use server::{
    process_daemon_message, process_message, run_stdio, run_stdio_daemon, BoundRepo,
    McpServerConfig, RepoBinder, SessionAuthorityMode, WorkspaceBinding,
};
pub use session::{
    AssistantSession, CommitRefusal, CommitRefusalCode, CoordinationEnforcementMode,
    CoordinationSurfaceCoverage, CoordinationWritePreflight, IntentRegistrationAttempt,
    McpMutationOperation, McpMutationPayload, McpTransaction, SessionRegistry,
};
pub use startup_binding::{StartupBindingState, StartupDaemonBinding};
pub use tools::{
    agent_default_tool_names, benchmark_tool_names, context_bench_tool_names, tool_definitions,
};
pub use types::{
    ContentBlock, JsonRpcRequest, JsonRpcResponse, ToolCallParams, ToolCallResult, ToolDefinition,
};
pub use verdict::{disagreements as verdict_disagreements, Verdict, VERDICT_KEY};
