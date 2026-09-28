// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

pub mod agent_belt;
pub mod budget;
pub mod call_sites;
pub mod caller_arrival;
pub mod command_shape;
pub mod daemon_delegate;
pub mod edge_coverage;
pub mod entity_drafts;
pub mod entity_lifecycle;
pub mod entity_lines;
pub mod envelope;
pub mod error;
pub mod first_contact;
pub mod handlers;
pub mod input_contract;
pub mod negative;
pub mod outside_graph;
pub mod query_tokens;
pub mod reference_pages;
pub mod remediation;
pub mod repository_init;
pub mod routed;
pub mod server;
pub mod session;
pub mod session_exec;
pub mod session_idle_floor;
pub mod source_base;
pub mod source_derivation;
pub mod source_unit;
pub mod startup_binding;
pub(crate) mod tool_invocation;
pub mod tools;
pub mod trace_pages;
pub mod types;
pub mod verdict;
pub mod working_copy;

pub use agent_belt::{
    apply_belt_defaults, canonicalize_tool_name, compact_for_agent_default,
    AGENT_DEFAULT_DESCRIPTION_BUDGET, AGENT_DEFAULT_PROFILE_DESCRIPTION_BUDGET,
    DECLARATION_FILTER_ALIAS, DECLARATION_FILTER_CANONICAL,
};
pub use budget::{
    is_budgeted as is_budgeted_tool, BudgetAccounting, ResponseBudget, RESPONSE_DEFAULT_MAX_CHARS,
};
pub use call_sites::{
    publish_current_proof_contexts, published_current_proof_contexts, CALL_SITES_KEY,
};
pub use daemon_delegate::note_startup_repository;
pub use daemon_delegate::{readiness_budget, DAEMON_PATIENCE_ENV};
pub use edge_coverage::EDGE_COVERAGE_KEY;
pub use envelope::{
    annotate as annotate_with_envelope, finalize as finalize_with_envelope,
    finalize_bounded as finalize_with_envelope_bounded, Envelope, ENVELOPE_KEY, ENVELOPE_VERSION,
};
pub use error::{McpError, Result};
pub use handlers::LocalRepositoryAuthorityBinding;
pub use negative::NEGATIVE_KEY;
pub use outside_graph::OUTSIDE_GRAPH_KEY;
pub use repository_init::{InitOutcome, RepoInitializer};
pub use server::{
    process_daemon_message, process_message, run_stdio, run_stdio_daemon, BoundRepo,
    McpServerConfig, RepoBinder, SessionAuthorityMode, WorkspaceBinding,
};
pub use session::{
    AssistantSession, CommitRefusal, CommitRefusalCode, CoordinationEnforcementMode,
    CoordinationSurfaceCoverage, CoordinationWritePreflight, IntentRegistrationAttempt,
    McpMutationOperation, McpMutationPayload, McpTransaction, SessionRegistry,
};
pub use startup_binding::{StartupBindingState, StartupDaemonBinding, StartupProgress};
pub use tools::{
    agent_default_tool_names, agent_query_tool_names, agent_routed_tool_names,
    agent_search_tool_names, benchmark_tool_names, context_bench_tool_names,
    name_set as tool_name_set, served_tools_list, tool_definitions, AGENT_QUERY_LIST_CEILING_BYTES,
    AGENT_SEARCH_LIST_CEILING_BYTES,
};
pub use types::{
    ContentBlock, JsonRpcRequest, JsonRpcResponse, ToolCallParams, ToolCallResult, ToolDefinition,
};
pub use verdict::{disagreements as verdict_disagreements, Verdict, VERDICT_KEY};
pub use working_copy::{HostEntryReading, WorkingCopyProbe, WorkingCopySource, WorkingCopySurface};

pub mod status_pages;
