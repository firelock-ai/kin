// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

pub mod assistant;
pub mod assistant_sync;
pub mod behavior_env;
pub mod config;
pub mod dependencies;
pub mod diff;
pub mod disambiguation;
pub mod env_registry;
pub mod error;
pub mod exact_tree;
pub mod git_init;
pub mod hooks;
pub mod init;
pub mod layout;
pub mod manifest;
pub mod ranking;
pub mod ref_view;
pub mod registry;
pub mod resolver;
pub mod shims;
pub mod sync_state;
pub mod tree;

pub use assistant::{
    doctor, generate_assistant_prompt, generate_bootstrap_docs, generate_config_snippets,
    import_legacy_docs, install_adapter, list_adapters, resolve_actor_from_session,
    resolve_human_actor, write_config_snippets, AssistantAdapterConfig, AssistantKind,
    ConfigSnippet, DoctorReport, InstallResult, PromptMode,
};
pub use assistant_sync::{
    generate_managed_content, sync_all, sync_doc, ManagedDocConfig, ManagedDocTarget, RepoSummary,
    SyncMode, SyncResult,
};
pub use config::{
    ExecutionPolicyConfig, ExternalToolExecutionPolicy, GitBranchTrackingConfig,
    GitCoexistenceConfig, GitPushDefault, GitRemoteTransportConfig, KinConfig, RemoteConfig,
    RemoteHostKind, RemoteRefConfig, RemoteTransportKind, WorldConfig, WorldPreset,
};
pub use error::{KinError, Result};
pub use exact_tree::{
    exact_tree_correction, plan_artifact_copy, plan_artifact_move, plan_artifact_operations,
    plan_observed_tree_deltas, ArtifactTreeOperation,
};
pub use git_init::init_from_git;
pub use hooks::{
    generate_claude_hooks, render_hooks_instructions, render_hooks_json, HookTemplate,
};
pub use init::{
    init, initialize_repository_authority, prepare_repository_layout_at, publish_repository_layout,
    publish_repository_layout_linearized, InitResult, PreparedRepositoryInit, PublishedRepository,
    RepositoryBootstrap, RepositoryPublication,
};
pub use layout::KinLayout;
pub use manifest::KinManifest;
pub use resolver::{ImportResolver, PythonResolver, SymbolTable, TypeScriptResolver};
pub use sync_state::SyncStateStore;
pub use tree::{
    materialize_source_entry, materialize_source_tree, prepare_source_tree, reconcile_source_tree,
    reconcile_source_tree_and_commit_repository_transaction, replace_source_tree,
    resolve_change_tree, should_preserve_checkout_path, validate_portable_source_paths,
    validate_portable_source_symlink, validate_source_entry, validate_source_paths,
    validate_source_tree, ExactProjectionDetachTarget, ExactProjectionEjectOutcome,
    ExactProjectionFreeze, ExactProjectionGitStage, ExactProjectionVerification,
    ExactSessionProjection,
};

pub use diff::{compute_semantic_change_id, content_identity_from_deltas, whoami};
pub use disambiguation::{fallback_leaf_trace_matches, query_trace_matches};
pub use ranking::{
    normalize_symbol_hint, normalize_trace_name, qualifier_hint_from_query, select_best_match,
};
pub use ref_view::{build_graph_at_ref, collect_changes_at_ref, filter_vector_results_to_scope};
