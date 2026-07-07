// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Legacy Git adapter for Kin — import/export/sync.
//!
//! This crate is **optional**. Kin is a sovereign VCS and does not require
//! Git for any internal operation. This adapter provides:
//!
//! - **Import**: Read Git history via gitoxide and create SemanticChange objects
//! - **Export**: Translate SemanticChange DAG into Git commits/trees
//! - **Sync**: Bidirectional periodic sync for teams transitioning from Git

pub mod cochange;
pub mod error;
pub mod export;
pub mod genesis;
pub mod import;

pub use cochange::{mine_from_change_dag, mine_from_git_log, mine_from_git_log_with_limit};
pub use error::{GitError, Result};
pub use export::{export_changes, export_to_git, ExportOptions, ExportResult};
pub use genesis::is_genesis_change;
pub use import::{
    anchor_imported_history_at_base_link, expand_git_commit_prefix, import_git_history,
    import_git_history_to_commit_with_blobs, import_git_history_with_blobs, is_ancestor_commit,
    semantic_change_id_from_git_oid_hex, GitOidPrefixExpansion, ImportOptions, ImportedChange,
};
