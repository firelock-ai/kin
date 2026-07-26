// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Git migration and projection adapter for Kin.
//!
//! Kin is graph-native and does not use Git as an authority path. This optional
//! boundary imports exact Git repository state and projects Kin history back to
//! Git for migration and coexistence.
//!
//! - **Import**: Read Git history via gitoxide and create SemanticChange objects
//! - **Export**: Translate SemanticChange DAG into Git commits/trees
//! - **Co-change enrichment**: Mine non-authoritative historical signals

pub mod cochange;
pub mod error;
pub mod export;
pub mod genesis;
pub mod import;

pub use cochange::{mine_from_change_dag, mine_from_git_log, mine_from_git_log_with_limit};
pub use error::{GitError, Result};
pub use export::{export_changes, export_to_git, ExportOptions, ExportResult};
pub use genesis::is_genesis_change;
#[allow(deprecated)]
pub use import::{
    import_git_history, import_git_history_to_commit_with_blobs, import_git_history_with_blobs,
    semantic_change_id_from_git_oid_hex, GitImportMode, ImportOptions, ImportedChange,
};
