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

pub use cochange::{mine_from_change_dag, mine_from_git_log};
pub use error::{GitError, Result};
pub use export::{ExportOptions, ExportResult, export_changes, export_to_git};
pub use genesis::is_genesis_change;
pub use import::{
    ImportOptions, ImportedChange, import_git_history, import_git_history_with_blobs,
    semantic_change_id_from_git_oid_hex,
};
