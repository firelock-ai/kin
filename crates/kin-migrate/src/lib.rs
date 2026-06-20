// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Git forge migration pipeline for Kin.
//!
//! Converts a Git repository (from GitHub, GitLab, Bitbucket, or any Git
//! server) into a sovereign Kin repo by:
//! 1. Detecting the source forge and parsing repository coordinates
//! 2. Scanning the repo for source files, branches, and commits
//! 3. Planning the migration (shallow HEAD-only or deep full-history)
//! 4. Initializing the .kin/ directory structure
//! 5. Importing Git history as SemanticChange objects
//! 6. Indexing source files for entity/relation extraction
//! 7. Writing everything to the graph store

pub mod checkpoint;
pub mod converter;
pub mod error;
pub mod executor;
pub mod finalize;
pub mod forge;
pub(crate) mod resource_threads;
pub mod scanner;
pub mod strategy;

pub use checkpoint::{
    clear_checkpoint, read_checkpoint, write_checkpoint, MigrateCheckpoint, CHECKPOINT_INTERVAL,
};
pub use error::{MigrateError, Result};
pub use executor::{execute_migration, execute_migration_persisted, migrate_repo, MigrationResult};
pub use finalize::{
    build_and_save_kidx, ensure_eject_snapshot, trigger_lsp_sweep, update_registry,
};
pub use forge::{configure_forge_remote, detect_forge, ForgeInfo, ForgeKind};
pub use scanner::{scan_repo, RepoScan};
pub use strategy::{plan_migration, MigrationPlan, MigrationStrategy};
