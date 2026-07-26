// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Git forge migration pipeline for Kin.
//!
//! Converts a Git repository (from GitHub, GitLab, Bitbucket, or any Git
//! server) into a sovereign Kin repo by:
//! 1. Detecting the source forge and parsing repository coordinates
//! 2. Selecting the source ref without deriving membership from the worktree
//! 3. Planning the migration (exact HEAD snapshot or full reachable history)
//! 4. Initializing the .kin/ directory structure
//! 5. Importing Git history as SemanticChange objects
//! 6. Enriching the graph-owned imported head from blob-store bytes
//! 7. Writing everything to the graph store

pub mod converter;
pub mod error;
pub mod executor;
pub mod finalize;
pub mod forge;
pub mod scanner;
pub mod strategy;

pub use error::{MigrateError, Result};
pub use executor::{execute_migration_persisted, MigrationResult};
pub use finalize::{build_and_save_kidx, trigger_lsp_sweep, update_registry};
pub use forge::{configure_forge_remote, detect_forge, ForgeInfo, ForgeKind};
pub use scanner::{scan_repo, RepoScan};
pub use strategy::{plan_migration, MigrationPlan, MigrationStrategy};
