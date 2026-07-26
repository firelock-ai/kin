// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Git forge migration pipeline for Kin.
//!
//! Detects Git forges and delegates repository admission to Kin's single exact,
//! atomic repository-v6 bootstrap boundary.

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
