//! GitHub/Git repo migration pipeline for Kin.
//!
//! Converts a Git repository into a sovereign Kin repo by:
//! 1. Scanning the repo for source files, branches, and commits
//! 2. Planning the migration (shallow HEAD-only or deep full-history)
//! 3. Initializing the .kin/ directory structure
//! 4. Importing Git history as SemanticChange objects
//! 5. Indexing source files for entity/relation extraction
//! 6. Writing everything to the graph store

pub mod converter;
pub mod error;
pub mod executor;
pub mod scanner;
pub mod strategy;

pub use error::{MigrateError, Result};
pub use executor::{MigrationResult, execute_migration, migrate_repo};
pub use scanner::{RepoScan, scan_repo};
pub use strategy::{MigrationPlan, MigrationStrategy, plan_migration};
