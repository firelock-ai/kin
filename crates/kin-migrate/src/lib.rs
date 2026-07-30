// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Git forge migration pipeline for Kin.
//!
//! Detects Git forges and delegates repository admission to Kin's single exact,
//! atomic repository-v6 bootstrap boundary.

use std::path::PathBuf;

mod bounded_process;
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

/// Explicit process host for bounded migration metadata probes.
///
/// On Unix, migration probes use the configured executable to host a
/// parent-death process-group guardian. An executable passed to
/// [`Self::product`] must call [`run_migration_process_host_if_requested`]
/// before argument parsing or runtime construction and exit normally when it
/// returns `true`.
///
/// Other platforms retain the same explicit API contract even though their
/// native containment does not re-execute the host.
#[derive(Debug, Clone)]
pub struct MigrationProcessHost {
    #[cfg(unix)]
    guardian_launcher: kin_daemon_spawn::ProcessGroupGuardianLauncher,
}

impl MigrationProcessHost {
    /// Use a product executable as the migration guardian host.
    ///
    /// The executable's entrypoint must call
    /// [`run_migration_process_host_if_requested`] before normal startup.
    pub fn product(executable: impl Into<PathBuf>) -> Self {
        #[cfg(unix)]
        {
            Self {
                guardian_launcher: kin_daemon_spawn::ProcessGroupGuardianLauncher::product(
                    executable,
                ),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = executable.into();
            Self {}
        }
    }

    /// Use one exact Rust test as the migration guardian host.
    ///
    /// The named test must do nothing except call
    /// [`run_migration_process_host_if_requested`] and assert that it returned
    /// `true` when the private guardian mode was requested.
    #[doc(hidden)]
    pub fn exact_test(
        executable: impl Into<PathBuf>,
        exact_test_name: impl Into<std::ffi::OsString>,
    ) -> Self {
        #[cfg(unix)]
        {
            Self {
                guardian_launcher: kin_daemon_spawn::ProcessGroupGuardianLauncher::exact_test(
                    executable,
                    exact_test_name,
                ),
            }
        }
        #[cfg(not(unix))]
        {
            let _ = (executable.into(), exact_test_name.into());
            Self {}
        }
    }

    #[cfg(unix)]
    pub(crate) fn guardian_launcher(&self) -> &kin_daemon_spawn::ProcessGroupGuardianLauncher {
        &self.guardian_launcher
    }
}

/// Run a requested migration guardian mode before normal host startup.
///
/// Product executables supplied to [`MigrationProcessHost::product`] call this
/// before argument parsing or runtime construction and exit normally when it
/// returns `true`. Ordinary execution returns `Ok(false)`.
pub fn run_migration_process_host_if_requested() -> std::io::Result<bool> {
    kin_daemon_spawn::run_process_group_guardian_if_requested()
}

/// Exact test-harness entrypoint for the shared process-group guardian.
///
/// Migration probes run from both product executables and Rust test binaries.
/// Product mains dispatch the private guardian mode before argument parsing;
/// test binaries route the same mode through this one exact worker.
#[cfg(all(test, unix))]
#[test]
fn kin_process_group_guardian_worker() {
    let requested = std::env::var_os(kin_daemon_spawn::PROCESS_GROUP_GUARDIAN_MODE_ENV).is_some();
    let dispatched = run_migration_process_host_if_requested()
        .expect("run migration process-group guardian worker");
    assert_eq!(dispatched, requested);
}
