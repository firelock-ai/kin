// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Git migration and projection adapter for Kin.
//!
//! Kin is graph-native and does not use Git as an authority path. This optional
//! boundary imports exact Git repository state and projects Kin history back to
//! Git for migration and coexistence.
//!
//! The public boundary is deliberately lossless: capture raw Git objects and
//! exact refs into graph-owned descriptors, or rehydrate those same bytes.
//! Earlier lossy history conversion and commit-synthesizing export APIs are not
//! part of the clean-slate model-v6 surface.

#[cfg(all(test, unix))]
#[test]
fn kin_process_group_guardian_worker() {
    let requested = std::env::var_os(kin_daemon_spawn::PROCESS_GROUP_GUARDIAN_MODE_ENV).is_some();
    let dispatched = kin_daemon_spawn::run_process_group_guardian_if_requested()
        .expect("run Kin Git fixture process-group guardian");
    assert_eq!(dispatched, requested);
}

pub mod admission_blockers;
pub mod admission_history;
pub mod authority;
pub mod error;
pub mod global_config;
pub mod lossless;
pub mod preflight;
pub mod repository_export;
pub mod sealed_observation;
pub mod semantic_import;

#[cfg(any(test, feature = "test-support"))]
#[doc(hidden)]
pub mod test_support;

pub use admission_blockers::{
    check_git_admission_blockers, collect_git_admission_blockers, GitAdmissionReport,
};
pub use admission_history::{admit_semantic_git_import, AdmittedSemanticGitImportPlan};
pub use authority::build_git_external_authority;
pub use error::{
    GitAdmissionBlocker, GitCheckoutFilterFact, GitError, LocalGitHookExecutability,
    LocalGitHookFact, LocalGitHookKind, RegisteredGitWorktreeFact, RegisteredGitWorktreeKind,
    Result, UnsealedContentGap, UntolerableGitWorktree,
};
pub use global_config::empty_global_git_config;
pub use lossless::{
    capture_lossless_git_repository, rehydrate_lossless_git_repository,
    sync_git_repository_for_authority_handoff, GitObjectFormat, GitRehydrationResult,
    LosslessGitRepository,
};
pub use preflight::{
    kin_store_is_git_ignored, preflight_git_migration, preflight_git_migration_after_publication,
    reprove_git_migration, reprove_git_migration_after_publication, GitBranchTrackingFact,
    GitIndexPreflightProof, GitLocalIgnoreInputFact, GitLocalIgnoreSourceKind,
    GitMigrationCompatibilityFacts, GitMigrationPreflightProof, GitRemoteConfigFact,
    GitRemoteMappingFacts, GitTrackedWorktreeProof, GitWorkspaceDivergence,
    GitWorkspaceDivergenceFacts, GitWorkspaceDivergenceKind, IgnoredLocalEntry,
    IgnoredLocalEntryKind, IgnoredLocalWorktreeFact,
};
pub use repository_export::{
    export_repository_to_git, verify_repository_git_export, RepositoryGitCommitBinding,
    RepositoryGitExportPlan, RepositoryGitExportProof, RepositoryGitExportResult,
};
pub use sealed_observation::{
    seal_all_content_observation, seal_all_content_observation_observed, AdmittedContentClosure,
    ContentExclusionReason, DeclaredContentExclusion, SealedContentCoverage,
    SealedContentObservation, SealedContentSource,
};
pub use semantic_import::{plan_semantic_git_import, GitWorkspaceSeed, SemanticGitImportPlan};
