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

pub mod admission_history;
pub mod authority;
pub mod error;
pub mod lossless;
pub mod preflight;
pub mod repository_export;
pub mod semantic_import;

pub use admission_history::{admit_semantic_git_import, AdmittedSemanticGitImportPlan};
pub use authority::build_git_external_authority;
pub use error::{
    GitCheckoutFilterFact, GitError, LocalGitHookFact, LocalGitHookKind, RegisteredGitWorktreeFact,
    RegisteredGitWorktreeKind, Result,
};
pub use lossless::{
    capture_lossless_git_repository, rehydrate_lossless_git_repository, GitObjectFormat,
    GitRehydrationResult, LosslessGitRepository,
};
pub use preflight::{
    preflight_git_migration, preflight_git_migration_after_publication, GitBranchTrackingFact,
    GitIndexPreflightProof, GitLocalIgnoreInputFact, GitLocalIgnoreSourceKind,
    GitMigrationCompatibilityFacts, GitMigrationPreflightProof, GitRemoteConfigFact,
    GitRemoteMappingFacts, GitTrackedWorktreeProof, IgnoredLocalEntry, IgnoredLocalEntryKind,
    IgnoredLocalWorktreeFact,
};
pub use repository_export::{
    export_repository_to_git, verify_repository_git_export, RepositoryGitCommitBinding,
    RepositoryGitExportPlan, RepositoryGitExportProof, RepositoryGitExportResult,
};
pub use semantic_import::{plan_semantic_git_import, GitWorkspaceSeed, SemanticGitImportPlan};
