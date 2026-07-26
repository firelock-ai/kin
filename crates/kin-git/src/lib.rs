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

pub mod error;
pub mod lossless;

pub use error::{GitError, Result};
pub use lossless::{
    capture_lossless_git_repository, rehydrate_lossless_git_repository, GitObjectFormat,
    GitRehydrationResult, LosslessGitRepository,
};
