// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Kubernetes-style reconciliation loop for Kin.
//!
//! Derives exact semantic transaction deltas from filesystem input and projects
//! committed semantic transactions back to filesystem views.
//!
//! Two reconciliation directions:
//! - **File -> Transaction:** detect file edits, parse, return one validated
//!   [`kin_model::TransactionDelta`]
//! - **Transaction -> File:** project committed entity modifications into a
//!   filesystem view
//!
//! Enforces Last Known Good (LKG) semantics: broken ASTs do not corrupt
//! the graph. The LKG fingerprint, signature, and relations are retained
//! until the next valid parse.

pub mod collision;
pub mod cross_file;
pub mod error;
pub mod lkg;
pub mod reconciler;

pub use collision::{
    check_entity_collision, check_file_collision, check_signature_change, check_visibility_change,
    group_conflicts_by_file, CollisionCheck, MergeConflict, MergeConflictKind, TrafficChecker,
};
pub use cross_file::{CrossFilePass, LiveCrossFileLinker, ReferencedDestinations};
pub use error::{ReconcileError, Result};
pub use lkg::LkgStore;
pub use reconciler::{
    MergePreview, ReconcileOutcome, ReconcileResult, Reconciler, SemanticDelta, SemanticDeltaKind,
};
