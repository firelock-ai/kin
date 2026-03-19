// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Firelock, LLC

//! Kubernetes-style reconciliation loop for Kin.
//!
//! Keeps the working directory files and the working copy overlay in sync.
//!
//! Two reconciliation directions:
//! - **File -> Overlay:** detect file edits, parse, update WorkingCopy overlay
//! - **Overlay -> File:** detect overlay mutations, re-project affected files
//!
//! Enforces Last Known Good (LKG) semantics: broken ASTs do not corrupt
//! the graph. The LKG fingerprint, signature, and relations are retained
//! until the next valid parse.

pub mod collision;
pub mod error;
pub mod lkg;
pub mod reconciler;

pub use collision::{
    check_entity_collision, check_file_collision, check_signature_change, check_visibility_change,
    group_conflicts_by_file, CollisionCheck, MergeConflict, MergeConflictKind, TrafficChecker,
};
pub use error::{ReconcileError, Result};
pub use lkg::LkgStore;
pub use reconciler::{
    MergePreview, ReconcileOutcome, Reconciler, SemanticDelta, SemanticDeltaKind,
};
