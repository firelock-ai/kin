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
//! the graph. LKG declarations and call relations are retained while obsolete
//! whole-file coverage is withdrawn until the next valid parse.

mod admitted_source;
mod batch_debt;
mod binding_debt;
pub mod collision;
mod coverage;
pub mod cross_file;
pub mod error;
mod external;
mod linker_surface;
pub mod lkg;
mod move_bindings;
mod named_imports;
pub mod reconciler;
mod rust_project;

pub use binding_debt::has_reintroduced_withdrawn_guess;
pub use collision::{
    check_entity_collision, check_file_collision, check_signature_change, check_visibility_change,
    group_conflicts_by_file, CollisionCheck, MergeConflict, MergeConflictKind, TrafficChecker,
};
pub use coverage::{plan_local_binding_obligations, plan_withdrawn_local_binding_obligations};
pub use cross_file::{CrossFilePass, LiveCrossFileLinker, ReferencedDestinations};
pub use error::{ReconcileError, Result};
pub use external::verify_external_import_predecessor;
pub use lkg::LkgStore;
pub use move_bindings::{plan_moved_import_bindings, relocate_binding_obligations};
pub use reconciler::{
    MergePreview, PreparedAdmittedSourceBatch, PreparedBatchAdoption, PreparedBatchSource,
    ReconcileOutcome, ReconcileResult, Reconciler, SemanticDelta, SemanticDeltaKind,
    StaleCanonicalSource,
};
