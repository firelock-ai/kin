// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! File/doc projection engine for Kin.
//!
//! Projects semantic state into working directory files without destructive
//! formatting churn. Uses surgical byte-range splicing on CST-preserving
//! `FileLayout` structures.
//!
//! Key invariant: after any projection, the working directory must still be
//! runnable (`npm test`, `cargo build`, etc. still pass if they passed before).

pub mod engine;
pub mod error;
pub mod imports;
pub mod layout_tracker;
pub mod living_docs;
pub mod placement;
pub mod splice;

pub use engine::{
    project_entity_mutations, project_entity_mutations_with_policy, project_file_from_entities,
    project_overlay_to_bytes, project_to_bytes, ProjectionState,
};
pub use error::{ProjectionError, Result};
pub use imports::{add_import, remove_import, update_import_symbols};
pub use layout_tracker::{build_layout, entity_at_offset, entity_byte_range, update_layout};
pub use living_docs::generate_living_docs;
pub use placement::{decide_placement, generate_file_template, PlacementDecision};
pub use splice::{apply_splices, reconstruct_file, splice_entity, Splice};
