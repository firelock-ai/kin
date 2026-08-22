// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Token-budgeted context pack builder for Kin.

pub mod builder;
pub mod error;
pub mod tokens;

pub use builder::{
    build_context_pack, build_context_pack_from_plan, build_context_pack_with_provenance,
    build_context_pack_with_traffic, build_context_pack_with_traffic_and_provenance, group,
    AssistantHint, ContextOptions, DependencyRelation, DependencySelection, DependencySource,
    SAME_FILE_FALLBACK_MAX,
};
pub use error::{ContextError, Result};
pub use tokens::estimate_tokens;
