// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Token-budgeted context pack builder for Kin.

pub mod builder;
pub mod error;
pub mod multi;
pub mod tokens;

pub use builder::{
    build_context_pack, build_context_pack_from_plan, build_context_pack_with_provenance,
    build_context_pack_with_traffic, build_context_pack_with_traffic_and_provenance, group,
    AssistantHint, ContextOptions, DependencyRelation, DependencySelection, DependencySource,
    FULL_BODY_PROJECTION_NAME, SAME_FILE_FALLBACK_MAX, SERVED_BODY_PROJECTION_NAME,
};
pub use error::{ContextError, Result};
pub use multi::{
    build_multi_focal_pack, method_line, neighborhood_depth_for, render_multi_focal_lines,
    water_fill, FocalContribution, FocalResolution, MultiFocalOptions, MultiFocalReport,
    PackElision, RouteReport, RouteSearch, ELISION_REASON_TOKEN_BUDGET, FOCAL_GROUP, ROUTE_GROUP,
    ROUTE_MARKER, ROUTE_MAX_HOPS, ROUTE_VISIT_MAX,
};
pub use tokens::estimate_tokens;
