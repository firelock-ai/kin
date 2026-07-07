// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

pub mod diff;
pub mod error;
pub mod format;
pub mod gate;
pub mod impact;
pub mod inline;
pub mod ref_graph;
pub mod release_gate;
pub mod revert_history;
pub mod review;
pub mod risk;
pub mod shadow;

pub use diff::{
    compute_diff, diff_from_change, diff_from_changes, diff_from_entity_ids, diff_from_files,
    EntityChange, EntityChangeKind, SemanticDiff,
};
pub use error::ReviewError;
pub use format::{
    format_diff, format_impact, format_inline_comments, format_review, format_risk_highlights,
};
pub use gate::{derive_decision, GateStatus, ReviewDecision, ReviewFinding, ReviewSignalKind};
pub use impact::{analyze_impact, analyze_impact_at, EntityImpact, ImpactGraph, ImpactReport};
pub use inline::{
    collect_inline_comments, group_by_file, InlineComment, InlineCommentKind,
    CONSUMER_FANOUT_THRESHOLD,
};
pub use ref_graph::GraphAtRef;
pub use release_gate::{
    entities_touched_by_change, security_findings, unapproved_agent_changes, SecurityFinding,
    SecurityFindingCounts, SecuritySeverity, UnapprovedAgentChange,
};
pub use review::{Review, SemanticReview};
pub use risk::assess_risk;
pub use shadow::{
    build_shadow_report, build_shadow_report_at, format_shadow_report, ShadowGateReport,
    ShadowGateVerdict, ShadowRequest, SHADOW_ENFORCEMENT_REPORT_ONLY,
    SHADOW_GATE_REPORT_SCHEMA_VERSION,
};
