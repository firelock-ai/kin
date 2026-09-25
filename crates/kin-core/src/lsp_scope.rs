// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The Python enrichment invalidated by naming the LSP workspace explicitly.
//!
//! This is one processing-semantics transition, not an environment fingerprint.
//! Parser relations and other languages keep their independent provenance.

use kin_model::{EntityId, GraphNodeId, LanguageId, Relation, RelationOrigin};
use serde::{Deserialize, Serialize};

/// The first served-state upgrade that retires rootless Python bindings.
pub const HYDRATION_VERSION: u32 = 31;

/// The initialize contract under which accepted Python evidence was obtained.
pub const WORKSPACE_SCOPE: u32 = 1;

/// A completion skip must not outlive an unfinished upgrade. The upgrade
/// writes this existing claim only after its transaction and sidecar cleanup.
pub fn upgrade_recorded(layout: &crate::KinLayout) -> bool {
    let record = crate::hydration_semantics::read(layout);
    record
        .upgrade()
        .map(|upgrade| upgrade.under)
        .or(record.created_under())
        .is_some_and(|version| version >= HYDRATION_VERSION)
}

/// The accepted-evidence journal's relation, with its initialization contract.
/// Older journal rows deserialize without a scope. Other languages still use
/// those rows; Python cannot replay an answer from the old rootless contract.
#[derive(Serialize, Deserialize)]
pub struct AcceptedRelation {
    #[serde(flatten)]
    pub relation: Relation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub python_workspace_scope: Option<u32>,
}

pub fn is_python_path(path: &str) -> bool {
    path.ends_with(".py") || path.ends_with(".pyi")
}

/// Identify the enrichment domain from admitted endpoints, retaining the
/// source-site fallback for legacy records whose endpoint no longer exists.
/// Origin is checked first: a manual or parsed edge is never retired here.
pub fn is_python_relation(
    relation: &Relation,
    mut language: impl FnMut(&EntityId) -> Option<LanguageId>,
) -> bool {
    relation.origin == RelationOrigin::Lsp
        && ([relation.src, relation.dst].iter().any(|node| {
            matches!(node, GraphNodeId::Entity(id) if language(id) == Some(LanguageId::Python))
        }) || relation.evidence.iter().any(|evidence| {
            evidence
                .source_span
                .as_ref()
                .is_some_and(|span| is_python_path(&span.file.0))
        }))
}
