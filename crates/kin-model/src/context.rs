// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use serde::{Deserialize, Serialize};

use crate::ids::*;
use crate::layout::ArtifactKind;
use crate::retrieval::RetrievalKey;
use crate::session::IntentSummary;
use crate::work::{Annotation, WorkItem};

/// Token-budgeted context pack for AI assistants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextPack {
    pub focal_entities: Vec<ContextEntry>,
    pub dependency_signatures: Vec<ContextEntry>,
    pub transitive_deps: Vec<ContextEntry>,
    pub contracts: Vec<ContextEntry>,
    pub tests: Vec<ContextEntry>,
    /// Active work items scoped to entities in this context pack.
    pub work_items: Vec<WorkItemEntry>,
    /// Fresh annotations on entities in this context pack.
    pub annotations: Vec<AnnotationEntry>,
    /// Nearby active traffic (other agents working on related entities).
    /// Populated when `include_traffic=true`.
    pub traffic: Vec<TrafficEntry>,
    /// Graph-owned non-entity context projected into the pack.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supporting_artifacts: Vec<ArtifactContextEntry>,
    pub token_budget: TokenBudget,
    pub actual_tokens: usize,
}

/// Planner handoff describing which retrieval seeds should shape a context pack.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContextPlan {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub seeds: Vec<ContextPlanSeed>,
}

/// A single retrieval seed carried from locate into context assembly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextPlanSeed {
    pub retrieval_key: RetrievalKey,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_path: Option<FilePathId>,
    pub score: f32,
    #[serde(default)]
    pub lexical: bool,
    #[serde(default)]
    pub semantic: bool,
}

/// Graph-owned non-entity context emitted alongside entity entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactContextEntry {
    pub retrieval_key: RetrievalKey,
    pub file_path: FilePathId,
    pub kind: ArtifactContextKind,
    pub content: String,
}

/// Classification of supporting artifact context.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ArtifactContextKind {
    ShallowFile,
    StructuredArtifact(ArtifactKind),
    OpaqueArtifact,
}

/// A work item included in a context pack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkItemEntry {
    pub work_item: WorkItem,
    pub content: String,
}

/// An annotation included in a context pack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnotationEntry {
    pub annotation: Annotation,
    pub content: String,
}

/// An entry describing nearby agent traffic included in a context pack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficEntry {
    /// The intent summary (who is doing what).
    pub intent: IntentSummary,
    /// How the traffic relates to the focal entity.
    pub proximity: TrafficProximity,
}

/// How nearby traffic relates to the focal entity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TrafficProximity {
    /// Directly locks the focal entity or one of its direct dependencies.
    Direct,
    /// Locks a transitive dependency of the focal entity.
    Downstream,
    /// Locks a file that contains the focal entity.
    SameFile,
}

/// A single entry in a context pack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextEntry {
    pub entity_id: EntityId,
    pub projection_level: ProjectionLevel,
    pub content: String,
}

/// How much of an entity to include in a context pack.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProjectionLevel {
    FullBody,
    SignatureOnly,
    NameAndKind,
}

/// Configurable token budget tiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TokenBudget {
    Small8k,
    Medium16k,
    Large32k,
    Custom(usize),
}

impl TokenBudget {
    pub fn max_tokens(&self) -> usize {
        match self {
            TokenBudget::Small8k => 8_000,
            TokenBudget::Medium16k => 16_000,
            TokenBudget::Large32k => 32_000,
            TokenBudget::Custom(n) => *n,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_budget_values() {
        assert_eq!(TokenBudget::Small8k.max_tokens(), 8_000);
        assert_eq!(TokenBudget::Medium16k.max_tokens(), 16_000);
        assert_eq!(TokenBudget::Large32k.max_tokens(), 32_000);
        assert_eq!(TokenBudget::Custom(4096).max_tokens(), 4096);
    }

    #[test]
    fn token_budget_roundtrip() {
        let budget = TokenBudget::Custom(12345);
        let json = serde_json::to_string(&budget).unwrap();
        let parsed: TokenBudget = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, budget);
    }

    #[test]
    fn context_pack_defaults_supporting_artifacts_when_absent() {
        let json = r#"{
            "focal_entities": [],
            "dependency_signatures": [],
            "transitive_deps": [],
            "contracts": [],
            "tests": [],
            "work_items": [],
            "annotations": [],
            "traffic": [],
            "token_budget": "Small8k",
            "actual_tokens": 0
        }"#;

        let pack: ContextPack = serde_json::from_str(json).unwrap();
        assert!(pack.supporting_artifacts.is_empty());
    }

    #[test]
    fn context_plan_seed_defaults_optional_fields() {
        let json = r#"{
            "retrieval_key": { "Entity": "00000000-0000-0000-0000-000000000000" },
            "score": 1.5
        }"#;

        let seed: ContextPlanSeed = serde_json::from_str(json).unwrap();
        assert!(seed.file_path.is_none());
        assert!(!seed.lexical);
        assert!(!seed.semantic);
    }
}
