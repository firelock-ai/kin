// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Verification graph types: test cases, assertions, and coverage tracking.
//!
//! Phase 9 introduces first-class graph objects for verification — test cases
//! anchored to semantic scopes, assertions about expected behavior, and
//! coverage summaries that track which entities have proof of correctness.

use crate::ids::{ContractId, EntityId, FilePathId, Hash256};
use crate::timestamp::Timestamp;
use crate::work::WorkScope;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// IDs
// ---------------------------------------------------------------------------

/// Unique identifier for a test case.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct TestId(pub Hash256);

impl TestId {
    pub fn new() -> Self {
        let bytes = *uuid::Uuid::new_v4().as_bytes();
        let mut buf = [0u8; 32];
        buf[..16].copy_from_slice(&bytes);
        Self(Hash256::from_bytes(buf))
    }

    pub fn from_hash(h: Hash256) -> Self {
        Self(h)
    }
}

impl Default for TestId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for TestId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for an assertion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AssertionId(pub Hash256);

impl AssertionId {
    pub fn new() -> Self {
        let bytes = *uuid::Uuid::new_v4().as_bytes();
        let mut buf = [0u8; 32];
        buf[..16].copy_from_slice(&bytes);
        Self(Hash256::from_bytes(buf))
    }
}

impl Default for AssertionId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for AssertionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for a verification run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
pub struct VerificationRunId(pub Hash256);

impl VerificationRunId {
    pub fn new() -> Self {
        let bytes = *uuid::Uuid::new_v4().as_bytes();
        let mut buf = [0u8; 32];
        buf[..16].copy_from_slice(&bytes);
        Self(Hash256::from_bytes(buf))
    }

    pub fn from_hash(h: Hash256) -> Self {
        Self(h)
    }
}

impl Default for VerificationRunId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for VerificationRunId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for a mock hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MockHintId(pub Hash256);

impl MockHintId {
    pub fn new() -> Self {
        let bytes = *uuid::Uuid::new_v4().as_bytes();
        let mut buf = [0u8; 32];
        buf[..16].copy_from_slice(&bytes);
        Self(Hash256::from_bytes(buf))
    }

    pub fn from_hash(h: Hash256) -> Self {
        Self(h)
    }
}

impl Default for MockHintId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for MockHintId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ---------------------------------------------------------------------------
// Enums
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TestKind {
    Unit,
    Integration,
    Contract,
    Property,
}

impl std::fmt::Display for TestKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unit => write!(f, "unit"),
            Self::Integration => write!(f, "integration"),
            Self::Contract => write!(f, "contract"),
            Self::Property => write!(f, "property"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TestRunner {
    Cargo,
    Jest,
    Pytest,
    Go,
    JUnit,
    Custom(String),
}

impl std::fmt::Display for TestRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Cargo => write!(f, "cargo"),
            Self::Jest => write!(f, "jest"),
            Self::Pytest => write!(f, "pytest"),
            Self::Go => write!(f, "go"),
            Self::JUnit => write!(f, "junit"),
            Self::Custom(s) => write!(f, "{}", s),
        }
    }
}

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestCase {
    pub test_id: TestId,
    pub name: String,
    pub language: String,
    pub kind: TestKind,
    pub scopes: Vec<WorkScope>,
    pub runner: TestRunner,
    pub file_origin: Option<FilePathId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Assertion {
    pub assertion_id: AssertionId,
    pub summary: String,
    pub expected_behavior: String,
    pub target_scope: WorkScope,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VerificationStatus {
    Missing,
    Pending,
    Passing,
    Failing,
}

impl std::fmt::Display for VerificationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing => write!(f, "missing"),
            Self::Pending => write!(f, "pending"),
            Self::Passing => write!(f, "passing"),
            Self::Failing => write!(f, "failing"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageSummary {
    pub total_entities: usize,
    pub covered_entities: usize,
    pub coverage_ratio: f64,
    pub missing_proof: Vec<EntityId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CompletionState {
    Incomplete,
    Covered,
    Verified,
}

impl std::fmt::Display for CompletionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Incomplete => write!(f, "incomplete"),
            Self::Covered => write!(f, "covered"),
            Self::Verified => write!(f, "verified"),
        }
    }
}

/// Strategy used to mock a dependency during a test run.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MockStrategy {
    InMemory,
    Stub,
    Fake,
    Recorded,
    Custom(String),
}

impl std::fmt::Display for MockStrategy {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InMemory => write!(f, "in_memory"),
            Self::Stub => write!(f, "stub"),
            Self::Fake => write!(f, "fake"),
            Self::Recorded => write!(f, "recorded"),
            Self::Custom(s) => write!(f, "{}", s),
        }
    }
}

// ---------------------------------------------------------------------------
// Verification runs and mock hints (Phase 9 completion)
// ---------------------------------------------------------------------------

/// A single execution of one or more tests with captured evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationRun {
    pub run_id: VerificationRunId,
    pub test_ids: Vec<TestId>,
    pub status: VerificationStatus,
    pub runner: TestRunner,
    pub started_at: Timestamp,
    pub finished_at: Option<Timestamp>,
    pub duration_ms: Option<u64>,
    pub evidence_blob: Option<Hash256>,
    pub exit_code: Option<i32>,
}

/// Advisory hint that a dependency was mocked during a test run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MockHint {
    pub hint_id: MockHintId,
    pub test_id: TestId,
    pub dependency_scope: WorkScope,
    pub strategy: MockStrategy,
}

/// Contract-level coverage summary (how many contracts have test coverage).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractCoverageSummary {
    pub total_contracts: usize,
    pub covered_contracts: usize,
    pub coverage_ratio: f64,
    pub uncovered_contract_ids: Vec<ContractId>,
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ids::{ContractId, EntityId};

    #[test]
    fn test_id_display_not_empty() {
        let id = TestId::new();
        let s = id.to_string();
        assert!(!s.is_empty());
    }

    #[test]
    fn test_id_from_hash_roundtrip() {
        let h = Hash256::from_bytes([0xaa; 32]);
        let id = TestId::from_hash(h);
        assert_eq!(id.0, h);
    }

    #[test]
    fn assertion_id_display_not_empty() {
        let id = AssertionId::new();
        assert!(!id.to_string().is_empty());
    }

    #[test]
    fn test_kind_display() {
        assert_eq!(TestKind::Unit.to_string(), "unit");
        assert_eq!(TestKind::Integration.to_string(), "integration");
        assert_eq!(TestKind::Contract.to_string(), "contract");
        assert_eq!(TestKind::Property.to_string(), "property");
    }

    #[test]
    fn test_runner_display() {
        assert_eq!(TestRunner::Cargo.to_string(), "cargo");
        assert_eq!(TestRunner::Jest.to_string(), "jest");
        assert_eq!(TestRunner::Pytest.to_string(), "pytest");
        assert_eq!(TestRunner::Go.to_string(), "go");
        assert_eq!(TestRunner::JUnit.to_string(), "junit");
        assert_eq!(TestRunner::Custom("rspec".into()).to_string(), "rspec");
    }

    #[test]
    fn verification_status_display() {
        assert_eq!(VerificationStatus::Missing.to_string(), "missing");
        assert_eq!(VerificationStatus::Pending.to_string(), "pending");
        assert_eq!(VerificationStatus::Passing.to_string(), "passing");
        assert_eq!(VerificationStatus::Failing.to_string(), "failing");
    }

    #[test]
    fn completion_state_display() {
        assert_eq!(CompletionState::Incomplete.to_string(), "incomplete");
        assert_eq!(CompletionState::Covered.to_string(), "covered");
        assert_eq!(CompletionState::Verified.to_string(), "verified");
    }

    #[test]
    fn test_case_serialization_roundtrip() {
        let tc = TestCase {
            test_id: TestId::new(),
            name: "test_checkout_flow".into(),
            language: "rust".into(),
            kind: TestKind::Integration,
            scopes: vec![WorkScope::Entity(EntityId::new())],
            runner: TestRunner::Cargo,
            file_origin: Some(FilePathId::new("tests/checkout.rs")),
        };

        let json = serde_json::to_string(&tc).unwrap();
        let parsed: TestCase = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.test_id, tc.test_id);
        assert_eq!(parsed.name, tc.name);
        assert_eq!(parsed.kind, tc.kind);
        assert_eq!(parsed.runner, tc.runner);
    }

    #[test]
    fn assertion_serialization_roundtrip() {
        let a = Assertion {
            assertion_id: AssertionId::new(),
            summary: "Checkout must validate card".into(),
            expected_behavior: "Returns error on invalid card number".into(),
            target_scope: WorkScope::Entity(EntityId::new()),
        };

        let json = serde_json::to_string(&a).unwrap();
        let parsed: Assertion = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.assertion_id, a.assertion_id);
        assert_eq!(parsed.summary, a.summary);
    }

    #[test]
    fn coverage_summary_serialization_roundtrip() {
        let cs = CoverageSummary {
            total_entities: 100,
            covered_entities: 75,
            coverage_ratio: 0.75,
            missing_proof: vec![EntityId::new(), EntityId::new()],
        };

        let json = serde_json::to_string(&cs).unwrap();
        let parsed: CoverageSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_entities, 100);
        assert_eq!(parsed.covered_entities, 75);
        assert_eq!(parsed.missing_proof.len(), 2);
    }

    #[test]
    fn test_id_serialization_roundtrip() {
        let id = TestId::new();
        let json = serde_json::to_string(&id).unwrap();
        let parsed: TestId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn verification_status_serialization_roundtrip() {
        for status in [
            VerificationStatus::Missing,
            VerificationStatus::Pending,
            VerificationStatus::Passing,
            VerificationStatus::Failing,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let parsed: VerificationStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, parsed);
        }
    }

    // --- Phase 9 completion types ---

    #[test]
    fn verification_run_id_display_not_empty() {
        let id = VerificationRunId::new();
        assert!(!id.to_string().is_empty());
    }

    #[test]
    fn verification_run_id_serialization_roundtrip() {
        let id = VerificationRunId::new();
        let json = serde_json::to_string(&id).unwrap();
        let parsed: VerificationRunId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn mock_hint_id_display_not_empty() {
        let id = MockHintId::new();
        assert!(!id.to_string().is_empty());
    }

    #[test]
    fn mock_hint_id_serialization_roundtrip() {
        let id = MockHintId::new();
        let json = serde_json::to_string(&id).unwrap();
        let parsed: MockHintId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn mock_strategy_display() {
        assert_eq!(MockStrategy::InMemory.to_string(), "in_memory");
        assert_eq!(MockStrategy::Stub.to_string(), "stub");
        assert_eq!(MockStrategy::Fake.to_string(), "fake");
        assert_eq!(MockStrategy::Recorded.to_string(), "recorded");
        assert_eq!(
            MockStrategy::Custom("wiremock".into()).to_string(),
            "wiremock"
        );
    }

    #[test]
    fn mock_strategy_serialization_roundtrip() {
        for strategy in [
            MockStrategy::InMemory,
            MockStrategy::Stub,
            MockStrategy::Fake,
            MockStrategy::Recorded,
            MockStrategy::Custom("wiremock".into()),
        ] {
            let json = serde_json::to_string(&strategy).unwrap();
            let parsed: MockStrategy = serde_json::from_str(&json).unwrap();
            assert_eq!(strategy, parsed);
        }
    }

    #[test]
    fn verification_run_serialization_roundtrip() {
        use crate::timestamp::Timestamp;

        let run = VerificationRun {
            run_id: VerificationRunId::new(),
            test_ids: vec![TestId::new(), TestId::new()],
            status: VerificationStatus::Passing,
            runner: TestRunner::Cargo,
            started_at: Timestamp::now(),
            finished_at: Some(Timestamp::now()),
            duration_ms: Some(1234),
            evidence_blob: Some(Hash256::from_bytes([0xee; 32])),
            exit_code: Some(0),
        };

        let json = serde_json::to_string(&run).unwrap();
        let parsed: VerificationRun = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.run_id, run.run_id);
        assert_eq!(parsed.test_ids.len(), 2);
        assert_eq!(parsed.status, VerificationStatus::Passing);
        assert_eq!(parsed.duration_ms, Some(1234));
        assert_eq!(parsed.exit_code, Some(0));
    }

    #[test]
    fn mock_hint_serialization_roundtrip() {
        let hint = MockHint {
            hint_id: MockHintId::new(),
            test_id: TestId::new(),
            dependency_scope: WorkScope::Entity(EntityId::new()),
            strategy: MockStrategy::InMemory,
        };

        let json = serde_json::to_string(&hint).unwrap();
        let parsed: MockHint = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.hint_id, hint.hint_id);
        assert_eq!(parsed.strategy, MockStrategy::InMemory);
    }

    #[test]
    fn contract_coverage_summary_serialization_roundtrip() {
        let cs = ContractCoverageSummary {
            total_contracts: 10,
            covered_contracts: 7,
            coverage_ratio: 0.7,
            uncovered_contract_ids: vec![ContractId::new()],
        };

        let json = serde_json::to_string(&cs).unwrap();
        let parsed: ContractCoverageSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.total_contracts, 10);
        assert_eq!(parsed.covered_contracts, 7);
        assert_eq!(parsed.uncovered_contract_ids.len(), 1);
    }
}
