// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use serde::{Deserialize, Serialize};

use crate::ids::*;

/// Execution provenance record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence {
    pub id: EvidenceId,
    pub assistant_identity: Option<String>,
    pub prompt_provenance: Option<String>,
    pub tool_calls: Vec<String>,
    pub touched_entities: Vec<EntityId>,
    pub validation_commands: Vec<String>,
    pub stdout: Option<String>,
    pub stderr: Option<String>,
    pub test_results: Vec<TestResult>,
    pub replay_metadata: Option<serde_json::Value>,
    pub workspace_snapshot_id: Option<String>,
}

/// Result of a single test execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TestResult {
    pub name: String,
    pub passed: bool,
    pub duration_ms: Option<u64>,
    pub output: Option<String>,
}
