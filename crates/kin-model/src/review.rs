// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Firelock, LLC

use serde::{Deserialize, Serialize};

/// Summary of risk associated with a semantic change.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskSummary {
    pub overall_risk: RiskLevel,
    pub breaking_changes: Vec<String>,
    pub test_coverage_gaps: Vec<String>,
    pub contract_violations: Vec<String>,
    /// Risks related to in-progress work items affected by changes.
    pub work_risks: Vec<String>,
    pub notes: Vec<String>,
}

/// Risk classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn risk_level_roundtrip() {
        let level = RiskLevel::High;
        let json = serde_json::to_string(&level).unwrap();
        let parsed: RiskLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, level);
    }
}
