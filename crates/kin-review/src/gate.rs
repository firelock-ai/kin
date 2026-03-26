// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReviewSignalKind {
    ProofGap,
    PolicyViolation,
    DownstreamRisk,
    CoverageGap,
    Strength,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewFinding {
    pub kind: ReviewSignalKind,
    pub title: String,
    pub blocking: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GateStatus {
    Pass,
    NeedsAttention,
    Blocked,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewDecision {
    pub status: GateStatus,
    pub blocking_count: usize,
    pub attention_count: usize,
    pub summary: String,
}

pub fn derive_decision(findings: &[ReviewFinding], approvals_required: usize) -> ReviewDecision {
    let blocking_count = findings.iter().filter(|finding| finding.blocking).count();
    let attention_count = findings.len().saturating_sub(blocking_count);

    let status = if blocking_count > 0 || approvals_required > 1 && attention_count > 2 {
        GateStatus::Blocked
    } else if attention_count > 0 || approvals_required > 0 {
        GateStatus::NeedsAttention
    } else {
        GateStatus::Pass
    };

    let summary = match status {
        GateStatus::Pass => "ready to approve".to_string(),
        GateStatus::NeedsAttention => {
            format!("{attention_count} attention signals, {blocking_count} blocking findings")
        }
        GateStatus::Blocked => {
            format!("blocked by {blocking_count} blocking findings and {attention_count} attention signals")
        }
    };

    ReviewDecision {
        status,
        blocking_count,
        attention_count,
        summary,
    }
}

#[cfg(test)]
mod tests {
    use super::{derive_decision, GateStatus, ReviewFinding, ReviewSignalKind};

    #[test]
    fn blocking_findings_block_review() {
        let decision = derive_decision(
            &[ReviewFinding {
                kind: ReviewSignalKind::PolicyViolation,
                title: "policy".into(),
                blocking: true,
            }],
            1,
        );

        assert_eq!(decision.status, GateStatus::Blocked);
        assert_eq!(decision.blocking_count, 1);
    }

    #[test]
    fn attention_without_blockers_needs_attention() {
        let decision = derive_decision(
            &[ReviewFinding {
                kind: ReviewSignalKind::CoverageGap,
                title: "coverage".into(),
                blocking: false,
            }],
            0,
        );

        assert_eq!(decision.status, GateStatus::NeedsAttention);
        assert_eq!(decision.attention_count, 1);
    }

    #[test]
    fn clean_change_passes() {
        let decision = derive_decision(&[], 0);

        assert_eq!(decision.status, GateStatus::Pass);
        assert_eq!(decision.summary, "ready to approve");
    }

    // ── Coverage gate tests ─────────────────────────────────────────────

    #[test]
    fn coverage_gap_is_non_blocking() {
        let decision = derive_decision(
            &[ReviewFinding {
                kind: ReviewSignalKind::CoverageGap,
                title: "missing tests for helper".into(),
                blocking: false,
            }],
            0,
        );
        assert_eq!(decision.status, GateStatus::NeedsAttention);
        assert_eq!(decision.blocking_count, 0);
        assert_eq!(decision.attention_count, 1);
    }

    #[test]
    fn coverage_gap_blocking_blocks() {
        let decision = derive_decision(
            &[ReviewFinding {
                kind: ReviewSignalKind::CoverageGap,
                title: "critical path uncovered".into(),
                blocking: true,
            }],
            0,
        );
        assert_eq!(decision.status, GateStatus::Blocked);
    }

    // ── Release gate tests ──────────────────────────────────────────────

    #[test]
    fn proof_gap_blocks_release() {
        let decision = derive_decision(
            &[ReviewFinding {
                kind: ReviewSignalKind::ProofGap,
                title: "no proof for entity".into(),
                blocking: true,
            }],
            0,
        );
        assert_eq!(decision.status, GateStatus::Blocked);
        assert!(decision.summary.contains("blocking"));
    }

    // ── Dead-code gate tests ────────────────────────────────────────────

    #[test]
    fn downstream_risk_non_blocking_needs_attention() {
        let decision = derive_decision(
            &[ReviewFinding {
                kind: ReviewSignalKind::DownstreamRisk,
                title: "downstream consumer may break".into(),
                blocking: false,
            }],
            0,
        );
        assert_eq!(decision.status, GateStatus::NeedsAttention);
    }

    // ── Contract-shift gate tests ───────────────────────────────────────

    #[test]
    fn policy_violation_always_blocks() {
        let decision = derive_decision(
            &[ReviewFinding {
                kind: ReviewSignalKind::PolicyViolation,
                title: "schema changed without migration".into(),
                blocking: true,
            }],
            0,
        );
        assert_eq!(decision.status, GateStatus::Blocked);
    }

    // ── Combined findings tests ─────────────────────────────────────────

    #[test]
    fn multiple_non_blocking_needs_attention() {
        let findings = vec![
            ReviewFinding {
                kind: ReviewSignalKind::CoverageGap,
                title: "gap 1".into(),
                blocking: false,
            },
            ReviewFinding {
                kind: ReviewSignalKind::DownstreamRisk,
                title: "risk 1".into(),
                blocking: false,
            },
        ];
        let decision = derive_decision(&findings, 0);
        assert_eq!(decision.status, GateStatus::NeedsAttention);
        assert_eq!(decision.attention_count, 2);
    }

    #[test]
    fn mixed_blocking_and_non_blocking() {
        let findings = vec![
            ReviewFinding {
                kind: ReviewSignalKind::PolicyViolation,
                title: "policy".into(),
                blocking: true,
            },
            ReviewFinding {
                kind: ReviewSignalKind::CoverageGap,
                title: "coverage".into(),
                blocking: false,
            },
        ];
        let decision = derive_decision(&findings, 1);
        assert_eq!(decision.status, GateStatus::Blocked);
        assert_eq!(decision.blocking_count, 1);
        assert_eq!(decision.attention_count, 1);
    }

    #[test]
    fn many_attention_with_high_approvals_blocks() {
        // approvals_required > 1 && attention_count > 2 => Blocked
        let findings = vec![
            ReviewFinding {
                kind: ReviewSignalKind::CoverageGap,
                title: "a".into(),
                blocking: false,
            },
            ReviewFinding {
                kind: ReviewSignalKind::CoverageGap,
                title: "b".into(),
                blocking: false,
            },
            ReviewFinding {
                kind: ReviewSignalKind::CoverageGap,
                title: "c".into(),
                blocking: false,
            },
        ];
        let decision = derive_decision(&findings, 2);
        assert_eq!(decision.status, GateStatus::Blocked);
    }

    #[test]
    fn strength_finding_is_non_blocking() {
        let decision = derive_decision(
            &[ReviewFinding {
                kind: ReviewSignalKind::Strength,
                title: "well-tested change".into(),
                blocking: false,
            }],
            0,
        );
        assert_eq!(decision.status, GateStatus::NeedsAttention);
    }

    #[test]
    fn approvals_required_without_findings_needs_attention() {
        let decision = derive_decision(&[], 1);
        assert_eq!(decision.status, GateStatus::NeedsAttention);
    }

    #[test]
    fn zero_approvals_zero_findings_passes() {
        let decision = derive_decision(&[], 0);
        assert_eq!(decision.status, GateStatus::Pass);
    }
}
