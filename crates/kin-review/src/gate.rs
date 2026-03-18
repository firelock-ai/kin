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
}
