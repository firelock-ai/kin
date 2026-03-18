#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostKind {
    GitHub,
    KinHub,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    GitExport,
    NativeKin,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteCapabilitySet {
    pub publish_semantic_changes: bool,
    pub publish_review_state: bool,
    pub publish_proofs: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteRef {
    pub name: String,
    pub host: HostKind,
    pub transport: TransportKind,
    pub capabilities: RemoteCapabilitySet,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepoState {
    pub local_head: Option<String>,
    pub remote_head: Option<String>,
    pub approved: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PushDecision {
    Publish,
    FastForwardRequired,
    ApprovalRequired,
    SemanticStateRequired,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushPlan {
    pub decision: PushDecision,
    pub publish_review_state: bool,
    pub publish_proofs: bool,
}

pub fn plan_push(remote: &RemoteRef, state: &RepoState) -> PushPlan {
    let Some(local_head) = state.local_head.as_deref() else {
        return PushPlan {
            decision: PushDecision::SemanticStateRequired,
            publish_review_state: false,
            publish_proofs: false,
        };
    };

    if !state.approved && remote.capabilities.publish_review_state {
        return PushPlan {
            decision: PushDecision::ApprovalRequired,
            publish_review_state: true,
            publish_proofs: false,
        };
    }

    if matches!(state.remote_head.as_deref(), Some(remote_head) if remote_head != local_head) {
        return PushPlan {
            decision: PushDecision::FastForwardRequired,
            publish_review_state: remote.capabilities.publish_review_state,
            publish_proofs: false,
        };
    }

    PushPlan {
        decision: PushDecision::Publish,
        publish_review_state: remote.capabilities.publish_review_state,
        publish_proofs: remote.capabilities.publish_proofs,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        plan_push, HostKind, PushDecision, RemoteCapabilitySet, RemoteRef, RepoState, TransportKind,
    };

    #[test]
    fn native_kithub_remote_requires_approval_before_publish() {
        let remote = RemoteRef {
            name: "origin".into(),
            host: HostKind::KinHub,
            transport: TransportKind::NativeKin,
            capabilities: RemoteCapabilitySet {
                publish_semantic_changes: true,
                publish_review_state: true,
                publish_proofs: true,
            },
        };

        let plan = plan_push(
            &remote,
            &RepoState {
                local_head: Some("change:abc".into()),
                remote_head: Some("change:abc".into()),
                approved: false,
            },
        );

        assert_eq!(plan.decision, PushDecision::ApprovalRequired);
        assert!(plan.publish_review_state);
        assert!(!plan.publish_proofs);
    }

    #[test]
    fn divergent_remote_requires_fast_forward() {
        let remote = RemoteRef {
            name: "origin".into(),
            host: HostKind::GitHub,
            transport: TransportKind::GitExport,
            capabilities: RemoteCapabilitySet {
                publish_semantic_changes: true,
                publish_review_state: false,
                publish_proofs: false,
            },
        };

        let plan = plan_push(
            &remote,
            &RepoState {
                local_head: Some("change:abc".into()),
                remote_head: Some("change:def".into()),
                approved: true,
            },
        );

        assert_eq!(plan.decision, PushDecision::FastForwardRequired);
    }

    #[test]
    fn publish_allowed_when_remote_is_aligned_and_approved() {
        let remote = RemoteRef {
            name: "origin".into(),
            host: HostKind::KinHub,
            transport: TransportKind::NativeKin,
            capabilities: RemoteCapabilitySet {
                publish_semantic_changes: true,
                publish_review_state: true,
                publish_proofs: true,
            },
        };

        let plan = plan_push(
            &remote,
            &RepoState {
                local_head: Some("change:abc".into()),
                remote_head: Some("change:abc".into()),
                approved: true,
            },
        );

        assert_eq!(plan.decision, PushDecision::Publish);
        assert!(plan.publish_proofs);
    }

    #[test]
    fn semantic_state_is_required_before_publish() {
        let remote = RemoteRef {
            name: "origin".into(),
            host: HostKind::GitHub,
            transport: TransportKind::GitExport,
            capabilities: RemoteCapabilitySet {
                publish_semantic_changes: true,
                publish_review_state: false,
                publish_proofs: false,
            },
        };

        let plan = plan_push(
            &remote,
            &RepoState {
                local_head: None,
                remote_head: None,
                approved: false,
            },
        );

        assert_eq!(plan.decision, PushDecision::SemanticStateRequired);
        assert!(!plan.publish_review_state);
        assert!(!plan.publish_proofs);
    }
}
