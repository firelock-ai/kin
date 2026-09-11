// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Merge state that is independent of repository-ref representation.
//!
//! Named pointers and working-copy authority live in [`crate::refs`] and
//! [`crate::repository`]. The former branch-only and lossy graph-overlay types
//! intentionally do not survive the clean-slate repository model.

use serde::{Deserialize, Serialize};

use crate::conflict::ConflictObject;

/// State of a semantic merge operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MergeState {
    Clean,
    Conflicted(Vec<ConflictObject>),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn merge_state_roundtrip() {
        let clean = MergeState::Clean;
        let json = serde_json::to_string(&clean).unwrap();
        let parsed: MergeState = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, MergeState::Clean));
    }
}
