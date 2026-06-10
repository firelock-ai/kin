// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use serde::{Deserialize, Serialize};

use crate::ids::*;

/// A rendered output from semantic state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Projection {
    pub kind: ProjectionKind,
    pub source_change: SemanticChangeId,
    pub projected_files: Vec<FilePathId>,
    pub content_hashes: Vec<Hash256>,
}

/// Classification of projection output types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ProjectionKind {
    SourceFile,
    GitCommit,
    PullRequestView,
    LivingDoc,
    BenchmarkReport,
}
