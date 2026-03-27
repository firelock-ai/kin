// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineRun {
    pub run_id: String,
    pub pipeline_name: String,
    pub repo_id: String,
    pub org_id: String,
    pub status: PipelineStatus,
    pub trigger: PipelineTrigger,
    pub commit_sha: Option<String>,
    pub branch: Option<String>,
    pub started_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
    pub duration_ms: Option<u64>,
    pub logs_url: Option<String>,
    pub artifacts: Vec<PipelineArtifact>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PipelineStatus {
    Pending,
    Running,
    Success,
    Failure,
    Cancelled,
    TimedOut,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PipelineTrigger {
    Push,
    Tag,
    PullRequest,
    Manual,
    Schedule,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineArtifact {
    pub name: String,
    pub path: String,
    pub size_bytes: u64,
    pub url: String,
}
