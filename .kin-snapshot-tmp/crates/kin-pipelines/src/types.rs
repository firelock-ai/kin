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
    pub step_results: Vec<PipelineStepResult>,
    /// Proof record linking inputs to outputs for auditability.
    pub proof: Option<PipelineProofRecord>,
    /// Number of times this pipeline configuration has been executed.
    pub attempt: u32,
    /// If this run is a retry, the run_id of the original run.
    pub retry_of_run_id: Option<String>,
    /// Execution environment identifier (e.g. "local", "kubernetes").
    pub execution_mode: String,
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

/// Result of a single pipeline step execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineStepResult {
    pub name: String,
    pub status: StepStatus,
    pub started_at: Option<DateTime<Utc>>,
    pub completed_at: Option<DateTime<Utc>>,
    pub exit_code: Option<i32>,
    pub log_snippet: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum StepStatus {
    Queued,
    Running,
    Success,
    Failure,
    Skipped,
}

/// An artifact produced by a pipeline run, with full lineage back to
/// the graph entities that generated it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineArtifact {
    pub name: String,
    pub path: String,
    pub size_bytes: u64,
    pub url: String,
    /// SHA-256 hash of the artifact content.
    pub content_hash: Option<String>,
    /// URL/path in durable storage (GCS, local blob store, etc.).
    pub storage_url: Option<String>,
    /// Entity IDs in the graph that were inputs to producing this artifact.
    pub source_entity_ids: Vec<String>,
    /// Timestamp when this artifact was produced.
    pub produced_at: Option<DateTime<Utc>>,
}

/// Cryptographic proof record for a pipeline run, creating an auditable
/// chain: input entities -> pipeline execution -> output artifacts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineProofRecord {
    /// SHA-256 hashes of the input entity states at execution time.
    pub input_entity_hashes: Vec<EntityHashEntry>,
    /// SHA-256 hashes of the output artifacts.
    pub output_artifact_hashes: Vec<ArtifactHashEntry>,
    /// Hash of the execution environment (image digest, config hash, etc.).
    pub environment_hash: String,
    /// Hash of the pipeline configuration used for this run.
    pub config_hash: String,
    /// Combined proof hash: H(input_hashes || output_hashes || env_hash || config_hash).
    pub proof_hash: String,
    /// Timestamp when the proof was computed.
    pub computed_at: DateTime<Utc>,
}

/// A hash entry for a single entity that served as pipeline input.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityHashEntry {
    pub entity_id: String,
    pub entity_kind: String,
    pub content_hash: String,
}

/// A hash entry for a single artifact produced by the pipeline.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactHashEntry {
    pub artifact_name: String,
    pub content_hash: String,
    pub storage_url: Option<String>,
}
