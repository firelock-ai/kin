// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::assistant_import::AssistantArtifact;
use crate::metrics::{AssistantRunSource, AssistantTaskRun, BenchmarkSubstrate, DurationMs};

/// Configuration for a benchmark capture session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureConfig {
    pub assistant: String,
    pub substrate: BenchmarkSubstrate,
    pub task_name: String,
    pub model_name: Option<String>,
}

/// An active capture session that tracks timing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaptureSession {
    pub config: CaptureConfig,
    pub started_at: chrono::DateTime<Utc>,
}

impl CaptureSession {
    pub fn start(config: CaptureConfig) -> Self {
        Self {
            config,
            started_at: Utc::now(),
        }
    }

    /// Create a CaptureSession from an already-parsed AssistantArtifact.
    ///
    /// Populates config from the artifact's vendor and fills notes with
    /// file-level statistics (files touched, lines added/removed, tool calls).
    pub fn from_artifact(
        artifact: &AssistantArtifact,
        task_name: &str,
        substrate: BenchmarkSubstrate,
    ) -> AssistantTaskRun {
        let duration_ms = artifact
            .raw_duration_secs
            .map(|s| s * 1000.0)
            .unwrap_or(0.0);

        let notes = format!(
            "files={}, +{}/-{}, tools={}, iterations={}",
            artifact.files_touched.len(),
            artifact.lines_added,
            artifact.lines_removed,
            artifact.tool_calls,
            artifact.iterations,
        );

        AssistantTaskRun {
            task_name: task_name.to_string(),
            assistant_name: artifact.vendor.clone(),
            model_name: None,
            substrate,
            duration_ms: DurationMs(duration_ms),
            input_tokens: 0,
            output_tokens: 0,
            total_tokens: 0,
            estimated_cost_usd: 0.0,
            first_pass_success: false,
            validation_passed: false,
            run_source: AssistantRunSource::ArtifactImport,
            notes: Some(notes),
            recorded_at: Utc::now(),
        }
    }

    /// Finish the session and produce an AssistantTaskRun.
    pub fn finish(
        &self,
        duration_ms: f64,
        input_tokens: u64,
        output_tokens: u64,
        cost_usd: f64,
        passed: bool,
    ) -> AssistantTaskRun {
        AssistantTaskRun {
            task_name: self.config.task_name.clone(),
            assistant_name: self.config.assistant.clone(),
            model_name: self.config.model_name.clone(),
            substrate: self.config.substrate,
            duration_ms: DurationMs(duration_ms),
            input_tokens,
            output_tokens,
            total_tokens: input_tokens + output_tokens,
            estimated_cost_usd: cost_usd,
            first_pass_success: passed,
            validation_passed: passed,
            run_source: AssistantRunSource::LiveHarness,
            notes: None,
            recorded_at: Utc::now(),
        }
    }
}

/// Build an AssistantTaskRun directly from CLI flags without a timed session.
#[allow(clippy::too_many_arguments)]
pub fn build_run_from_flags(
    assistant: &str,
    task: &str,
    substrate: BenchmarkSubstrate,
    model: Option<&str>,
    duration_ms: f64,
    tokens_in: u64,
    tokens_out: u64,
    cost: f64,
    passed: bool,
) -> AssistantTaskRun {
    AssistantTaskRun {
        task_name: task.to_string(),
        assistant_name: assistant.to_string(),
        model_name: model.map(|s| s.to_string()),
        substrate,
        duration_ms: DurationMs(duration_ms),
        input_tokens: tokens_in,
        output_tokens: tokens_out,
        total_tokens: tokens_in + tokens_out,
        estimated_cost_usd: cost,
        first_pass_success: passed,
        validation_passed: passed,
        run_source: AssistantRunSource::ManualFlags,
        notes: Some("manual benchmark capture from explicit CLI flags".to_string()),
        recorded_at: Utc::now(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> CaptureConfig {
        CaptureConfig {
            assistant: "claude".to_string(),
            substrate: BenchmarkSubstrate::Kin,
            task_name: "semantic-review".to_string(),
            model_name: Some("opus".to_string()),
        }
    }

    #[test]
    fn capture_session_start_and_finish() {
        let session = CaptureSession::start(test_config());
        assert_eq!(session.config.assistant, "claude");
        assert_eq!(session.config.task_name, "semantic-review");

        let run = session.finish(1500.0, 1000, 500, 0.10, true);
        assert_eq!(run.task_name, "semantic-review");
        assert_eq!(run.assistant_name, "claude");
        assert_eq!(run.model_name, Some("opus".to_string()));
        assert_eq!(run.substrate, BenchmarkSubstrate::Kin);
        assert!((run.duration_ms.0 - 1500.0).abs() < f64::EPSILON);
        assert_eq!(run.input_tokens, 1000);
        assert_eq!(run.output_tokens, 500);
        assert_eq!(run.total_tokens, 1500);
        assert!((run.estimated_cost_usd - 0.10).abs() < f64::EPSILON);
        assert!(run.first_pass_success);
        assert!(run.validation_passed);
        assert_eq!(run.run_source, AssistantRunSource::LiveHarness);
        assert!(run.notes.is_none());
    }

    #[test]
    fn capture_session_finish_with_failure() {
        let config = CaptureConfig {
            assistant: "codex".to_string(),
            substrate: BenchmarkSubstrate::Git,
            task_name: "dead-code-detection".to_string(),
            model_name: None,
        };

        let session = CaptureSession::start(config);
        let run = session.finish(3000.0, 2000, 1000, 0.25, false);
        assert!(!run.first_pass_success);
        assert!(!run.validation_passed);
        assert_eq!(run.run_source, AssistantRunSource::LiveHarness);
        assert!(run.model_name.is_none());
        assert_eq!(run.substrate, BenchmarkSubstrate::Git);
    }

    #[test]
    fn build_run_from_flags_produces_correct_run() {
        let run = build_run_from_flags(
            "gemini",
            "impact-analysis",
            BenchmarkSubstrate::Kin,
            Some("pro"),
            2000.0,
            800,
            400,
            0.05,
            true,
        );

        assert_eq!(run.task_name, "impact-analysis");
        assert_eq!(run.assistant_name, "gemini");
        assert_eq!(run.model_name, Some("pro".to_string()));
        assert_eq!(run.substrate, BenchmarkSubstrate::Kin);
        assert!((run.duration_ms.0 - 2000.0).abs() < f64::EPSILON);
        assert_eq!(run.input_tokens, 800);
        assert_eq!(run.output_tokens, 400);
        assert_eq!(run.total_tokens, 1200);
        assert!((run.estimated_cost_usd - 0.05).abs() < f64::EPSILON);
        assert!(run.first_pass_success);
        assert!(run.validation_passed);
        assert_eq!(run.run_source, AssistantRunSource::ManualFlags);
        assert!(run
            .notes
            .as_ref()
            .unwrap()
            .contains("manual benchmark capture"));
    }

    #[test]
    fn build_run_from_flags_without_model() {
        let run = build_run_from_flags(
            "claude",
            "context-pack",
            BenchmarkSubstrate::Git,
            None,
            500.0,
            100,
            50,
            0.01,
            false,
        );

        assert!(run.model_name.is_none());
        assert!(!run.first_pass_success);
        assert_eq!(run.total_tokens, 150);
    }

    #[test]
    fn from_artifact_produces_run_with_notes() {
        let artifact = AssistantArtifact {
            vendor: "claude".to_string(),
            files_touched: vec!["src/main.rs".into(), "src/lib.rs".into()],
            lines_added: 25,
            lines_removed: 10,
            tool_calls: 5,
            iterations: 3,
            raw_duration_secs: Some(12.5),
        };

        let run = CaptureSession::from_artifact(&artifact, "review-task", BenchmarkSubstrate::Kin);
        assert_eq!(run.task_name, "review-task");
        assert_eq!(run.assistant_name, "claude");
        assert_eq!(run.substrate, BenchmarkSubstrate::Kin);
        assert_eq!(run.run_source, AssistantRunSource::ArtifactImport);
        assert!((run.duration_ms.0 - 12500.0).abs() < f64::EPSILON);
        assert!(run.notes.as_ref().unwrap().contains("files=2"));
        assert!(run.notes.as_ref().unwrap().contains("+25/-10"));
        assert!(run.notes.as_ref().unwrap().contains("tools=5"));
        assert!(run.notes.as_ref().unwrap().contains("iterations=3"));
    }

    #[test]
    fn session_serialization_roundtrip() {
        let session = CaptureSession::start(test_config());
        let json = serde_json::to_string(&session).unwrap();
        let deserialized: CaptureSession = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.config.assistant, "claude");
        assert_eq!(deserialized.config.task_name, "semantic-review");
    }
}
