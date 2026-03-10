use kin_blobs::BlobStore;
use kin_model::{Evidence, EvidenceId, EntityId, TestResult};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::error::{RuntimeError, Result};
use crate::run::ValidationRun;

/// Raw captured evidence from a validation run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedEvidence {
    /// Standard output (if any).
    pub stdout: Option<String>,
    /// Standard error (if any).
    pub stderr: Option<String>,
    /// Parsed test results (if applicable).
    pub test_results: Vec<TestResult>,
}

/// Store captured evidence in the blob store and return an Evidence model.
///
/// The stdout and stderr are stored as separate blobs. The Evidence record
/// references them by content for later retrieval.
pub fn store_evidence(
    captured: &CapturedEvidence,
    run: &ValidationRun,
    blob_store: &BlobStore,
    touched_entities: Vec<EntityId>,
) -> Result<Evidence> {
    let mut stdout_stored = None;
    let mut stderr_stored = None;

    if let Some(ref out) = captured.stdout {
        blob_store
            .write(out.as_bytes())
            .map_err(|e| RuntimeError::Blob(e.to_string()))?;
        stdout_stored = Some(out.clone());
    }

    if let Some(ref err) = captured.stderr {
        blob_store
            .write(err.as_bytes())
            .map_err(|e| RuntimeError::Blob(e.to_string()))?;
        stderr_stored = Some(err.clone());
    }

    let evidence = Evidence {
        id: EvidenceId::new(),
        assistant_identity: None,
        prompt_provenance: None,
        tool_calls: vec![run.command.clone()],
        touched_entities,
        validation_commands: vec![run.command.clone()],
        stdout: stdout_stored,
        stderr: stderr_stored,
        test_results: captured.test_results.clone(),
        replay_metadata: Some(serde_json::json!({
            "run_id": run.id,
            "label": run.label,
            "exit_code": run.exit_code,
            "duration_ms": run.duration_ms,
            "snapshot_id": run.snapshot_id,
        })),
        workspace_snapshot_id: run.snapshot_id.clone(),
    };

    info!(
        evidence_id = %evidence.id,
        run_id = %run.id,
        "stored evidence"
    );

    Ok(evidence)
}

/// Parse test output into structured TestResult entries.
///
/// This is a best-effort parser that recognizes common test output patterns.
/// Currently supports "test <name> ... ok/FAILED" format (Rust cargo test).
pub fn parse_test_output(output: &str) -> Vec<TestResult> {
    let mut results = Vec::new();

    for line in output.lines() {
        let trimmed = line.trim();

        // Rust cargo test format: "test <name> ... ok" or "test <name> ... FAILED"
        if trimmed.starts_with("test ") && trimmed.contains(" ... ") {
            if let Some(rest) = trimmed.strip_prefix("test ") {
                if let Some(idx) = rest.rfind(" ... ") {
                    let name = rest[..idx].trim().to_string();
                    let status = rest[idx + 5..].trim();
                    let passed = status == "ok";
                    results.push(TestResult {
                        name,
                        passed,
                        duration_ms: None,
                        output: None,
                    });
                }
            }
        }
    }

    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rust_test_output() {
        let output = r#"
running 3 tests
test tests::it_works ... ok
test tests::another ... ok
test tests::failing_test ... FAILED
"#;
        let results = parse_test_output(output);
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].name, "tests::it_works");
        assert!(results[0].passed);
        assert_eq!(results[1].name, "tests::another");
        assert!(results[1].passed);
        assert_eq!(results[2].name, "tests::failing_test");
        assert!(!results[2].passed);
    }

    #[test]
    fn parse_empty_output() {
        let results = parse_test_output("");
        assert!(results.is_empty());
    }

    #[test]
    fn parse_non_test_output() {
        let output = "Compiling kin-runtime v0.1.0\nFinished test\n";
        let results = parse_test_output(output);
        assert!(results.is_empty());
    }

    #[test]
    fn store_evidence_creates_model() {
        let dir = tempfile::tempdir().unwrap();
        let blob_store = BlobStore::new(dir.path().join("objects")).unwrap();

        let captured = CapturedEvidence {
            stdout: Some("hello world\n".into()),
            stderr: None,
            test_results: vec![],
        };

        let run = crate::run::create_run(crate::run::RunOptions {
            label: "test".into(),
            command: "echo hello".into(),
            working_dir: "/tmp".into(),
            snapshot_id: Some("snap-123".into()),
        });

        let evidence = store_evidence(&captured, &run, &blob_store, vec![]).unwrap();
        assert!(evidence.stdout.is_some());
        assert!(evidence.stderr.is_none());
        assert_eq!(evidence.validation_commands, vec!["echo hello"]);
        assert_eq!(evidence.workspace_snapshot_id, Some("snap-123".into()));
    }

    #[test]
    fn captured_evidence_serializes() {
        let ev = CapturedEvidence {
            stdout: Some("ok".into()),
            stderr: Some("warn".into()),
            test_results: vec![TestResult {
                name: "test_foo".into(),
                passed: true,
                duration_ms: Some(42),
                output: None,
            }],
        };
        let json = serde_json::to_string(&ev).unwrap();
        let parsed: CapturedEvidence = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.test_results.len(), 1);
        assert!(parsed.test_results[0].passed);
    }
}
