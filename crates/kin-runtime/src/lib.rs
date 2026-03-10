//! Workspace runs, validation, and evidence capture for Kin.
//!
//! This crate provides the runtime layer for executing validation commands,
//! capturing evidence (stdout, stderr, test results), and managing workspace
//! snapshots for reproducibility.

pub mod error;
pub mod evidence;
pub mod replay;
pub mod run;
pub mod workspace;

pub use error::{RuntimeError, Result};
pub use evidence::{CapturedEvidence, parse_test_output, store_evidence};
pub use replay::{ReplayMetadata, extract_replay_metadata};
pub use run::{RunOptions, RunStatus, ValidationRun, create_run, execute_run};
pub use workspace::{Workspace, WorkspaceSnapshot, create_workspace, snapshot_workspace};
