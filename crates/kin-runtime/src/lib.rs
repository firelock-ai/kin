// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Workspace runs, validation, and evidence capture for Kin.
//!
//! This crate provides the runtime layer for executing validation commands,
//! capturing evidence (stdout, stderr, test results), and managing workspace
//! snapshots for reproducibility.

pub mod error;
pub mod evidence;
pub mod exec;
pub mod replay;
pub mod run;
pub mod workspace;

pub use error::{Result, RuntimeError};
pub use evidence::{parse_test_output, store_evidence, CapturedEvidence};
pub use exec::{cleanup_workspace, exec_in_workspace, ExecContext, ExecResult, MaterializeConfig};
pub use replay::{extract_replay_metadata, ReplayMetadata};
pub use run::{create_run, execute_run, RunOptions, RunStatus, ValidationRun};
pub use workspace::{
    create_workspace, snapshot_workspace, MaterializeStrategy, MaterializedWorkspace, Workspace,
    WorkspaceSnapshot,
};
