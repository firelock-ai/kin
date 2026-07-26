// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Graph-backed session execution, validation, and evidence capture for Kin.
//!
//! This crate provides the runtime layer for executing validation commands,
//! capturing evidence (stdout, stderr, test results), and materializing
//! graph-owned repository state for isolated command execution.

pub mod error;
pub mod evidence;
pub mod exec;
pub mod replay;
pub mod run;
pub mod workspace;

pub use error::{Result, RuntimeError};
pub use evidence::{parse_test_output, store_evidence, CapturedEvidence};
pub use exec::{ExecContext, ExecResult};
pub use replay::{extract_replay_metadata, ReplayMetadata};
pub use run::{create_run, execute_run, RunOptions, RunStatus, ValidationRun};
pub use workspace::{MaterializeStrategy, MaterializedWorkspace};
