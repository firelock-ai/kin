// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Fail-closed repository-v6 reconcile protocol.

use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconcileSummary {
    pub changes: Vec<(String, String)>,
    pub change_count: usize,
    pub files_indexed: usize,
    pub total_upserted: usize,
    pub total_removed: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconcileRequest {
    pub session_dir: PathBuf,
}

pub async fn run(_session_id: Option<String>, _cleanup: bool) -> Result<()> {
    crate::commands::capabilities::require_ready("reconcile")
}

pub async fn reconcile_session_dir(
    _layout: &kin_core::KinLayout,
    _session_dir: &Path,
) -> Result<ReconcileSummary> {
    fail_closed()
}

pub fn execute_reconcile_session_dir(
    _layout: &kin_core::KinLayout,
    _graph: &kin_db::InMemoryGraph,
    _session_dir: &Path,
) -> Result<ReconcileSummary> {
    fail_closed()
}

pub fn execute_reconcile_session_dir_scoped(
    _layout: &kin_core::KinLayout,
    _graph: &kin_db::InMemoryGraph,
    _session_dir: &Path,
) -> Result<ReconcileSummary> {
    fail_closed()
}

pub fn execute_reconcile_session_dir_with_persist<F>(
    _layout: &kin_core::KinLayout,
    _graph: &kin_db::InMemoryGraph,
    _session_dir: &Path,
    _persist: F,
) -> Result<ReconcileSummary>
where
    F: FnOnce() -> Result<()>,
{
    fail_closed()
}

fn fail_closed<T>() -> Result<T> {
    bail!(
        "reconcile is fail-closed until explicit projection observations are admitted through one \
         repository-v6 workspace transaction; inspect `kin capabilities --json`"
    )
}
