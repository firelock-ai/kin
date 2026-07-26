// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Fail-closed repository-v6 session-workspace protocol.

use std::path::Path;

use anyhow::{bail, Result};
use kin_runtime::workspace::{MaterializeStrategy, MaterializedWorkspace};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionWorkspaceRequest {
    pub session_dir: String,
    #[serde(default)]
    pub strategy: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionWorkspaceResponse {
    pub root: String,
    pub strategy: String,
    pub source_kind: String,
}

pub fn create_session_workspace_from_graph(
    _layout: &kin_core::KinLayout,
    _graph: &kin_db::InMemoryGraph,
    _session_dir: &Path,
    _strategy: Option<MaterializeStrategy>,
    _scope: Option<&str>,
) -> Result<MaterializedWorkspace> {
    fail_closed()
}

pub fn materialize_session_workspace(
    _layout: &kin_core::KinLayout,
    _graph: &kin_db::InMemoryGraph,
    _request: &SessionWorkspaceRequest,
) -> Result<SessionWorkspaceResponse> {
    fail_closed()
}

fn fail_closed<T>() -> Result<T> {
    bail!(
        "session workspaces are fail-closed until repository-v6 materialization reads exact \
         workspace trees and source bodies from repository authority; no filesystem fallback is \
         permitted"
    )
}
