// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Repository-v6 branch protocol boundary.
//!
//! Ref mutations are deliberately unavailable until the daemon commits them
//! through repository transactions. No legacy graph-branch compatibility is
//! retained.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum BranchRequest {
    List,
    Create { name: String },
    Delete { name: String },
    Switch { name: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BranchResponse {
    #[serde(default)]
    pub lines: Vec<String>,
    #[serde(default)]
    pub mutated: bool,
}

pub fn execute_branch_request(
    _layout: &kin_core::KinLayout,
    _graph: &kin_db::InMemoryGraph,
    request: &BranchRequest,
) -> Result<BranchResponse> {
    let command = match request {
        BranchRequest::List => "branch list",
        BranchRequest::Create { .. } => "branch create",
        BranchRequest::Delete { .. } => "branch delete",
        BranchRequest::Switch { .. } => "branch switch",
    };
    bail!(
        "`kin {command}` is fail-closed: repository-v6 ref/workspace transactions have not \
         replaced the removed legacy branch store; inspect `kin capabilities --json`"
    )
}
