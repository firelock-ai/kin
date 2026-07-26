// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Repository-v6 rename protocol boundary.
//!
//! The legacy planner read source from `.kin/objects` and the working
//! directory. Keep the wire contract available to daemon clients while the
//! graph/CAS planner is rebuilt, but never answer through that retired path.

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenameRequest {
    pub symbol: String,
    pub new_name: String,
    #[serde(default)]
    pub file: Option<String>,
    #[serde(default)]
    pub line: Option<u32>,
    #[serde(default)]
    pub column: Option<u32>,
    #[serde(default)]
    pub json: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenameResponse {
    #[serde(default)]
    pub lines: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json: Option<String>,
}

pub async fn run(
    _symbol: String,
    _new_name: String,
    _file: Option<String>,
    _line: Option<u32>,
    _column: Option<u32>,
    _json: bool,
) -> Result<()> {
    super::capabilities::require_ready("rename")
}

pub fn build_rename_response(
    _layout: &kin_core::KinLayout,
    _graph: &kin_db::InMemoryGraph,
    _request: &RenameRequest,
) -> Result<RenameResponse> {
    super::capabilities::require_ready("rename")?;
    unreachable!("ready rename capability must replace the fail-closed executor")
}
