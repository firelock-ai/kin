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

/// What a caller can reach today, named at the point the gate refuses.
///
/// The gate text states the two acceptance conditions, which says what Kin
/// cannot do without saying what it can. Every reference a rename would have to
/// touch is already a graph answer, so the refusal points at it.
pub fn available_today(symbol: &str) -> Vec<String> {
    vec![
        format!("`kin refs {symbol}` lists every reference the graph holds for this symbol."),
        format!("`kin locate {symbol}` finds the declaration to edit."),
        "Editing and committing by hand keeps graph truth exact; the gate is the planner and the \
         single-transaction apply, not the rename itself."
            .to_string(),
    ]
}

pub async fn run(
    symbol: String,
    _new_name: String,
    _file: Option<String>,
    _line: Option<u32>,
    _column: Option<u32>,
    _json: bool,
) -> Result<()> {
    let refusal = match super::capabilities::require_ready("rename") {
        Ok(()) => unreachable!("a ready rename capability must replace the fail-closed executor"),
        Err(refusal) => refusal,
    };
    let mut message = refusal.to_string();
    message.push_str("\nwhat works today:");
    for line in available_today(&symbol) {
        message.push_str("\n  - ");
        message.push_str(&line);
    }
    Err(anyhow::anyhow!(message))
}

pub fn build_rename_response(
    _layout: &kin_core::KinLayout,
    _graph: &kin_db::InMemoryGraph,
    _request: &RenameRequest,
) -> Result<RenameResponse> {
    super::capabilities::require_ready("rename")?;
    unreachable!("ready rename capability must replace the fail-closed executor")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A gate that only states what is missing leaves a first-time caller with
    /// nowhere to go. The refusal has to name a command that works now.
    #[test]
    fn refusal_guidance_names_the_reachable_surfaces() {
        let lines = available_today("parse_config").join("\n");
        assert!(
            lines.contains("kin refs parse_config"),
            "guidance must name the reference surface for the symbol asked about: {lines}"
        );
        assert!(
            lines.contains("kin locate parse_config"),
            "guidance must name the declaration surface: {lines}"
        );
    }

    /// The executor stays fail-closed; guidance must not read as a partial
    /// rename having happened.
    #[test]
    fn build_rename_response_stays_fail_closed() {
        assert!(super::super::capabilities::require_ready("rename").is_err());
    }
}
