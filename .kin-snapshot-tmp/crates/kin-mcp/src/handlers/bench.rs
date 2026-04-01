// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;

use kin_model::graph::GraphStore;

use crate::error::Result;
use crate::types::ToolCallResult;

pub fn handle_benchmark<G: GraphStore>(
    _args: &HashMap<String, serde_json::Value>,
    _store: &G,
) -> Result<ToolCallResult> {
    Ok(ToolCallResult::text(
        "The benchmark engine has moved to the standalone `kin-bench` binary.\n\n\
         Install it with:\n  \
         cargo install --git https://github.com/firelock-ai/kin-bench kin-bench-cli\n\n\
         Then run: kin bench <subcommand>",
    ))
}
