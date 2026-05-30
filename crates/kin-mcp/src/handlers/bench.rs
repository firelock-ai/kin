// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;

use kin_model::graph::GraphStore;

use crate::error::Result;
use crate::types::ToolCallResult;

pub const BENCHMARK_DESC: &str = "\
Report on Kin's benchmark results and metrics. The benchmark engine now lives in the \
standalone `kin-bench` binary, so this tool returns pointers on how to install and run \
it (e.g. `kin bench <subcommand>`) rather than computing metrics in-process. Reach for \
it when you want to know where Kin's velocity/reliability/economic measurements come \
from or how to reproduce them.";

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
