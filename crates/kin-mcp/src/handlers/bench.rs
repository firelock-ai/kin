// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;

use kin_model::graph::GraphStore;

use crate::error::Result;
use crate::types::ToolCallResult;

pub const BENCHMARK_BOUNDARY_NOTICE: &str = "Kin's benchmark and proof-packaging harness is a \
private Firelock operator surface and is not distributed with the OSS Kin release.";

pub const BENCHMARK_DESC: &str = "\
Describe Kin's benchmark availability and evidence boundary. The benchmark and proof-packaging \
harness is a private Firelock operator surface and is not distributed with the OSS Kin release. \
This tool reports that boundary rather than private metrics or install instructions. Reach for \
it to distinguish separately published proof artifacts from unpublished internal measurements.";

pub fn handle_benchmark<G: GraphStore>(
    _args: &HashMap<String, serde_json::Value>,
    _store: &G,
) -> Result<ToolCallResult> {
    Ok(ToolCallResult::text(format!(
        "{BENCHMARK_BOUNDARY_NOTICE}\n\n\
         Authorized internal operators who already have the harness binaries installed can run \
         `kin bench <subcommand>`. This public tool provides no clone or install path. Treat only \
         separately published, versioned proof artifacts as independently reproducible evidence."
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::ContentBlock;
    use kin_db::InMemoryGraph;

    #[test]
    fn benchmark_tool_preserves_private_harness_boundary() {
        let result = handle_benchmark(&HashMap::new(), &InMemoryGraph::new()).unwrap();
        let ContentBlock::Text { text } = &result.content[0];

        for required in [
            BENCHMARK_BOUNDARY_NOTICE,
            "Authorized internal operators",
            "no clone or install path",
            "separately published, versioned proof artifacts",
        ] {
            assert!(text.contains(required), "missing boundary text: {required}");
        }
        for forbidden in ["github.com/", "cargo install", "cd "] {
            assert!(
                !text.contains(forbidden) && !BENCHMARK_DESC.contains(forbidden),
                "public benchmark surface exposes private install guidance: {forbidden}"
            );
        }
        assert!(BENCHMARK_DESC.contains("private Firelock operator surface"));
        assert!(BENCHMARK_DESC.contains("not distributed with the OSS Kin release"));
    }
}
