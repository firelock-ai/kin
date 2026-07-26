// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;

/// Historical views already carry graph-owned, temporally filtered CoChanges
/// relations. Until the shared repository-v6 enrichment pass owns recomputing
/// them, retain those relations instead of replacing them from Git or files.
pub fn refresh_from_changes(
    _graph: &kin_db::InMemoryGraph,
    _changes: &[kin_model::SemanticChange],
) -> Result<usize> {
    Ok(0)
}
