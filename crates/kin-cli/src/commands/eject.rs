// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Eject remains an explicit repository-v6 acceptance gate.

use anyhow::Result;

pub async fn run(_yes: bool, _purge_metadata: bool) -> Result<()> {
    crate::commands::capabilities::require_ready("eject")
}
