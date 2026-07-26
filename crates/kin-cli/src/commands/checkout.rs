// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Fail-closed repository-v6 checkout protocol.

use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckoutRequest {
    pub path: String,
    #[serde(default)]
    pub change_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckoutResponse {
    #[serde(default)]
    pub lines: Vec<String>,
    #[serde(default)]
    pub mutated: bool,
}

pub fn execute_checkout_request(
    _layout: &kin_core::KinLayout,
    _graph: &kin_db::InMemoryGraph,
    _request: &CheckoutRequest,
) -> Result<CheckoutResponse> {
    bail!(
        "checkout is fail-closed until repository-v6 exact tree projection reads source bodies \
         from repository CAS; inspect `kin capabilities --json`"
    )
}
