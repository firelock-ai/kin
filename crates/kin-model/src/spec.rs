// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use serde::{Deserialize, Serialize};

use crate::ids::*;

/// Planning primitive -- captures intent, scope, and acceptance criteria.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Spec {
    pub id: SpecId,
    pub intent: String,
    pub scope: Vec<String>,
    pub constraints: Vec<String>,
    pub acceptance_criteria: Vec<String>,
    pub affected_systems: Vec<String>,
    pub validation_requirements: Vec<String>,
}
