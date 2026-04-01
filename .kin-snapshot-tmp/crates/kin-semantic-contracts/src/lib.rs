// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Cross-language contract linking for Kin.
//!
//! This crate handles contract discovery from schema files (OpenAPI, Protobuf,
//! GraphQL, DB schemas, event schemas) and links producers/consumers across
//! language boundaries.

pub mod discovery;
pub mod error;
pub mod linking;
pub mod validation;

pub use discovery::{detect_contract, detect_version_bump, DiscoveredContract, SemverBump};
pub use error::{ContractError, Result};
pub use linking::{link_contract, propagate_contract_impact, LinkResult};
pub use validation::{detect_breaking_changes, BreakageKind, ContractBreakage};
