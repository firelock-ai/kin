//! Cross-language contract linking for Kin.
//!
//! This crate handles contract discovery from schema files (OpenAPI, Protobuf,
//! GraphQL, DB schemas, event schemas) and links producers/consumers across
//! language boundaries.

pub mod discovery;
pub mod error;
pub mod linking;

pub use discovery::{detect_contract, DiscoveredContract};
pub use error::{ContractError, Result};
pub use linking::{link_contract, propagate_contract_impact, LinkResult};
