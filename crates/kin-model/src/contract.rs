// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use serde::{Deserialize, Serialize};

use crate::ids::*;

/// Cross-language linking primitive.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Contract {
    pub id: EntityId,
    pub kind: ContractKind,
    pub name: String,
    pub schema_hash: Hash256,
    pub producers: Vec<EntityId>,
    pub consumers: Vec<EntityId>,
    pub version: Option<String>,
}

/// Classification of a contract type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ContractKind {
    OpenApi,
    Protobuf,
    GraphQL,
    DbSchema,
    EventSchema,
    TypedInterface,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_kind_roundtrip() {
        let kind = ContractKind::OpenApi;
        let json = serde_json::to_string(&kind).unwrap();
        let parsed: ContractKind = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, kind);
    }
}
