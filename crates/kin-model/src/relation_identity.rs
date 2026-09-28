// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The identity of an edge a language server proved between two repository
//! entities.
//!
//! An edge's id is what the graph keys it by, so a second proof of the same
//! edge merges into the first instead of landing beside it. The id has to be
//! the same in every process and under every toolchain that builds Kin, or an
//! upgrade gives every edge a new id and leaves the old one behind as a
//! duplicate. It used to come from the standard library's default hasher,
//! whose algorithm is not guaranteed across Rust releases. It is now SHA-256
//! over a fixed byte string that this module spells out field by field.
//!
//! An edge into a symbol outside the repository is keyed by
//! [`crate::RelationId::resolver`] instead. The two schemes use different
//! domains, and the parser's edges use a third, so no two of them can name
//! the same edge.

use crate::{EntityId, RelationId, RelationKind, RelationOrigin};
use sha2::{Digest, Sha256};

/// Domain of [`language_server_relation_id`], version 1. A later scheme takes
/// a new version, so its ids can never equal these.
const LANGUAGE_SERVER_RELATION_ID_DOMAIN_V1: &[u8] = b"kin.relation.language_server.v1\0";

/// The spelling of an entity end, the only kind of node this scheme names.
const ENTITY_NODE: &str = "entity";

/// The id of the `kind` edge a language server proved from `src` to `dst`,
/// both entities in the repository.
///
/// SHA-256 over [`preimage`], truncated to a UUID-v8. Every field of the
/// preimage is written with its length in front, so no two different edges
/// share one.
pub fn language_server_relation_id(kind: RelationKind, src: EntityId, dst: EntityId) -> RelationId {
    let digest = Sha256::digest(preimage(RelationOrigin::Lsp, kind, src, dst));
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    RelationId::from_bytes(bytes)
}

/// The bytes an edge's id is the digest of: the domain, then six fields, each
/// as a little-endian `u64` length and then its bytes.
///
/// 1. the origin's name (`Lsp`);
/// 2. the kind's name (`Calls`);
/// 3. the source's kind of node (`entity`);
/// 4. the source's id, as its 16 UUID bytes;
/// 5. the destination's kind of node;
/// 6. the destination's id.
///
/// Every field that tells one edge from another is here. An edge's evidence
/// and confidence change as it is proven again, so they are not.
fn preimage(origin: RelationOrigin, kind: RelationKind, src: EntityId, dst: EntityId) -> Vec<u8> {
    let fields: [&[u8]; 6] = [
        origin_name(origin).as_bytes(),
        kind_name(kind).as_bytes(),
        ENTITY_NODE.as_bytes(),
        src.0.as_bytes(),
        ENTITY_NODE.as_bytes(),
        dst.0.as_bytes(),
    ];
    let mut bytes = LANGUAGE_SERVER_RELATION_ID_DOMAIN_V1.to_vec();
    for field in fields {
        bytes.extend_from_slice(&(field.len() as u64).to_le_bytes());
        bytes.extend_from_slice(field);
    }
    bytes
}

/// The origin's name, as it is serialized. Spelled out here so no formatter
/// decides the bytes an id is made of.
fn origin_name(origin: RelationOrigin) -> &'static str {
    match origin {
        RelationOrigin::Parsed => "Parsed",
        RelationOrigin::Inferred => "Inferred",
        RelationOrigin::Manual => "Manual",
        RelationOrigin::Lsp => "Lsp",
    }
}

/// The kind's name, as it is serialized. Spelled out for the same reason as
/// [`origin_name`]; a new kind cannot compile until it is given one.
fn kind_name(kind: RelationKind) -> &'static str {
    match kind {
        RelationKind::Contains => "Contains",
        RelationKind::Extends => "Extends",
        RelationKind::Implements => "Implements",
        RelationKind::Overrides => "Overrides",
        RelationKind::Calls => "Calls",
        RelationKind::Instantiates => "Instantiates",
        RelationKind::References => "References",
        RelationKind::UsesMacro => "UsesMacro",
        RelationKind::UsesType => "UsesType",
        RelationKind::Imports => "Imports",
        RelationKind::Includes => "Includes",
        RelationKind::DependsOn => "DependsOn",
        RelationKind::EmitsEvent => "EmitsEvent",
        RelationKind::SubscribesTo => "SubscribesTo",
        RelationKind::DefinesContract => "DefinesContract",
        RelationKind::ConsumesContract => "ConsumesContract",
        RelationKind::SendsMessage => "SendsMessage",
        RelationKind::Spawns => "Spawns",
        RelationKind::Tests => "Tests",
        RelationKind::Covers => "Covers",
        RelationKind::CoChanges => "CoChanges",
        RelationKind::DerivedFrom => "DerivedFrom",
        RelationKind::DocumentedBy => "DocumentedBy",
        RelationKind::OwnedBy => "OwnedBy",
        RelationKind::OwnedByFile => "OwnedByFile",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GraphNodeId;

    const ALL_KINDS: [RelationKind; 25] = [
        RelationKind::Contains,
        RelationKind::Extends,
        RelationKind::Implements,
        RelationKind::Overrides,
        RelationKind::Calls,
        RelationKind::Instantiates,
        RelationKind::References,
        RelationKind::UsesMacro,
        RelationKind::UsesType,
        RelationKind::Imports,
        RelationKind::Includes,
        RelationKind::DependsOn,
        RelationKind::EmitsEvent,
        RelationKind::SubscribesTo,
        RelationKind::DefinesContract,
        RelationKind::ConsumesContract,
        RelationKind::SendsMessage,
        RelationKind::Spawns,
        RelationKind::Tests,
        RelationKind::Covers,
        RelationKind::CoChanges,
        RelationKind::DerivedFrom,
        RelationKind::DocumentedBy,
        RelationKind::OwnedBy,
        RelationKind::OwnedByFile,
    ];

    fn entity(uuid: &str) -> EntityId {
        serde_json::from_value(serde_json::Value::from(uuid)).unwrap()
    }

    /// The ids of fixed edges, written out. The digest is over bytes this
    /// module spells, so every process and every toolchain that builds Kin
    /// derives exactly these, and a change to the scheme fails here before it
    /// can give a store's edges new ids.
    #[test]
    fn language_server_relation_ids_are_pinned() {
        let a = entity("01234567-89ab-cdef-0123-456789abcdef");
        let b = entity("fedcba98-7654-3210-fedc-ba9876543210");
        let one = entity("00000000-0000-0000-0000-000000000001");
        let two = entity("00000000-0000-0000-0000-000000000002");
        let golden = [
            (
                RelationKind::Calls,
                a,
                b,
                "632f0c30-6713-8f4a-a1ac-755831bbf5ea",
            ),
            (
                RelationKind::Calls,
                b,
                a,
                "cbda2865-50c5-8753-b698-6454944a37bc",
            ),
            (
                RelationKind::References,
                a,
                b,
                "3d252bb5-1b08-86b9-8e28-1e6b9a665b87",
            ),
            (
                RelationKind::UsesType,
                a,
                b,
                "7090f503-c29b-896f-a3c5-a365011058ea",
            ),
            (
                RelationKind::Overrides,
                a,
                b,
                "6199ee67-c4ab-82b4-8fe2-0f169f2a251a",
            ),
            (
                RelationKind::Calls,
                one,
                two,
                "621bd95f-076d-8dfb-9d35-8c592539123d",
            ),
        ];
        for (kind, src, dst, expected) in golden {
            let id = language_server_relation_id(kind, src, dst);
            assert_eq!(id.to_string(), expected, "{kind:?} {src} -> {dst}");
            assert_eq!(id.0.get_version_num(), 8);
        }
    }

    /// The preimage, byte for byte: the versioned domain, then each field
    /// behind its own length. A field cannot run into the next, and a name
    /// cannot be read as part of an id.
    #[test]
    fn every_field_stands_behind_its_own_length() {
        let src = entity("00000000-0000-0000-0000-000000000001");
        let dst = entity("00000000-0000-0000-0000-000000000002");
        let mut expected = b"kin.relation.language_server.v1\0".to_vec();
        for field in [
            b"Lsp".as_slice(),
            b"References",
            b"entity",
            src.0.as_bytes(),
            b"entity",
            dst.0.as_bytes(),
        ] {
            expected.extend_from_slice(&(field.len() as u64).to_le_bytes());
            expected.extend_from_slice(field);
        }
        assert_eq!(
            preimage(RelationOrigin::Lsp, RelationKind::References, src, dst),
            expected
        );
    }

    /// Kind, direction and origin each change the id, and so does the
    /// domain: an external-symbol edge keyed by the resolver over the same
    /// ends is a different edge.
    #[test]
    fn every_identity_field_and_the_domain_separate_edges() {
        let src = entity("00000000-0000-0000-0000-000000000001");
        let dst = entity("00000000-0000-0000-0000-000000000002");
        let calls = language_server_relation_id(RelationKind::Calls, src, dst);
        let mut seen = std::collections::HashSet::new();
        for kind in ALL_KINDS {
            assert!(
                seen.insert(language_server_relation_id(kind, src, dst)),
                "{kind:?} shares an id with another kind"
            );
        }
        assert_ne!(
            language_server_relation_id(RelationKind::Calls, dst, src),
            calls,
            "direction is part of the identity"
        );
        assert_ne!(
            preimage(RelationOrigin::Parsed, RelationKind::Calls, src, dst),
            preimage(RelationOrigin::Lsp, RelationKind::Calls, src, dst),
            "origin is part of the identity"
        );
        assert_ne!(
            RelationId::resolver(
                RelationKind::Calls,
                &GraphNodeId::Entity(src),
                &GraphNodeId::Entity(dst)
            ),
            calls,
            "the resolver's domain names other edges"
        );
    }

    /// The names spelled here are the names every kind and origin is
    /// serialized under, so the preimage says what a stored edge says.
    #[test]
    fn spelled_names_are_the_serialized_names() {
        for kind in ALL_KINDS {
            assert_eq!(
                serde_json::to_value(kind).unwrap(),
                serde_json::Value::from(kind_name(kind))
            );
        }
        for origin in [
            RelationOrigin::Parsed,
            RelationOrigin::Inferred,
            RelationOrigin::Manual,
            RelationOrigin::Lsp,
        ] {
            assert_eq!(
                serde_json::to_value(origin).unwrap(),
                serde_json::Value::from(origin_name(origin))
            );
        }
    }
}
