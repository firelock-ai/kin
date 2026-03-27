// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Kin Spine — federation layer for cross-repo intelligence.
//!
//! The spine is a metadata index that knows where every entity lives
//! across all repos. It resolves cross-repo queries by routing hops
//! to the correct daemon, caches entity metadata, and provides
//! federated BFS for cross-repo impact analysis.
//!
//! DNS model: each repo is authoritative for its zone.
//! The spine is a recursive resolver that caches and federates.

pub mod backend;
pub mod federation;
#[cfg(feature = "firestore")]
pub mod firestore;
pub mod index;
pub mod routing;
pub mod xref;

pub use backend::{InMemorySpineBackend, SpineBackend, SpineError};
pub use federation::{federated_impact, FederatedEdge, FederatedImpact, FederatedNode};
#[cfg(feature = "firestore")]
pub use firestore::FirestoreSpineBackend;
pub use index::{CrossRepoEdge, EntityEntry, SpineIndex};
pub use routing::{RepoEndpoint, RoutingTable};
pub use xref::{
    collect_unresolved_imports, materialize_edges, resolve_imports, ResolveResult, UnresolvedImport,
};
