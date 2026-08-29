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
pub mod firestore;
pub mod index;
pub mod publication;
pub mod query;
pub mod routing;
pub mod store;

/// In-memory durable spine store for this crate's tests and for consumers that
/// enable `test-support`. Not part of the product surface.
#[cfg(any(test, feature = "test-support"))]
pub mod test_support;
pub mod xref;

/// Wire-format version of the spine HTTP payloads (`/spine/impact`, `/spine/xref`).
/// Stamped on every response so consumers (CLI, MCP, KinLab control-plane) can
/// detect payload-shape changes and adapt. Bump on any breaking field change.
pub const SPINE_PAYLOAD_VERSION: u32 = 1;

pub use backend::{
    InMemorySpineBackend, PreparedRepoSpinePublication, SpineBackend, SpineError,
    SpinePublicationBackendId,
};
pub use federation::{federated_impact, FederatedEdge, FederatedImpact, FederatedNode};
pub use firestore::FirestoreSpineBackend;
#[cfg(feature = "firestore")]
pub use firestore::FirestoreStore;
pub use index::{
    AuthorityRootState, CrossRepoEdge, CrossRepoEdgesSnapshot, EntityEntry, SpineIndex,
    SpineXrefAuthorityAnchor, SpineXrefDecodeError, SpineXrefResponse,
};
pub use publication::{
    LegacySpineWriterDrainAttestation, RepoPublicationCommit, RepoPublicationConflict,
    RepoPublicationHead, RepoPublicationPhase, RepoSpinePublication, SpineRolloutFence,
    SpineRolloutFenceCommit, SpineRolloutFenceEvidence, SpineRolloutRepositoryFence,
    SpineSourceCursor, LEGACY_SPINE_WRITER_DRAIN_SCHEMA, REPO_PUBLICATION_SCHEMA_VERSION,
    SPINE_ROLLOUT_FENCE_SCHEMA,
};
pub use query::{classify_spine_probe, SpineProbe, SpineQuery};
pub use routing::{RepoEndpoint, RoutingTable};
pub use store::{
    LoadedRepo, LoadedRepoPublication, LoadedSpineRolloutFence, PreparedStorePublication,
    RepoPublicationCleanupProgress, SpineStore, StoreHeadPrecondition, StorePublicationStageGuard,
    StoreRepoHeadGuard,
};
pub use xref::{
    collect_unresolved_imports, materialize_edges, resolve_imports, ResolveResult, UnresolvedImport,
};
