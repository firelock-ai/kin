// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Persistence boundary for a store-backed spine.
//!
//! A [`SpineStore`] is the durable store behind [`crate::FirestoreSpineBackend`]:
//! it persists entity metadata and cross-repo edges and reloads them so a freshly
//! started backend can rebuild its in-memory cache. The store is the only seam
//! that talks to an external system, so the backend's hydrate and write-through
//! behavior can be exercised end-to-end against an in-memory fake with no live
//! service.

use crate::backend::SpineError;
use crate::index::{CrossRepoEdge, EntityEntry};

/// A repo's persisted entity set together with its graph root hash.
#[derive(Debug, Clone)]
pub struct LoadedRepo {
    pub repo_id: String,
    pub root_hash: String,
    pub entries: Vec<EntityEntry>,
}

/// Durable storage for spine metadata.
///
/// Implementations persist entities and cross-repo edges and reload them on
/// hydrate. Methods are synchronous to match the [`crate::SpineBackend`] call
/// sites; an implementation backed by a network service bridges async
/// internally.
pub trait SpineStore: Send + Sync {
    /// Load every persisted repo (entities grouped by repo, with root hash).
    fn load_repos(&self) -> Result<Vec<LoadedRepo>, SpineError>;

    /// Load every persisted cross-repo edge.
    fn load_edges(&self) -> Result<Vec<CrossRepoEdge>, SpineError>;

    /// Persist one entity belonging to `root_hash`'s repo, replacing any prior
    /// copy of the same entity.
    fn write_entity(&self, entry: &EntityEntry, root_hash: &str) -> Result<(), SpineError>;

    /// Remove every persisted entity for `repo_id`.
    fn delete_repo_entities(&self, repo_id: &str) -> Result<(), SpineError>;

    /// Persist one cross-repo edge.
    fn write_edge(&self, edge: &CrossRepoEdge) -> Result<(), SpineError>;

    /// Remove every persisted edge whose source repo is `repo_id`.
    fn delete_repo_edges(&self, repo_id: &str) -> Result<(), SpineError>;
}
