// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Language-server queries use a captured entity/tree universe. Network work
//! holds no edit lock; buffered answers regain that lock and prove freshness
//! before reading held evidence or changing the graph.

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use kin_model::{
    Entity, EntityStore, FilePathId, GraphNodeId, Relation, RepoPath, ResolvedTree, TreeEntry,
};

use super::{DaemonState, EnrichmentWrite, PendingEnrichment};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refused {
    Stale,
    UnprovenSource,
}

pub(crate) struct QueryInputs {
    pub(crate) entities: Vec<Entity>,
    tree: ResolvedTree,
    ids: HashSet<kin_model::EntityId>,
    pub(crate) marker_epoch: u64,
    source: crate::state::GraphOwnedSourceView,
    epoch: AtomicU64,
    source_failed: AtomicBool,
}

impl QueryInputs {
    pub(crate) async fn capture(state: &DaemonState) -> Result<Self, Refused> {
        let _coordinated = state.coordination_gate.lock().await;
        let epoch = state.stable_graph_authority_epoch().ok_or(Refused::Stale)?;
        let tree = state.graph.resolved_tree();
        let entities = state
            .graph
            .list_all_entities()
            .map_err(|_| Refused::UnprovenSource)?;
        // A retained last-known-good declaration must not lend its old span to
        // newly admitted, unparsed bytes. Check the whole matching universe:
        // an empty answer depends on absent targets too, not just offered edges.
        for entity in &entities {
            let (Some(file), Some(span)) = (&entity.file_origin, &entity.span) else {
                continue;
            };
            let path = RepoPath::from_utf8(file.0.clone()).map_err(|_| Refused::UnprovenSource)?;
            let Some(artifact) = tree.artifact_at_path(&path) else {
                return Err(Refused::UnprovenSource);
            };
            let TreeEntry::Blob { hash, .. } = &artifact.entry else {
                return Err(Refused::UnprovenSource);
            };
            if span.file != *file
                || span.start_byte > span.end_byte
                || entity
                    .metadata
                    .extra
                    .get("blob_hash")
                    .and_then(|v| v.as_str())
                    != Some(hash.to_string().as_str())
            {
                return Err(Refused::UnprovenSource);
            }
        }
        let source = state
            .graph_owned_source_view()
            .map_err(|_| Refused::UnprovenSource)?;
        if !state.graph_authority_epoch_is_current(epoch) {
            return Err(Refused::Stale);
        }
        Ok(Self {
            ids: entities.iter().map(|e| e.id).collect(),
            marker_epoch: super::current_marker_epoch(state),
            entities,
            tree,
            source,
            epoch: AtomicU64::new(epoch),
            source_failed: AtomicBool::new(false),
        })
    }

    /// The blob this pass's captured tree holds at `path`, which is what an
    /// owed file's backoff is keyed to.
    pub(crate) fn blob(&self, path: &str) -> Option<String> {
        let path_id = RepoPath::from_utf8(path.to_string()).ok()?;
        match &self.tree.artifact_at_path(&path_id)?.entry {
            TreeEntry::Blob { hash, .. } => Some(hash.to_string()),
            _ => None,
        }
    }

    pub(crate) fn document(&self, path: &str) -> Option<String> {
        // A server may mention external library files. Those have no authority
        // here and are not opened; an admitted source whose CAS read fails is
        // a different outcome and disqualifies this query's completion.
        let path_id = RepoPath::from_utf8(path.to_string()).ok()?;
        self.tree.artifact_at_path(&path_id)?;
        match self
            .source
            .load_text_from_tree(&FilePathId::new(path), &self.tree)
        {
            Ok(text) => Some(text),
            Err(_) => {
                self.source_failed.store(true, Ordering::SeqCst);
                None
            }
        }
    }

    fn validate(&self, state: &DaemonState) -> Result<(), Refused> {
        if !state.graph_authority_epoch_is_current(self.epoch.load(Ordering::SeqCst)) {
            return Err(Refused::Stale);
        }
        if self.source_failed.load(Ordering::SeqCst) {
            return Err(Refused::UnprovenSource);
        }
        Ok(())
    }

    pub(crate) async fn current(&self, state: &DaemonState) -> Result<(), Refused> {
        let _coordinated = state.coordination_gate.lock().await;
        self.validate(state)
    }

    pub(crate) async fn mark_completed(
        &self,
        state: &DaemonState,
        files: &[String],
        relations: EnrichmentWrite,
        published: bool,
    ) -> Result<bool, Refused> {
        let _coordinated = state.coordination_gate.lock().await;
        self.validate(state)?;
        // The marker is a semantic claim too. Keep this final validation and
        // insertion together, including the zero-relation negative case.
        Ok(super::mark_completed_sweep_files(
            state,
            files,
            self.marker_epoch,
            relations,
            published,
        ))
    }

    pub(crate) async fn absorb(
        &self,
        state: &DaemonState,
        pending: &mut PendingEnrichment,
        derived: Vec<Relation>,
    ) -> Result<EnrichmentWrite, Refused> {
        let _coordinated = state.coordination_gate.lock().await;
        self.validate(state)?;
        // The LSP matching index offers local entity endpoints only. An
        // unknown endpoint must not exploit the graph's permissive upsert.
        for relation in &derived {
            for node in [&relation.src, &relation.dst] {
                let GraphNodeId::Entity(id) = node else {
                    return Err(Refused::UnprovenSource);
                };
                if !self.ids.contains(id) {
                    return Err(Refused::UnprovenSource);
                }
            }
        }
        let written = pending.absorb(derived, |batch| {
            super::install_lsp_relations_locked(state, batch)
        });
        self.accept_own_write(state)?;
        Ok(written)
    }

    pub(crate) async fn flush(
        &self,
        state: &DaemonState,
        pending: &mut PendingEnrichment,
    ) -> Result<EnrichmentWrite, Refused> {
        let _coordinated = state.coordination_gate.lock().await;
        // Even an empty buffer must pass: stale negative answers are not
        // successful enrichment and cannot set a durable completion marker.
        self.validate(state)?;
        let written = pending.flush(|batch| super::install_lsp_relations_locked(state, batch));
        self.accept_own_write(state)?;
        Ok(written)
    }

    fn accept_own_write(&self, state: &DaemonState) -> Result<(), Refused> {
        // Still under coordination. Only our synchronous relation installer
        // could have advanced the epoch here; never refresh after waiting on a
        // foreign edit. This permits files larger than one 256-edge batch.
        let epoch = state.stable_graph_authority_epoch().ok_or(Refused::Stale)?;
        self.epoch.store(epoch, Ordering::SeqCst);
        Ok(())
    }
}

pub(crate) fn request_fresh_sweep(state: &DaemonState) {
    // Retry derivation, never replay obsolete relation payloads. The worker's
    // receive boundary drains this coalesced bit, retaining it on a full queue.
    state.lsp_sweep_pending.store(true, Ordering::SeqCst);
}
