// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Reconstruct a complete source observation from current graph-owned bytes.

use std::collections::{HashMap, HashSet};

use kin_blobs::BlobStore;
use kin_index::IndexedFile;
use kin_model::{FilePathId, GraphStore, ParseState, RepoPath, TreeEntry};

use crate::error::{ReconcileError, Result};

/// One checked parse and the exact bytes it consumed. Kept only by callers
/// that must restore projection state; ordinary dependency reads drop the body.
pub(crate) struct AdmittedSource {
    pub indexed: IndexedFile,
    pub content: Vec<u8>,
}

/// What the graph holds for one admitted source, read against a fresh parse of
/// the exact bytes the tree names for it.
pub(crate) enum AdmittedSourceReading {
    /// A complete parse whose declarations the graph holds exactly.
    Complete(AdmittedSource),
    /// Not complete entity source: another facet, or bytes that do not parse
    /// cleanly. It keeps its last-good state and supplies no dependency
    /// authority.
    NotComplete,
    /// The graph's declarations for this file were not derived from these
    /// bytes by this build's parser. A daemon that stopped between admitting
    /// new bytes and deriving them leaves this, and so does a store an older
    /// Kin build wrote, because its parser minted a different declaration set.
    /// Re-deriving the file from its bytes clears it.
    Stale(&'static str),
}

impl AdmittedSourceReading {
    /// The strict reading every dependency read takes: a stale derivation is
    /// an error, never a quiet absence.
    pub(crate) fn into_complete(self, file: &FilePathId) -> Result<Option<AdmittedSource>> {
        match self {
            Self::Complete(source) => Ok(Some(source)),
            Self::NotComplete => Ok(None),
            Self::Stale(reason) => Err(invalid(file, reason)),
        }
    }
}

fn invalid(file: &FilePathId, reason: &str) -> ReconcileError {
    ReconcileError::InvalidTransaction(format!("admitted dependent source {file}: {reason}"))
}

/// Partial source is useful last-good state, but cannot supply new dependency
/// authority. Every complete observation must match the current declaration
/// slice exactly; cached names never repair an identity mismatch.
pub(crate) fn load<G: GraphStore>(
    graph: &G,
    blobs: &BlobStore,
    file: &FilePathId,
) -> Result<Option<IndexedFile>> {
    load_with(graph, file, |hash| {
        let digest = kin_blobs::Hash256::from_bytes(*hash.as_bytes());
        blobs.read(&digest).map_err(Into::into)
    })
}

pub(crate) fn load_with<G: GraphStore>(
    graph: &G,
    file: &FilePathId,
    read: impl FnMut(kin_model::Hash256) -> Result<Vec<u8>>,
) -> Result<Option<IndexedFile>> {
    load_with_content(graph, file, read).map(|source| source.map(|source| source.indexed))
}

pub(crate) fn load_with_content<G: GraphStore>(
    graph: &G,
    file: &FilePathId,
    read: impl FnMut(kin_model::Hash256) -> Result<Vec<u8>>,
) -> Result<Option<AdmittedSource>> {
    inspect_with_content(graph, file, read)?.into_complete(file)
}

/// Read one admitted source against a fresh parse of its exact bytes, and say
/// whether the graph's declarations for it were derived from those bytes.
///
/// Only a stale derivation is reported as a reading. An unreadable body, a
/// digest that does not match the tree, or a path the tree does not admit is
/// still an error, because re-deriving from those bytes cannot repair it.
pub(crate) fn inspect_with_content<G: GraphStore>(
    graph: &G,
    file: &FilePathId,
    mut read: impl FnMut(kin_model::Hash256) -> Result<Vec<u8>>,
) -> Result<AdmittedSourceReading> {
    let path = RepoPath::from_utf8(file.0.clone()).map_err(|e| invalid(file, &e.to_string()))?;
    if graph.artifact_id_at_path(&path).is_none() {
        return Err(invalid(file, "source has no admitted artifact"));
    }
    let entry = graph
        .get_tree_entry(file)
        .map_err(|e| ReconcileError::Graph(e.to_string()))?;
    let Some(TreeEntry::Blob { hash, .. }) = entry else {
        return Err(invalid(file, "source has no admitted blob"));
    };
    let digest = kin_blobs::Hash256::from_hex(&hash.to_string())
        .map_err(|e| invalid(file, &e.to_string()))?;
    let bytes = read(hash)?;
    if kin_blobs::digest(&bytes) != digest {
        return Err(invalid(file, "source blob digest mismatch"));
    }
    // A source extension is only a hint. Exact admitted binary bytes retain
    // their non-source facet and cannot become an editable source projection.
    if !matches!(
        kin_index::FileClassifier::classify_with_content(std::path::Path::new(&file.0), &bytes),
        kin_index::FileClassification::EntitySource
    ) {
        return Ok(AdmittedSourceReading::NotComplete);
    }
    let mut indexed = kin_index::IndexPipeline::new()
        .index_file_content_with_tests(file, &bytes, digest)?
        .indexed_file;
    if !matches!(indexed.parse_state, ParseState::Valid) {
        return Ok(AdmittedSourceReading::NotComplete);
    }
    let entities = graph
        .query_entities(&kin_model::EntityFilter {
            file_path: Some(file.clone()),
            ..Default::default()
        })
        .map_err(|e| ReconcileError::Graph(e.to_string()))?;
    let hash_text = hash.to_string();
    if entities.iter().any(|entity| {
        entity
            .metadata
            .extra
            .get("blob_hash")
            .and_then(|value| value.as_str())
            != Some(hash_text.as_str())
    }) {
        return Ok(AdmittedSourceReading::Stale(
            "source entity metadata differs from its admitted blob",
        ));
    }
    if indexed.entities.len() != entities.len() {
        return Ok(AdmittedSourceReading::Stale(
            "declaration set differs from graph truth",
        ));
    }
    let mut remapped = Vec::new();
    let mut identities = HashMap::new();
    let mut claimed = HashSet::new();
    for parsed in &indexed.entities {
        let matches: Vec<_> = entities
            .iter()
            .filter(|entity| {
                entity.name == parsed.name
                    && entity.kind == parsed.kind
                    && entity.span == parsed.span
                    && entity.fingerprint == parsed.fingerprint
            })
            .collect();
        if matches.len() != 1 || !claimed.insert(matches[0].id) {
            return Ok(AdmittedSourceReading::Stale(
                "declaration identity is ambiguous or stale",
            ));
        }
        identities.insert(parsed.id, matches[0].id);
        remapped.push(matches[0].clone());
    }
    for region in &mut indexed.file_layout.regions {
        if let kin_model::SourceRegion::EntityRef { entity_id, .. } = region {
            *entity_id = *identities.get(entity_id).ok_or_else(|| {
                invalid(file, "parsed layout refers to an unverified declaration")
            })?;
        }
    }
    indexed.entities = remapped;
    Ok(AdmittedSourceReading::Complete(AdmittedSource {
        indexed,
        content: bytes,
    }))
}
