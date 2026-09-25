// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Final source-bound Rust named-import pass over a coherent unpublished graph.

use kin_blobs::BlobStore;
use kin_index::{
    linker::{named_import_observations, ArtifactIdentityMap},
    rust_project::{RustProjectAuthority, RustProjectLimits},
    FileParseCompletenessMap, FileParseData, IncrementalLinker,
};
use kin_model::{EntityStore, FilePathId, TransactionDelta, TreeEntry};

use crate::error::{ReconcileError, Result};

fn invalid(reason: impl std::fmt::Display) -> ReconcileError {
    ReconcileError::InvalidTransaction(format!("admitted Rust project: {reason}"))
}

/// Must run after all candidate declarations and ordinary settlement, before
/// publication/adoption. No filesystem view or checkpoint supplies membership.
/// Count/body limits bound this census; the owned tree/CAS APIs materialize
/// their inputs before this layer can enforce those processing bounds.
pub(crate) fn finalize(graph: &kin_db::InMemoryGraph, blobs: &BlobStore) -> Result<()> {
    finalize_with_limits(graph, blobs, RustProjectLimits::default())
}

fn finalize_with_limits(
    graph: &kin_db::InMemoryGraph,
    blobs: &BlobStore,
    limits: RustProjectLimits,
) -> Result<()> {
    let tree = graph
        .resolved_tree_snapshot()
        .map_err(|error| ReconcileError::Graph(error.to_string()))?
        .ok_or_else(|| invalid("selected tree is unavailable"))?;
    if !tree
        .artifacts_by_path()
        .any(|artifact| artifact.path.as_bytes().ends_with(b".rs"))
    {
        return Ok(());
    }
    let observation = RustProjectAuthority::observe_admitted_tree(&tree, limits, |hash| {
        blobs
            .read(&kin_blobs::Hash256::from_bytes(*hash.as_bytes()))
            .map_err(|error| error.to_string())
    })
    .map_err(invalid)?;
    let mut sources = Vec::new();
    let mut caller_count = 0usize;
    let mut caller_bytes = 0usize;
    let mut ids = ArtifactIdentityMap::new();
    let mut completeness = FileParseCompletenessMap::new();
    for artifact in tree
        .artifacts_by_path()
        .filter(|artifact| artifact.path.as_bytes().ends_with(b".rs"))
    {
        let path = std::str::from_utf8(artifact.path.as_bytes())
            .map_err(|_| invalid("Rust caller path is not UTF8"))?;
        if !matches!(artifact.entry, TreeEntry::Blob { .. }) {
            continue;
        }
        caller_count = caller_count
            .checked_add(1)
            .ok_or_else(|| invalid("caller count overflow"))?;
        if caller_count > limits.artifacts {
            return Err(invalid("caller inventory limit exceeded"));
        }
        let Some(source) =
            crate::admitted_source::load_with(graph, &FilePathId::new(path), |hash| {
                let bytes = blobs.read(&kin_blobs::Hash256::from_bytes(*hash.as_bytes()))?;
                caller_bytes = caller_bytes
                    .checked_add(bytes.len())
                    .ok_or_else(|| invalid("caller byte count overflow"))?;
                if bytes.len() > limits.body_bytes || caller_bytes > limits.total_body_bytes {
                    return Err(invalid("caller body processing limit exceeded"));
                }
                Ok(bytes)
            })?
        else {
            // Existing LKG answers remain held; a partial caller supplies no
            // exact occurrence authority for destructive replacement.
            continue;
        };
        ids.insert(path.to_owned(), artifact.artifact_id);
        completeness.insert(
            path.to_owned(),
            source.file_layout.parse_completeness.clone(),
        );
        sources.push(source);
    }
    let parsed: Vec<_> = sources
        .iter()
        .map(|source| FileParseData {
            file_path: source.file_id.0.clone(),
            entities: source.entities.clone(),
            relations: source.extracted_relations.clone(),
            imports: source.imports.clone(),
        })
        .collect();
    let entities: Vec<_> = sources
        .iter()
        .flat_map(|source| source.entities.iter().cloned())
        .collect();
    let mut linker = IncrementalLinker::new();
    for file in &parsed {
        linker.add_file(&file.file_path, ids[&file.file_path], &file.entities);
    }
    if let Some(authority) = observation.authority() {
        linker
            .install_rust_project(authority.clone(), &entities)
            .map_err(invalid)?;
    }
    let mut observations = named_import_observations(&parsed, &linker);
    for site in &mut observations {
        site.rust_project_tree = Some(observation.tree_digest());
    }
    let linked =
        kin_index::link_cross_file_incremental_with_completeness(&parsed, &linker, &completeness)?;
    let mut delta = TransactionDelta::default();
    let accepted = crate::named_imports::stage_project_derivations(
        graph,
        &sources,
        &observations,
        &linked,
        &mut delta,
    )?;
    let external = crate::external::retire_rebound(
        graph,
        &[],
        &std::collections::HashSet::new(),
        &accepted,
        blobs,
        false,
        |source| {
            kin_index::link_cross_file_incremental_with_completeness(
                std::slice::from_ref(source),
                &linker,
                &completeness,
            )
            .map_err(Into::into)
        },
    )?;
    for old in external {
        delta
            .relation_deltas
            .push(kin_model::RelationDelta::Removed { old });
    }
    crate::named_imports::refresh(graph, &sources, &observations, &accepted, &mut delta)?;
    graph
        .apply_transaction_delta(&delta)
        .map_err(|error| ReconcileError::Graph(error.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{ArtifactId, LocatedEntry, RepoPath, TreeDelta};

    #[test]
    fn disconnected_source_census_refuses_body_and_cumulative_limits_before_parsing() {
        let root = tempfile::tempdir().unwrap();
        let blobs = BlobStore::new(root.path().join("blobs")).unwrap();
        let graph = kin_db::InMemoryGraph::new();
        for file in ["a.rs", "b.rs"] {
            // No Cargo root can visit these files; the finalizer must charge
            // them independently, including entity-free comment-only sources.
            let hash = blobs.write(b"// body\n").unwrap();
            let indexed = kin_index::IndexPipeline::new()
                .index_file_content_with_tests(
                    &FilePathId::new(file),
                    b"// body\n",
                    kin_model::Hash256::from_bytes(hash.0),
                )
                .unwrap()
                .indexed_file;
            let entity_deltas = indexed
                .entities
                .into_iter()
                .map(|mut entity| {
                    entity
                        .metadata
                        .extra
                        .insert("blob_hash".into(), hash.to_string().into());
                    kin_model::EntityDelta::Added { new: entity }
                })
                .collect();
            graph
                .apply_transaction_delta(&TransactionDelta {
                    tree_deltas: vec![TreeDelta::Added {
                        artifact_id: ArtifactId::new(),
                        new: LocatedEntry::new(
                            RepoPath::from_utf8(file).unwrap(),
                            TreeEntry::blob(kin_model::Hash256::from_bytes(hash.0), false),
                        ),
                    }],
                    entity_deltas,
                    ..Default::default()
                })
                .unwrap();
        }
        let before = serde_json::to_value(graph.to_snapshot()).unwrap();
        for (body_bytes, total_body_bytes) in [(7, 32), (8, 15)] {
            let error = finalize_with_limits(
                &graph,
                &blobs,
                RustProjectLimits {
                    body_bytes,
                    total_body_bytes,
                    ..Default::default()
                },
            )
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("caller body processing limit exceeded"),
                "{error}"
            );
            assert_eq!(
                serde_json::to_value(graph.to_snapshot()).unwrap(),
                before,
                "refusal must leave graph unchanged"
            );
        }
        finalize_with_limits(
            &graph,
            &blobs,
            RustProjectLimits {
                body_bytes: 8,
                total_body_bytes: 16,
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(serde_json::to_value(graph.to_snapshot()).unwrap(), before);
    }
}
