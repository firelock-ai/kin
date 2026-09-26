// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Preserve withdrawn bindings from exact immutable merge predecessors.
//! A mixed planning tree is never used as evidence of an old source body.

use std::collections::{BTreeMap, HashSet};

use kin_db::{GraphSnapshot, InMemoryGraph};
use kin_index::binding_debt::{
    build_local_binding_debt, decode_local_binding_debt, LocalBindingDebt,
};
use kin_model::{
    graph::ResolvedGraphState, EntityStore, FilePathId, GraphNodeId, RelationDelta, RepoPath,
    TransactionDelta, TreeEntry,
};

use crate::error::{ReconcileError, Result};

fn invalid(reason: impl std::fmt::Display) -> ReconcileError {
    ReconcileError::InvalidTransaction(format!("authored batch prior binding: {reason}"))
}

/// A private batch can withdraw an unchanged occurrence twice: once while
/// retiring the target against the authored caller, then from the immutable
/// predecessor. Only this checked current-body duplicate may yield to the old
/// obligation. Different historical records still collide rather than losing
/// provenance. No relation is invented or discharged by this comparison.
fn is_current_reobservation(
    original: &kin_index::binding_debt::LocalBindingObligation,
    observed: &kin_index::binding_debt::LocalBindingObligation,
    current: &kin_index::IndexedFile,
    blobs: &kin_blobs::BlobStore,
) -> Result<bool> {
    if observed.source_digest != kin_model::Hash256::from_bytes(current.blob_hash.0)
        || original
            .prior_source_file
            .as_ref()
            .is_some_and(|file| file != &current.file_id)
    {
        return Ok(false);
    }
    let mut same = observed.clone();
    same.source_digest = original.source_digest;
    if &same != original {
        return Ok(false);
    }
    let digest = kin_blobs::Hash256::from_bytes(*original.source_digest.as_bytes());
    let bytes = blobs.read(&digest)?;
    if kin_blobs::digest(&bytes) != digest {
        return Err(invalid("original duplicate source digest mismatch"));
    }
    let prior = kin_index::IndexPipeline::new()
        .index_file_content_with_tests(&current.file_id, &bytes, digest)?
        .indexed_file;
    if !matches!(prior.parse_state, kin_model::ParseState::Valid)
        || !matches!(current.parse_state, kin_model::ParseState::Valid)
        // Import maps are syntax-grounded and include module, exported/local
        // alias and exact site. Equal call spelling alone is not binding proof.
        || serde_json::to_value(&prior.imports).map_err(invalid)?
            != serde_json::to_value(&current.imports).map_err(invalid)?
    {
        return Ok(false);
    }
    let source_id = original
        .retired_relation
        .src
        .as_entity()
        .ok_or_else(|| invalid("duplicate source is not an entity"))?;
    let Some(source) = current
        .entities
        .iter()
        .find(|entity| entity.id == source_id)
    else {
        return Ok(false);
    };
    if source.name != original.source_name || kin_model::is_derived_member(source) {
        return Ok(false);
    }
    // Occurrence certificates qualify source records but carry no source span
    // themselves. Ignore them only after validating that they preserve the
    // relation's existing confidence and origin.
    let Some(evidence) =
        kin_index::occurrence::uniform_original_evidence(&original.retired_relation)
    else {
        return Ok(false);
    };
    let sites: Option<Vec<_>> = evidence.iter().map(|e| e.source_span.as_ref()).collect();
    let Some(sites) = sites.filter(|sites| !sites.is_empty()) else {
        return Ok(false);
    };
    for site in sites {
        if site.file != current.file_id {
            return Ok(false);
        }
        for indexed in [&prior, current] {
            let owners: Vec<_> = indexed
                .entities
                .iter()
                .filter(|entity| {
                    entity.name == source.name
                        && entity.kind == source.kind
                        && entity.span.as_ref().is_some_and(|span| {
                            span.file == site.file
                                && span.start_byte <= site.start_byte
                                && site.end_byte <= span.end_byte
                        })
                })
                .collect();
            if owners.len() != 1 || kin_model::is_derived_member(owners[0]) {
                return Ok(false);
            }
        }
        let at_site = |indexed: &kin_index::IndexedFile| -> Result<Vec<serde_json::Value>> {
            indexed
                .extracted_relations
                .iter()
                .filter(|raw| {
                    raw.kind == original.retired_relation.kind
                        && raw.src_name == source.name
                        && raw.site.as_ref().is_some_and(|raw_site| {
                            raw_site.to_source_span(&indexed.file_id) == *site
                        })
                })
                .map(|raw| serde_json::to_value(raw).map_err(invalid))
                .collect()
        };
        let old = at_site(&prior)?;
        let new = at_site(current)?;
        if old.len() != 1 || old != new {
            return Ok(false);
        }
    }
    Ok(true)
}

/// What a batch does with a withdrawn binding whose caller its predecessor
/// cannot certify.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UncertifiedCallers {
    /// Refuse the batch. Every withdrawn binding needs an exact predecessor.
    Refuse,
    /// Drop the binding and count it.
    ///
    /// Only for a startup re-derivation, whose one predecessor is the store as
    /// the daemon loaded it. A caller whose own declarations its current bytes
    /// do not produce there has no observation left to ground a withdrawal
    /// record in: the live parse that bound it did not survive the restart. A
    /// caller that store does certify keeps its record, exactly as under
    /// `Refuse`.
    Drop,
}

/// Returns how many withdrawn bindings were dropped unrecorded, which is zero
/// under [`UncertifiedCallers::Refuse`].
pub(crate) fn retain_removed_bindings(
    anchors: &ResolvedGraphState,
    current: &InMemoryGraph,
    predecessors: &[ResolvedGraphState],
    blobs: &kin_blobs::BlobStore,
    uncertified: UncertifiedCallers,
) -> Result<usize> {
    let final_state = current.to_snapshot();
    let departing: HashSet<_> = anchors
        .entities
        .keys()
        .filter(|id| !final_state.entities.contains_key(id))
        .copied()
        .collect();
    let mut unclaimed: BTreeMap<_, _> = anchors
        .relations
        .values()
        .filter(|relation| {
            let (Some(source), Some(target)) = (relation.src.as_entity(), relation.dst.as_entity())
            else {
                return false;
            };
            let source_file = anchors
                .entities
                .get(&source)
                .and_then(|entity| entity.file_origin.as_ref());
            let source_survives = source_file
                .and_then(|file| RepoPath::from_utf8(file.0.clone()).ok())
                .is_some_and(|path| final_state.resolved_tree.artifact_at_path(&path).is_some())
                || predecessors.iter().any(|prior| {
                    prior
                        .entities
                        .get(&source)
                        .and_then(|entity| entity.file_origin.as_ref())
                        .and_then(|file| RepoPath::from_utf8(file.0.clone()).ok())
                        .and_then(|path| prior.tree.artifact_id_at_path(&path))
                        .is_some_and(|artifact| final_state.resolved_tree.get(&artifact).is_some())
                });
            departing.contains(&target)
                && source_survives
                && matches!(
                    relation.origin,
                    kin_model::RelationOrigin::Parsed | kin_model::RelationOrigin::Inferred
                )
                && anchors
                    .entities
                    .get(&source)
                    .and_then(|e| e.file_origin.as_ref())
                    != anchors
                        .entities
                        .get(&target)
                        .and_then(|e| e.file_origin.as_ref())
        })
        .map(|relation| (relation.id, relation.clone()))
        .collect();
    if unclaimed.is_empty() {
        return Ok(0);
    }
    let mut dropped = 0;
    let mut additions: BTreeMap<kin_model::ArtifactId, LocalBindingDebt> = BTreeMap::new();
    for prior in predecessors {
        let selected: Vec<_> = unclaimed
            .values()
            .filter_map(|relation| {
                let held = prior.relations.get(&relation.id)?;
                if (held.src, held.dst, held.kind) != (relation.src, relation.dst, relation.kind) {
                    return None;
                }
                let source = relation.src.as_entity()?;
                let anchor = anchors.entities.get(&source)?;
                let old = prior.entities.get(&source)?;
                let digest = anchor.metadata.extra.get("blob_hash")?.as_str()?;
                if old
                    .metadata
                    .extra
                    .get("blob_hash")
                    .and_then(|value| value.as_str())
                    != Some(digest)
                {
                    return None;
                }
                let path = RepoPath::from_utf8(old.file_origin.as_ref()?.0.clone()).ok()?;
                let artifact = prior.tree.artifact_at_path(&path)?;
                final_state.resolved_tree.get(&artifact.artifact_id)?;
                // Composition may re-anchor spans. Use the exact predecessor
                // copy grounded in the selected caller body, not those spans.
                Some(held.clone())
            })
            .collect();
        if selected.is_empty() {
            continue;
        }
        let graph = InMemoryGraph::from_snapshot(GraphSnapshot {
            entities: prior.entities.clone(),
            relations: prior.relations.clone(),
            resolved_tree: prior.tree.clone(),
            external_references: prior.external_references.clone(),
            ..InMemoryGraph::new().to_snapshot()
        })
        .map_err(invalid)?;
        let selected = if uncertified == UncertifiedCallers::Drop {
            let mut certified = std::collections::HashMap::new();
            let mut kept = Vec::new();
            for relation in selected {
                let source = prior
                    .entities
                    .get(&relation.src.as_entity().unwrap())
                    .and_then(|entity| entity.file_origin.clone())
                    .ok_or_else(|| invalid("prior source has no file"))?;
                let complete = match certified.get(&source) {
                    Some(complete) => *complete,
                    None => {
                        let reading = crate::admitted_source::inspect_with_content(
                            &graph,
                            &source,
                            |hash| {
                                blobs
                                    .read(&kin_blobs::Hash256::from_bytes(*hash.as_bytes()))
                                    .map_err(Into::into)
                            },
                        )?;
                        let complete = matches!(
                            reading,
                            crate::admitted_source::AdmittedSourceReading::Complete(_)
                        );
                        certified.insert(source, complete);
                        complete
                    }
                };
                if complete {
                    kept.push(relation);
                } else {
                    unclaimed.remove(&relation.id);
                    dropped += 1;
                }
            }
            if kept.is_empty() {
                continue;
            }
            kept
        } else {
            selected
        };
        let mut checked = HashSet::new();
        for relation in &selected {
            let source = prior
                .entities
                .get(&relation.src.as_entity().unwrap())
                .and_then(|entity| entity.file_origin.as_ref())
                .ok_or_else(|| invalid("prior source has no file"))?;
            if checked.insert(source.clone())
                && crate::admitted_source::load(&graph, blobs, source)?.is_none()
            {
                return Err(invalid("prior source is incomplete"));
            }
        }
        let planned = crate::coverage::plan_withdrawn_local_binding_obligations(
            &selected,
            |id| graph.get_entity(&id).map_err(invalid),
            |file| {
                let path = RepoPath::from_utf8(file.0.clone()).map_err(invalid)?;
                let Some(artifact) = graph.artifact_id_at_path(&path) else {
                    return Ok(None);
                };
                Ok(graph
                    .get_tree_entry(file)
                    .map_err(invalid)?
                    .and_then(|entry| match entry {
                        TreeEntry::Blob { hash, .. } => Some((artifact, hash)),
                        _ => None,
                    }))
            },
            |artifact| crate::binding_debt::held(&graph, artifact),
            |id| crate::binding_debt::exact(&graph, id),
        )?;
        let selected_ids: HashSet<_> = selected.iter().map(|relation| relation.id).collect();
        for change in planned {
            let relation = match change {
                RelationDelta::Added { new } | RelationDelta::Modified { new, .. } => new,
                _ => continue,
            };
            let GraphNodeId::Artifact(artifact) = relation.src else {
                return Err(invalid("prior debt has no source artifact"));
            };
            let old_path = FilePathId::new(
                prior
                    .tree
                    .get(&artifact)
                    .ok_or_else(|| invalid("prior source disappeared"))?
                    .path
                    .to_string(),
            );
            let mut debt = decode_local_binding_debt(&old_path, artifact, &relation)
                .map_err(invalid)?
                .ok_or_else(|| invalid("prior planner omitted debt"))?;
            debt.obligations
                .retain(|o| selected_ids.contains(&o.retired_relation.id));
            let source_path = FilePathId::new(
                final_state
                    .resolved_tree
                    .get(&artifact)
                    .ok_or_else(|| invalid("surviving source lost its artifact"))?
                    .path
                    .to_string(),
            );
            if source_path != old_path {
                for obligation in &mut debt.obligations {
                    obligation.prior_source_file = Some(old_path.clone());
                }
                debt.source_file = source_path;
            }
            let merged = additions
                .entry(artifact)
                .or_insert_with(|| LocalBindingDebt {
                    obligations: vec![],
                    ..debt.clone()
                });
            merged.obligations.extend(debt.obligations);
        }
        for relation in selected {
            unclaimed.remove(&relation.id);
        }
    }
    if !unclaimed.is_empty() {
        return Err(invalid(
            "withdrawn binding has no exact immutable predecessor",
        ));
    }
    for (artifact, mut debt) in additions {
        let indexed = crate::admitted_source::load(current, blobs, &debt.source_file)?
            .ok_or_else(|| invalid("current source is incomplete"))?;
        let mut old = None;
        for relation in crate::binding_debt::held(current, artifact)? {
            if let Some(held) = decode_local_binding_debt(&debt.source_file, artifact, &relation)
                .map_err(invalid)?
            {
                if old.replace(relation).is_some() {
                    return Err(invalid("multiple current debt records"));
                }
                for obligation in held.obligations {
                    if let Some(added) = debt
                        .obligations
                        .iter()
                        .find(|new| new.retired_relation.id == obligation.retired_relation.id)
                    {
                        if added != &obligation
                            && !is_current_reobservation(added, &obligation, &indexed, blobs)?
                        {
                            return Err(invalid("prior binding identity collision"));
                        }
                    } else {
                        debt.obligations.push(obligation);
                    }
                }
            }
        }
        // This stamp describes the checked current observation. Each obligation
        // retains its own immutable prior-source digest for exact settlement.
        debt.observed_source_digest = kin_model::Hash256::from_bytes(indexed.blob_hash.0);
        let mut new = build_local_binding_debt(artifact, debt).map_err(invalid)?;
        let change = if let Some(old) = old {
            new.created_in = old.created_in;
            RelationDelta::Modified { old, new }
        } else {
            RelationDelta::Added { new }
        };
        current
            .apply_transaction_delta(&TransactionDelta {
                relation_deltas: vec![change],
                ..Default::default()
            })
            .map_err(invalid)?;
        let mut produced = Vec::new();
        for node in indexed
            .entities
            .iter()
            .map(|entity| GraphNodeId::Entity(entity.id))
            .chain(std::iter::once(GraphNodeId::Artifact(artifact)))
        {
            produced.extend(
                current
                    .get_all_relations_for_node(&node)
                    .map_err(invalid)?
                    .into_iter()
                    .filter(|relation| relation.src == node),
            );
        }
        let settled = crate::binding_debt::settle(
            current,
            blobs,
            &indexed,
            &indexed.entities,
            &produced,
            |id| current.get_entity(&id).map_err(invalid),
        )?;
        current
            .apply_transaction_delta(&TransactionDelta {
                relation_deltas: settled,
                ..Default::default()
            })
            .map_err(invalid)?;
    }
    Ok(dropped)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_index::{
        binding_debt::LocalBindingObligation, FileParseData, IndexPipeline, IndexedFile,
    };
    use kin_model::{ArtifactId, EntityKind, Hash256, RelationKind};

    const OLD: &str = "from local import beta\n\ndef run(value):\n    return beta(value)\n";
    const CURRENT: &str = "from local import beta\n\ndef run(value):\n    return beta(value) + 1\n";

    fn indexed(blobs: &kin_blobs::BlobStore, file: &str, body: &str) -> IndexedFile {
        IndexPipeline::new()
            .index_file_content_with_tests(
                &FilePathId::new(file),
                body.as_bytes(),
                blobs.write(body.as_bytes()).unwrap(),
            )
            .unwrap()
            .indexed_file
    }

    fn fixture(
        blobs: &kin_blobs::BlobStore,
        body: &str,
    ) -> (LocalBindingObligation, LocalBindingObligation, IndexedFile) {
        let prior = indexed(blobs, "caller.py", OLD);
        let target = indexed(blobs, "local.py", "def beta(value):\n    return value\n");
        let caller = prior
            .entities
            .iter()
            .find(|e| e.name == "run" && e.kind == EntityKind::Function)
            .unwrap();
        let target_artifact = ArtifactId::new();
        let files = [&prior, &target].map(|f| FileParseData {
            file_path: f.file_id.0.clone(),
            entities: f.entities.clone(),
            relations: f.extracted_relations.clone(),
            imports: f.imports.clone(),
        });
        let relation = kin_index::link_cross_file(
            &files,
            &std::collections::HashMap::from([
                ("caller.py".to_string(), ArtifactId::new()),
                ("local.py".to_string(), target_artifact),
            ]),
        )
        .unwrap()
        .into_iter()
        .find(|r| r.kind == RelationKind::Calls && r.src.as_entity() == Some(caller.id))
        .unwrap();
        let original = LocalBindingObligation {
            retired_relation: relation,
            source_name: "run".into(),
            source_digest: Hash256::from_bytes(prior.blob_hash.0),
            prior_source_file: None,
            target_artifact,
            target_file: FilePathId::new("local.py"),
            target_name: "beta".into(),
        };
        let mut current = indexed(blobs, "caller.py", body);
        // The live fixture establishes this continuity through reconcile; this
        // pure comparison control supplies that same already-preserved ID.
        current
            .entities
            .iter_mut()
            .find(|e| e.name == "run" && e.kind == EntityKind::Function)
            .unwrap()
            .id = caller.id;
        let mut observed = original.clone();
        observed.source_digest = Hash256::from_bytes(current.blob_hash.0);
        (original, observed, current)
    }

    #[test]
    fn current_reobservation_requires_real_unchanged_occurrence_and_import_bindings() {
        let root = tempfile::tempdir().unwrap();
        let blobs = kin_blobs::BlobStore::new(root.path().to_path_buf()).unwrap();
        for (body, accepted) in [
            (CURRENT, true),
            (
                "from other import beta\n\ndef run(value):\n    return beta(value) + 1\n",
                false,
            ),
            (
                "from local import gamma as beta\n\ndef run(value):\n    return beta(value) + 1\n",
                false,
            ),
            (
                "from local import beta\n\ndef run(value):\n    return beta(value + 1)\n",
                false,
            ),
        ] {
            let (old, observed, current) = fixture(&blobs, body);
            assert_eq!(
                is_current_reobservation(&old, &observed, &current, &blobs).unwrap(),
                accepted,
                "{body}"
            );
        }
    }

    #[test]
    fn current_reobservation_refuses_target_provenance_digest_and_ownership_conflicts() {
        let root = tempfile::tempdir().unwrap();
        let blobs = kin_blobs::BlobStore::new(root.path().to_path_buf()).unwrap();
        for control in [
            "target",
            "provenance",
            "digest",
            "source",
            "ambiguous-owner",
            "site",
        ] {
            let (mut old, mut observed, mut current) = fixture(&blobs, CURRENT);
            match control {
                "target" => observed.target_artifact = ArtifactId::new(),
                "provenance" => observed.retired_relation.confidence = 0.5,
                "digest" => observed.source_digest = old.source_digest,
                "source" => observed.source_name = "another".into(),
                "ambiguous-owner" => {
                    let mut duplicate = current
                        .entities
                        .iter()
                        .find(|e| e.name == "run")
                        .unwrap()
                        .clone();
                    duplicate.id = kin_model::EntityId::new();
                    current.entities.push(duplicate);
                }
                "site" => {
                    old.retired_relation.evidence[0]
                        .source_span
                        .as_mut()
                        .unwrap()
                        .start_byte += 1;
                    observed.retired_relation = old.retired_relation.clone();
                }
                _ => unreachable!(),
            }
            assert!(
                !is_current_reobservation(&old, &observed, &current, &blobs).unwrap(),
                "{control}"
            );
        }
    }

    #[test]
    fn current_reobservation_validates_certificates_and_requires_original_sites() {
        let root = tempfile::tempdir().unwrap();
        let blobs = kin_blobs::BlobStore::new(root.path().to_path_buf()).unwrap();
        for (control, accepted) in [
            ("malformed-certificate", false),
            ("weaker-certificate", false),
            ("spanless-source", false),
            ("legacy-source-only", true),
        ] {
            let (mut old, mut observed, current) = fixture(&blobs, CURRENT);
            assert!(old
                .retired_relation
                .evidence
                .iter()
                .any(kin_index::occurrence::is_certificate));
            match control {
                "malformed-certificate" | "weaker-certificate" => {
                    let certificate = old
                        .retired_relation
                        .evidence
                        .iter_mut()
                        .find(|record| kin_index::occurrence::is_certificate(record))
                        .unwrap();
                    if control == "malformed-certificate" {
                        certificate.token = Some("invalid certificate".into());
                    } else {
                        let mut proof: serde_json::Value =
                            serde_json::from_str(certificate.token.as_deref().unwrap()).unwrap();
                        proof["confidence"] = serde_json::json!(0.2);
                        certificate.token = Some(proof.to_string());
                        // This is a valid, weaker occurrence tier, not a
                        // malformed record refused before the uniform check.
                        assert!(
                            kin_index::occurrence::original_evidence(&old.retired_relation)
                                .is_some()
                        );
                    }
                }
                "spanless-source" => {
                    let mut source = old
                        .retired_relation
                        .evidence
                        .iter()
                        .find(|record| record.source_span.is_some())
                        .unwrap()
                        .clone();
                    source.source_span = None;
                    old.retired_relation.evidence.push(source);
                }
                "legacy-source-only" => old
                    .retired_relation
                    .evidence
                    .retain(|record| !kin_index::occurrence::is_certificate(record)),
                _ => unreachable!(),
            }
            // Keep both observations identical so refusal must come from
            // source/certificate validation, not the early equality guard.
            observed.retired_relation = old.retired_relation.clone();
            assert_eq!(
                is_current_reobservation(&old, &observed, &current, &blobs).unwrap(),
                accepted,
                "{control}"
            );
        }
    }

    #[test]
    fn current_reobservation_cannot_replace_missing_or_unreconstructable_original_cas() {
        let root = tempfile::tempdir().unwrap();
        let blobs = kin_blobs::BlobStore::new(root.path().to_path_buf()).unwrap();
        let (old, observed, current) = fixture(&blobs, CURRENT);
        blobs
            .delete(&kin_blobs::Hash256::from_bytes(
                *old.source_digest.as_bytes(),
            ))
            .unwrap();
        assert!(is_current_reobservation(&old, &observed, &current, &blobs).is_err());
        let (mut old, observed, current) = fixture(&blobs, CURRENT);
        let other = blobs.write(b"def run(value):\n    return value\n").unwrap();
        old.source_digest = Hash256::from_bytes(other.0);
        assert!(!is_current_reobservation(&old, &observed, &current, &blobs).unwrap());
    }
}
