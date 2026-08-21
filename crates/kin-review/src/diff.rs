// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;

use kin_model::change::{EntityDelta, RelationDelta, SemanticChange};
use kin_model::entity::Entity;
use kin_model::graph::GraphStore;
use kin_model::ids::{EntityId, RelationId, SemanticChangeId};
use kin_model::relation::Relation;
use serde::{Deserialize, Serialize};

use crate::error::ReviewError;

/// The kind of change applied to a single entity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(clippy::large_enum_variant)]
pub enum EntityChangeKind {
    Added(Entity),
    Modified {
        old: Entity,
        new: Entity,
    },
    /// The base-side record of a removed entity. The delta that produced the
    /// removal already carries this entity, so a review can name what was
    /// deleted instead of printing an opaque id. `None` only when no version of
    /// the entity is recoverable from the graph or its history, which a renderer
    /// must report as an unresolved removal rather than as a bare id.
    Removed {
        old: Option<Entity>,
    },
}

/// A single entity-level diff entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntityChange {
    pub entity_id: EntityId,
    pub kind: EntityChangeKind,
}

/// The kind of change applied to a single relation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RelationChangeKind {
    Added(Relation),
    Modified {
        old: Relation,
        new: Relation,
    },
    /// The base-side record of a removed relation, which carries both endpoints
    /// and the edge kind. Every producer holds it, so it is not optional.
    Removed {
        old: Relation,
    },
}

/// A single relation-level diff entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelationChange {
    pub kind: RelationChangeKind,
}

/// Entity-level diff between a base and head semantic change.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SemanticDiff {
    pub base: Option<SemanticChangeId>,
    pub head: Option<SemanticChangeId>,
    pub entity_changes: Vec<EntityChange>,
    pub relation_changes: Vec<RelationChange>,
    /// How many recorded modifications this range carried whose entity did not
    /// change: same name, kind, signature, visibility, role, and fingerprint,
    /// with only the span and the source-blob provenance advanced.
    ///
    /// They are excluded from `entity_changes` because a review that names them
    /// is naming work nobody did, but the count is published rather than
    /// dropped. It is the honest measure of how much of a stored change is
    /// re-emission, and a reader who sees "Modified (1)" beside 60 suppressed
    /// entries knows the storage layer touched the whole file while the review
    /// found one edit.
    #[serde(default)]
    pub provenance_only_entity_changes: usize,
}

/// Whether a recorded modification changed what the entity IS, rather than only
/// where it sits or which blob it was last read out of.
///
/// The reconciler stamps the touched file's blob hash onto every declaration in
/// that file (`kin-reconcile/src/reconciler.rs`), and an edit that adds or
/// removes bytes shifts the span of every declaration below it. Both are true
/// provenance and the storage delta must carry them, because the workspace
/// overlay is derived by whole-value difference and a payload held back there
/// strands the workspace dirty forever. Neither is a change a reviewer can act
/// on, so this is where the two meanings of "modified" separate.
///
/// The comparison normalizes the provenance fields onto the base value and then
/// compares the whole entity, rather than listing the fields that count. A field
/// added to `Entity` later is therefore treated as semantic until someone
/// decides otherwise, which fails toward reporting a change rather than hiding
/// one.
pub fn is_semantic_modification(old: &Entity, new: &Entity) -> bool {
    let mut normalized = new.clone();
    normalized.span.clone_from(&old.span);
    normalized.metadata.clone_from(&old.metadata);
    normalized.created_in = old.created_in;
    normalized != *old
}

impl SemanticDiff {
    pub fn added_entities(&self) -> Vec<&Entity> {
        self.entity_changes
            .iter()
            .filter_map(|c| match &c.kind {
                EntityChangeKind::Added(e) => Some(e),
                _ => None,
            })
            .collect()
    }

    pub fn modified_entities(&self) -> Vec<(&Entity, &Entity)> {
        self.entity_changes
            .iter()
            .filter_map(|c| match &c.kind {
                EntityChangeKind::Modified { old, new } => Some((old, new)),
                _ => None,
            })
            .collect()
    }

    pub fn removed_entity_ids(&self) -> Vec<&EntityId> {
        self.entity_changes
            .iter()
            .filter_map(|c| match &c.kind {
                EntityChangeKind::Removed { .. } => Some(&c.entity_id),
                _ => None,
            })
            .collect()
    }

    /// Removed entities paired with the id they were recorded under. The entity
    /// is `None` only for a removal whose base-side record could not be
    /// recovered; a caller must render that case as unresolved rather than
    /// falling back to the id alone as if it were a name.
    pub fn removed_entities(&self) -> Vec<(&EntityId, Option<&Entity>)> {
        self.entity_changes
            .iter()
            .filter_map(|c| match &c.kind {
                EntityChangeKind::Removed { old } => Some((&c.entity_id, old.as_ref())),
                _ => None,
            })
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.entity_changes.is_empty() && self.relation_changes.is_empty()
    }

    /// All entity IDs touched by this diff (added, modified, or removed).
    pub fn changed_entity_ids(&self) -> Vec<EntityId> {
        self.entity_changes.iter().map(|c| c.entity_id).collect()
    }
}

/// Stable ordering key for a relation change. Relation deltas are accumulated
/// through HashMaps whose iteration order is not stable, so emitted diffs sort
/// on this key to stay byte-identical across repeated runs. A relation id is
/// unique to a single add-or-remove within one diff, so the id alone totally
/// orders the set.
/// Drop the modifications that only advanced provenance, returning how many
/// were dropped so the caller can publish the count.
fn split_provenance_only(changes: Vec<EntityChange>) -> (Vec<EntityChange>, usize) {
    let before = changes.len();
    let kept: Vec<EntityChange> = changes
        .into_iter()
        .filter(|change| match &change.kind {
            EntityChangeKind::Modified { old, new } => is_semantic_modification(old, new),
            EntityChangeKind::Added(_) | EntityChangeKind::Removed { .. } => true,
        })
        .collect();
    let suppressed = before - kept.len();
    (kept, suppressed)
}

/// Fold one `Modified` delta into the accumulated state for its entity.
///
/// The accumulated `old` stays the FIRST base-side payload the range recorded,
/// never the latest delta's. Overwriting it collapsed `base..head` into
/// `last_change..head`: an entity whose signature moved in the first change and
/// whose blob provenance advanced in a later one would be compared against a
/// base that already carried the new signature, and the range would report no
/// change at all.
fn fold_modified(
    entity_states: &mut HashMap<EntityId, EntityChangeKind>,
    old: &Entity,
    new: &Entity,
) {
    let id = new.id;
    match entity_states.get(&id) {
        // Added in this range and then edited: still an addition from the
        // range's point of view.
        Some(EntityChangeKind::Added(_)) => {
            entity_states.insert(id, EntityChangeKind::Added(new.clone()));
        }
        Some(EntityChangeKind::Modified { old: first, .. }) => {
            let first = first.clone();
            entity_states.insert(
                id,
                EntityChangeKind::Modified {
                    old: first,
                    new: new.clone(),
                },
            );
        }
        _ => {
            entity_states.insert(
                id,
                EntityChangeKind::Modified {
                    old: old.clone(),
                    new: new.clone(),
                },
            );
        }
    }
}

fn relation_change_key(change: &RelationChange) -> String {
    match &change.kind {
        RelationChangeKind::Added(rel) => rel.id.to_string(),
        RelationChangeKind::Modified { new, .. } => new.id.to_string(),
        RelationChangeKind::Removed { old } => old.id.to_string(),
    }
}

/// Compute a semantic diff between two change IDs by collecting all
/// intermediate changes from the graph store.
pub fn compute_diff<G: GraphStore>(
    store: &G,
    base: &SemanticChangeId,
    head: &SemanticChangeId,
) -> Result<SemanticDiff, ReviewError> {
    compute_diff_scoped(store, base, head, |_| true)
}

/// Compute a semantic diff accumulating only the walked changes `in_range`
/// accepts, in their walked order.
///
/// The store's backward walk stops at the literal base node, not at the
/// base's ancestors, so on a merge head it crosses into the base's own
/// history through the other parent and the accumulated diff spans eras the
/// range never touched. Range-aware callers pass the DAG-true membership
/// test (reachable from head, not reachable from base) to restore
/// `base..head` semantics without a storage-layer change.
pub fn compute_diff_scoped<G: GraphStore>(
    store: &G,
    base: &SemanticChangeId,
    head: &SemanticChangeId,
    in_range: impl Fn(&SemanticChangeId) -> bool,
) -> Result<SemanticDiff, ReviewError> {
    let changes: Vec<_> = store
        .get_changes_since(base, head)
        .map_err(ReviewError::graph)?
        .into_iter()
        .filter(|change| in_range(&change.id))
        .collect();

    if changes.is_empty() {
        return Err(ReviewError::NoChanges);
    }

    let mut diff = SemanticDiff {
        base: Some(*base),
        head: Some(*head),
        ..Default::default()
    };

    // Accumulate entity deltas across all intermediate changes.
    // Later changes override earlier ones for the same entity.
    let mut entity_states: HashMap<EntityId, EntityChangeKind> = HashMap::new();

    for change in &changes {
        for delta in &change.entity_deltas {
            match delta {
                EntityDelta::Added { new: entity } => {
                    let id = entity.id;
                    match entity_states.get(&id) {
                        Some(EntityChangeKind::Removed { .. }) => {
                            // The model delta carries the removed payload, but
                            // the public review summary remains ID-shaped for
                            // now. Treat a reintroduction as an add rather than
                            // inventing an old body.
                            entity_states.insert(id, EntityChangeKind::Added(entity.clone()));
                        }
                        _ => {
                            entity_states.insert(id, EntityChangeKind::Added(entity.clone()));
                        }
                    }
                }
                EntityDelta::Modified { old, new } => {
                    fold_modified(&mut entity_states, old, new);
                }
                EntityDelta::Removed { old } => {
                    let id = old.id;
                    match entity_states.get(&id) {
                        Some(EntityChangeKind::Added(_)) => {
                            // Added then removed in this range — net zero
                            entity_states.remove(&id);
                        }
                        _ => {
                            entity_states.insert(
                                id,
                                EntityChangeKind::Removed {
                                    old: Some(old.clone()),
                                },
                            );
                        }
                    }
                }
            }
        }
    }

    // `entity_states` is a HashMap, so its iteration order is not stable across
    // runs. Emit entity changes in a deterministic entity-id order so every
    // downstream consumer (findings, inline comments, JSON payloads) is
    // byte-identical across repeated evaluations of the same change.
    let mut entity_changes: Vec<EntityChange> = entity_states
        .into_iter()
        .map(|(entity_id, kind)| EntityChange { entity_id, kind })
        .collect();
    entity_changes.sort_by_key(|change| change.entity_id);
    let (entity_changes, provenance_only) = split_provenance_only(entity_changes);
    diff.entity_changes = entity_changes;
    diff.provenance_only_entity_changes = provenance_only;

    // Accumulate relation deltas
    let mut relation_added: HashMap<RelationId, Relation> = HashMap::new();
    let mut relation_modified: HashMap<RelationId, (Relation, Relation)> = HashMap::new();
    let mut relation_removed: HashMap<RelationId, Relation> = HashMap::new();

    for change in &changes {
        for delta in &change.relation_deltas {
            match delta {
                RelationDelta::Added { new: rel } => {
                    if let Some(old) = relation_removed.remove(&rel.id) {
                        relation_modified.insert(rel.id, (old, rel.clone()));
                    } else {
                        relation_added.insert(rel.id, rel.clone());
                    }
                }
                RelationDelta::Modified { old, new } => {
                    if let Some(added) = relation_added.get_mut(&new.id) {
                        *added = new.clone();
                    } else {
                        relation_modified
                            .entry(new.id)
                            .and_modify(|(_, latest)| *latest = new.clone())
                            .or_insert_with(|| (old.clone(), new.clone()));
                    }
                }
                RelationDelta::Removed { old } => {
                    if relation_added.remove(&old.id).is_none() {
                        let removed = relation_modified
                            .remove(&old.id)
                            .map_or_else(|| old.clone(), |(original, _)| original);
                        relation_removed.insert(old.id, removed);
                    }
                }
            }
        }
    }

    for (_, rel) in relation_added {
        diff.relation_changes.push(RelationChange {
            kind: RelationChangeKind::Added(rel),
        });
    }
    for (_, (old, new)) in relation_modified {
        diff.relation_changes.push(RelationChange {
            kind: RelationChangeKind::Modified { old, new },
        });
    }
    for (_, old) in relation_removed {
        diff.relation_changes.push(RelationChange {
            kind: RelationChangeKind::Removed { old },
        });
    }
    diff.relation_changes.sort_by_key(relation_change_key);

    Ok(diff)
}

/// Build a semantic diff directly from a single SemanticChange (useful
/// when you already have the change object).
pub fn diff_from_change(change: &SemanticChange) -> SemanticDiff {
    let mut diff = SemanticDiff {
        base: change.parents.first().copied(),
        head: Some(change.id),
        ..Default::default()
    };

    let mut entity_changes = Vec::new();
    for delta in &change.entity_deltas {
        let (entity_id, kind) = match delta {
            EntityDelta::Added { new: e } => (e.id, EntityChangeKind::Added(e.clone())),
            EntityDelta::Modified { old, new } => (
                new.id,
                EntityChangeKind::Modified {
                    old: old.clone(),
                    new: new.clone(),
                },
            ),
            EntityDelta::Removed { old } => (
                old.id,
                EntityChangeKind::Removed {
                    old: Some(old.clone()),
                },
            ),
        };
        entity_changes.push(EntityChange { entity_id, kind });
    }
    let (entity_changes, provenance_only) = split_provenance_only(entity_changes);
    diff.entity_changes = entity_changes;
    diff.provenance_only_entity_changes = provenance_only;

    for delta in &change.relation_deltas {
        let kind = match delta {
            RelationDelta::Added { new: rel } => RelationChangeKind::Added(rel.clone()),
            RelationDelta::Modified { old, new } => RelationChangeKind::Modified {
                old: old.clone(),
                new: new.clone(),
            },
            RelationDelta::Removed { old } => RelationChangeKind::Removed { old: old.clone() },
        };
        diff.relation_changes.push(RelationChange { kind });
    }

    diff
}

/// Build a semantic diff from an explicit list of `SemanticChange` objects.
///
/// This lets users cherry-pick arbitrary changes — across branches, out of
/// order, or from non-contiguous history — and review them as a single unit.
/// Deltas are accumulated in order using the same override logic as
/// `compute_diff`.
pub fn diff_from_changes(changes: &[SemanticChange]) -> SemanticDiff {
    let mut diff = SemanticDiff::default();

    if changes.is_empty() {
        return diff;
    }

    // Use first change's parent as base, last change's id as head.
    diff.base = changes.first().and_then(|c| c.parents.first().copied());
    diff.head = changes.last().map(|c| c.id);

    let mut entity_states: HashMap<EntityId, EntityChangeKind> = HashMap::new();

    for change in changes {
        for delta in &change.entity_deltas {
            match delta {
                EntityDelta::Added { new: entity } => {
                    let id = entity.id;
                    entity_states.insert(id, EntityChangeKind::Added(entity.clone()));
                }
                EntityDelta::Modified { old, new } => {
                    fold_modified(&mut entity_states, old, new);
                }
                EntityDelta::Removed { old } => match entity_states.get(&old.id) {
                    Some(EntityChangeKind::Added(_)) => {
                        entity_states.remove(&old.id);
                    }
                    _ => {
                        entity_states.insert(
                            old.id,
                            EntityChangeKind::Removed {
                                old: Some(old.clone()),
                            },
                        );
                    }
                },
            }
        }
    }

    // Deterministic entity-id order: `entity_states` is a HashMap whose
    // iteration order varies run-to-run.
    let mut entity_changes: Vec<EntityChange> = entity_states
        .into_iter()
        .map(|(entity_id, kind)| EntityChange { entity_id, kind })
        .collect();
    entity_changes.sort_by_key(|change| change.entity_id);
    let (entity_changes, provenance_only) = split_provenance_only(entity_changes);
    diff.entity_changes = entity_changes;
    diff.provenance_only_entity_changes = provenance_only;

    // Accumulate relation deltas
    let mut relation_added: HashMap<RelationId, Relation> = HashMap::new();
    let mut relation_modified: HashMap<RelationId, (Relation, Relation)> = HashMap::new();
    let mut relation_removed: HashMap<RelationId, Relation> = HashMap::new();

    for change in changes {
        for delta in &change.relation_deltas {
            match delta {
                RelationDelta::Added { new: rel } => {
                    if let Some(old) = relation_removed.remove(&rel.id) {
                        relation_modified.insert(rel.id, (old, rel.clone()));
                    } else {
                        relation_added.insert(rel.id, rel.clone());
                    }
                }
                RelationDelta::Modified { old, new } => {
                    if let Some(added) = relation_added.get_mut(&new.id) {
                        *added = new.clone();
                    } else {
                        relation_modified
                            .entry(new.id)
                            .and_modify(|(_, latest)| *latest = new.clone())
                            .or_insert_with(|| (old.clone(), new.clone()));
                    }
                }
                RelationDelta::Removed { old } => {
                    if relation_added.remove(&old.id).is_none() {
                        let removed = relation_modified
                            .remove(&old.id)
                            .map_or_else(|| old.clone(), |(original, _)| original);
                        relation_removed.insert(old.id, removed);
                    }
                }
            }
        }
    }

    for (_, rel) in relation_added {
        diff.relation_changes.push(RelationChange {
            kind: RelationChangeKind::Added(rel),
        });
    }
    for (_, (old, new)) in relation_modified {
        diff.relation_changes.push(RelationChange {
            kind: RelationChangeKind::Modified { old, new },
        });
    }
    for (_, old) in relation_removed {
        diff.relation_changes.push(RelationChange {
            kind: RelationChangeKind::Removed { old },
        });
    }
    diff.relation_changes.sort_by_key(relation_change_key);

    diff
}

/// Build a semantic diff by looking up a user-specified set of entity IDs.
///
/// For each entity ID the caller provides, we look up the entity's current
/// state in the graph and its most recent history entry.  If the entity exists
/// in the graph and has prior history we emit a `Modified` change; if it exists
/// but has no prior history (or only one entry) we emit `Added`; if the entity
/// is not in the graph we emit `Removed`.
///
/// This is the primary mechanism for "review from arbitrary user-specified
/// change sets" — callers can hand-pick any set of entities and get a full
/// review with impact analysis and risk scoring.
pub fn diff_from_entity_ids<G: GraphStore>(
    store: &G,
    entity_ids: &[EntityId],
) -> Result<SemanticDiff, ReviewError> {
    let mut diff = SemanticDiff::default();

    for &eid in entity_ids {
        match store.get_entity(&eid).map_err(ReviewError::graph)? {
            Some(current_entity) => {
                // Entity exists — check history to determine Added vs Modified
                let history = store.get_entity_history(&eid).map_err(ReviewError::graph)?;

                // Find the previous version from the most recent change that
                // contains a Modified or Added delta for this entity.
                let previous = history.iter().rev().find_map(|change| {
                    change.entity_deltas.iter().find_map(|delta| match delta {
                        EntityDelta::Modified { old, .. } if old.id == eid => Some(old.clone()),
                        _ => None,
                    })
                });

                let kind = match previous {
                    Some(old_entity) => EntityChangeKind::Modified {
                        old: old_entity,
                        new: current_entity.clone(),
                    },
                    None => EntityChangeKind::Added(current_entity.clone()),
                };

                diff.entity_changes.push(EntityChange {
                    entity_id: eid,
                    kind,
                });
            }
            None => {
                // Entity not in graph, so treat as removed. The entity is absent
                // at head by definition here, but its history still holds the
                // last version that existed, and that record is what lets a
                // review name what was deleted. Prefer the payload the removal
                // delta itself carried, then the newest surviving version.
                let history = store.get_entity_history(&eid).map_err(ReviewError::graph)?;
                let old = history.iter().rev().find_map(|change| {
                    change.entity_deltas.iter().find_map(|delta| match delta {
                        EntityDelta::Removed { old } if old.id == eid => Some(old.clone()),
                        EntityDelta::Modified { new, .. } if new.id == eid => Some(new.clone()),
                        EntityDelta::Added { new } if new.id == eid => Some(new.clone()),
                        _ => None,
                    })
                });
                diff.entity_changes.push(EntityChange {
                    entity_id: eid,
                    kind: EntityChangeKind::Removed { old },
                });
            }
        }
    }

    Ok(diff)
}

/// Build a semantic diff from file paths by resolving each path to the
/// entities it contains, then running entity-level diff logic on all of them.
pub fn diff_from_files<G: GraphStore>(
    store: &G,
    files: &[String],
) -> Result<SemanticDiff, ReviewError> {
    use kin_model::graph::EntityFilter;
    use kin_model::ids::FilePathId;

    let mut all_entity_ids = Vec::new();

    for file_path in files {
        let filter = EntityFilter {
            file_path: Some(FilePathId::new(file_path)),
            ..Default::default()
        };
        let entities = store.query_entities(&filter).map_err(ReviewError::graph)?;

        for entity in &entities {
            if !all_entity_ids.contains(&entity.id) {
                all_entity_ids.push(entity.id);
            }
        }
    }

    if all_entity_ids.is_empty() {
        return Err(ReviewError::NoChanges);
    }

    diff_from_entity_ids(store, &all_entity_ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::change::{EntityDelta, RelationDelta};
    use kin_model::entity::{
        Entity, EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, SemanticFingerprint,
        Visibility,
    };
    use kin_model::ids::*;
    use kin_model::relation::{Relation, RelationKind, RelationOrigin};
    use kin_model::timestamp::Timestamp;

    fn test_entity(name: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: None,
            span: None,
            signature: format!("fn {}()", name),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn test_change_id(byte: u8) -> SemanticChangeId {
        SemanticChangeId::from_hash(Hash256::from_bytes([byte; 32]))
    }

    fn test_relation() -> Relation {
        Relation {
            id: RelationId::new(),
            kind: RelationKind::Calls,
            src: kin_model::GraphNodeId::Entity(EntityId::new()),
            dst: kin_model::GraphNodeId::Entity(EntityId::new()),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        }
    }

    #[test]
    fn diff_from_single_change_added() {
        let entity = test_entity("foo");
        let change = SemanticChange {
            id: test_change_id(1),
            parents: vec![test_change_id(0)],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "add foo".into(),
            entity_deltas: vec![EntityDelta::Added {
                new: entity.clone(),
            }],
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        };

        let diff = diff_from_change(&change);
        assert_eq!(diff.entity_changes.len(), 1);
        assert_eq!(diff.added_entities().len(), 1);
        assert_eq!(diff.modified_entities().len(), 0);
        assert_eq!(diff.removed_entity_ids().len(), 0);
        assert!(!diff.is_empty());
    }

    #[test]
    fn diff_from_single_change_modified() {
        let old_entity = test_entity("bar");
        let mut new_entity = old_entity.clone();
        new_entity.signature = "fn bar(x: i32)".to_string();

        let change = SemanticChange {
            id: test_change_id(2),
            parents: vec![test_change_id(1)],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "modify bar".into(),
            entity_deltas: vec![EntityDelta::Modified {
                old: old_entity,
                new: new_entity,
            }],
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        };

        let diff = diff_from_change(&change);
        assert_eq!(diff.modified_entities().len(), 1);
    }

    #[test]
    fn diff_from_single_change_with_relations() {
        let entity = test_entity("baz");
        let rel = Relation {
            id: RelationId::new(),
            kind: RelationKind::Calls,
            src: kin_model::GraphNodeId::Entity(entity.id),
            dst: kin_model::GraphNodeId::Entity(EntityId::new()),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        };

        let change = SemanticChange {
            id: test_change_id(3),
            parents: vec![test_change_id(2)],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "add baz with call".into(),
            entity_deltas: vec![EntityDelta::Added { new: entity }],
            relation_deltas: vec![RelationDelta::Added { new: rel }],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        };

        let diff = diff_from_change(&change);
        assert_eq!(diff.entity_changes.len(), 1);
        assert_eq!(diff.relation_changes.len(), 1);
    }

    #[test]
    fn empty_diff() {
        let change = SemanticChange {
            id: test_change_id(4),
            parents: vec![test_change_id(3)],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "noop".into(),
            entity_deltas: vec![],
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        };

        let diff = diff_from_change(&change);
        assert!(diff.is_empty());
    }

    #[test]
    fn diff_from_removal() {
        let entity = test_entity("removed");
        let entity_id = entity.id;
        let change = SemanticChange {
            id: test_change_id(5),
            parents: vec![test_change_id(4)],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "remove entity".into(),
            entity_deltas: vec![EntityDelta::Removed { old: entity }],
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        };

        let diff = diff_from_change(&change);
        assert_eq!(diff.removed_entity_ids().len(), 1);
        assert_eq!(*diff.removed_entity_ids()[0], entity_id);
    }

    #[test]
    fn diff_changed_entity_ids_covers_all_kinds() {
        let added = test_entity("added");
        let old_mod = test_entity("modified");
        let mut new_mod = old_mod.clone();
        new_mod.signature = "fn modified(x: i32)".to_string();
        let removed = test_entity("removed");
        let removed_id = removed.id;

        let change = SemanticChange {
            id: test_change_id(6),
            parents: vec![test_change_id(5)],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "mixed change".into(),
            entity_deltas: vec![
                EntityDelta::Added { new: added.clone() },
                EntityDelta::Modified {
                    old: old_mod,
                    new: new_mod.clone(),
                },
                EntityDelta::Removed { old: removed },
            ],
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        };

        let diff = diff_from_change(&change);
        let ids = diff.changed_entity_ids();
        assert_eq!(ids.len(), 3);
        assert!(ids.contains(&added.id));
        assert!(ids.contains(&new_mod.id));
        assert!(ids.contains(&removed_id));
    }

    #[test]
    fn diff_relation_removal() {
        let relation = test_relation();
        let change = SemanticChange {
            id: test_change_id(7),
            parents: vec![test_change_id(6)],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "remove relation".into(),
            entity_deltas: vec![],
            relation_deltas: vec![RelationDelta::Removed { old: relation }],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        };

        let diff = diff_from_change(&change);
        assert_eq!(diff.relation_changes.len(), 1);
        assert!(!diff.is_empty());
    }

    #[test]
    fn diff_only_additions() {
        let e1 = test_entity("fn_a");
        let e2 = test_entity("fn_b");
        let change = SemanticChange {
            id: test_change_id(8),
            parents: vec![test_change_id(7)],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "add two".into(),
            entity_deltas: vec![
                EntityDelta::Added { new: e1.clone() },
                EntityDelta::Added { new: e2.clone() },
            ],
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        };

        let diff = diff_from_change(&change);
        assert_eq!(diff.added_entities().len(), 2);
        assert!(diff.modified_entities().is_empty());
        assert!(diff.removed_entity_ids().is_empty());
    }

    #[test]
    fn diff_only_deletions() {
        let first = test_entity("first");
        let second = test_entity("second");
        let change = SemanticChange {
            id: test_change_id(9),
            parents: vec![test_change_id(8)],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "remove two".into(),
            entity_deltas: vec![
                EntityDelta::Removed { old: first },
                EntityDelta::Removed { old: second },
            ],
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        };

        let diff = diff_from_change(&change);
        assert!(diff.added_entities().is_empty());
        assert!(diff.modified_entities().is_empty());
        assert_eq!(diff.removed_entity_ids().len(), 2);
    }

    #[test]
    fn diff_from_changes_emits_entity_changes_in_id_order() {
        // Deltas arrive out of id order and are accumulated through a HashMap,
        // whose iteration order is not stable. The builder must emit entity
        // changes in a deterministic entity-id order so anything derived from
        // them (findings, inline comments, JSON payloads) is byte-identical
        // across repeated runs of the same change.
        let entities: Vec<Entity> = (0..6u32)
            .map(|i| {
                let mut entity = test_entity(&format!("e{i}"));
                entity.id = EntityId::from_content("src/tie.rs", &format!("e{i}"), "function", i);
                entity
            })
            .collect();
        let ids: Vec<EntityId> = entities.iter().map(|entity| entity.id).collect();
        let entity_deltas: Vec<EntityDelta> = entities
            .iter()
            .rev()
            .cloned()
            .map(|old| EntityDelta::Removed { old })
            .collect();
        let change = SemanticChange {
            id: test_change_id(21),
            parents: vec![test_change_id(20)],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "remove many".into(),
            entity_deltas,
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        };

        let emitted: Vec<EntityId> = diff_from_changes(&[change])
            .entity_changes
            .iter()
            .map(|change| change.entity_id)
            .collect();

        assert_eq!(emitted.len(), ids.len());
        let mut sorted = emitted.clone();
        sorted.sort();
        assert_eq!(
            emitted, sorted,
            "entity_changes must be emitted in ascending entity-id order"
        );
    }

    #[test]
    fn semantic_diff_default_is_empty() {
        let diff = SemanticDiff::default();
        assert!(diff.is_empty());
        assert!(diff.base.is_none());
        assert!(diff.head.is_none());
        assert!(diff.changed_entity_ids().is_empty());
    }

    // --- Tests for diff_from_changes ---

    #[test]
    fn diff_from_changes_empty() {
        let diff = diff_from_changes(&[]);
        assert!(diff.is_empty());
        assert!(diff.base.is_none());
        assert!(diff.head.is_none());
    }

    #[test]
    fn diff_from_changes_single() {
        let entity = test_entity("single");
        let change = SemanticChange {
            id: test_change_id(10),
            parents: vec![test_change_id(9)],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "add single".into(),
            entity_deltas: vec![EntityDelta::Added {
                new: entity.clone(),
            }],
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        };

        let diff = diff_from_changes(&[change]);
        assert_eq!(diff.entity_changes.len(), 1);
        assert_eq!(diff.added_entities().len(), 1);
        assert_eq!(diff.base, Some(test_change_id(9)));
        assert_eq!(diff.head, Some(test_change_id(10)));
    }

    #[test]
    fn diff_from_changes_multiple_accumulates() {
        let e1 = test_entity("first");
        let e2 = test_entity("second");

        let c1 = SemanticChange {
            id: test_change_id(20),
            parents: vec![test_change_id(19)],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "add first".into(),
            entity_deltas: vec![EntityDelta::Added { new: e1.clone() }],
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        };

        let c2 = SemanticChange {
            id: test_change_id(21),
            parents: vec![test_change_id(20)],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "add second".into(),
            entity_deltas: vec![EntityDelta::Added { new: e2.clone() }],
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        };

        let diff = diff_from_changes(&[c1, c2]);
        assert_eq!(diff.entity_changes.len(), 2);
        assert_eq!(diff.base, Some(test_change_id(19)));
        assert_eq!(diff.head, Some(test_change_id(21)));
    }

    #[test]
    fn diff_from_changes_add_then_remove_nets_zero() {
        let entity = test_entity("ephemeral");

        let c1 = SemanticChange {
            id: test_change_id(30),
            parents: vec![test_change_id(29)],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "add ephemeral".into(),
            entity_deltas: vec![EntityDelta::Added {
                new: entity.clone(),
            }],
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        };

        let c2 = SemanticChange {
            id: test_change_id(31),
            parents: vec![test_change_id(30)],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "remove ephemeral".into(),
            entity_deltas: vec![EntityDelta::Removed { old: entity }],
            relation_deltas: vec![],
            tree_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        };

        let diff = diff_from_changes(&[c1, c2]);
        assert!(diff.entity_changes.is_empty());
    }
}
