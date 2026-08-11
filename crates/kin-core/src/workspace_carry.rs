// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Replaying a pending workspace onto another branch.
//!
//! A Kin workspace holds uncommitted work as graph truth rather than as loose
//! bytes on disk: an exact tree that may sit ahead of its base change, plus a
//! base-relative semantic overlay. A branch transition therefore has to decide
//! what happens to that pending state, and the answer implemented here is the
//! one a working day already expects from Git. Pending work is a diff against
//! the base, and a transition replays that diff onto the destination instead of
//! demanding an empty workspace first.
//!
//! The contract, stated as rules a reader can apply by hand:
//!
//! 1. A pending entry at a path the destination does not track **carries**. It
//!    stays pending on the destination under the same artifact identity it was
//!    admitted with. This is the case Git covers by leaving untracked files
//!    alone across a checkout, and it is the common one: a scratch note that
//!    ambient observation admitted must not block a switch.
//! 2. A pending entry at a path the destination tracks with byte-identical
//!    content is **absorbed**. The destination already holds that content, so
//!    the entry stops being pending and becomes an ordinary tracked member.
//! 3. A pending entry at a path the destination tracks with different content
//!    **refuses**. Carrying it would overwrite a member of the branch being
//!    switched to, which is exactly the case Git refuses with "untracked
//!    working tree file would be overwritten by checkout".
//! 4. A pending change to a tracked member **carries** when the destination
//!    holds that member in precisely the state the change was made against, and
//!    **refuses** otherwise, including when the destination does not hold the
//!    member at all. This is Git refusing "your local changes would be
//!    overwritten by checkout": replaying an edit is safe exactly when both
//!    branches agree about what was being edited.
//!
//! Rule 4 is decided by artifact identity and located entry together, not by
//! path, so a member the destination renamed is correctly treated as differing
//! rather than silently accepting an edit planned against its old location.
//!
//! The semantic overlay follows the same shape one layer up: it is replayed
//! onto the destination's entities and relations under the same precondition,
//! so carried work keeps its semantics instead of degrading into tree-only
//! bytes. A precondition that does not hold fails closed as a conflict rather
//! than publishing a graph nobody observed.

use std::collections::{BTreeMap, HashMap};

use kin_model::{
    Entity, EntityDelta, EntityId, Relation, RelationDelta, RelationId, RepoPath, ResolvedTree,
    TreeDelta, WorkspaceSemanticOverlay,
};

use crate::{KinError, Result};

/// Why one pending entry cannot be replayed onto the destination.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceCarryConflictKind {
    /// The destination tracks this path with different content, so carrying the
    /// pending addition would overwrite a member of the branch being entered.
    AdditionWouldOverwriteMember,
    /// The destination holds this member differently from the state the pending
    /// change was made against, or does not hold it at all, so replaying the
    /// change would discard whichever side the transition landed on.
    MemberDiffersBetweenBranches,
}

impl WorkspaceCarryConflictKind {
    /// The clause naming what this conflict would have cost, phrased for a
    /// caller who is looking at their own working tree.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::AdditionWouldOverwriteMember => {
                "the destination branch tracks this path with different content, so carrying the \
                 pending addition would overwrite it"
            }
            Self::MemberDiffersBetweenBranches => {
                "the destination branch holds this member differently from the state the pending \
                 change was made against"
            }
        }
    }
}

/// One pending entry that refuses to replay, named by the path a caller sees.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceCarryConflict {
    pub path: RepoPath,
    pub kind: WorkspaceCarryConflictKind,
}

/// The exact destination state a carried workspace resolves to.
///
/// `tree`, `entities`, and `relations` describe the whole workspace after the
/// transition, destination members and replayed pending work together. They are
/// what the transition must publish and what its preflight must reproduce.
#[derive(Debug, Clone)]
pub struct WorkspaceCarryPlan {
    pub tree: ResolvedTree,
    pub entities: HashMap<EntityId, Entity>,
    pub relations: HashMap<RelationId, Relation>,
    /// Paths that remain pending on the destination, in tree order.
    pub carried: Vec<RepoPath>,
    /// Paths the destination already tracked at identical content, so they are
    /// tracked members after the transition rather than pending work.
    pub absorbed: Vec<RepoPath>,
}

/// The outcome of planning a carry: either the exact destination state, or
/// every reason the transition must refuse.
#[derive(Debug, Clone)]
pub enum WorkspaceCarry {
    Carried(Box<WorkspaceCarryPlan>),
    Refused(Vec<WorkspaceCarryConflict>),
}

/// Plan the replay of one workspace's pending state onto a destination branch.
///
/// `base_tree` is the tree at the workspace's own base change, so the diff
/// between it and `pending_tree` is precisely the uncommitted work. Nothing
/// here reads the filesystem: the pending state is graph truth already, and the
/// destination is resolved from graph history.
pub fn plan_workspace_carry(
    base_tree: &ResolvedTree,
    pending_tree: &ResolvedTree,
    pending_overlay: &WorkspaceSemanticOverlay,
    destination_tree: &ResolvedTree,
    destination_entities: &HashMap<EntityId, Entity>,
    destination_relations: &HashMap<RelationId, Relation>,
) -> Result<WorkspaceCarry> {
    let pending = crate::exact_tree_correction(base_tree, pending_tree)
        .map_err(|error| KinError::Other(format!("plan pending workspace state: {error}")))?;

    let mut conflicts = BTreeMap::new();
    let mut replay = Vec::new();
    let mut carried = Vec::new();
    let mut absorbed = Vec::new();

    for delta in &pending {
        match delta {
            TreeDelta::Added { new, .. } => match destination_tree.artifact_at_path(&new.path) {
                None => {
                    replay.push(delta.clone());
                    carried.push(new.path.clone());
                }
                Some(member) if member.entry == new.entry => absorbed.push(new.path.clone()),
                Some(_) => {
                    conflicts.insert(
                        new.path.clone(),
                        WorkspaceCarryConflictKind::AdditionWouldOverwriteMember,
                    );
                }
            },
            TreeDelta::Updated {
                artifact_id, old, ..
            }
            | TreeDelta::Removed { artifact_id, old } => {
                let held_identically = destination_tree
                    .get(artifact_id)
                    .is_some_and(|member| member.located_entry() == *old);
                if held_identically {
                    replay.push(delta.clone());
                    if matches!(delta, TreeDelta::Updated { .. }) {
                        carried.push(old.path.clone());
                    }
                } else {
                    conflicts.insert(
                        old.path.clone(),
                        WorkspaceCarryConflictKind::MemberDiffersBetweenBranches,
                    );
                }
            }
        }
    }

    if !conflicts.is_empty() {
        return Ok(WorkspaceCarry::Refused(
            conflicts
                .into_iter()
                .map(|(path, kind)| WorkspaceCarryConflict { path, kind })
                .collect(),
        ));
    }

    let tree = destination_tree.apply(&replay).map_err(|error| {
        KinError::Other(format!(
            "replay pending workspace state onto the destination tree: {error}"
        ))
    })?;
    let entities = replay_entities(pending_overlay.entity_deltas(), destination_entities)?;
    let relations = replay_relations(pending_overlay.relation_deltas(), destination_relations)?;

    Ok(WorkspaceCarry::Carried(Box::new(WorkspaceCarryPlan {
        tree,
        entities,
        relations,
        carried,
        absorbed,
    })))
}

/// Replay the overlay's entity deltas onto the destination's live entities.
///
/// An addition the destination already holds identically is absorbed, matching
/// rule 2 one layer up. Every other precondition mismatch fails closed: the
/// alternative is publishing a workspace whose semantics no observation
/// produced.
fn replay_entities(
    deltas: &[EntityDelta],
    destination: &HashMap<EntityId, Entity>,
) -> Result<HashMap<EntityId, Entity>> {
    let mut entities = destination.clone();
    for delta in deltas {
        match delta {
            EntityDelta::Added { new } => match entities.get(&new.id) {
                Some(held) if held == new => {}
                Some(_) => return Err(semantic_replay_conflict("entity", &new.name)),
                None => {
                    entities.insert(new.id, new.clone());
                }
            },
            EntityDelta::Modified { old, new } => {
                if entities.get(&old.id) != Some(old) {
                    return Err(semantic_replay_conflict("entity", &old.name));
                }
                entities.insert(new.id, new.clone());
            }
            EntityDelta::Removed { old } => {
                if entities.get(&old.id) != Some(old) {
                    return Err(semantic_replay_conflict("entity", &old.name));
                }
                entities.remove(&old.id);
            }
        }
    }
    Ok(entities)
}

/// Replay the overlay's relation deltas under the same precondition as
/// [`replay_entities`].
fn replay_relations(
    deltas: &[RelationDelta],
    destination: &HashMap<RelationId, Relation>,
) -> Result<HashMap<RelationId, Relation>> {
    let mut relations = destination.clone();
    for delta in deltas {
        match delta {
            RelationDelta::Added { new } => match relations.get(&new.id) {
                Some(held) if held == new => {}
                Some(_) => return Err(semantic_replay_conflict("relation", &render_relation(new))),
                None => {
                    relations.insert(new.id, new.clone());
                }
            },
            RelationDelta::Modified { old, new } => {
                if relations.get(&old.id) != Some(old) {
                    return Err(semantic_replay_conflict("relation", &render_relation(old)));
                }
                relations.insert(new.id, new.clone());
            }
            RelationDelta::Removed { old } => {
                if relations.get(&old.id) != Some(old) {
                    return Err(semantic_replay_conflict("relation", &render_relation(old)));
                }
                relations.remove(&old.id);
            }
        }
    }
    Ok(relations)
}

fn render_relation(relation: &Relation) -> String {
    format!("{:?}", relation.kind)
}

fn semantic_replay_conflict(noun: &str, name: &str) -> KinError {
    KinError::Other(format!(
        "pending {noun} {name} cannot be replayed onto the destination branch, which holds it in a \
         state this pending work was never planned against; commit the pending work or set it \
         aside with `kin stash push` before switching branches"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{ArtifactId, Hash256, LocatedEntry, TreeEntry};

    fn path(value: &str) -> RepoPath {
        RepoPath::from_bytes(value.as_bytes().to_vec()).expect("repository path")
    }

    fn entry(body: &str) -> TreeEntry {
        TreeEntry::blob(
            Hash256::from_bytes(kin_blobs::digest_bytes(body.as_bytes())),
            false,
        )
    }

    fn tree(members: &[(u128, &str, &str)]) -> ResolvedTree {
        let deltas = members
            .iter()
            .map(|(id, at, body)| TreeDelta::Added {
                artifact_id: ArtifactId(uuid::Uuid::from_u128(*id)),
                new: LocatedEntry::new(path(at), entry(body)),
            })
            .collect::<Vec<_>>();
        ResolvedTree::default()
            .apply(&deltas)
            .expect("build fixture tree")
    }

    fn plan(
        base: &ResolvedTree,
        pending: &ResolvedTree,
        destination: &ResolvedTree,
    ) -> WorkspaceCarry {
        plan_workspace_carry(
            base,
            pending,
            &WorkspaceSemanticOverlay::default(),
            destination,
            &HashMap::new(),
            &HashMap::new(),
        )
        .expect("plan workspace carry")
    }

    fn conflicts(carry: &WorkspaceCarry) -> Vec<(String, WorkspaceCarryConflictKind)> {
        match carry {
            WorkspaceCarry::Refused(conflicts) => conflicts
                .iter()
                .map(|conflict| (conflict.path.to_string(), conflict.kind))
                .collect(),
            WorkspaceCarry::Carried(_) => panic!("expected a refusal"),
        }
    }

    fn carried(carry: &WorkspaceCarry) -> &WorkspaceCarryPlan {
        match carry {
            WorkspaceCarry::Carried(plan) => plan,
            WorkspaceCarry::Refused(conflicts) => {
                panic!("expected a carry, refused with {conflicts:?}")
            }
        }
    }

    #[test]
    fn an_addition_at_a_path_the_destination_does_not_track_carries() {
        let base = tree(&[(1, "shared.txt", "shared")]);
        let pending = tree(&[(1, "shared.txt", "shared"), (2, "note.md", "scratch")]);
        let destination = tree(&[(1, "shared.txt", "shared"), (3, "only-there.txt", "there")]);

        let plan = plan(&base, &pending, &destination);
        let plan = carried(&plan);

        assert_eq!(
            plan.carried
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            vec!["note.md".to_string()]
        );
        assert!(plan.absorbed.is_empty());
        let note = plan
            .tree
            .artifact_at_path(&path("note.md"))
            .expect("carried addition stays in the destination tree");
        assert_eq!(
            note.artifact_id,
            ArtifactId(uuid::Uuid::from_u128(2)),
            "carrying preserves the identity the entry was admitted under"
        );
        assert!(plan
            .tree
            .artifact_at_path(&path("only-there.txt"))
            .is_some());
    }

    #[test]
    fn an_addition_the_destination_tracks_with_different_content_refuses() {
        let base = tree(&[(1, "shared.txt", "shared")]);
        let pending = tree(&[(1, "shared.txt", "shared"), (2, "Dockerfile", "mine")]);
        let destination = tree(&[(1, "shared.txt", "shared"), (3, "Dockerfile", "theirs")]);

        assert_eq!(
            conflicts(&plan(&base, &pending, &destination)),
            vec![(
                "Dockerfile".to_string(),
                WorkspaceCarryConflictKind::AdditionWouldOverwriteMember
            )]
        );
    }

    #[test]
    fn an_addition_the_destination_tracks_at_identical_content_is_absorbed() {
        let base = tree(&[(1, "shared.txt", "shared")]);
        let pending = tree(&[(1, "shared.txt", "shared"), (2, "Dockerfile", "same")]);
        let destination = tree(&[(1, "shared.txt", "shared"), (3, "Dockerfile", "same")]);

        let plan = plan(&base, &pending, &destination);
        let plan = carried(&plan);

        assert!(plan.carried.is_empty());
        assert_eq!(
            plan.absorbed
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            vec!["Dockerfile".to_string()]
        );
        assert_eq!(
            plan.tree, destination,
            "an absorbed addition leaves the destination tree exactly as it was"
        );
    }

    #[test]
    fn a_modification_to_a_member_identical_across_branches_carries() {
        let base = tree(&[(1, "shared.txt", "shared"), (2, "differs.txt", "base")]);
        let pending = tree(&[(1, "shared.txt", "edited"), (2, "differs.txt", "base")]);
        let destination = tree(&[(1, "shared.txt", "shared"), (2, "differs.txt", "other")]);

        let plan = plan(&base, &pending, &destination);
        let plan = carried(&plan);

        assert_eq!(
            plan.carried
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            vec!["shared.txt".to_string()]
        );
        assert_eq!(
            plan.tree
                .artifact_at_path(&path("shared.txt"))
                .expect("carried edit")
                .entry,
            entry("edited")
        );
        assert_eq!(
            plan.tree
                .artifact_at_path(&path("differs.txt"))
                .expect("untouched member")
                .entry,
            entry("other"),
            "a member the workspace never touched takes the destination's content"
        );
    }

    #[test]
    fn a_modification_to_a_member_that_differs_between_branches_refuses() {
        let base = tree(&[(1, "compose.yaml", "base")]);
        let pending = tree(&[(1, "compose.yaml", "mine")]);
        let destination = tree(&[(1, "compose.yaml", "theirs")]);

        assert_eq!(
            conflicts(&plan(&base, &pending, &destination)),
            vec![(
                "compose.yaml".to_string(),
                WorkspaceCarryConflictKind::MemberDiffersBetweenBranches
            )]
        );
    }

    #[test]
    fn a_modification_to_a_member_the_destination_never_had_refuses() {
        let base = tree(&[(1, "only-here.txt", "base")]);
        let pending = tree(&[(1, "only-here.txt", "mine")]);
        let destination = tree(&[(2, "elsewhere.txt", "there")]);

        assert_eq!(
            conflicts(&plan(&base, &pending, &destination)),
            vec![(
                "only-here.txt".to_string(),
                WorkspaceCarryConflictKind::MemberDiffersBetweenBranches
            )]
        );
    }

    #[test]
    fn a_removal_of_a_member_identical_across_branches_carries() {
        let base = tree(&[(1, "shared.txt", "shared"), (2, "gone.txt", "bytes")]);
        let pending = tree(&[(1, "shared.txt", "shared")]);
        let destination = tree(&[(1, "shared.txt", "shared"), (2, "gone.txt", "bytes")]);

        let plan = plan(&base, &pending, &destination);
        let plan = carried(&plan);

        assert!(plan.tree.artifact_at_path(&path("gone.txt")).is_none());
    }

    #[test]
    fn every_conflicting_path_is_reported_in_one_refusal() {
        let base = tree(&[(1, "compose.yaml", "base"), (2, "shared.txt", "shared")]);
        let pending = tree(&[
            (1, "compose.yaml", "mine"),
            (2, "shared.txt", "shared"),
            (3, "Dockerfile", "mine"),
        ]);
        let destination = tree(&[
            (1, "compose.yaml", "theirs"),
            (2, "shared.txt", "shared"),
            (4, "Dockerfile", "theirs"),
        ]);

        assert_eq!(
            conflicts(&plan(&base, &pending, &destination)),
            vec![
                (
                    "Dockerfile".to_string(),
                    WorkspaceCarryConflictKind::AdditionWouldOverwriteMember
                ),
                (
                    "compose.yaml".to_string(),
                    WorkspaceCarryConflictKind::MemberDiffersBetweenBranches
                ),
            ],
            "a caller must learn about every blocked path from one refusal"
        );
    }

    #[test]
    fn a_round_trip_reproduces_the_pending_tree_exactly() {
        let base = tree(&[(1, "shared.txt", "shared")]);
        let pending = tree(&[(1, "shared.txt", "shared"), (2, "note.md", "scratch")]);
        let destination = tree(&[(1, "shared.txt", "shared"), (3, "only-there.txt", "there")]);

        let away = plan(&base, &pending, &destination);
        let away = carried(&away).tree.clone();
        let back = plan_workspace_carry(
            &destination,
            &away,
            &WorkspaceSemanticOverlay::default(),
            &base,
            &HashMap::new(),
            &HashMap::new(),
        )
        .expect("plan the return carry");

        assert_eq!(
            carried(&back).tree,
            pending,
            "switching away and back reproduces the pending tree byte for byte"
        );
    }
}
