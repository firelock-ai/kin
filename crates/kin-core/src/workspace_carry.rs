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
//!
//! Relations get one rule the tree side does not need, because relations are
//! derived continuously and trees are not. A pending relation delta whose
//! subject the destination does not hold **at all** is not a conflict: the
//! destination branch simply never observed that edge, usually because its head
//! predates the enrichment pass that derived it, so there is no destination
//! state for the replay to discard. The pending observation installs. A
//! destination that holds the subject as a *different edge* is a real conflict
//! and still refuses, and the refusal says which edge and how many.
//!
//! Rule 5 closes the loop and is a property of the whole plan rather than of any
//! one entry: no relation may leave here pointing at a node the same plan does
//! not hold. Entities and relations replay independently, so a pending entity
//! retirement can strand a destination edge into that entity, and every
//! downstream consumer then refuses at the storage layer naming an id no query
//! returns. An edge into a node the plan retired states nothing that can be
//! read, so [`plan_workspace_carry`] retires it in the same plan and reports it.

use std::collections::{BTreeMap, HashMap};

use kin_model::{
    Entity, EntityDelta, EntityId, GraphNodeId, Relation, RelationDelta, RelationId, RelationKind,
    RepoPath, ResolvedTree, TreeDelta, WorkspaceSemanticOverlay,
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
    /// The destination holds a member at an enclosing path, so the carried path
    /// would have to live inside a file or a Gitlink.
    ///
    /// The common case is a Gitlink: content written beneath an independent
    /// checkout is ordinary new content once that checkout stops being a member,
    /// and carrying it onto a branch that has the Gitlink back would build a
    /// tree with a path underneath a non-directory. Git refuses the same shape.
    PathIsInsideADestinationMember,
    /// The destination holds members beneath this path, so the carried entry
    /// would have to replace a directory with a file.
    PathIsADestinationDirectory,
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
            Self::PathIsInsideADestinationMember => {
                "the destination branch tracks a file or an independent checkout at an enclosing \
                 path, so this path cannot exist there"
            }
            Self::PathIsADestinationDirectory => {
                "the destination branch tracks members beneath this path, so a file cannot take \
                 its place"
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
    /// Relations this plan retired because the plan itself does not hold one of
    /// their endpoints, in id order. Carrying them would hand a graph with a
    /// dangling edge to the storage layer, which refuses it naming an entity no
    /// query returns; they state nothing readable, so the caller reports the
    /// count rather than the ids.
    pub retired_relations: Vec<RelationId>,
}

/// The outcome of planning a carry: either the exact destination state, or
/// every reason the transition must refuse.
///
/// The two refusals are kept apart because they read differently to a caller.
/// [`Self::Refused`] is about paths on disk and names each one;
/// [`Self::SemanticallyRefused`] is about graph subjects and names counts and
/// kinds, because there is no path to point at.
#[derive(Debug, Clone)]
pub enum WorkspaceCarry {
    Carried(Box<WorkspaceCarryPlan>),
    Refused(Vec<WorkspaceCarryConflict>),
    SemanticallyRefused(WorkspaceSemanticCarryRefusal),
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
    let destination_paths = destination_tree
        .artifacts_by_path()
        .map(|artifact| artifact.path.clone())
        .collect::<Vec<_>>();

    for delta in &pending {
        match delta {
            TreeDelta::Added { new, .. } => match destination_tree.artifact_at_path(&new.path) {
                None => {
                    match path_shape_conflict(&new.path, destination_tree, &destination_paths) {
                        Some(kind) => {
                            conflicts.insert(new.path.clone(), kind);
                        }
                        None => {
                            replay.push(delta.clone());
                            carried.push(new.path.clone());
                        }
                    }
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
                if !held_identically {
                    conflicts.insert(
                        old.path.clone(),
                        WorkspaceCarryConflictKind::MemberDiffersBetweenBranches,
                    );
                    continue;
                }
                // A pending move lands the member somewhere the destination
                // never held it, so its new location needs the same shape and
                // occupancy checks an addition gets. A same-path edit does not:
                // the destination already holds this member right there.
                let moved_to = match delta {
                    TreeDelta::Updated { new, .. } if new.path != old.path => Some(&new.path),
                    _ => None,
                };
                if let Some(destination_path) = moved_to {
                    let blocked = destination_tree
                        .artifact_at_path(destination_path)
                        .map(|_| WorkspaceCarryConflictKind::AdditionWouldOverwriteMember)
                        .or_else(|| {
                            path_shape_conflict(
                                destination_path,
                                destination_tree,
                                &destination_paths,
                            )
                        });
                    if let Some(kind) = blocked {
                        conflicts.insert(destination_path.clone(), kind);
                        continue;
                    }
                }
                replay.push(delta.clone());
                if matches!(delta, TreeDelta::Updated { .. }) {
                    carried.push(old.path.clone());
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
    // Both replays report into one refusal, so a caller learns everything the
    // destination cannot take in one message rather than one entry per retry.
    let mut refused = WorkspaceSemanticCarryRefusal::default();
    let entities = replay_entities(
        pending_overlay.entity_deltas(),
        destination_entities,
        &mut refused,
    );
    let mut relations = replay_relations(
        pending_overlay.relation_deltas(),
        destination_relations,
        &mut refused,
    );
    if !refused.is_empty() {
        return Ok(WorkspaceCarry::SemanticallyRefused(refused));
    }

    // Rule 5, decided once over the finished plan. Entities and relations
    // replayed independently above, so this is the only place that can see a
    // retired entity and a surviving edge into it at the same time.
    let retired_relations = unadmitted_endpoints(&relations, &entities, &tree);
    for relation_id in &retired_relations {
        relations.remove(relation_id);
    }

    Ok(WorkspaceCarry::Carried(Box::new(WorkspaceCarryPlan {
        tree,
        entities,
        relations,
        carried,
        absorbed,
        retired_relations,
    })))
}

/// Every relation the finished plan holds whose endpoint the same plan does not.
///
/// Only `Entity` and `Artifact` endpoints are decidable from a carry plan: the
/// plan owns exactly those two node populations. Tests, contracts, work items,
/// verification runs and external references live in tables this planner never
/// sees, so kin-db validates those and this does not pretend to.
fn unadmitted_endpoints(
    relations: &HashMap<RelationId, Relation>,
    entities: &HashMap<EntityId, Entity>,
    tree: &ResolvedTree,
) -> Vec<RelationId> {
    let mut retired = relations
        .values()
        .filter(|relation| {
            [relation.src, relation.dst]
                .into_iter()
                .any(|node| match node {
                    GraphNodeId::Entity(entity_id) => !entities.contains_key(&entity_id),
                    GraphNodeId::Artifact(artifact_id) => tree.get(&artifact_id).is_none(),
                    _ => false,
                })
        })
        .map(|relation| relation.id)
        .collect::<Vec<_>>();
    retired.sort_unstable();
    retired
}

/// Whether the destination's own members leave room for a path at all.
///
/// A tree is a flat set of paths, so nothing in [`ResolvedTree::apply`] stops a
/// carried entry from landing beneath a member that is a file or an independent
/// checkout, or on top of a path the destination uses as a directory. Both
/// produce a tree that no filesystem can hold, and the failure surfaces much
/// later as a materialization error naming two paths and no remedy. Deciding it
/// here keeps it a refusal a caller can act on.
///
/// `destination_paths` is the destination's paths in sorted order, so the
/// descendant test is a range probe rather than a scan per candidate.
fn path_shape_conflict(
    path: &RepoPath,
    destination_tree: &ResolvedTree,
    destination_paths: &[RepoPath],
) -> Option<WorkspaceCarryConflictKind> {
    let bytes = path.as_bytes();
    let mut boundary = 0;
    while let Some(offset) = bytes[boundary..].iter().position(|byte| *byte == b'/') {
        boundary += offset;
        let ancestor = RepoPath::from_bytes(bytes[..boundary].to_vec())
            .expect("a prefix of a valid repository path up to a separator is itself valid");
        if destination_tree.artifact_at_path(&ancestor).is_some() {
            return Some(WorkspaceCarryConflictKind::PathIsInsideADestinationMember);
        }
        boundary += 1;
    }

    let mut prefix = bytes.to_vec();
    prefix.push(b'/');
    let first = destination_paths.partition_point(|held| held.as_bytes() < prefix.as_slice());
    destination_paths
        .get(first)
        .is_some_and(|held| held.as_bytes().starts_with(&prefix))
        .then_some(WorkspaceCarryConflictKind::PathIsADestinationDirectory)
}

/// Every pending semantic entry the destination cannot take, kept until both
/// replays have run so one refusal can say how much work is pending and of what
/// kind.
///
/// The stranger who found this refusal read "commit the pending work" and had no
/// way to learn that the pending work was sixty-eight relation deltas a
/// background sweep had derived. Counting them here is the whole difference
/// between a mystery and a one-command fix.
///
/// This is a refusal rather than an error, and it is typed so its caller can say
/// so. Returned as a plain error it reached a client as an HTTP 500 with an
/// internal invariant in the body, which is how a designed refusal ends up
/// reading like a crash.
#[derive(Debug, Clone, Default)]
pub struct WorkspaceSemanticCarryRefusal {
    /// Names of the entities the destination holds in another state.
    pub entities: Vec<String>,
    /// Kinds of the edges the destination holds as a *different* edge. A
    /// relation the destination does not hold at all never lands here, because
    /// it is not a conflict.
    pub relations: Vec<RelationKind>,
}

impl WorkspaceSemanticCarryRefusal {
    pub fn is_empty(&self) -> bool {
        self.entities.is_empty() && self.relations.is_empty()
    }

    /// The refusal, naming the pending work, its kinds, and both commands that
    /// clear it.
    pub fn reason(&self) -> String {
        let mut clauses = Vec::new();
        if !self.relations.is_empty() {
            let mut counts = BTreeMap::new();
            for kind in &self.relations {
                *counts.entry(format!("{kind:?}")).or_insert(0_usize) += 1;
            }
            let breakdown = counts
                .into_iter()
                .map(|(kind, count)| format!("{count} {kind}"))
                .collect::<Vec<_>>()
                .join(", ");
            clauses.push(format!(
                "{} pending relation {} ({breakdown})",
                self.relations.len(),
                plural(self.relations.len(), "delta", "deltas")
            ));
        }
        if !self.entities.is_empty() {
            let mut named = self.entities.clone();
            named.sort();
            named.dedup();
            clauses.push(format!(
                "{} pending entity {} ({})",
                self.entities.len(),
                plural(self.entities.len(), "delta", "deltas"),
                named.join(", ")
            ));
        }
        format!(
            "this workspace holds pending work the destination branch cannot take: {}. The \
             destination holds those subjects in a state this pending work was never planned \
             against, so replaying them would discard one side or the other. Run `kin commit` to \
             publish the pending work, or `kin stash push --yes` to set it aside",
            clauses.join(" and ")
        )
    }
}

const fn plural(count: usize, one: &'static str, many: &'static str) -> &'static str {
    if count == 1 {
        one
    } else {
        many
    }
}

/// Whether two relations describe the same edge.
///
/// Identity for the carry precondition is the edge itself: which node points at
/// which, under which kind. `confidence`, `origin`, `created_in`,
/// `import_source` and `evidence` are derivation quality, republished
/// continuously by parser reconciliation and the asynchronous enrichment worker
/// outside the compare-and-swap. Two sides that observed the same edge with
/// different evidence have not disagreed about anything a switch can lose, so
/// requiring byte equality there refuses on the writer's tick rather than on the
/// caller's work.
fn same_edge(left: &Relation, right: &Relation) -> bool {
    left.id == right.id && left.kind == right.kind && left.src == right.src && left.dst == right.dst
}

/// Replay the overlay's entity deltas onto the destination's live entities.
///
/// An addition or a change the destination already holds identically is
/// absorbed, matching rule 2 one layer up. Every other precondition mismatch is
/// recorded as a conflict: the alternative is publishing a workspace whose
/// semantics no observation produced. An entity payload is authored truth rather
/// than derived evidence, so this keeps the strict equality that relations
/// relax.
fn replay_entities(
    deltas: &[EntityDelta],
    destination: &HashMap<EntityId, Entity>,
    refused: &mut WorkspaceSemanticCarryRefusal,
) -> HashMap<EntityId, Entity> {
    let mut entities = destination.clone();
    for delta in deltas {
        match delta {
            EntityDelta::Added { new } => match entities.get(&new.id) {
                Some(held) if held == new => {}
                Some(_) => refused.entities.push(new.name.clone()),
                None => {
                    entities.insert(new.id, new.clone());
                }
            },
            EntityDelta::Modified { old, new } => match entities.get(&old.id) {
                Some(held) if held == old => {
                    entities.insert(new.id, new.clone());
                }
                // The destination already holds exactly what this change
                // produces, so there is nothing left to replay.
                Some(held) if held == new => {}
                Some(_) | None => refused.entities.push(old.name.clone()),
            },
            EntityDelta::Removed { old } => match entities.get(&old.id) {
                Some(held) if held == old => {
                    entities.remove(&old.id);
                }
                Some(_) => refused.entities.push(old.name.clone()),
                // Already retired on the destination, so this pending work is
                // work the destination has done.
                None => {}
            },
        }
    }
    entities
}

/// Replay the overlay's relation deltas onto the destination's live relations.
///
/// Same shape as [`replay_entities`], with the two cases that make a derived
/// edge different from an authored entity kept apart deliberately:
///
/// * the destination holds this relation id as a **different edge**, which is a
///   real conflict and refuses, naming the kind, and
/// * the destination **does not hold it at all**, which is not a conflict. Its
///   head predates the pass that derived the edge, so there is no destination
///   state a replay could discard and the pending observation installs.
///
/// Conflating those two is the defect a stranger hit on v0.7.0: after a
/// background sweep derived sixty-eight relation deltas, every branch switch
/// refused until a commit published them, because each `Modified` delta over an
/// edge the destination had never seen took the conflict path.
fn replay_relations(
    deltas: &[RelationDelta],
    destination: &HashMap<RelationId, Relation>,
    refused: &mut WorkspaceSemanticCarryRefusal,
) -> HashMap<RelationId, Relation> {
    let mut relations = destination.clone();
    for delta in deltas {
        match delta {
            RelationDelta::Added { new } => match relations.get(&new.id) {
                Some(held) if same_edge(held, new) => {
                    relations.insert(new.id, new.clone());
                }
                Some(_) => refused.relations.push(new.kind),
                None => {
                    relations.insert(new.id, new.clone());
                }
            },
            RelationDelta::Modified { old, new } => match relations.get(&old.id) {
                Some(held) if same_edge(held, old) || same_edge(held, new) => {
                    relations.insert(new.id, new.clone());
                }
                Some(_) => refused.relations.push(old.kind),
                None => {
                    relations.insert(new.id, new.clone());
                }
            },
            RelationDelta::Removed { old } => match relations.get(&old.id) {
                Some(held) if same_edge(held, old) => {
                    relations.remove(&old.id);
                }
                Some(_) => refused.relations.push(old.kind),
                None => {}
            },
        }
    }
    relations
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
            other => panic!("expected a path refusal, got {other:?}"),
        }
    }

    fn carried(carry: &WorkspaceCarry) -> &WorkspaceCarryPlan {
        match carry {
            WorkspaceCarry::Carried(plan) => plan,
            other => panic!("expected a carry, refused with {other:?}"),
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

    /// The shape a Gitlink produces, which reached materialization before this
    /// rule existed and failed there as an unactionable internal error.
    #[test]
    fn an_addition_beneath_a_destination_member_refuses() {
        let base = tree(&[(1, "shared.txt", "shared")]);
        let pending = tree(&[
            (1, "shared.txt", "shared"),
            (2, "vendor/dependency/nested/owned.txt", "independent"),
        ]);
        let destination = tree(&[
            (1, "shared.txt", "shared"),
            (3, "vendor/dependency", "link"),
        ]);

        assert_eq!(
            conflicts(&plan(&base, &pending, &destination)),
            vec![(
                "vendor/dependency/nested/owned.txt".to_string(),
                WorkspaceCarryConflictKind::PathIsInsideADestinationMember
            )]
        );
    }

    #[test]
    fn an_addition_over_a_destination_directory_refuses() {
        let base = tree(&[(1, "shared.txt", "shared")]);
        let pending = tree(&[(1, "shared.txt", "shared"), (2, "src", "a file now")]);
        let destination = tree(&[(1, "shared.txt", "shared"), (3, "src/lib.rs", "a module")]);

        assert_eq!(
            conflicts(&plan(&base, &pending, &destination)),
            vec![(
                "src".to_string(),
                WorkspaceCarryConflictKind::PathIsADestinationDirectory
            )]
        );
    }

    /// A path that merely shares a textual prefix with a destination member is
    /// not inside it, so the shape rule must not fire on `src-notes.md` because
    /// the destination happens to track `src/lib.rs`.
    #[test]
    fn a_sibling_sharing_a_textual_prefix_still_carries() {
        let base = tree(&[(1, "shared.txt", "shared")]);
        let pending = tree(&[(1, "shared.txt", "shared"), (2, "src-notes.md", "notes")]);
        let destination = tree(&[(1, "shared.txt", "shared"), (3, "src/lib.rs", "a module")]);

        let plan = plan(&base, &pending, &destination);
        assert_eq!(
            carried(&plan)
                .carried
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            vec!["src-notes.md".to_string()]
        );
    }

    /// The mirror of the above on the ancestor side: `vendor/dependency2` is not
    /// inside `vendor/dependency`, and a byte-prefix test with no separator
    /// boundary would wrongly refuse it.
    #[test]
    fn an_addition_beside_a_destination_member_still_carries() {
        let base = tree(&[(1, "shared.txt", "shared")]);
        let pending = tree(&[
            (1, "shared.txt", "shared"),
            (2, "vendor/dependency2/note.md", "beside"),
        ]);
        let destination = tree(&[
            (1, "shared.txt", "shared"),
            (3, "vendor/dependency", "link"),
        ]);

        let plan = plan(&base, &pending, &destination);
        assert_eq!(
            carried(&plan)
                .carried
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            vec!["vendor/dependency2/note.md".to_string()]
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

/// The stranger-run reproduction of the two v0.7.0 branch-switch defects, and
/// the contract that replaced them.
///
/// Kept in its own module so the fixtures that build a semantic overlay do not
/// crowd the tree-only fixtures above, and so a reader chasing either defect
/// lands on the whole story in one place.
#[cfg(test)]
mod semantic_carry_tests {
    use super::*;
    use kin_model::{
        entity::Entity, ArtifactId, EntityKind, EntityMetadata, EntityRole, FilePathId,
        FingerprintAlgorithm, GraphNodeId, Hash256, LanguageId, LocatedEntry, RelationKind,
        RelationOrigin, SemanticFingerprint, TreeEntry, Visibility,
    };

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

    fn entity_id(value: u128) -> EntityId {
        EntityId(uuid::Uuid::from_u128(value))
    }

    fn relation_id(value: u128) -> RelationId {
        RelationId(uuid::Uuid::from_u128(value))
    }

    fn entity(id: u128, name: &str, file: &str) -> Entity {
        Entity {
            id: entity_id(id),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Python,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([1; 32]),
                signature_hash: Hash256::from_bytes([2; 32]),
                behavior_hash: Hash256::from_bytes([3; 32]),
                equivalence_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(file)),
            span: None,
            signature: format!("def {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn relation(id: u128, src: u128, dst: u128, kind: RelationKind) -> Relation {
        Relation {
            id: relation_id(id),
            kind,
            src: GraphNodeId::Entity(entity_id(src)),
            dst: GraphNodeId::Entity(entity_id(dst)),
            confidence: 0.5,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        }
    }

    /// The same edge one enrichment pass later: the LSP worker resolved the
    /// type, so origin and confidence move and the edge itself does not.
    fn enriched(relation: &Relation) -> Relation {
        Relation {
            confidence: 1.0,
            origin: RelationOrigin::Lsp,
            ..relation.clone()
        }
    }

    fn entities(members: &[Entity]) -> HashMap<EntityId, Entity> {
        members
            .iter()
            .map(|entity| (entity.id, entity.clone()))
            .collect()
    }

    fn relations(members: &[Relation]) -> HashMap<RelationId, Relation> {
        members
            .iter()
            .map(|relation| (relation.id, relation.clone()))
            .collect()
    }

    fn overlay(
        entity_deltas: Vec<EntityDelta>,
        relation_deltas: Vec<RelationDelta>,
    ) -> WorkspaceSemanticOverlay {
        WorkspaceSemanticOverlay::new(entity_deltas, relation_deltas)
            .expect("build a fixture workspace semantic overlay")
    }

    fn carried(carry: &WorkspaceCarry) -> &WorkspaceCarryPlan {
        match carry {
            WorkspaceCarry::Carried(plan) => plan,
            other => panic!("expected a carry, refused with {other:?}"),
        }
    }

    /// Defect 1, the one that stopped the stranger: background enrichment
    /// leaves relation-only pending state, and every switch refuses until a
    /// commit publishes it.
    ///
    /// The workspace edited `parsing.py`, a member both branches hold
    /// byte-identically, so rule 4 carries the tree side. The enrichment worker
    /// then upgraded one `UsesType` edge over that member from a parsed guess
    /// to an LSP-resolved fact, which is a relation-only `Modified` delta. On
    /// v0.7.0 that alone refused the switch with `pending relation UsesType
    /// cannot be replayed onto the destination branch`.
    #[test]
    fn an_enrichment_upgrade_over_a_member_both_branches_hold_carries() {
        let base = tree(&[(1, "parsing.py", "base"), (2, "storage.py", "shared")]);
        let pending = tree(&[(1, "parsing.py", "edited"), (2, "storage.py", "shared")]);
        let destination = tree(&[(1, "parsing.py", "base"), (2, "storage.py", "shared")]);

        let parse = entity(10, "parse", "parsing.py");
        let store = entity(11, "store", "storage.py");
        let edge = relation(20, 10, 11, RelationKind::UsesType);

        let carry = plan_workspace_carry(
            &base,
            &pending,
            &overlay(
                Vec::new(),
                vec![RelationDelta::Modified {
                    old: edge.clone(),
                    new: enriched(&edge),
                }],
            ),
            &destination,
            &entities(&[parse, store]),
            &relations(std::slice::from_ref(&edge)),
        )
        .expect("a relation-only enrichment upgrade must not refuse the switch");

        let plan = carried(&carry);
        assert_eq!(
            plan.relations.get(&edge.id),
            Some(&enriched(&edge)),
            "the enriched edge must arrive on the destination in its enriched form"
        );
        assert!(plan.retired_relations.is_empty());
    }

    /// Defect 1, probe 3: a five-word untracked markdown file, with the same
    /// relation-only enrichment pending behind it. The file is the only tree
    /// work, so nothing about it can conflict, and the switch still refused on
    /// v0.7.0 because the overlay went through the same replay.
    ///
    /// The destination does not hold the edge, which is the shape that actually
    /// refused: its head predates the sweep that derived it. A first draft of
    /// this test gave the destination the edge, and it passed with the defect
    /// reinstated, which is a test that cannot fail for what it claims to cover.
    #[test]
    fn a_lone_untracked_file_carries_while_enrichment_is_pending() {
        let base = tree(&[(1, "parsing.py", "base")]);
        let pending = tree(&[
            (1, "parsing.py", "base"),
            (2, "notes.md", "five words here"),
        ]);
        let destination = tree(&[(1, "parsing.py", "base"), (3, "export.py", "only there")]);

        let parse = entity(10, "parse", "parsing.py");
        let edge = relation(20, 10, 10, RelationKind::References);

        let carry = plan_workspace_carry(
            &base,
            &pending,
            &overlay(
                Vec::new(),
                vec![RelationDelta::Modified {
                    old: edge.clone(),
                    new: enriched(&edge),
                }],
            ),
            &destination,
            &entities(&[parse]),
            &relations(&[]),
        )
        .expect("an untracked file plus pending enrichment must not refuse the switch");

        let plan = carried(&carry);
        assert_eq!(
            plan.carried
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            vec!["notes.md".to_string()]
        );
        assert_eq!(plan.relations.get(&edge.id), Some(&enriched(&edge)));
    }

    /// The destination branch never observed the edge at all, because its head
    /// predates the enrichment pass. Carrying the pending work means installing
    /// it, and both endpoints are present, so nothing is invented.
    #[test]
    fn an_enrichment_upgrade_the_destination_never_observed_carries() {
        let base = tree(&[(1, "parsing.py", "base")]);
        let pending = tree(&[(1, "parsing.py", "edited")]);
        let destination = tree(&[(1, "parsing.py", "base")]);

        let parse = entity(10, "parse", "parsing.py");
        let store = entity(11, "store", "parsing.py");
        let edge = relation(20, 10, 11, RelationKind::UsesType);

        let carry = plan_workspace_carry(
            &base,
            &pending,
            &overlay(
                Vec::new(),
                vec![RelationDelta::Modified {
                    old: edge.clone(),
                    new: enriched(&edge),
                }],
            ),
            &destination,
            &entities(&[parse, store]),
            &relations(&[]),
        )
        .expect("a destination that never observed the edge must not refuse the switch");

        assert_eq!(
            carried(&carry).relations.get(&edge.id),
            Some(&enriched(&edge))
        );
    }

    /// Defect 2, the wedge: pending work retires an entity, the destination
    /// holds an edge into it, and nothing retires that edge. On v0.7.0 the plan
    /// carried the orphan through, kin-db's preflight refused the resulting
    /// transaction with `has unadmitted source endpoint entity:<id>`, and
    /// commit, stash push and branch switch then all refused at once naming an
    /// entity `kin graph inspect` says does not exist.
    ///
    /// A plan may not hand that shape downstream. The edge into a retired
    /// entity is retired in the same plan and counted.
    #[test]
    fn an_edge_into_an_entity_the_pending_work_retires_is_retired_with_it() {
        let base = tree(&[(1, "storage.py", "base"), (2, "reporting.py", "shared")]);
        let pending = tree(&[(1, "storage.py", "edited"), (2, "reporting.py", "shared")]);
        let destination = tree(&[(1, "storage.py", "base"), (2, "reporting.py", "shared")]);

        let gone = entity(10, "grand_total", "storage.py");
        let report = entity(11, "format_report", "reporting.py");
        let orphaning = relation(20, 11, 10, RelationKind::UsesType);

        let carry = plan_workspace_carry(
            &base,
            &pending,
            &overlay(vec![EntityDelta::Removed { old: gone.clone() }], Vec::new()),
            &destination,
            &entities(&[gone.clone(), report]),
            &relations(std::slice::from_ref(&orphaning)),
        )
        .expect("retiring an entity must not refuse the switch");

        let plan = carried(&carry);
        assert!(
            !plan.entities.contains_key(&gone.id),
            "the pending removal still retires the entity"
        );
        assert!(
            !plan.relations.contains_key(&orphaning.id),
            "the edge into the retired entity must not survive the plan"
        );
        assert_eq!(plan.retired_relations, vec![orphaning.id]);
        assert_eq!(
            unadmitted_endpoints(&plan.relations, &plan.entities, &plan.tree),
            Vec::<RelationId>::new(),
            "no relation in a carry plan may point at a node the plan does not hold"
        );
    }

    /// A relation whose endpoint artifact the pending work removes is the same
    /// class one node kind over, and it is retired the same way.
    #[test]
    fn an_edge_into_an_artifact_the_pending_work_removes_is_retired_with_it() {
        let base = tree(&[(1, "storage.py", "base"), (2, "reporting.py", "shared")]);
        let pending = tree(&[(2, "reporting.py", "shared")]);
        let destination = tree(&[(1, "storage.py", "base"), (2, "reporting.py", "shared")]);

        let report = entity(11, "format_report", "reporting.py");
        let into_artifact = Relation {
            dst: GraphNodeId::Artifact(ArtifactId(uuid::Uuid::from_u128(1))),
            ..relation(20, 11, 11, RelationKind::References)
        };

        let carry = plan_workspace_carry(
            &base,
            &pending,
            &overlay(Vec::new(), Vec::new()),
            &destination,
            &entities(&[report]),
            &relations(std::slice::from_ref(&into_artifact)),
        )
        .expect("removing a member must not refuse the switch");

        let plan = carried(&carry);
        assert_eq!(plan.retired_relations, vec![into_artifact.id]);
        assert!(!plan.relations.contains_key(&into_artifact.id));
    }

    /// The refusal that remains has to say what it is refusing on. The stranger
    /// read `commit the pending work` and had no way to learn that the pending
    /// work was 68 relation deltas from a background sweep.
    #[test]
    fn a_refusal_names_the_pending_work_its_kinds_and_the_command_that_clears_it() {
        let base = tree(&[(1, "parsing.py", "base")]);
        let pending = tree(&[(1, "parsing.py", "edited")]);
        let destination = tree(&[(1, "parsing.py", "base")]);

        let parse = entity(10, "parse", "parsing.py");
        let store = entity(11, "store", "parsing.py");
        let mine = relation(20, 10, 11, RelationKind::UsesType);
        let theirs = Relation {
            kind: RelationKind::Calls,
            ..mine.clone()
        };
        let second = relation(21, 11, 10, RelationKind::References);
        let second_theirs = Relation {
            kind: RelationKind::Implements,
            ..second.clone()
        };

        let carry = plan_workspace_carry(
            &base,
            &pending,
            &overlay(
                Vec::new(),
                vec![
                    RelationDelta::Modified {
                        old: mine.clone(),
                        new: enriched(&mine),
                    },
                    RelationDelta::Modified {
                        old: second.clone(),
                        new: enriched(&second),
                    },
                ],
            ),
            &destination,
            &entities(&[parse, store]),
            &relations(&[theirs, second_theirs]),
        )
        .expect("a semantic conflict is a refusal, not an error");
        let WorkspaceCarry::SemanticallyRefused(refusal) = &carry else {
            panic!(
                "a destination holding a different edge under the same id is a real conflict, got \
                 {carry:?}"
            );
        };
        let error = refusal.reason();

        assert!(
            error.contains("2 pending relation deltas"),
            "the refusal must count the pending work: {error}"
        );
        assert!(
            error.contains("UsesType") && error.contains("References"),
            "the refusal must name the kinds it is refusing on: {error}"
        );
        assert!(
            error.contains("kin commit"),
            "the refusal must name the command that publishes the pending work: {error}"
        );
        assert!(
            error.contains("kin stash push --yes"),
            "the refusal must name the command that sets the pending work aside: {error}"
        );
    }
}
